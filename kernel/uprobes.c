/*
 * Userspace Probes (UProbes)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2008-2011
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/uprobes.h>

static struct rb_root uprobes_tree = RB_ROOT;
static DEFINE_SPINLOCK(uprobes_treelock);	/* serialize rbtree access */

#define UPROBES_HASH_SZ	13
/* serialize (un)register */
static struct mutex uprobes_mutex[UPROBES_HASH_SZ];
#define uprobes_hash(v)	(&uprobes_mutex[((unsigned long)(v)) %\
						UPROBES_HASH_SZ])

/*
 * Maintain a temporary per vma info that can be used to search if a vma
 * has already been handled. This structure is introduced since extending
 * vm_area_struct wasnt recommended.
 */
struct vma_info {
	struct list_head probe_list;
	struct mm_struct *mm;
	loff_t vaddr;
};

/*
 * valid_vma: Verify if the specified vma is an executable vma
 * Relax restrictions while unregistering: vm_flags might have
 * changed after breakpoint was inserted.
 *	- is_reg: indicates if we are in register context.
 *	- Return 1 if the specified virtual address is in an
 *	  executable vma.
 */
static bool valid_vma(struct vm_area_struct *vma, bool is_reg)
{
	if (!vma->vm_file)
		return false;

	if (!is_reg)
		return true;

	if ((vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)) ==
						(VM_READ|VM_EXEC))
		return true;

	return false;
}

static int match_uprobe(struct uprobe *l, struct uprobe *r)
{
	if (l->inode < r->inode)
		return -1;
	if (l->inode > r->inode)
		return 1;
	else {
		if (l->offset < r->offset)
			return -1;

		if (l->offset > r->offset)
			return 1;
	}

	return 0;
}

static struct uprobe *__find_uprobe(struct inode *inode, loff_t offset)
{
	struct uprobe u = { .inode = inode, .offset = offset };
	struct rb_node *n = uprobes_tree.rb_node;
	struct uprobe *uprobe;
	int match;

	while (n) {
		uprobe = rb_entry(n, struct uprobe, rb_node);
		match = match_uprobe(&u, uprobe);
		if (!match) {
			atomic_inc(&uprobe->ref);
			return uprobe;
		}
		if (match < 0)
			n = n->rb_left;
		else
			n = n->rb_right;

	}
	return NULL;
}

/*
 * Find a uprobe corresponding to a given inode:offset
 * Acquires uprobes_treelock
 */
static struct uprobe *find_uprobe(struct inode *inode, loff_t offset)
{
	struct uprobe *uprobe;
	unsigned long flags;

	spin_lock_irqsave(&uprobes_treelock, flags);
	uprobe = __find_uprobe(inode, offset);
	spin_unlock_irqrestore(&uprobes_treelock, flags);
	return uprobe;
}

static struct uprobe *__insert_uprobe(struct uprobe *uprobe)
{
	struct rb_node **p = &uprobes_tree.rb_node;
	struct rb_node *parent = NULL;
	struct uprobe *u;
	int match;

	while (*p) {
		parent = *p;
		u = rb_entry(parent, struct uprobe, rb_node);
		match = match_uprobe(uprobe, u);
		if (!match) {
			atomic_inc(&u->ref);
			return u;
		}

		if (match < 0)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;

	}
	u = NULL;
	rb_link_node(&uprobe->rb_node, parent, p);
	rb_insert_color(&uprobe->rb_node, &uprobes_tree);
	/* get access + creation ref */
	atomic_set(&uprobe->ref, 2);
	return u;
}

/*
 * Acquires uprobes_treelock.
 * Matching uprobe already exists in rbtree;
 *	increment (access refcount) and return the matching uprobe.
 *
 * No matching uprobe; insert the uprobe in rb_tree;
 *	get a double refcount (access + creation) and return NULL.
 */
static struct uprobe *insert_uprobe(struct uprobe *uprobe)
{
	unsigned long flags;
	struct uprobe *u;

	spin_lock_irqsave(&uprobes_treelock, flags);
	u = __insert_uprobe(uprobe);
	spin_unlock_irqrestore(&uprobes_treelock, flags);
	return u;
}

static void put_uprobe(struct uprobe *uprobe)
{
	if (atomic_dec_and_test(&uprobe->ref))
		kfree(uprobe);
}

static struct uprobe *alloc_uprobe(struct inode *inode, loff_t offset)
{
	struct uprobe *uprobe, *cur_uprobe;

	uprobe = kzalloc(sizeof(struct uprobe), GFP_KERNEL);
	if (!uprobe)
		return NULL;

	uprobe->inode = igrab(inode);
	uprobe->offset = offset;
	init_rwsem(&uprobe->consumer_rwsem);

	/* add to uprobes_tree, sorted on inode:offset */
	cur_uprobe = insert_uprobe(uprobe);

	/* a uprobe exists for this inode:offset combination */
	if (cur_uprobe) {
		kfree(uprobe);
		uprobe = cur_uprobe;
		iput(inode);
	}
	return uprobe;
}

/* Returns the previous consumer */
static struct uprobe_consumer *add_consumer(struct uprobe *uprobe,
				struct uprobe_consumer *consumer)
{
	down_write(&uprobe->consumer_rwsem);
	consumer->next = uprobe->consumers;
	uprobe->consumers = consumer;
	up_write(&uprobe->consumer_rwsem);
	return consumer->next;
}

/*
 * For uprobe @uprobe, delete the consumer @consumer.
 * Return true if the @consumer is deleted successfully
 * or return false.
 */
static bool del_consumer(struct uprobe *uprobe,
				struct uprobe_consumer *consumer)
{
	struct uprobe_consumer **con;
	bool ret = false;

	down_write(&uprobe->consumer_rwsem);
	for (con = &uprobe->consumers; *con; con = &(*con)->next) {
		if (*con == consumer) {
			*con = consumer->next;
			ret = true;
			break;
		}
	}
	up_write(&uprobe->consumer_rwsem);
	return ret;
}

static int install_breakpoint(struct mm_struct *mm)
{
	/* Placeholder: Yet to be implemented */
	return 0;
}

static void remove_breakpoint(struct mm_struct *mm)
{
	/* Placeholder: Yet to be implemented */
	return;
}

static void delete_uprobe(struct uprobe *uprobe)
{
	unsigned long flags;

	spin_lock_irqsave(&uprobes_treelock, flags);
	rb_erase(&uprobe->rb_node, &uprobes_tree);
	spin_unlock_irqrestore(&uprobes_treelock, flags);
	iput(uprobe->inode);
	put_uprobe(uprobe);
}

static struct vma_info *__find_next_vma_info(struct list_head *head,
			loff_t offset, struct address_space *mapping,
			struct vma_info *vi, bool is_register)
{
	struct prio_tree_iter iter;
	struct vm_area_struct *vma;
	struct vma_info *tmpvi;
	loff_t vaddr;
	unsigned long pgoff = offset >> PAGE_SHIFT;
	int existing_vma;

	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if (!valid_vma(vma, is_register))
			continue;

		existing_vma = 0;
		vaddr = vma->vm_start + offset;
		vaddr -= vma->vm_pgoff << PAGE_SHIFT;
		list_for_each_entry(tmpvi, head, probe_list) {
			if (tmpvi->mm == vma->vm_mm && tmpvi->vaddr == vaddr) {
				existing_vma = 1;
				break;
			}
		}

		/*
		 * Another vma needs a probe to be installed. However skip
		 * installing the probe if the vma is about to be unlinked.
		 */
		if (!existing_vma &&
				atomic_inc_not_zero(&vma->vm_mm->mm_users)) {
			vi->mm = vma->vm_mm;
			vi->vaddr = vaddr;
			list_add(&vi->probe_list, head);
			return vi;
		}
	}
	return NULL;
}

/*
 * Iterate in the rmap prio tree  and find a vma where a probe has not
 * yet been inserted.
 */
static struct vma_info *find_next_vma_info(struct list_head *head,
			loff_t offset, struct address_space *mapping,
			bool is_register)
{
	struct vma_info *vi, *retvi;
	vi = kzalloc(sizeof(struct vma_info), GFP_KERNEL);
	if (!vi)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&mapping->i_mmap_mutex);
	retvi = __find_next_vma_info(head, offset, mapping, vi, is_register);
	mutex_unlock(&mapping->i_mmap_mutex);

	if (!retvi)
		kfree(vi);
	return retvi;
}

static int __register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe *uprobe)
{
	struct list_head try_list;
	struct vm_area_struct *vma;
	struct address_space *mapping;
	struct vma_info *vi, *tmpvi;
	struct mm_struct *mm;
	loff_t vaddr;
	int ret = 0;

	mapping = inode->i_mapping;
	INIT_LIST_HEAD(&try_list);
	while ((vi = find_next_vma_info(&try_list, offset,
						mapping, true)) != NULL) {
		if (IS_ERR(vi)) {
			ret = -ENOMEM;
			break;
		}
		mm = vi->mm;
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, (unsigned long)vi->vaddr);
		if (!vma || !valid_vma(vma, true)) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}
		vaddr = vma->vm_start + offset;
		vaddr -= vma->vm_pgoff << PAGE_SHIFT;
		if (vma->vm_file->f_mapping->host != inode ||
						vaddr != vi->vaddr) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}
		ret = install_breakpoint(mm);
		up_read(&mm->mmap_sem);
		mmput(mm);
		if (ret && ret == -EEXIST)
			ret = 0;
		if (!ret)
			break;
	}
	list_for_each_entry_safe(vi, tmpvi, &try_list, probe_list) {
		list_del(&vi->probe_list);
		kfree(vi);
	}
	return ret;
}

static void __unregister_uprobe(struct inode *inode, loff_t offset,
						struct uprobe *uprobe)
{
	struct list_head try_list;
	struct address_space *mapping;
	struct vma_info *vi, *tmpvi;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	loff_t vaddr;

	mapping = inode->i_mapping;
	INIT_LIST_HEAD(&try_list);
	while ((vi = find_next_vma_info(&try_list, offset,
						mapping, false)) != NULL) {
		if (IS_ERR(vi))
			break;
		mm = vi->mm;
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, (unsigned long)vi->vaddr);
		if (!vma || !valid_vma(vma, false)) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}
		vaddr = vma->vm_start + offset;
		vaddr -= vma->vm_pgoff << PAGE_SHIFT;
		if (vma->vm_file->f_mapping->host != inode ||
						vaddr != vi->vaddr) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}
		remove_breakpoint(mm);
		up_read(&mm->mmap_sem);
		mmput(mm);
	}

	list_for_each_entry_safe(vi, tmpvi, &try_list, probe_list) {
		list_del(&vi->probe_list);
		kfree(vi);
	}
	delete_uprobe(uprobe);
}

/*
 * register_uprobe - register a probe
 * @inode: the file in which the probe has to be placed.
 * @offset: offset from the start of the file.
 * @consumer: information on howto handle the probe..
 *
 * Apart from the access refcount, register_uprobe() takes a creation
 * refcount (thro alloc_uprobe) if and only if this @uprobe is getting
 * inserted into the rbtree (i.e first consumer for a @inode:@offset
 * tuple).  Creation refcount stops unregister_uprobe from freeing the
 * @uprobe even before the register operation is complete. Creation
 * refcount is released when the last @consumer for the @uprobe
 * unregisters.
 *
 * Return errno if it cannot successully install probes
 * else return 0 (success)
 */
int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	struct uprobe *uprobe;
	int ret = -EINVAL;

	if (!consumer || consumer->next)
		return ret;

	inode = igrab(inode);
	if (!inode)
		return ret;

	if (offset > i_size_read(inode))
		goto reg_out;

	ret = 0;
	mutex_lock(uprobes_hash(inode));
	uprobe = alloc_uprobe(inode, offset);
	if (uprobe && !add_consumer(uprobe, consumer)) {
		ret = __register_uprobe(inode, offset, uprobe);
		if (ret) {
			uprobe->consumers = NULL;
			__unregister_uprobe(inode, offset, uprobe);
		}
	}

	mutex_unlock(uprobes_hash(inode));
	put_uprobe(uprobe);

reg_out:
	iput(inode);
	return ret;
}

/*
 * unregister_uprobe - unregister a already registered probe.
 * @inode: the file in which the probe has to be removed.
 * @offset: offset from the start of the file.
 * @consumer: identify which probe if multiple probes are colocated.
 */
void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	struct uprobe *uprobe = NULL;

	inode = igrab(inode);
	if (!inode || !consumer)
		goto unreg_out;

	uprobe = find_uprobe(inode, offset);
	if (!uprobe)
		goto unreg_out;

	mutex_lock(uprobes_hash(inode));
	if (!del_consumer(uprobe, consumer)) {
		mutex_unlock(uprobes_hash(inode));
		goto unreg_out;
	}

	if (!uprobe->consumers)
		__unregister_uprobe(inode, offset, uprobe);

	mutex_unlock(uprobes_hash(inode));

unreg_out:
	if (uprobe)
		put_uprobe(uprobe);
	if (inode)
		iput(inode);
}

static int __init init_uprobes(void)
{
	int i;

	for (i = 0; i < UPROBES_HASH_SZ; i++)
		mutex_init(&uprobes_mutex[i]);

	return 0;
}

static void __exit exit_uprobes(void)
{
}

module_init(init_uprobes);
module_exit(exit_uprobes);
