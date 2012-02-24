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
#include <linux/pagemap.h>	/* read_mapping_page */
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/rmap.h>		/* anon_vma_prepare */
#include <linux/mmu_notifier.h>	/* set_pte_at_notify */
#include <linux/swap.h>		/* try_to_free_swap */
#include <linux/ptrace.h>	/* user_enable_single_step */
#include <linux/kdebug.h>	/* notifier mechanism */
#include <linux/uprobes.h>

#define UINSNS_PER_PAGE	(PAGE_SIZE/UPROBES_XOL_SLOT_BYTES)
#define MAX_UPROBES_XOL_SLOTS UINSNS_PER_PAGE

static struct srcu_struct uprobes_srcu;
static struct rb_root uprobes_tree = RB_ROOT;
static DEFINE_SPINLOCK(uprobes_treelock);	/* serialize rbtree access */

#define UPROBES_HASH_SZ	13
/* serialize (un)register */
static struct mutex uprobes_mutex[UPROBES_HASH_SZ];
#define uprobes_hash(v)	(&uprobes_mutex[((unsigned long)(v)) %\
						UPROBES_HASH_SZ])

/* serialize uprobe->pending_list */
static struct mutex uprobes_mmap_mutex[UPROBES_HASH_SZ];
#define uprobes_mmap_hash(v)	(&uprobes_mmap_mutex[((unsigned long)(v)) %\
						UPROBES_HASH_SZ])

/*
 * uprobe_events allows us to skip the mmap_uprobe if there are no uprobe
 * events active at this time.  Probably a fine grained per inode count is
 * better?
 */
static atomic_t uprobe_events = ATOMIC_INIT(0);

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
 *	- is_register: indicates if we are in register context.
 *	- Return 1 if the specified virtual address is in an
 *	  executable vma.
 */
static bool valid_vma(struct vm_area_struct *vma, bool is_register)
{
	if (!vma->vm_file)
		return false;

	if (!is_register)
		return true;

	if ((vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)) ==
						(VM_READ|VM_EXEC))
		return true;

	return false;
}

static loff_t vma_address(struct vm_area_struct *vma, loff_t offset)
{
	loff_t vaddr;

	vaddr = vma->vm_start + offset;
	vaddr -= vma->vm_pgoff << PAGE_SHIFT;
	return vaddr;
}

/**
 * __replace_page - replace page in vma by new page.
 * based on replace_page in mm/ksm.c
 *
 * @vma:      vma that holds the pte pointing to page
 * @page:     the cowed page we are replacing by kpage
 * @kpage:    the modified page we replace page by
 *
 * Returns 0 on success, -EFAULT on failure.
 */
static int __replace_page(struct vm_area_struct *vma, struct page *page,
					struct page *kpage)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	spinlock_t *ptl;
	unsigned long addr;
	int err = -EFAULT;

	addr = page_address_in_vma(page, vma);
	if (addr == -EFAULT)
		goto out;

	pgd = pgd_offset(mm, addr);
	if (!pgd_present(*pgd))
		goto out;

	pud = pud_offset(pgd, addr);
	if (!pud_present(*pud))
		goto out;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		goto out;

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!ptep)
		goto out;

	get_page(kpage);
	page_add_new_anon_rmap(kpage, vma, addr);

	flush_cache_page(vma, addr, pte_pfn(*ptep));
	ptep_clear_flush(vma, addr, ptep);
	set_pte_at_notify(mm, addr, ptep, mk_pte(kpage, vma->vm_page_prot));

	page_remove_rmap(page);
	if (!page_mapped(page))
		try_to_free_swap(page);
	put_page(page);
	pte_unmap_unlock(ptep, ptl);
	err = 0;

out:
	return err;
}

/**
 * is_bkpt_insn - check if instruction is breakpoint instruction.
 * @insn: instruction to be checked.
 * Default implementation of is_bkpt_insn
 * Returns true if @insn is a breakpoint instruction.
 */
bool __weak is_bkpt_insn(uprobe_opcode_t *insn)
{
	return (*insn == UPROBES_BKPT_INSN);
}

/*
 * NOTE:
 * Expect the breakpoint instruction to be the smallest size instruction for
 * the architecture. If an arch has variable length instruction and the
 * breakpoint instruction is not of the smallest length instruction
 * supported by that architecture then we need to modify read_opcode /
 * write_opcode accordingly. This would never be a problem for archs that
 * have fixed length instructions.
 */

/*
 * write_opcode - write the opcode at a given virtual address.
 * @mm: the probed process address space.
 * @uprobe: the breakpointing information.
 * @vaddr: the virtual address to store the opcode.
 * @opcode: opcode to be written at @vaddr.
 *
 * Called with mm->mmap_sem held (for read and with a reference to
 * mm).
 *
 * For mm @mm, write the opcode at @vaddr.
 * Return 0 (success) or a negative errno.
 */
static int write_opcode(struct mm_struct *mm, struct uprobe *uprobe,
			unsigned long vaddr, uprobe_opcode_t opcode)
{
	struct page *old_page, *new_page;
	struct address_space *mapping;
	void *vaddr_old, *vaddr_new;
	struct vm_area_struct *vma;
	loff_t addr;
	int ret;

	/* Read the page with vaddr into memory */
	ret = get_user_pages(NULL, mm, vaddr, 1, 0, 0, &old_page, &vma);
	if (ret <= 0)
		return ret;
	ret = -EINVAL;

	/*
	 * We are interested in text pages only. Our pages of interest
	 * should be mapped for read and execute only. We desist from
	 * adding probes in write mapped pages since the breakpoints
	 * might end up in the file copy.
	 */
	if (!valid_vma(vma, is_bkpt_insn(&opcode)))
		goto put_out;

	mapping = uprobe->inode->i_mapping;
	if (mapping != vma->vm_file->f_mapping)
		goto put_out;

	addr = vma_address(vma, uprobe->offset);
	if (vaddr != (unsigned long)addr)
		goto put_out;

	ret = -ENOMEM;
	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vaddr);
	if (!new_page)
		goto put_out;

	__SetPageUptodate(new_page);

	/*
	 * lock page will serialize against do_wp_page()'s
	 * PageAnon() handling
	 */
	lock_page(old_page);
	/* copy the page now that we've got it stable */
	vaddr_old = kmap_atomic(old_page);
	vaddr_new = kmap_atomic(new_page);

	memcpy(vaddr_new, vaddr_old, PAGE_SIZE);
	/* poke the new insn in, ASSUMES we don't cross page boundary */
	vaddr &= ~PAGE_MASK;
	BUG_ON(vaddr + uprobe_opcode_sz > PAGE_SIZE);
	memcpy(vaddr_new + vaddr, &opcode, uprobe_opcode_sz);

	kunmap_atomic(vaddr_new);
	kunmap_atomic(vaddr_old);

	ret = anon_vma_prepare(vma);
	if (ret)
		goto unlock_out;

	lock_page(new_page);
	ret = __replace_page(vma, old_page, new_page);
	unlock_page(new_page);

unlock_out:
	unlock_page(old_page);
	page_cache_release(new_page);

put_out:
	put_page(old_page);	/* we did a get_page in the beginning */
	return ret;
}

/**
 * read_opcode - read the opcode at a given virtual address.
 * @mm: the probed process address space.
 * @vaddr: the virtual address to read the opcode.
 * @opcode: location to store the read opcode.
 *
 * Called with mm->mmap_sem held (for read and with a reference to
 * mm.
 *
 * For mm @mm, read the opcode at @vaddr and store it in @opcode.
 * Return 0 (success) or a negative errno.
 */
static int read_opcode(struct mm_struct *mm, unsigned long vaddr,
						uprobe_opcode_t *opcode)
{
	struct page *page;
	void *vaddr_new;
	int ret;

	ret = get_user_pages(NULL, mm, vaddr, 1, 0, 0, &page, NULL);
	if (ret <= 0)
		return ret;

	lock_page(page);
	vaddr_new = kmap_atomic(page);
	vaddr &= ~PAGE_MASK;
	memcpy(opcode, vaddr_new + vaddr, uprobe_opcode_sz);
	kunmap_atomic(vaddr_new);
	unlock_page(page);
	put_page(page);		/* we did a get_user_pages in the beginning */
	return 0;
}

static int is_bkpt_at_addr(struct mm_struct *mm, unsigned long vaddr)
{
	uprobe_opcode_t opcode;
	int result = read_opcode(mm, vaddr, &opcode);

	if (result)
		return result;

	if (is_bkpt_insn(&opcode))
		return 1;

	return 0;
}

/**
 * set_bkpt - store breakpoint at a given address.
 * @mm: the probed process address space.
 * @uprobe: the probepoint information.
 * @vaddr: the virtual address to insert the opcode.
 *
 * For mm @mm, store the breakpoint instruction at @vaddr.
 * Return 0 (success) or a negative errno.
 */
int __weak set_bkpt(struct mm_struct *mm, struct uprobe *uprobe,
						unsigned long vaddr)
{
	int result = is_bkpt_at_addr(mm, vaddr);

	if (result == 1)
		return -EEXIST;

	if (result)
		return result;

	return write_opcode(mm, uprobe, vaddr, UPROBES_BKPT_INSN);
}

/**
 * set_orig_insn - Restore the original instruction.
 * @mm: the probed process address space.
 * @uprobe: the probepoint information.
 * @vaddr: the virtual address to insert the opcode.
 * @verify: if true, verify existance of breakpoint instruction.
 *
 * For mm @mm, restore the original opcode (opcode) at @vaddr.
 * Return 0 (success) or a negative errno.
 */
int __weak set_orig_insn(struct mm_struct *mm, struct uprobe *uprobe,
					unsigned long vaddr, bool verify)
{
	if (verify) {
		int result = is_bkpt_at_addr(mm, vaddr);

		if (!result)
			return -EINVAL;

		if (result != 1)
			return result;
	}
	return write_opcode(mm, uprobe, vaddr,
				*(uprobe_opcode_t *)uprobe->insn);
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

	/* For now assume that the instruction need not be single-stepped */
	uprobe->flags |= UPROBES_SKIP_SSTEP;
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
	INIT_LIST_HEAD(&uprobe->pending_list);

	/* add to uprobes_tree, sorted on inode:offset */
	cur_uprobe = insert_uprobe(uprobe);

	/* a uprobe exists for this inode:offset combination */
	if (cur_uprobe) {
		kfree(uprobe);
		uprobe = cur_uprobe;
		iput(inode);
	} else
		atomic_inc(&uprobe_events);
	return uprobe;
}

static void handler_chain(struct uprobe *uprobe, struct pt_regs *regs)
{
	struct uprobe_consumer *consumer;

	if (!(uprobe->flags & UPROBES_RUN_HANDLER))
		return;

	down_read(&uprobe->consumer_rwsem);
	consumer = uprobe->consumers;
	for (consumer = uprobe->consumers; consumer;
					consumer = consumer->next) {
		if (!consumer->filter ||
				consumer->filter(consumer, current))
			consumer->handler(consumer, regs);
	}
	up_read(&uprobe->consumer_rwsem);
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

static int __copy_insn(struct address_space *mapping,
			struct vm_area_struct *vma, char *insn,
			unsigned long nbytes, unsigned long offset)
{
	struct file *filp = vma->vm_file;
	struct page *page;
	void *vaddr;
	unsigned long off1;
	unsigned long idx;

	if (!filp)
		return -EINVAL;

	idx = (unsigned long)(offset >> PAGE_CACHE_SHIFT);
	off1 = offset &= ~PAGE_MASK;

	/*
	 * Ensure that the page that has the original instruction is
	 * populated and in page-cache.
	 */
	page = read_mapping_page(mapping, idx, filp);
	if (IS_ERR(page))
		return PTR_ERR(page);

	vaddr = kmap_atomic(page);
	memcpy(insn, vaddr + off1, nbytes);
	kunmap_atomic(vaddr);
	page_cache_release(page);
	return 0;
}

static int copy_insn(struct uprobe *uprobe, struct vm_area_struct *vma,
					unsigned long addr)
{
	struct address_space *mapping;
	int bytes;
	unsigned long nbytes;

	addr &= ~PAGE_MASK;
	nbytes = PAGE_SIZE - addr;
	mapping = uprobe->inode->i_mapping;

	/* Instruction at end of binary; copy only available bytes */
	if (uprobe->offset + MAX_UINSN_BYTES > uprobe->inode->i_size)
		bytes = uprobe->inode->i_size - uprobe->offset;
	else
		bytes = MAX_UINSN_BYTES;

	/* Instruction at the page-boundary; copy bytes in second page */
	if (nbytes < bytes) {
		if (__copy_insn(mapping, vma, uprobe->insn + nbytes,
				bytes - nbytes, uprobe->offset + nbytes))
			return -ENOMEM;

		bytes = nbytes;
	}
	return __copy_insn(mapping, vma, uprobe->insn, bytes, uprobe->offset);
}

/*
 * How mm_uprobes_count gets updated
 * mmap_uprobe() increments the count if
 * 	- it successfully adds a breakpoint.
 * 	- it not add a breakpoint, but sees that there is a underlying
 * 	  breakpoint (via a is_bkpt_at_addr()).
 *
 * munmap_uprobe() decrements the count if
 * 	- it sees a underlying breakpoint, (via is_bkpt_at_addr)
 * 	- Subsequent unregister_uprobe wouldnt find the breakpoint
 * 	  unless a mmap_uprobe kicks in, since the old vma would be
 * 	  dropped just after munmap_uprobe.
 *
 * register_uprobe increments the count if:
 * 	- it successfully adds a breakpoint.
 *
 * unregister_uprobe decrements the count if:
 * 	- it sees a underlying breakpoint and removes successfully.
 * 			(via is_bkpt_at_addr)
 * 	- Subsequent munmap_uprobe wouldnt find the breakpoint
 * 	  since there is no underlying breakpoint after the
 * 	  breakpoint removal.
 */

static int install_breakpoint(struct mm_struct *mm, struct uprobe *uprobe,
				struct vm_area_struct *vma, loff_t vaddr)
{
	unsigned long addr;
	int ret;

	/*
	 * If probe is being deleted, unregister thread could be done with
	 * the vma-rmap-walk through. Adding a probe now can be fatal since
	 * nobody will be able to cleanup. Also we could be from fork or
	 * mremap path, where the probe might have already been inserted.
	 * Hence behave as if probe already existed.
	 */
	if (!uprobe->consumers)
		return -EEXIST;

	addr = (unsigned long)vaddr;
	if (!(uprobe->flags & UPROBES_COPY_INSN)) {
		ret = copy_insn(uprobe, vma, addr);
		if (ret)
			return ret;

		if (is_bkpt_insn((uprobe_opcode_t *)uprobe->insn))
			return -EEXIST;

		ret = analyze_insn(mm, uprobe);
		if (ret)
			return ret;

		uprobe->flags |= UPROBES_COPY_INSN;
	}

	/*
	 * Ideally, should be updating the probe count after the breakpoint
	 * has been successfully inserted. However a thread could hit the
	 * breakpoint we just inserted even before the probe count is
	 * incremented. If this is the first breakpoint placed, breakpoint
	 * notifier might ignore uprobes and pass the trap to the thread.
	 * Hence increment before and decrement on failure.
	 */
	atomic_inc(&mm->mm_uprobes_count);
	ret = set_bkpt(mm, uprobe, addr);
	if (ret)
		atomic_dec(&mm->mm_uprobes_count);

	return ret;
}

static void remove_breakpoint(struct mm_struct *mm, struct uprobe *uprobe,
							loff_t vaddr)
{
	if (!set_orig_insn(mm, uprobe, (unsigned long)vaddr, true))
		atomic_dec(&mm->mm_uprobes_count);
}

/*
 * There could be threads that have hit the breakpoint and are entering the
 * notifier code and trying to acquire the uprobes_treelock. The thread
 * calling delete_uprobe() that is removing the uprobe from the rb_tree can
 * race with these threads and might acquire the uprobes_treelock compared
 * to some of the breakpoint hit threads. In such a case, the breakpoint hit
 * threads will not find the uprobe. Hence wait till the current breakpoint
 * hit threads acquire the uprobes_treelock before the uprobe is removed
 * from the rbtree.
 */
static void delete_uprobe(struct uprobe *uprobe)
{
	unsigned long flags;

	synchronize_srcu(&uprobes_srcu);
	spin_lock_irqsave(&uprobes_treelock, flags);
	rb_erase(&uprobe->rb_node, &uprobes_tree);
	spin_unlock_irqrestore(&uprobes_treelock, flags);
	iput(uprobe->inode);
	put_uprobe(uprobe);
	atomic_dec(&uprobe_events);
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
		vaddr = vma_address(vma, offset);
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

static int register_for_each_vma(struct uprobe *uprobe, bool is_register)
{
	struct list_head try_list;
	struct vm_area_struct *vma;
	struct address_space *mapping;
	struct vma_info *vi, *tmpvi;
	struct mm_struct *mm;
	loff_t vaddr;
	int ret = 0;

	mapping = uprobe->inode->i_mapping;
	INIT_LIST_HEAD(&try_list);
	while ((vi = find_next_vma_info(&try_list, uprobe->offset,
					mapping, is_register)) != NULL) {
		if (IS_ERR(vi)) {
			ret = PTR_ERR(vi);
			break;
		}
		mm = vi->mm;
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, (unsigned long)vi->vaddr);
		if (!vma || !valid_vma(vma, is_register)) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}
		vaddr = vma_address(vma, uprobe->offset);
		if (vma->vm_file->f_mapping->host != uprobe->inode ||
						vaddr != vi->vaddr) {
			list_del(&vi->probe_list);
			kfree(vi);
			up_read(&mm->mmap_sem);
			mmput(mm);
			continue;
		}

		if (is_register)
			ret = install_breakpoint(mm, uprobe, vma, vi->vaddr);
		else
			remove_breakpoint(mm, uprobe, vi->vaddr);

		up_read(&mm->mmap_sem);
		mmput(mm);
		if (is_register) {
			if (ret && ret == -EEXIST)
				ret = 0;
			if (ret)
				break;
		}
	}
	list_for_each_entry_safe(vi, tmpvi, &try_list, probe_list) {
		list_del(&vi->probe_list);
		kfree(vi);
	}
	return ret;
}

static int __register_uprobe(struct uprobe *uprobe)
{
	return register_for_each_vma(uprobe, true);
}

static void __unregister_uprobe(struct uprobe *uprobe)
{
	if (!register_for_each_vma(uprobe, false))
		delete_uprobe(uprobe);

	/* TODO : cant unregister? schedule a worker thread */
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

	if (!inode || !consumer || consumer->next)
		return ret;

	if (offset > i_size_read(inode))
		return ret;

	ret = 0;
	mutex_lock(uprobes_hash(inode));
	uprobe = alloc_uprobe(inode, offset);
	if (uprobe && !add_consumer(uprobe, consumer)) {
		ret = __register_uprobe(uprobe);
		if (ret) {
			uprobe->consumers = NULL;
			__unregister_uprobe(uprobe);
		} else
			uprobe->flags |= UPROBES_RUN_HANDLER;
	}

	mutex_unlock(uprobes_hash(inode));
	put_uprobe(uprobe);

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

	if (!inode || !consumer)
		return;

	uprobe = find_uprobe(inode, offset);
	if (!uprobe)
		return;

	mutex_lock(uprobes_hash(inode));
	if (!del_consumer(uprobe, consumer))
		goto unreg_out;

	if (!uprobe->consumers) {
		__unregister_uprobe(uprobe);
		uprobe->flags &= ~UPROBES_RUN_HANDLER;
	}

unreg_out:
	mutex_unlock(uprobes_hash(inode));
	if (uprobe)
		put_uprobe(uprobe);
}

/*
 * Of all the nodes that correspond to the given inode, return the node
 * with the least offset.
 */
static struct rb_node *find_least_offset_node(struct inode *inode)
{
	struct uprobe u = { .inode = inode, .offset = 0};
	struct rb_node *n = uprobes_tree.rb_node;
	struct rb_node *close_node = NULL;
	struct uprobe *uprobe;
	int match;

	while (n) {
		uprobe = rb_entry(n, struct uprobe, rb_node);
		match = match_uprobe(&u, uprobe);
		if (uprobe->inode == inode)
			close_node = n;

		if (!match)
			return close_node;

		if (match < 0)
			n = n->rb_left;
		else
			n = n->rb_right;
	}
	return close_node;
}

/*
 * For a given inode, build a list of probes that need to be inserted.
 */
static void build_probe_list(struct inode *inode, struct list_head *head)
{
	struct uprobe *uprobe;
	struct rb_node *n;
	unsigned long flags;

	spin_lock_irqsave(&uprobes_treelock, flags);
	n = find_least_offset_node(inode);
	for (; n; n = rb_next(n)) {
		uprobe = rb_entry(n, struct uprobe, rb_node);
		if (uprobe->inode != inode)
			break;

		list_add(&uprobe->pending_list, head);
		atomic_inc(&uprobe->ref);
	}
	spin_unlock_irqrestore(&uprobes_treelock, flags);
}

/*
 * Called from mmap_region.
 * called with mm->mmap_sem acquired.
 *
 * Return -ve no if we fail to insert probes and we cannot
 * bail-out.
 * Return 0 otherwise. i.e :
 *	- successful insertion of probes
 *	- (or) no possible probes to be inserted.
 *	- (or) insertion of probes failed but we can bail-out.
 */
int mmap_uprobe(struct vm_area_struct *vma)
{
	struct list_head tmp_list;
	struct uprobe *uprobe, *u;
	struct inode *inode;
	int ret = 0, count = 0;

	if (!atomic_read(&uprobe_events) || !valid_vma(vma, true))
		return ret;	/* Bail-out */

	inode = vma->vm_file->f_mapping->host;
	if (!inode)
		return ret;

	INIT_LIST_HEAD(&tmp_list);
	mutex_lock(uprobes_mmap_hash(inode));
	build_probe_list(inode, &tmp_list);
	list_for_each_entry_safe(uprobe, u, &tmp_list, pending_list) {
		loff_t vaddr;

		list_del(&uprobe->pending_list);
		if (!ret) {
			vaddr = vma_address(vma, uprobe->offset);
			if (vaddr < vma->vm_start || vaddr >= vma->vm_end) {
				put_uprobe(uprobe);
				continue;
			}
			ret = install_breakpoint(vma->vm_mm, uprobe, vma,
								vaddr);
			if (ret == -EEXIST) {
				ret = 0;
				if (!is_bkpt_at_addr(vma->vm_mm, vaddr))
					continue;

				/*
				 * Unable to insert a breakpoint, but
				 * breakpoint lies underneath. Increment the
				 * probe count.
				 */
				atomic_inc(&vma->vm_mm->mm_uprobes_count);
			}
			if (!ret)
				count++;

		}
		put_uprobe(uprobe);
	}

	mutex_unlock(uprobes_mmap_hash(inode));
	if (ret)
		atomic_sub(count, &vma->vm_mm->mm_uprobes_count);

	return ret;
}

/*
 * Called in context of a munmap of a vma.
 */
void munmap_uprobe(struct vm_area_struct *vma)
{
	struct list_head tmp_list;
	struct uprobe *uprobe, *u;
	struct inode *inode;

	if (!atomic_read(&uprobe_events) || !valid_vma(vma, false))
		return;		/* Bail-out */

	if (!atomic_read(&vma->vm_mm->mm_uprobes_count))
		return;

	inode = vma->vm_file->f_mapping->host;
	if (!inode)
		return;

	INIT_LIST_HEAD(&tmp_list);
	mutex_lock(uprobes_mmap_hash(inode));
	build_probe_list(inode, &tmp_list);
	list_for_each_entry_safe(uprobe, u, &tmp_list, pending_list) {
		loff_t vaddr;

		list_del(&uprobe->pending_list);
		vaddr = vma_address(vma, uprobe->offset);
		if (vaddr >= vma->vm_start && vaddr < vma->vm_end) {

			/*
			 * An unregister could have removed the probe before
			 * unmap. So check before we decrement the count.
			 */
			if (is_bkpt_at_addr(vma->vm_mm, vaddr) == 1)
				atomic_dec(&vma->vm_mm->mm_uprobes_count);
		}
		put_uprobe(uprobe);
	}
	mutex_unlock(uprobes_mmap_hash(inode));
	return;
}

/* Slot allocation for XOL */
static int xol_add_vma(struct uprobes_xol_area *area)
{
	struct mm_struct *mm;
	int ret;

	area->page = alloc_page(GFP_HIGHUSER);
	if (!area->page)
		return -ENOMEM;

	mm = current->mm;
	down_write(&mm->mmap_sem);
	ret = -EALREADY;
	if (mm->uprobes_xol_area)
		goto fail;

	ret = -ENOMEM;

	/* Try to map as high as possible, this is only a hint. */
	area->vaddr = get_unmapped_area(NULL, TASK_SIZE - PAGE_SIZE,
							PAGE_SIZE, 0, 0);
	if (area->vaddr & ~PAGE_MASK) {
		ret = area->vaddr;
		goto fail;
	}

	ret = install_special_mapping(mm, area->vaddr, PAGE_SIZE,
				VM_EXEC|VM_MAYEXEC|VM_DONTCOPY|VM_IO,
				&area->page);
	if (ret)
		goto fail;

	smp_wmb();	/* pairs with get_uprobes_xol_area() */
	mm->uprobes_xol_area = area;
	ret = 0;

fail:
	up_write(&mm->mmap_sem);
	if (ret)
		__free_page(area->page);

	return ret;
}

static struct uprobes_xol_area *get_uprobes_xol_area(struct mm_struct *mm)
{
	struct uprobes_xol_area *area = mm->uprobes_xol_area;
	smp_read_barrier_depends();/* pairs with wmb in xol_add_vma() */
	return area;
}

/*
 * xol_alloc_area - Allocate process's uprobes_xol_area.
 * This area will be used for storing instructions for execution out of
 * line.
 *
 * Returns the allocated area or NULL.
 */
static struct uprobes_xol_area *xol_alloc_area(void)
{
	struct uprobes_xol_area *area;

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (unlikely(!area))
		return NULL;

	area->bitmap = kzalloc(BITS_TO_LONGS(UINSNS_PER_PAGE) * sizeof(long),
								GFP_KERNEL);

	if (!area->bitmap)
		goto fail;

	init_waitqueue_head(&area->wq);
	if (!xol_add_vma(area))
		return area;

fail:
	kfree(area->bitmap);
	kfree(area);
	return get_uprobes_xol_area(current->mm);
}

/*
 * free_uprobes_xol_area - Free the area allocated for slots.
 */
void free_uprobes_xol_area(struct mm_struct *mm)
{
	struct uprobes_xol_area *area = mm->uprobes_xol_area;

	if (!area)
		return;

	put_page(area->page);
	kfree(area->bitmap);
	kfree(area);
}

/*
 *  - search for a free slot.
 */
static unsigned long xol_take_insn_slot(struct uprobes_xol_area *area)
{
	unsigned long slot_addr;
	int slot_nr;

	do {
		slot_nr = find_first_zero_bit(area->bitmap, UINSNS_PER_PAGE);
		if (slot_nr < UINSNS_PER_PAGE) {
			if (!test_and_set_bit(slot_nr, area->bitmap))
				break;

			slot_nr = UINSNS_PER_PAGE;
			continue;
		}
		wait_event(area->wq,
			(atomic_read(&area->slot_count) < UINSNS_PER_PAGE));
	} while (slot_nr >= UINSNS_PER_PAGE);

	slot_addr = area->vaddr + (slot_nr * UPROBES_XOL_SLOT_BYTES);
	atomic_inc(&area->slot_count);
	return slot_addr;
}

/*
 * xol_get_insn_slot - If was not allocated a slot, then
 * allocate a slot.
 * Returns the allocated slot address or 0.
 */
static unsigned long xol_get_insn_slot(struct uprobe *uprobe,
					unsigned long slot_addr)
{
	struct uprobes_xol_area *area;
	unsigned long offset;
	void *vaddr;

	area = get_uprobes_xol_area(current->mm);
	if (!area) {
		area = xol_alloc_area();
		if (!area)
			return 0;
	}
	current->utask->xol_vaddr = xol_take_insn_slot(area);

	/*
	 * Initialize the slot if xol_vaddr points to valid
	 * instruction slot.
	 */
	if (unlikely(!current->utask->xol_vaddr))
		return 0;

	current->utask->vaddr = slot_addr;
	offset = current->utask->xol_vaddr & ~PAGE_MASK;
	vaddr = kmap_atomic(area->page);
	memcpy(vaddr + offset, uprobe->insn, MAX_UINSN_BYTES);
	kunmap_atomic(vaddr);
	return current->utask->xol_vaddr;
}

/*
 * xol_free_insn_slot - If slot was earlier allocated by
 * @xol_get_insn_slot(), make the slot available for
 * subsequent requests.
 */
static void xol_free_insn_slot(struct task_struct *tsk)
{
	struct uprobes_xol_area *area;
	unsigned long vma_end;
	unsigned long slot_addr;

	if (!tsk->mm || !tsk->mm->uprobes_xol_area || !tsk->utask)
		return;

	slot_addr = tsk->utask->xol_vaddr;

	if (unlikely(!slot_addr || IS_ERR_VALUE(slot_addr)))
		return;

	area = tsk->mm->uprobes_xol_area;
	vma_end = area->vaddr + PAGE_SIZE;
	if (area->vaddr <= slot_addr && slot_addr < vma_end) {
		int slot_nr;
		unsigned long offset = slot_addr - area->vaddr;

		slot_nr = offset / UPROBES_XOL_SLOT_BYTES;
		if (slot_nr >= UINSNS_PER_PAGE)
			return;

		clear_bit(slot_nr, area->bitmap);
		atomic_dec(&area->slot_count);
		if (waitqueue_active(&area->wq))
			wake_up(&area->wq);
		tsk->utask->xol_vaddr = 0;
	}
}

/**
 * get_uprobe_bkpt_addr - compute address of bkpt given post-bkpt regs
 * @regs: Reflects the saved state of the task after it has hit a breakpoint
 * instruction.
 * Return the address of the breakpoint instruction.
 */
unsigned long __weak get_uprobe_bkpt_addr(struct pt_regs *regs)
{
	return instruction_pointer(regs) - UPROBES_BKPT_INSN_SIZE;
}

/*
 * Called with no locks held.
 * Called in context of a exiting or a exec-ing thread.
 */
void free_uprobe_utask(struct task_struct *tsk)
{
	struct uprobe_task *utask = tsk->utask;

	if (tsk->uprobes_srcu_id != -1)
		srcu_read_unlock_raw(&uprobes_srcu, tsk->uprobes_srcu_id);

	if (!utask)
		return;

	if (utask->active_uprobe)
		put_uprobe(utask->active_uprobe);

	xol_free_insn_slot(tsk);
	kfree(utask);
	tsk->utask = NULL;
}

/*
 * Allocate a uprobe_task object for the task.
 * Called when the thread hits a breakpoint for the first time.
 *
 * Returns:
 * - pointer to new uprobe_task on success
 * - NULL otherwise
 */
static struct uprobe_task *add_utask(void)
{
	struct uprobe_task *utask;

	utask = kzalloc(sizeof *utask, GFP_KERNEL);
	if (unlikely(utask == NULL))
		return NULL;

	utask->active_uprobe = NULL;
	current->utask = utask;
	return utask;
}

/* Prepare to single-step probed instruction out of line. */
static int pre_ssout(struct uprobe *uprobe, struct pt_regs *regs,
				unsigned long vaddr)
{
	if (xol_get_insn_slot(uprobe, vaddr) && !pre_xol(uprobe, regs))
		return 0;
	return -EFAULT;
}

/*
 * If we are singlestepping, then ensure this thread is not connected to
 * non-fatal signals until completion of singlestep.  When xol insn itself
 * triggers the signal,  restart the original insn even if the task is
 * already SIGKILL'ed (since coredump should report the correct ip).  This
 * is even more important if the task has a handler for SIGSEGV/etc, The
 * _same_ instruction should be repeated again after return from the signal
 * handler, and SSTEP can never finish in this case.
 */
bool uprobe_deny_signal(void)
{
	struct task_struct *tsk = current;
	struct uprobe_task *utask = tsk->utask;

	if (likely(!utask || !utask->active_uprobe))
		return false;

	WARN_ON_ONCE(utask->state != UTASK_SSTEP);

	if (signal_pending(tsk)) {
		spin_lock_irq(&tsk->sighand->siglock);
		clear_tsk_thread_flag(tsk, TIF_SIGPENDING);
		spin_unlock_irq(&tsk->sighand->siglock);

		if (__fatal_signal_pending(tsk) || xol_was_trapped(tsk)) {
			utask->state = UTASK_SSTEP_TRAPPED;
			set_tsk_thread_flag(tsk, TIF_UPROBE);
			set_tsk_thread_flag(tsk, TIF_NOTIFY_RESUME);
		}
	}

	return true;
}

bool __weak uprobe_skip_sstep(struct pt_regs *regs, struct uprobe *u)
{
	u->flags &= ~UPROBES_SKIP_SSTEP;
	return false;
}

/*
 * On breakpoint hit, breakpoint notifier sets the TIF_UPROBE flag.  (and on
 * subsequent probe hits on the thread sets the state to UTASK_BP_HIT) and
 * allows the thread to return from interrupt.  While returning to
 * userspace, thread noticies the TIF_UPROBE flag and calls
 * uprobe_notify_resume(). uprobe_notify_resume will run the handler and ask
 * the thread to singlestep.
 *
 * On subsequent singlestep exception, singlestep notifier sets the
 * TIF_UPROBE flag and also sets the state to UTASK_SSTEP_ACK and allows the
 * thread to return from interrupt. While returning to userspace, thread
 * notices the TIF_UPROBE and calls uprobe_notify_resume().
 * uprobe_notify_resume disables singlestep and performs the required
 * fix-ups.
 *
 * All non-fatal signals cannot interrupt thread while the thread singlesteps.
 */
void uprobe_notify_resume(struct pt_regs *regs)
{
	struct vm_area_struct *vma;
	struct uprobe_task *utask;
	struct mm_struct *mm;
	struct uprobe *u = NULL;
	unsigned long probept;

	utask = current->utask;
	mm = current->mm;
	if (!utask || utask->state == UTASK_BP_HIT) {
		probept = get_uprobe_bkpt_addr(regs);
		down_read(&mm->mmap_sem);
		vma = find_vma(mm, probept);
		if (vma && vma->vm_start <= probept && valid_vma(vma, false))
			u = find_uprobe(vma->vm_file->f_mapping->host,
					probept - vma->vm_start +
					(vma->vm_pgoff << PAGE_SHIFT));

		srcu_read_unlock_raw(&uprobes_srcu,
					current->uprobes_srcu_id);
		current->uprobes_srcu_id = -1;
		up_read(&mm->mmap_sem);
		if (!u)
			/* No matching uprobe; signal SIGTRAP. */
			goto cleanup_ret;
		if (!utask) {
			utask = add_utask();
			/* Cannot Allocate; re-execute the instruction. */
			if (!utask)
				goto cleanup_ret;
		}
		utask->active_uprobe = u;
		handler_chain(u, regs);

		if (u->flags & UPROBES_SKIP_SSTEP && uprobe_skip_sstep(regs, u))
			goto cleanup_ret;

		utask->state = UTASK_SSTEP;
		if (!pre_ssout(u, regs, probept))
			user_enable_single_step(current);
		else
			/* Cannot Singlestep; re-execute the instruction. */
			goto cleanup_ret;
	} else {
		u = utask->active_uprobe;
		if (utask->state == UTASK_SSTEP_ACK)
			post_xol(u, regs);
		else if (utask->state == UTASK_SSTEP_TRAPPED)
			abort_xol(regs, u);
		else
			WARN_ON_ONCE(1);

		put_uprobe(u);
		utask->active_uprobe = NULL;
		utask->state = UTASK_RUNNING;
		user_disable_single_step(current);
		xol_free_insn_slot(current);

		spin_lock_irq(&current->sighand->siglock);
		recalc_sigpending(); /* see uprobe_deny_signal() */
		spin_unlock_irq(&current->sighand->siglock);
	}
	return;

cleanup_ret:
	if (utask) {
		utask->active_uprobe = NULL;
		utask->state = UTASK_RUNNING;
	}
	if (u) {
		if (!(u->flags & UPROBES_SKIP_SSTEP))
			instruction_pointer_set(regs, probept);

		put_uprobe(u);
	} else
		send_sig(SIGTRAP, current, 0);
}

/*
 * uprobe_bkpt_notifier gets called from interrupt context as part of
 * notifier mechanism. Set TIF_UPROBE flag and indicate breakpoint hit.
 */
int uprobe_bkpt_notifier(struct pt_regs *regs)
{
	struct uprobe_task *utask;

	if (!current->mm || !atomic_read(&current->mm->mm_uprobes_count))
		/* task is currently not uprobed */
		return 0;

	utask = current->utask;
	if (utask)
		utask->state = UTASK_BP_HIT;

	set_thread_flag(TIF_UPROBE);
	current->uprobes_srcu_id = srcu_read_lock_raw(&uprobes_srcu);
	return 1;
}

/*
 * uprobe_post_notifier gets called in interrupt context as part of notifier
 * mechanism. Set TIF_UPROBE flag and indicate completion of singlestep.
 */
int uprobe_post_notifier(struct pt_regs *regs)
{
	struct uprobe_task *utask = current->utask;

	if (!current->mm || !utask || !utask->active_uprobe)
		/* task is currently not uprobed */
		return 0;

	utask->state = UTASK_SSTEP_ACK;
	set_thread_flag(TIF_UPROBE);
	return 1;
}

struct notifier_block uprobe_exception_nb = {
	.notifier_call = uprobe_exception_notify,
	.priority = INT_MAX - 1,	/* notified after kprobes, kgdb */
};

static int __init init_uprobes(void)
{
	int i;

	for (i = 0; i < UPROBES_HASH_SZ; i++) {
		mutex_init(&uprobes_mutex[i]);
		mutex_init(&uprobes_mmap_mutex[i]);
	}
	init_srcu_struct(&uprobes_srcu);
	return register_die_notifier(&uprobe_exception_nb);
}

static void __exit exit_uprobes(void)
{
}

module_init(init_uprobes);
module_exit(exit_uprobes);
