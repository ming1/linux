#ifndef _LINUX_UPROBES_H
#define _LINUX_UPROBES_H
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

#include <linux/rbtree.h>

struct vm_area_struct;
#ifdef CONFIG_ARCH_SUPPORTS_UPROBES
#include <asm/uprobes.h>
#else
typedef u8 uprobe_opcode_t;
struct uprobe_arch_info {};
struct uprobe_task_arch_info {};	/* arch specific task info */
#define MAX_UINSN_BYTES 4
#endif

#define uprobe_opcode_sz sizeof(uprobe_opcode_t)

/* Post-execution fixups.  Some architectures may define others. */

/* No fixup needed */
#define UPROBES_FIX_NONE	0x0
/* Adjust IP back to vicinity of actual insn */
#define UPROBES_FIX_IP	0x1
/* Adjust the return address of a call insn */
#define UPROBES_FIX_CALL	0x2

struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *self, struct pt_regs *regs);
	/*
	 * filter is optional; If a filter exists, handler is run
	 * if and only if filter returns true.
	 */
	bool (*filter)(struct uprobe_consumer *self, struct task_struct *task);

	struct uprobe_consumer *next;
};

struct uprobe {
	struct rb_node		rb_node;	/* node in the rb tree */
	atomic_t		ref;
	struct rw_semaphore	consumer_rwsem;
	struct list_head	pending_list;
	struct uprobe_arch_info arch_info;
	struct uprobe_consumer	*consumers;
	struct inode		*inode;		/* Also hold a ref to inode */
	loff_t			offset;
	int			copy;
	u16			fixups;
	u8			insn[MAX_UINSN_BYTES];
};

enum uprobe_task_state {
	UTASK_RUNNING,
	UTASK_BP_HIT,
	UTASK_SSTEP,
	UTASK_SSTEP_ACK,
	UTASK_SSTEP_TRAPPED,
};

/*
 * uprobe_task: Metadata of a task while it singlesteps.
 */
struct uprobe_task {
	unsigned long xol_vaddr;
	unsigned long vaddr;

	enum uprobe_task_state state;
	struct uprobe_task_arch_info tskinfo;

	struct uprobe *active_uprobe;
};

/*
 * On a breakpoint hit, thread contests for a slot.  It free the
 * slot after singlestep.  Only definite number of slots are
 * allocated.
 */

struct uprobes_xol_area {
	wait_queue_head_t wq;	/* if all slots are busy */
	atomic_t slot_count;	/* currently in use slots */
	unsigned long *bitmap;	/* 0 = free slot */
	struct page *page;

	/*
	 * We keep the vma's vm_start rather than a pointer to the vma
	 * itself.  The probed process or a naughty kernel module could make
	 * the vma go away, and we must handle that reasonably gracefully.
	 */
	unsigned long vaddr;		/* Page(s) of instruction slots */
};

#ifdef CONFIG_UPROBES
extern int __weak set_bkpt(struct mm_struct *mm, struct uprobe *uprobe,
							unsigned long vaddr);
extern int __weak set_orig_insn(struct mm_struct *mm, struct uprobe *uprobe,
					unsigned long vaddr, bool verify);
extern bool __weak is_bkpt_insn(u8 *insn);
extern int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer);
extern void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer);
extern void free_uprobe_utask(struct task_struct *tsk);
extern void free_uprobes_xol_area(struct mm_struct *mm);
extern int mmap_uprobe(struct vm_area_struct *vma);
extern void munmap_uprobe(struct vm_area_struct *vma);
extern unsigned long __weak get_uprobe_bkpt_addr(struct pt_regs *regs);
extern int uprobe_post_notifier(struct pt_regs *regs);
extern int uprobe_bkpt_notifier(struct pt_regs *regs);
extern void uprobe_notify_resume(struct pt_regs *regs);
extern bool uprobe_deny_signal(void);
#else /* CONFIG_UPROBES is not defined */
static inline int register_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
	return -ENOSYS;
}
static inline void unregister_uprobe(struct inode *inode, loff_t offset,
				struct uprobe_consumer *consumer)
{
}
static inline int mmap_uprobe(struct vm_area_struct *vma)
{
	return 0;
}
static inline void munmap_uprobe(struct vm_area_struct *vma)
{
}
static inline void uprobe_notify_resume(struct pt_regs *regs)
{
}
static inline bool uprobe_deny_signal(void)
{
	return false;
}
static inline unsigned long get_uprobe_bkpt_addr(struct pt_regs *regs)
{
	return 0;
}
static inline void free_uprobe_utask(struct task_struct *tsk)
{
}
static inline void free_uprobes_xol_area(struct mm_struct *mm)
{
}
#endif /* CONFIG_UPROBES */
#endif	/* _LINUX_UPROBES_H */
