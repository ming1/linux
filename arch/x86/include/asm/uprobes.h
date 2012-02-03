#ifndef _ASM_UPROBES_H
#define _ASM_UPROBES_H
/*
 * Userspace Probes (UProbes) for x86
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

#include <linux/notifier.h>

typedef u8 uprobe_opcode_t;
#define MAX_UINSN_BYTES 16
#define UPROBES_XOL_SLOT_BYTES	128	/* to keep it cache aligned */

#define UPROBES_BKPT_INSN 0xcc
#define UPROBES_BKPT_INSN_SIZE 1

struct uprobe_arch_info {
	u16			fixups;
#ifdef CONFIG_X86_64
	unsigned long rip_rela_target_address;
#endif
};

struct uprobe_task_arch_info {
	unsigned long saved_trap_no;
#ifdef CONFIG_X86_64
	unsigned long saved_scratch_register;
#endif
};

struct uprobe;

extern int analyze_insn(struct mm_struct *mm, struct uprobe *uprobe);
extern int pre_xol(struct uprobe *uprobe, struct pt_regs *regs);
extern int post_xol(struct uprobe *uprobe, struct pt_regs *regs);
extern bool xol_was_trapped(struct task_struct *tsk);
extern int uprobe_exception_notify(struct notifier_block *self,
				       unsigned long val, void *data);
extern void abort_xol(struct pt_regs *regs, struct uprobe *uprobe);
#endif	/* _ASM_UPROBES_H */
