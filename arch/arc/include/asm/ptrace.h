/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Amit Bhor, Sameer Dhavale: Codito Technologies 2004
 */

#ifndef __ASM_ARC_PTRACE_H
#define __ASM_ARC_PTRACE_H

/*
 * XXX: ABI hack.
 * The offset calc can be cleanly done in asm-offset.c, however gdb includes
 * this header directly.
 */
#define PT_bta		4
#define PT_lp_start	8
#define PT_lp_end	12
#define PT_lp_count	16
#define PT_status32	20
#define PT_ret		24
#define PT_blink	28
#define PT_fp		32
#define PT_r26		36
#define PT_r12		40
#define PT_r11		44
#define PT_r10		48
#define PT_r9		52
#define PT_r8		56
#define PT_r7		60
#define PT_r6		64
#define PT_r5		68
#define PT_r4		72
#define PT_r3		76
#define PT_r2		80
#define PT_r1		84
#define PT_r0		88
#define PT_sp		92
#define PT_orig_r0	96
#define PT_orig_r8	100

#ifdef __KERNEL__

#ifndef __ASSEMBLY__

/* THE pt_regs: Defines how regs are saved during entry into kernel */

struct pt_regs {
	/*
	 * 1 word gutter after reg-file has been saved
	 * Technically not needed, Since SP always points to a "full" location
	 * (vs. "empty"). But pt_regs is shared with tools....
	 */
	long res;

	/* Real registers */
	long bta;	/* bta_l1, bta_l2, erbta */
	long lp_start;
	long lp_end;
	long lp_count;
	long status32;	/* status32_l1, status32_l2, erstatus */
	long ret;	/* ilink1, ilink2 or eret */
	long blink;
	long fp;
	long r26;	/* gp */
	long r12;
	long r11;
	long r10;
	long r9;
	long r8;
	long r7;
	long r6;
	long r5;
	long r4;
	long r3;
	long r2;
	long r1;
	long r0;
	long sp;	/* user/kernel sp depending on where we came from  */
	long orig_r0;

	/*to distinguish bet excp, syscall, irq */
#ifdef CONFIG_CPU_BIG_ENDIAN
	/* so that assembly code is same for LE/BE */
	unsigned long orig_r8:16, event:16;
#else
	unsigned long event:16, orig_r8:16;
#endif
};

/* Callee saved registers - need to be saved only when you are scheduled out */

struct callee_regs {
	long res;	/* Again this is not needed */
	long r25;
	long r24;
	long r23;
	long r22;
	long r21;
	long r20;
	long r19;
	long r18;
	long r17;
	long r16;
	long r15;
	long r14;
	long r13;
};

/* User mode registers, used for core dumps. */
struct user_regs_struct {
	struct pt_regs scratch;
	struct callee_regs callee;
	long efa;	/* break pt addr, for break points in delay slots */
	long stop_pc;	/* give dbg stop_pc directly after checking orig_r8 */
};

#define instruction_pointer(regs)	((regs)->ret)
#define profile_pc(regs)		instruction_pointer(regs)

/* return 1 if user mode or 0 if kernel mode */
#define user_mode(regs) (regs->status32 & STATUS_U_MASK)

#define user_stack_pointer(regs)\
({  unsigned int sp;		\
	if (user_mode(regs))	\
		sp = (regs)->sp;\
	else			\
		sp = -1;	\
	sp;			\
})

/* return 1 if PC in delay slot */
#define delay_mode(regs) ((regs->status32 & STATUS_DE_MASK) == STATUS_DE_MASK)

#define in_syscall(regs)    (regs->event & orig_r8_IS_SCALL)
#define in_brkpt_trap(regs) (regs->event & orig_r8_IS_BRKPT)

#define syscall_wont_restart(regs) (regs->event |= orig_r8_IS_SCALL_RESTARTED)
#define syscall_restartable(regs) !(regs->event &  orig_r8_IS_SCALL_RESTARTED)

#define current_pt_regs()					\
({								\
	/* open-coded current_thread_info() */			\
	register unsigned long sp asm ("sp");			\
	unsigned long pg_start = (sp & ~(THREAD_SIZE - 1));	\
	(struct pt_regs *)(pg_start + THREAD_SIZE - 4) - 1;	\
})

static inline long regs_return_value(struct pt_regs *regs)
{
	return regs->r0;
}

#endif /* !__ASSEMBLY__ */

#define orig_r8_IS_SCALL		0x0001
#define orig_r8_IS_SCALL_RESTARTED	0x0002
#define orig_r8_IS_BRKPT		0x0004
#define orig_r8_IS_EXCPN		0x0004
#define orig_r8_IS_IRQ1			0x0010
#define orig_r8_IS_IRQ2			0x0020

#endif /* __KERNEL__ */

#endif /* __ASM_PTRACE_H */
