/*
 * Ptrace support for Hexagon
 *
 * Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <generated/compile.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/regset.h>
#include <linux/user.h>

#include <asm/system.h>
#include <asm/user.h>

struct pt_regs_offset {
	const char *name;
	int offset;
};

#define REG_OFFSET_NAME(r) {.name = #r, .offset = offsetof(struct pt_regs, r)}
#define REG_OFFSET_HVM_NAME(r, s) {.name = #r, \
				  .offset = offsetof(struct pt_regs, s)}
#define REG_OFFSET_END {.name = NULL, .offset = 0}

static const struct pt_regs_offset regoffset_table[] = {
	REG_OFFSET_NAME(r00),
	REG_OFFSET_NAME(r01),
	REG_OFFSET_NAME(r02),
	REG_OFFSET_NAME(r03),
	REG_OFFSET_NAME(r04),
	REG_OFFSET_NAME(r05),
	REG_OFFSET_NAME(r06),
	REG_OFFSET_NAME(r07),
	REG_OFFSET_NAME(r08),
	REG_OFFSET_NAME(r09),

	REG_OFFSET_NAME(r10),
	REG_OFFSET_NAME(r11),
	REG_OFFSET_NAME(r12),
	REG_OFFSET_NAME(r13),
	REG_OFFSET_NAME(r14),
	REG_OFFSET_NAME(r15),
	REG_OFFSET_NAME(r16),
	REG_OFFSET_NAME(r17),
	REG_OFFSET_NAME(r18),
	REG_OFFSET_NAME(r19),

	REG_OFFSET_NAME(r20),
	REG_OFFSET_NAME(r21),
	REG_OFFSET_NAME(r22),
	REG_OFFSET_NAME(r23),
	REG_OFFSET_NAME(r24),
	REG_OFFSET_NAME(r25),
	REG_OFFSET_NAME(r26),
	REG_OFFSET_NAME(r27),
	REG_OFFSET_NAME(r28),
	REG_OFFSET_NAME(r29),

	REG_OFFSET_NAME(r30),
	REG_OFFSET_NAME(r31),

	REG_OFFSET_NAME(gp),
	REG_OFFSET_NAME(ugp),
	REG_OFFSET_NAME(sa0),
	REG_OFFSET_NAME(lc0),
	REG_OFFSET_NAME(sa1),
	REG_OFFSET_NAME(lc1),
	REG_OFFSET_NAME(m0),
	REG_OFFSET_NAME(m1),
	REG_OFFSET_NAME(preds),
	REG_OFFSET_HVM_NAME(pc, hvmer.vmel),
	REG_OFFSET_HVM_NAME(cause, hvmer.vmest),
	REG_OFFSET_HVM_NAME(badva, hvmer.vmbadva),
};

/**
 * regs_query_register_offset() - query register offset from its name
 * @name:      the name of a register
 *
 * regs_query_register_offset() returns the offset of a register in struct
 * pt_regs from its name. If the name is invalid, this returns -EINVAL;
 */
int regs_query_register_offset(const char *name)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (!strcmp(roff->name, name))
			return roff->offset;
	return -EINVAL;
}

/**
 * regs_query_register_name() - query register name from its offset
 * @offset:    the offset of a register in struct pt_regs.
 *
 * regs_query_register_name() returns the name of a register from its
 * offset in struct pt_regs. If the @offset is invalid, this returns NULL;
 */
const char *regs_query_register_name(unsigned int offset)
{
	const struct pt_regs_offset *roff;
	for (roff = regoffset_table; roff->name != NULL; roff++)
		if (roff->offset == offset)
			return roff->name;
	return NULL;
}

static int gpr_get(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   void *kbuf, void __user *ubuf)
{
	int ret;
	unsigned int dummy;
	struct pt_regs *regs = task_pt_regs(target);


	if (!regs)
		return -EIO;

	/* The general idea here is that the copyout must happen in
	 * exactly the same order in which the userspace expects these
	 * regs. Now, the sequence in userspace does not match the
	 * sequence in the kernel, so everything past the 32 gprs
	 * happens one at a time.
	 */
	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  &regs->r00, 0, 32*sizeof(unsigned long));

#define ONEXT(KPT_REG, USR_REG) \
	if (!ret) \
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, \
			KPT_REG, offsetof(struct user_regs_struct, USR_REG), \
			offsetof(struct user_regs_struct, USR_REG) + \
				 sizeof(unsigned long));

	/* Must be exactly same sequence as struct user_regs_struct */
	ONEXT(&regs->gp, gp);
	ONEXT(&regs->ugp, ugp);
	ONEXT(&regs->sa0, sa0);
	ONEXT(&regs->lc0, lc0);
	ONEXT(&regs->sa1, sa1);
	ONEXT(&regs->lc1, lc1);
	ONEXT(&regs->m0, m0);
	ONEXT(&regs->m1, m1);
	ONEXT(&regs->preds, p3_0);
	ONEXT(&pt_elr(regs), pc);
	dummy = pt_cause(regs);
	ONEXT(&dummy, cause);
	ONEXT(&pt_badva(regs), badva);

	/* Pad the rest with zeros, if needed */
	if (!ret)
		ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
					sizeof(struct user_regs_struct), -1);
	return ret;
}

static int gpr_set(struct task_struct *target,
		   const struct user_regset *regset,
		   unsigned int pos, unsigned int count,
		   const void *kbuf, const void __user *ubuf)
{
	int ret;
	unsigned long bucket;
	struct pt_regs *regs = task_pt_regs(target);

	if (!regs)
		return -EIO;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 &regs->r00, 0, 32*sizeof(unsigned long));

#define INEXT(KPT_REG, USR_REG) \
	if (!ret) \
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, \
			KPT_REG, offsetof(struct user_regs_struct, USR_REG), \
			offsetof(struct user_regs_struct, USR_REG) + \
				sizeof(unsigned long));

	/* Must be exactly same sequence as struct user_regs_struct */
	INEXT(&regs->gp, gp);
	INEXT(&regs->ugp, ugp);
	INEXT(&regs->sa0, sa0);
	INEXT(&regs->lc0, lc0);
	INEXT(&regs->sa1, sa1);
	INEXT(&regs->lc1, lc1);
	INEXT(&regs->m0, m0);
	INEXT(&regs->m1, m1);
	INEXT(&regs->preds, p3_0);
	INEXT(&pt_elr(regs), pc);

	/* CAUSE and BADVA aren't writeable. */
	INEXT(&bucket, cause);
	INEXT(&bucket, badva);

	/* Ignore the rest, if needed */
	if (!ret)
		ret = user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
					sizeof(struct user_regs_struct), -1);

	if (ret)
		return ret;

	/*
	 * This is special; SP is actually restored by the VM via the
	 * special event record which is set by the special trap.
	 */
	regs->hvmer.vmpsp = regs->r29;
	return 0;
}

enum hexagon_regset {
	REGSET_GPR,
};

static const struct user_regset hexagon_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.n = N_PTRACE_REGS,
		.size = sizeof(unsigned long),
		.align = sizeof(unsigned long),
		.get = gpr_get,
		.set = gpr_set
	},
};

static const struct user_regset_view hexagon_user_view = {
	.name = UTS_MACHINE,
	.e_machine = ELF_ARCH,
	.ei_osabi = ELF_OSABI,
	.regsets = hexagon_regsets,
	.n = ARRAY_SIZE(hexagon_regsets)
};

static int ptrace_pokeusr(struct task_struct *target, int regnum,
			  unsigned long data)
{
	struct pt_regs *regs = task_pt_regs(target);

	if (!regs || (regnum < 0))
		return -EIO;

	if (regnum < 32) {
		unsigned long *p = &regs->r00;
		*(p+regnum) = data;

		/* Return happens via HVM */
		if (regnum == 29)
			regs->hvmer.vmpsp = regs->r29;
		return 0;
	}

/*
 * Todo:  sync up with gdb on register passing numbering.
 */

#define SETREG(KPT_REG, USR_REG) \
	case offsetof(struct user_regs_struct, USR_REG)>>2: \
		KPT_REG = data; \
		return 0;

	/* Other regs are scattered about */
	switch (regnum) {
	SETREG(regs->gp, gp);
	SETREG(regs->ugp, ugp);
	SETREG(regs->sa0, sa0);
	SETREG(regs->lc0, lc0);
	SETREG(regs->sa1, sa1);
	SETREG(regs->lc1, lc1);
	SETREG(regs->m0, m0);
	SETREG(regs->m1, m1);
	SETREG(regs->preds, p3_0);
	SETREG(pt_elr(regs), pc);
	}

	/* CAUSE and BADVA aren't writeable. */
	return -EINVAL;
}

void ptrace_disable(struct task_struct *child)
{
	/* Boilerplate - resolves to null inline if no HW single-step */
	user_disable_single_step(child);
}

long arch_ptrace(struct task_struct *child, long request,
		 unsigned long addr, unsigned long data)
{
	void __user *udata = (void __user *) data;

	switch (request) {
	case PTRACE_POKETEXT:	/* write the word at location addr. */
	case PTRACE_POKEDATA:
		return generic_ptrace_pokedata(child, addr, data);
	case PTRACE_POKEUSR:	/* write register specified by addr. */
		return ptrace_pokeusr(child, addr, data);
	case PTRACE_GETREGS:
		return copy_regset_to_user(child, &hexagon_user_view,
					   REGSET_GPR, 0,
					   sizeof(struct user_regs_struct),
					   udata);
	case PTRACE_SETREGS:
		return copy_regset_from_user(child, &hexagon_user_view,
					     REGSET_GPR, 0,
					     sizeof(struct user_regs_struct),
					     udata);
	default:
		return ptrace_request(child, request, addr, data);
	}

	return 0;
}
