/*
 * Copyright (C) 2004, 2007-2010, 2011-2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Amit Bhor, Sameer Dhavale: Codito Technologies 2004
 */

#ifndef _UAPI__ASM_ARC_PTRACE_H
#define _UAPI__ASM_ARC_PTRACE_H

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


#endif /* _UAPI__ASM_ARC_PTRACE_H */
