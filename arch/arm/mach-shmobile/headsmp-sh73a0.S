/*
 * SMP support for SoC sh73a0
 *
 * Copyright (C) 2012 Bastian Hecht
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR /PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/memory.h>

/* Taken from arch/arm/mach-omap2/sleep44xx.S. Thanks! */
ENTRY(sh73a0_do_wfi)
        stmfd   sp!, {lr}

        /*
         * Execute an ISB instruction to ensure that all of the
         * CP15 register changes have been committed.
         */
        isb

        /*
         * Execute a barrier instruction to ensure that all cache,
         * TLB and branch predictor maintenance operations issued
         * by any CPU in the cluster have completed.
         */
        dsb
        dmb

        /*
         * Execute a WFI instruction and wait until the
         * STANDBYWFI output is asserted to indicate that the
         * CPU is in idle and low power state. CPU can specualatively
         * prefetch the instructions so add NOPs after WFI. Sixteen
         * NOPs as per Cortex-A9 pipeline.
         */
        wfi                                     @ Wait For Interrupt
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop
        nop

        ldmfd   sp!, {pc}
ENDPROC(sh73a0_do_wfi)

	__CPUINIT
/*
 * Reset vector for secondary CPUs.
 *
 * First we turn on L1 cache coherency for our CPU. Then we jump to
 * shmobile_invalidate_start that invalidates the cache and hands over control
 * to the common ARM startup code.
 * This function will be mapped to address 0 by the SBAR register.
 * A normal branch is out of range here so we need a long jump. We jump to
 * the physical address as the MMU is still turned off.
 */
	.align	12
ENTRY(sh73a0_secondary_vector)
	mrc     p15, 0, r0, c0, c0, 5	@ read MIPDR
	and	r0, r0, #3		@ mask out cpu ID
	lsl	r0, r0, #3		@ we will shift by cpu_id * 8 bits
	mov	r1, #0xf0000000		@ SCU base address
	ldr	r2, [r1, #8]		@ SCU Power Status Register
	mov	r3, #3
	bic	r2, r2, r3, lsl r0	@ Clear bits of our CPU (Run Mode)
	str	r2, [r1, #8]		@ write back

	ldr	pc, 1f
1:	.long shmobile_invalidate_start - PAGE_OFFSET + PLAT_PHYS_OFFSET
ENDPROC(sh73a0_secondary_vector)
