/*
 * reset AT91SAM9G45 as per errata
 *
 * Copyright (C) 2011 Jean-Christophe PLAGNIOL-VILLARD <plagnioj@jcosoft.com>
 *
 * unless the SDRAM is cleanly shutdown before we hit the
 * reset register it can be left driving the data bus and
 * killing the chance of a subsequent boot from NAND
 *
 * GPLv2 Only
 */

#include <linux/linkage.h>
#include <mach/hardware.h>
#if defined(CONFIG_ARCH_AT91CAP9)
#include <mach/at91cap9_ddrsdr.h>
#elif defined(CONFIG_ARCH_AT91SAM9G45)
#include <mach/at91sam9_ddrsdr.h>
#endif
#include <mach/at91_rstc.h>

			.arm

			.globl	at91sam9g45_restart

at91sam9g45_restart:
			ldr	r0, .at91_va_base_sdramc0	@ preload constants
			ldr	r5, .at91_va_base_sdramc1	@ preload constants
			ldr	r4, =at91_rstc_base
			ldr	r1, [r4]

			mov	r2, #1
			mov	r3, #AT91_DDRSDRC_LPCB_POWER_DOWN
			ldr	r4, =AT91_RSTC_KEY | AT91_RSTC_PERRST | AT91_RSTC_PROCRST

			.balign	32				@ align to cache line

			cmp	r5, #0
			strne	r2, [r5, #AT91_DDRSDRC_RTR]	@ disable DDR1 access
			strne	r3, [r5, #AT91_DDRSDRC_LPR]	@ power down DDR1
			str	r2, [r0, #AT91_DDRSDRC_RTR]	@ disable DDR0 access
			str	r3, [r0, #AT91_DDRSDRC_LPR]	@ power down DDR0
			str	r4, [r1, #AT91_RSTC_CR]		@ reset processor

			b	.

.at91_va_base_sdramc0:
	.word AT91_VA_BASE_SYS + AT91_DDRSDRC0
.at91_va_base_sdramc1:
#if defined(CONFIG_ARCH_AT91SAM9G45)
	.word AT91_VA_BASE_SYS + AT91_DDRSDRC1
#else
	.word 0
#endif
