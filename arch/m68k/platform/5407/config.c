/***************************************************************************/

/*
 *	linux/arch/m68knommu/platform/5407/config.c
 *
 *	Copyright (C) 1999-2002, Greg Ungerer (gerg@snapgear.com)
 *	Copyright (C) 2000, Lineo (www.lineo.com)
 */

/***************************************************************************/

#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/init.h>
#include <linux/io.h>
#include <asm/machdep.h>
#include <asm/coldfire.h>
#include <asm/mcfsim.h>

/***************************************************************************/

static void __init m5407_timers_init(void)
{
	/* Timer1 is always used as system timer */
	writeb(MCFSIM_ICR_AUTOVEC | MCFSIM_ICR_LEVEL6 | MCFSIM_ICR_PRI3,
		MCF_MBAR + MCFSIM_TIMER1ICR);
	mcf_mapirq2imr(MCF_IRQ_TIMER, MCFINTC_TIMER1);

#ifdef CONFIG_HIGHPROFILE
	/* Timer2 is to be used as a high speed profile timer  */
	writeb(MCFSIM_ICR_AUTOVEC | MCFSIM_ICR_LEVEL7 | MCFSIM_ICR_PRI3,
		MCF_MBAR + MCFSIM_TIMER2ICR);
	mcf_mapirq2imr(MCF_IRQ_PROFILER, MCFINTC_TIMER2);
#endif
}

/***************************************************************************/

void m5407_cpu_reset(void)
{
	local_irq_disable();
	/* set watchdog to soft reset, and enabled */
	__raw_writeb(0xc0, MCF_MBAR + MCFSIM_SYPCR);
	for (;;)
		/* wait for watchdog to timeout */;
}

/***************************************************************************/

void __init config_BSP(char *commandp, int size)
{
	mach_reset = m5407_cpu_reset;
	mach_sched_init = hw_timer_init;
	m5407_timers_init();

	/* Only support the external interrupts on their primary level */
	mcf_mapirq2imr(25, MCFINTC_EINT1);
	mcf_mapirq2imr(27, MCFINTC_EINT3);
	mcf_mapirq2imr(29, MCFINTC_EINT5);
	mcf_mapirq2imr(31, MCFINTC_EINT7);
}

/***************************************************************************/
