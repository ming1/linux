/***************************************************************************/

/*
 *	linux/arch/m68knommu/platform/523x/config.c
 *
 *	Sub-architcture dependent initialization code for the Freescale
 *	523x CPUs.
 *
 *	Copyright (C) 1999-2005, Greg Ungerer (gerg@snapgear.com)
 *	Copyright (C) 2001-2003, SnapGear Inc. (www.snapgear.com)
 */

/***************************************************************************/

#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/init.h>
#include <linux/io.h>
#include <asm/machdep.h>
#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/mcfuart.h>

/***************************************************************************/

#ifdef CONFIG_SPI_COLDFIRE_QSPI

static void __init m523x_qspi_init(void)
{
	u16 par;

	/* setup QSPS pins for QSPI with gpio CS control */
	writeb(0x1f, MCFGPIO_PAR_QSPI);
	/* and CS2 & CS3 as gpio */
	par = readw(MCFGPIO_PAR_TIMER);
	par &= 0x3f3f;
	writew(par, MCFGPIO_PAR_TIMER);
}

#endif /* CONFIG_SPI_COLDFIRE_QSPI */

/***************************************************************************/

static void __init m523x_fec_init(void)
{
	u16 par;
	u8 v;

	/* Set multi-function pins to ethernet use */
	par = readw(MCF_IPSBAR + 0x100082);
	writew(par | 0xf00, MCF_IPSBAR + 0x100082);
	v = readb(MCF_IPSBAR + 0x100078);
	writeb(v | 0xc0, MCF_IPSBAR + 0x100078);
}

/***************************************************************************/

static void m523x_cpu_reset(void)
{
	local_irq_disable();
	__raw_writeb(MCF_RCR_SWRESET, MCF_IPSBAR + MCF_RCR);
}

/***************************************************************************/

void __init config_BSP(char *commandp, int size)
{
	mach_reset = m523x_cpu_reset;
	mach_sched_init = hw_timer_init;
}

/***************************************************************************/

static int __init init_BSP(void)
{
#ifdef CONFIG_SPI_COLDFIRE_QSPI
	m523x_qspi_init();
#endif
	return 0;
}

arch_initcall(init_BSP);

/***************************************************************************/
