/*
 * Copyright 2012 Freescale Semiconductor, Inc.
 * Copyright 2012 Linaro Ltd.
 *
 * The code contained herein is licensed under the GNU General Public
 * License. You may obtain a copy of the GNU General Public License
 * Version 2 or later at the following locations:
 *
 * http://www.opensource.org/licenses/gpl-license.html
 * http://www.gnu.org/copyleft/gpl.html
 */

#include <linux/init.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <asm/mach/arch.h>
#include <asm/mach/time.h>
#include <mach/common.h>

static int __init mxs_icoll_add_irq_domain(struct device_node *np,
				struct device_node *interrupt_parent)
{
	irq_domain_add_legacy(np, 128, 0, 0, &irq_domain_simple_ops, NULL);

	return 0;
}

static const struct of_device_id mxs_irq_match[] __initconst = {
	{ .compatible = "fsl,mxs-icoll", .data = mxs_icoll_add_irq_domain, },
	{ /* sentinel */ }
};

static void __init mxs_dt_init_irq(void)
{
	icoll_init_irq();
	of_irq_init(mxs_irq_match);
}

static void __init imx28_timer_init(void)
{
	mx28_clocks_init();
}

static struct sys_timer imx28_timer = {
	.init = imx28_timer_init,
};

static void __init mxs_machine_init(void)
{
	of_platform_populate(NULL, of_default_bus_match_table,
				NULL, NULL);
}

static const char *imx28_dt_compat[] __initdata = {
	"fsl,imx28-evk",
	"fsl,imx28",
	NULL,
};

DT_MACHINE_START(IMX28, "Freescale i.MX28 (Device Tree)")
	.map_io		= mx28_map_io,
	.init_irq	= mxs_dt_init_irq,
	.timer		= &imx28_timer,
	.init_machine	= mxs_machine_init,
	.dt_compat	= imx28_dt_compat,
	.restart	= mxs_restart,
MACHINE_END
