/*
 * ARC FPGA Platform support code
 *
 * Copyright (C) 2012 Synopsys, Inc. (www.synopsys.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/console.h>
#include <linux/of_platform.h>
#include <asm/setup.h>
#include <asm/irq.h>
#include <asm/clk.h>
#include <plat/memmap.h>

/*----------------------- Platform Devices -----------------------------*/

static unsigned long arc_uart_info[] = {
	0,	/* uart->is_emulated (runtime @running_on_hw) */
	0,	/* uart->port.uartclk */
	0,	/* uart->baud */
	0
};

#if defined(CONFIG_SERIAL_ARC_CONSOLE)
/*
 * static platform data - but only for early serial
 * TBD: derive this from a special DT node
 */
static struct resource arc_uart0_res[] = {
	{
		.start = UART0_BASE,
		.end   = UART0_BASE + 0xFF,
		.flags = IORESOURCE_MEM,
	},
	{
		.start = UART0_IRQ,
		.end   = UART0_IRQ,
		.flags = IORESOURCE_IRQ,
	},
};

static struct platform_device arc_uart0_dev = {
	.name = "arc-uart",
	.id = 0,
	.num_resources = ARRAY_SIZE(arc_uart0_res),
	.resource = arc_uart0_res,
	.dev = {
		.platform_data = &arc_uart_info,
	},
};

static struct platform_device *fpga_early_devs[] __initdata = {
	&arc_uart0_dev,
};
#endif

static void arc_fpga_serial_init(void)
{
	/* To let driver workaround ISS bug: baudh Reg can't be set to 0 */
	arc_uart_info[0] = !running_on_hw;

	arc_uart_info[1] = arc_get_core_freq();

	arc_uart_info[2] = CONFIG_ARC_SERIAL_BAUD;

#if defined(CONFIG_SERIAL_ARC_CONSOLE)
	early_platform_add_devices(fpga_early_devs,
				   ARRAY_SIZE(fpga_early_devs));

	/*
	 * ARC console driver registers itself as an early platform driver
	 * of class "earlyprintk".
	 * Install it here, followed by probe of devices.
	 * The installation here doesn't require earlyprintk in command line
	 * To do so however, replace the lines below with
	 *	parse_early_param();
	 *	early_platform_driver_probe("earlyprintk", 1, 1);
	 *						      ^^
	 */
	early_platform_driver_register_all("earlyprintk");
	early_platform_driver_probe("earlyprintk", 1, 0);

	/*
	 * This is to make sure that arc uart would be preferred console
	 * despite one/more of following:
	 *   -command line lacked "console=ttyARC0" or
	 *   -CONFIG_VT_CONSOLE was enabled (for no reason whatsoever)
	 * Note that this needs to be done after above early console is reg,
	 * otherwise the early console never gets a chance to run.
	 */
	add_preferred_console("ttyARC", 0, "115200");
#endif
}

/*
 * Early Platform Initialization called from setup_arch()
 */
void __init arc_platform_early_init(void)
{
	pr_info("[plat-arcfpga]: registering early dev resources\n");

	arc_fpga_serial_init();
}

static struct of_dev_auxdata plat_auxdata_lookup[] __initdata = {
#if defined(CONFIG_SERIAL_ARC) || defined(CONFIG_SERIAL_ARC_MODULE)
	OF_DEV_AUXDATA("snps,arc-uart", UART0_BASE, "arc-uart", arc_uart_info),
#endif
	{}
};

int __init fpga_plat_init(void)
{
	pr_info("[plat-arcfpga]: registering device resources\n");

	/*
	 * Traverses flattened DeviceTree - registering platform devices
	 * complete with their resources
	 */
	of_platform_populate(NULL, of_default_bus_match_table,
			     plat_auxdata_lookup, NULL);

	return 0;
}
arch_initcall(fpga_plat_init);
