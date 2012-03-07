/*
 * Copyright 2012 (C), Jason Cooper <jason@lakedaemon.net>
 *
 * arch/arm/mach-kirkwood/board-dt.c
 *
 * Marvell DreamPlug Reference Board Setup
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/mtd/partitions.h>
#include <linux/ata_platform.h>
#include <linux/mv643xx_eth.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/gpio.h>
#include <linux/leds.h>
#include <linux/mtd/physmap.h>
#include <linux/spi/flash.h>
#include <linux/spi/spi.h>
#include <linux/spi/orion_spi.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <mach/kirkwood.h>
#include <mach/bridge-regs.h>
#include <plat/mvsdio.h>
#include "common.h"
#include "mpp.h"

static struct of_device_id kirkwood_dt_match_table[] __initdata = {
	{ .compatible = "simple-bus", },
	{ }
};

static struct mv643xx_eth_platform_data dreamplug_ge00_data = {
	.phy_addr	= MV643XX_ETH_PHY_ADDR(0),
};

static struct mv643xx_eth_platform_data dreamplug_ge01_data = {
	.phy_addr	= MV643XX_ETH_PHY_ADDR(1),
};

static struct mv_sata_platform_data dreamplug_sata_data = {
	.n_ports	= 1,
};

static struct mvsdio_platform_data dreamplug_mvsdio_data = {
	/* unfortunately the CD signal has not been connected */
};

static struct gpio_led dreamplug_led_pins[] = {
	{
		.name			= "dreamplug:blue:bluetooth",
		.gpio			= 47,
		.active_low		= 1,
	},
	{
		.name			= "dreamplug:green:wifi",
		.gpio			= 48,
		.active_low		= 1,
	},
	{
		.name			= "dreamplug:green:wifi_ap",
		.gpio			= 49,
		.active_low		= 1,
	},
};

static struct gpio_led_platform_data dreamplug_led_data = {
	.leds		= dreamplug_led_pins,
	.num_leds	= ARRAY_SIZE(dreamplug_led_pins),
};

static struct platform_device dreamplug_leds = {
	.name	= "leds-gpio",
	.id	= -1,
	.dev	= {
		.platform_data	= &dreamplug_led_data,
	}
};

static unsigned int dreamplug_mpp_config[] __initdata = {
	MPP0_SPI_SCn,
	MPP1_SPI_MOSI,
	MPP2_SPI_SCK,
	MPP3_SPI_MISO,
	MPP47_GPIO,	/* Bluetooth LED */
	MPP48_GPIO,	/* Wifi LED */
	MPP49_GPIO,	/* Wifi AP LED */
	0
};

static void __init dreamplug_init(void)
{
	/*
	 * Basic setup. Needs to be called early.
	 */
	kirkwood_mpp_conf(dreamplug_mpp_config);

	kirkwood_ehci_init();
	kirkwood_ge00_init(&dreamplug_ge00_data);
	kirkwood_ge01_init(&dreamplug_ge01_data);
	kirkwood_sata_init(&dreamplug_sata_data);
	kirkwood_sdio_init(&dreamplug_mvsdio_data);

	platform_device_register(&dreamplug_leds);
}

static void __init kirkwood_dt_init(void)
{
	pr_info("Kirkwood: %s, TCLK=%d.\n", kirkwood_id(), kirkwood_tclk);

	/*
	 * Disable propagation of mbus errors to the CPU local bus,
	 * as this causes mbus errors (which can occur for example
	 * for PCI aborts) to throw CPU aborts, which we're not set
	 * up to deal with.
	 */
	writel(readl(CPU_CONFIG) & ~CPU_CONFIG_ERROR_PROP, CPU_CONFIG);

	kirkwood_setup_cpu_mbus();

#ifdef CONFIG_CACHE_FEROCEON_L2
	kirkwood_l2_init();
#endif

	/* internal devices that every board has */
	kirkwood_xor0_init();
	kirkwood_xor1_init();
	kirkwood_crypto_init();

#ifdef CONFIG_KEXEC
	kexec_reinit = kirkwood_enable_pcie;
#endif

	if (of_machine_is_compatible("globalscale,dreamplug"))
		dreamplug_init();

	of_platform_populate(NULL, kirkwood_dt_match_table, NULL, NULL);
}

static const char *kirkwood_dt_board_compat[] = {
	"globalscale,dreamplug",
	NULL
};

DT_MACHINE_START(KIRKWOOD_DT, "Marvell Kirkwood (Flattened Device Tree)")
	/* Maintainer: Jason Cooper <jason@lakedaemon.net> */
	.map_io		= kirkwood_map_io,
	.init_early	= kirkwood_init_early,
	.init_irq	= kirkwood_init_irq,
	.timer		= &kirkwood_timer,
	.init_machine	= kirkwood_dt_init,
	.restart	= kirkwood_restart,
	.dt_compat	= kirkwood_dt_board_compat,
MACHINE_END
