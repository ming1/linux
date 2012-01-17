/*
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 *
 *  Copyright (C) 2010 John Crispin <blogic@openwrt.org>
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/mtd/physmap.h>
#include <linux/kernel.h>
#include <linux/reboot.h>
#include <linux/platform_device.h>
#include <linux/leds.h>
#include <linux/etherdevice.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/gpio.h>

#include <asm/bootinfo.h>
#include <asm/irq.h>

#include <lantiq_soc.h>
#include <lantiq_irq.h>
#include <lantiq_platform.h>

#include "devices.h"

/* gpio */
static struct resource ltq_gpio_resource[] = {
	MEM_RES("gpio0", LTQ_GPIO0_BASE_ADDR, LTQ_GPIO_SIZE),
	MEM_RES("gpio1", LTQ_GPIO1_BASE_ADDR, LTQ_GPIO_SIZE),
	MEM_RES("gpio2", LTQ_GPIO2_BASE_ADDR, LTQ_GPIO_SIZE),
};

void __init ltq_register_gpio(void)
{
	platform_device_register_simple("ltq_gpio", 0,
		&ltq_gpio_resource[0], 1);
	platform_device_register_simple("ltq_gpio", 1,
		&ltq_gpio_resource[1], 1);

	/* AR9 and VR9 have an extra gpio block */
	if (ltq_is_ar9() || ltq_is_vr9()) {
		platform_device_register_simple("ltq_gpio", 2,
			&ltq_gpio_resource[2], 1);
	}
}

/* serial to parallel conversion */
static struct resource ltq_stp_resource =
	MEM_RES("stp", LTQ_STP_BASE_ADDR, LTQ_STP_SIZE);

void __init ltq_register_gpio_stp(void)
{
	platform_device_register_simple("ltq_stp", 0, &ltq_stp_resource, 1);
}

/* asc ports - amazon se has its own serial mapping */
static struct resource ltq_ase_asc_resources[] = {
	MEM_RES("asc0", LTQ_ASC1_BASE_ADDR, LTQ_ASC_SIZE),
	IRQ_RES(tx, LTQ_ASC_ASE_TIR),
	IRQ_RES(rx, LTQ_ASC_ASE_RIR),
	IRQ_RES(err, LTQ_ASC_ASE_EIR),
};

void __init ltq_register_ase_asc(void)
{
	platform_device_register_simple("ltq_asc", 0,
		ltq_ase_asc_resources, ARRAY_SIZE(ltq_ase_asc_resources));
}

/* ethernet */
static struct resource ltq_etop_resources[] = {
	MEM_RES("etop", LTQ_ETOP_BASE_ADDR, LTQ_ETOP_SIZE),
	MEM_RES("gbit", LTQ_GBIT_BASE_ADDR, LTQ_GBIT_SIZE),
};

static struct platform_device ltq_etop = {
	.name		= "ltq_etop",
	.resource	= ltq_etop_resources,
	.num_resources	= 1,
};

void __init
ltq_register_etop(struct ltq_eth_data *eth)
{
	/* only register the gphy on socs that have one */
	if (ltq_is_ar9() | ltq_is_vr9())
		ltq_etop.num_resources = 2;
	if (eth) {
		ltq_etop.dev.platform_data = eth;
		platform_device_register(&ltq_etop);
	}
}
