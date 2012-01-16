/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * Copyright (C) 2011 Thomas Langer <thomas.langer@lantiq.com>
 * Copyright (C) 2011 John Crispin <blogic@openwrt.org>
 */

#include <linux/platform_device.h>
#include <linux/mtd/nand.h>

#include <lantiq_soc.h>

#include "devices.h"

/* nand flash */
/* address lines used for NAND control signals */
#define NAND_ADDR_ALE		0x10000
#define NAND_ADDR_CLE		0x20000
/* Ready/Busy Status */
#define MODCON_STS		0x0002
/* Ready/Busy Status Edge */
#define MODCON_STSEDGE		0x0004

static const char *part_probes[] = { "cmdlinepart", NULL };

static int
falcon_nand_ready(struct mtd_info *mtd)
{
	u32 modcon = ltq_ebu_r32(LTQ_EBU_MODCON);

	return (((modcon & (MODCON_STS | MODCON_STSEDGE)) ==
						(MODCON_STS | MODCON_STSEDGE)));
}

static void
falcon_hwcontrol(struct mtd_info *mtd, int cmd, unsigned int ctrl)
{
	struct nand_chip *this = mtd->priv;
	unsigned long nandaddr = (unsigned long) this->IO_ADDR_W;

	if (ctrl & NAND_CTRL_CHANGE) {
		nandaddr &= ~(NAND_ADDR_ALE | NAND_ADDR_CLE);

		if (ctrl & NAND_CLE)
			nandaddr |= NAND_ADDR_CLE;
		if (ctrl & NAND_ALE)
			nandaddr |= NAND_ADDR_ALE;

		this->IO_ADDR_W = (void __iomem *) nandaddr;
	}

	if (cmd != NAND_CMD_NONE)
		writeb(cmd, this->IO_ADDR_W);
}

static struct platform_nand_data falcon_flash_nand_data = {
	.chip = {
		.nr_chips		= 1,
		.chip_delay		= 25,
		.part_probe_types	= part_probes,
	},
	.ctrl = {
		.cmd_ctrl		= falcon_hwcontrol,
		.dev_ready		= falcon_nand_ready,
	}
};

static struct resource ltq_nand_res =
	MEM_RES("nand", LTQ_FLASH_START, LTQ_FLASH_MAX);

static struct platform_device ltq_flash_nand = {
	.name		= "gen_nand",
	.id		= -1,
	.num_resources	= 1,
	.resource	= &ltq_nand_res,
	.dev		= {
		.platform_data = &falcon_flash_nand_data,
	},
};

void __init
falcon_register_nand(void)
{
	platform_device_register(&ltq_flash_nand);
}
