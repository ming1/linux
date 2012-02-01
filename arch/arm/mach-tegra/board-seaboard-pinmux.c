/*
 * Copyright (C) 2010,2011 NVIDIA Corporation
 * Copyright (C) 2011 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>

#include "gpio-names.h"
#include "board-seaboard.h"
#include "board-pinmux.h"

#define DEFAULT_DRIVE(name)			\
	{					\
		.group = name,			\
		.high_speed_mode = 0,		\
		.schmitt = 0,			\
		.low_power_mode = 3,		\
		.drive_down_strength = 31,	\
		.drive_up_strength = 31,	\
		.slew_falling = 3,		\
		.slew_rising = 3,		\
	}

static struct tegra_board_pinmux_drive_conf seaboard_drive[] = {
	DEFAULT_DRIVE("drive_sdio1"),
};

static struct pinmux_map common_map[] = {
	TEGRA_PINMUX_MAP("ata",   "ide"),
	TEGRA_PINMUX_MAP("atb",   "sdio4"),
	TEGRA_PINMUX_MAP("atc",   "nand"),
	TEGRA_PINMUX_MAP("atd",   "gmi"),
	TEGRA_PINMUX_MAP("ate",   "gmi"),
	TEGRA_PINMUX_MAP("cdev1", "plla_out"),
	TEGRA_PINMUX_MAP("cdev2", "pllp_out4"),
	TEGRA_PINMUX_MAP("crtp",  "crt"),
	TEGRA_PINMUX_MAP("csus",  "vi_sensor_clk"),
	TEGRA_PINMUX_MAP("dap1",  "dap1"),
	TEGRA_PINMUX_MAP("dap2",  "dap2"),
	TEGRA_PINMUX_MAP("dap3",  "dap3"),
	TEGRA_PINMUX_MAP("dap4",  "dap4"),
	TEGRA_PINMUX_MAP("ddc",   "rsvd2"),
	TEGRA_PINMUX_MAP("dta",   "vi"),
	TEGRA_PINMUX_MAP("dtb",   "vi"),
	TEGRA_PINMUX_MAP("dtc",   "vi"),
	TEGRA_PINMUX_MAP("dtd",   "vi"),
	TEGRA_PINMUX_MAP("dte",   "vi"),
	TEGRA_PINMUX_MAP("dtf",   "i2c3"),
	TEGRA_PINMUX_MAP("gma",   "sdio4"),
	TEGRA_PINMUX_MAP("gmb",   "gmi"),
	TEGRA_PINMUX_MAP("gmc",   "uartd"),
	TEGRA_PINMUX_MAP("gmd",   "sflash"),
	TEGRA_PINMUX_MAP("gme",   "sdio4"),
	TEGRA_PINMUX_MAP("gpu",   "pwm"),
	TEGRA_PINMUX_MAP("gpu7",  "rtck"),
	TEGRA_PINMUX_MAP("gpv",   "pcie"),
	TEGRA_PINMUX_MAP("hdint", "hdmi"),
	TEGRA_PINMUX_MAP("i2cp",  "i2cp"),
	TEGRA_PINMUX_MAP("irrx",  "uartb"),
	TEGRA_PINMUX_MAP("irtx",  "uartb"),
	TEGRA_PINMUX_MAP("kbca",  "kbc"),
	TEGRA_PINMUX_MAP("kbcb",  "kbc"),
	TEGRA_PINMUX_MAP("kbcc",  "kbc"),
	TEGRA_PINMUX_MAP("kbcd",  "kbc"),
	TEGRA_PINMUX_MAP("kbce",  "kbc"),
	TEGRA_PINMUX_MAP("kbcf",  "kbc"),
	TEGRA_PINMUX_MAP("lcsn",  "rsvd4"),
	TEGRA_PINMUX_MAP("ld0",   "displaya"),
	TEGRA_PINMUX_MAP("ld1",   "displaya"),
	TEGRA_PINMUX_MAP("ld2",   "displaya"),
	TEGRA_PINMUX_MAP("ld3",   "displaya"),
	TEGRA_PINMUX_MAP("ld4",   "displaya"),
	TEGRA_PINMUX_MAP("ld5",   "displaya"),
	TEGRA_PINMUX_MAP("ld6",   "displaya"),
	TEGRA_PINMUX_MAP("ld7",   "displaya"),
	TEGRA_PINMUX_MAP("ld8",   "displaya"),
	TEGRA_PINMUX_MAP("ld9",   "displaya"),
	TEGRA_PINMUX_MAP("ld10",  "displaya"),
	TEGRA_PINMUX_MAP("ld11",  "displaya"),
	TEGRA_PINMUX_MAP("ld12",  "displaya"),
	TEGRA_PINMUX_MAP("ld13",  "displaya"),
	TEGRA_PINMUX_MAP("ld14",  "displaya"),
	TEGRA_PINMUX_MAP("ld15",  "displaya"),
	TEGRA_PINMUX_MAP("ld16",  "displaya"),
	TEGRA_PINMUX_MAP("ld17",  "displaya"),
	TEGRA_PINMUX_MAP("ldc",   "rsvd4"),
	TEGRA_PINMUX_MAP("ldi",   "displaya"),
	TEGRA_PINMUX_MAP("lhp0",  "displaya"),
	TEGRA_PINMUX_MAP("lhp1",  "displaya"),
	TEGRA_PINMUX_MAP("lhp2",  "displaya"),
	TEGRA_PINMUX_MAP("lhs",   "displaya"),
	TEGRA_PINMUX_MAP("lm0",   "rsvd4"),
	TEGRA_PINMUX_MAP("lm1",   "crt"),
	TEGRA_PINMUX_MAP("lpp",   "displaya"),
	TEGRA_PINMUX_MAP("lpw1",  "rsvd4"),
	TEGRA_PINMUX_MAP("lsc0",  "displaya"),
	TEGRA_PINMUX_MAP("lsdi",  "rsvd4"),
	TEGRA_PINMUX_MAP("lspi",  "displaya"),
	TEGRA_PINMUX_MAP("lvp0",  "rsvd4"),
	TEGRA_PINMUX_MAP("lvp1",  "displaya"),
	TEGRA_PINMUX_MAP("lvs",   "displaya"),
	TEGRA_PINMUX_MAP("owc",   "rsvd2"),
	TEGRA_PINMUX_MAP("pmc",   "pwr_on"),
	TEGRA_PINMUX_MAP("pta",   "hdmi"),
	TEGRA_PINMUX_MAP("rm",    "i2c1"),
	TEGRA_PINMUX_MAP("sdb",   "sdio3"),
	TEGRA_PINMUX_MAP("sdc",   "sdio3"),
	TEGRA_PINMUX_MAP("sdd",   "sdio3"),
	TEGRA_PINMUX_MAP("sdio1", "sdio1"),
	TEGRA_PINMUX_MAP("slxa",  "pcie"),
	TEGRA_PINMUX_MAP("slxd",  "spdif"),
	TEGRA_PINMUX_MAP("spdi",  "rsvd2"),
	TEGRA_PINMUX_MAP("spdo",  "rsvd2"),
	TEGRA_PINMUX_MAP("spia",  "gmi"),
	TEGRA_PINMUX_MAP("spib",  "gmi"),
	TEGRA_PINMUX_MAP("spic",  "gmi"),
	TEGRA_PINMUX_MAP("spid",  "spi1"),
	TEGRA_PINMUX_MAP("spie",  "spi1"),
	TEGRA_PINMUX_MAP("spif",  "spi1"),
	TEGRA_PINMUX_MAP("spig",  "spi2_alt"),
	TEGRA_PINMUX_MAP("spih",  "spi2_alt"),
	TEGRA_PINMUX_MAP("uaa",   "ulpi"),
	TEGRA_PINMUX_MAP("uab",   "ulpi"),
	TEGRA_PINMUX_MAP("uac",   "rsvd2"),
	TEGRA_PINMUX_MAP("uad",   "irda"),
	TEGRA_PINMUX_MAP("uca",   "uartc"),
	TEGRA_PINMUX_MAP("ucb",   "uartc"),
	TEGRA_PINMUX_MAP("uda",   "ulpi"),
};

static struct pinmux_map seaboard_map[] = {
	TEGRA_PINMUX_MAP("lpw0",  "hdmi"),
	TEGRA_PINMUX_MAP("lpw2",  "hdmi"),
	TEGRA_PINMUX_MAP("lsc1",  "hdmi"),
	TEGRA_PINMUX_MAP("lsck",  "hdmi"),
	TEGRA_PINMUX_MAP("lsda",  "hdmi"),
	TEGRA_PINMUX_MAP("slxc",  "spdif"),
	TEGRA_PINMUX_MAP("slxk",  "pcie"),
};

static struct pinmux_map ventana_map[] = {
	TEGRA_PINMUX_MAP("lpw0",  "displaya"),
	TEGRA_PINMUX_MAP("lpw2",  "displaya"),
	TEGRA_PINMUX_MAP("lsc1",  "displaya"),
	TEGRA_PINMUX_MAP("lsck",  "displaya"),
	TEGRA_PINMUX_MAP("lsda",  "displaya"),
	TEGRA_PINMUX_MAP("slxc",  "sdio3"),
	TEGRA_PINMUX_MAP("slxk",  "sdio3"),
};

static struct tegra_board_pinmux_pg_conf common_pg[] = {
	{"ata",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"atb",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"atc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"atd",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"ate",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"cdev1",   TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"cdev2",   TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"crtp",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
	{"csus",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"dap1",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"dap2",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"dap3",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"dap4",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"dta",     TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_DRIVEN},
	{"dtb",     TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_DRIVEN},
	{"dtc",     TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_DRIVEN},
	{"dtd",     TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_DRIVEN},
	{"dte",     TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_TRISTATE},
	{"dtf",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gma",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gmb",     TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
	{"gmc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gme",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gpu",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gpu7",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gpv",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"hdint",   TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"i2cp",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"irrx",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"irtx",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"kbca",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"kbcb",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"kbcc",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"kbcd",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"kbce",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"kbcf",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"lcsn",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"ld0",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld1",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld2",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld3",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld4",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld5",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld6",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld7",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld8",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld9",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld10",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld11",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld12",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld13",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld14",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld15",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld16",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ld17",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"ldc",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"ldi",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lhp0",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lhp1",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lhp2",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lhs",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lm0",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lm1",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lpp",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lpw0",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lpw1",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lpw2",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lsc0",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lsck",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lsda",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lsdi",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lspi",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lvp0",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"lvp1",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"lvs",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"owc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"pmc",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"rm",      TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"sdb",     TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"sdc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"sdd",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"sdio1",   TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"slxa",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
	{"slxd",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"slxk",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"spdi",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"spdo",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"spib",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spid",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spie",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spif",    TEGRA_PINCONFIG_PULL_DOWN, TEGRA_PINCONFIG_TRISTATE},
	{"spih",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
	{"uaa",     TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"uab",     TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"uac",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"uad",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"uca",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"ucb",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"uda",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"ck32",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ddrc",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"pmca",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"pmcb",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"pmcc",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"pmcd",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"pmce",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"xm2c",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"xm2d",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ls",      TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"lc",      TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ld17_0",  TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ld19_18", TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ld21_20", TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
	{"ld23_22", TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DONT_SET},
};

static struct tegra_board_pinmux_pg_conf seaboard_pg[] = {
	{"ddc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"gmd",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"lsc1",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_TRISTATE},
	{"pta",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"slxc",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spia",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
	{"spic",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_DRIVEN},
	{"spig",    TEGRA_PINCONFIG_PULL_UP,   TEGRA_PINCONFIG_TRISTATE},
};

static struct tegra_board_pinmux_pg_conf ventana_pg[] = {
	{"ddc",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"gmd",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"lsc1",    TEGRA_PINCONFIG_DONT_SET,  TEGRA_PINCONFIG_DRIVEN},
	{"pta",     TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"slxc",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_DRIVEN},
	{"spia",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spic",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
	{"spig",    TEGRA_PINCONFIG_PULL_NONE, TEGRA_PINCONFIG_TRISTATE},
};

static struct tegra_gpio_table common_gpio_table[] = {
	{ .gpio = TEGRA_GPIO_SD2_CD,		.enable = true },
	{ .gpio = TEGRA_GPIO_SD2_WP,		.enable = true },
	{ .gpio = TEGRA_GPIO_SD2_POWER,		.enable = true },
	{ .gpio = TEGRA_GPIO_CDC_IRQ,		.enable = true },
};

static struct tegra_gpio_table seaboard_gpio_table[] = {
	{ .gpio = TEGRA_GPIO_LIDSWITCH,		.enable = true },
	{ .gpio = TEGRA_GPIO_POWERKEY,		.enable = true },
	{ .gpio = TEGRA_GPIO_HP_DET,		.enable = true },
	{ .gpio = TEGRA_GPIO_ISL29018_IRQ,	.enable = true },
	{ .gpio = TEGRA_GPIO_USB1,		.enable = true },
};

static struct tegra_gpio_table ventana_gpio_table[] = {
	/* hp_det */
	{ .gpio = TEGRA_GPIO_PW2,		.enable = true },
	/* int_mic_en */
	{ .gpio = TEGRA_GPIO_PX0,		.enable = true },
	/* ext_mic_en */
	{ .gpio = TEGRA_GPIO_PX1,		.enable = true },
};

static struct tegra_board_pinmux_conf common_conf = {
	.maps = common_map,
	.map_count = ARRAY_SIZE(common_map),
	.pgs = common_pg,
	.pg_count = ARRAY_SIZE(common_pg),
	.gpios = common_gpio_table,
	.gpio_count = ARRAY_SIZE(common_gpio_table),
};

static struct tegra_board_pinmux_conf seaboard_conf = {
	.maps = seaboard_map,
	.map_count = ARRAY_SIZE(seaboard_map),
	.pgs = seaboard_pg,
	.pg_count = ARRAY_SIZE(seaboard_pg),
	.drives = seaboard_drive,
	.drive_count = ARRAY_SIZE(seaboard_drive),
	.gpios = seaboard_gpio_table,
	.gpio_count = ARRAY_SIZE(seaboard_gpio_table),
};

static struct tegra_board_pinmux_conf ventana_conf = {
	.maps = ventana_map,
	.map_count = ARRAY_SIZE(ventana_map),
	.pgs = ventana_pg,
	.pg_count = ARRAY_SIZE(ventana_pg),
	.gpios = ventana_gpio_table,
	.gpio_count = ARRAY_SIZE(ventana_gpio_table),
};

void seaboard_pinmux_init(void)
{
	tegra_board_pinmux_init(&common_conf, &seaboard_conf);
}

void ventana_pinmux_init(void)
{
	tegra_board_pinmux_init(&common_conf, &ventana_conf);
}
