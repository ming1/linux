/*
 * Copyright (c) 2011, NVIDIA CORPORATION.  All rights reserved.
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

#ifndef __MACH_TEGRA_BOARD_PINMUX_H
#define __MACH_TEGRA_BOARD_PINMUX_H

#include <linux/pinctrl/machine.h>

#include <mach/pinconf-tegra.h>

#define GPIO_DEV "tegra-gpio"
#define PINMUX_DEV "tegra-pinmux"

#define TEGRA_PINMUX_MAP(_group_, _function_) {	\
	.name = _group_,			\
	.ctrl_dev_name = PINMUX_DEV,		\
	.group = _group_,			\
	.function = _function_,			\
	.hog_on_boot = true,			\
}

#define TEGRA_PINCONFIG_DONT_SET 0xffff

struct tegra_board_pinmux_pg_conf {
	const char *group;
	u16 pull;
	u16 tristate;
};

struct tegra_board_pinmux_drive_conf {
	const char *group;
	u16 high_speed_mode;
	u16 schmitt;
	u16 low_power_mode;
	u16 drive_down_strength;
	u16 drive_up_strength;
	u16 slew_falling;
	u16 slew_rising;
};

struct tegra_board_pinmux_conf {
	struct pinmux_map *maps;
	int map_count;

	struct tegra_board_pinmux_pg_conf *pgs;
	int pg_count;

	struct tegra_board_pinmux_drive_conf *drives;
	int drive_count;

	struct tegra_gpio_table *gpios;
	int gpio_count;
};

void tegra_board_pinmux_init(struct tegra_board_pinmux_conf *conf_a,
			     struct tegra_board_pinmux_conf *conf_b);

#endif
