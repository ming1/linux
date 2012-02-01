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

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/notifier.h>
#include <linux/of.h>
#include <linux/pinctrl/pinconf.h>
#include <linux/string.h>

#include <mach/gpio-tegra.h>

#include "board-pinmux.h"
#include "devices.h"

struct tegra_board_pinmux_conf *confs[2];

static void tegra_board_pinmux_setup_gpios(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(confs); i++) {
		if (!confs[i])
			continue;

		tegra_gpio_config(confs[i]->gpios, confs[i]->gpio_count);
	}
}

static inline void tegra_board_pinmux_conf(const char *group, u16 param,
					   u16 arg)
{
	if (arg == TEGRA_PINCONFIG_DONT_SET)
		return;
	pin_config_group_set(PINMUX_DEV, group, TEGRA_PINCONF_PACK(param, arg));
}

static void tegra_board_pinmux_setup_pinmux(void)
{
	int i, j;
	const char *group;

	for (i = 0; i < ARRAY_SIZE(confs); i++) {
		if (!confs[i])
			continue;

		for (j = 0; j < confs[i]->pg_count; j++) {
			group = confs[i]->pgs[j].group;
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_PULL,
				confs[i]->pgs[j].pull);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_TRISTATE,
				confs[i]->pgs[j].tristate);
		}

		for (j = 0; j < confs[i]->drive_count; j++) {
			group = confs[i]->drives[j].group;

			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_HIGH_SPEED_MODE,
				confs[i]->drives[j].high_speed_mode);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_SCHMITT,
				confs[i]->drives[j].schmitt);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_LOW_POWER_MODE,
				confs[i]->drives[j].low_power_mode);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_DRIVE_DOWN_STRENGTH,
				confs[i]->drives[j].drive_down_strength);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_DRIVE_UP_STRENGTH,
				confs[i]->drives[j].drive_up_strength);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_SLEW_RATE_FALLING,
				confs[i]->drives[j].slew_falling);
			tegra_board_pinmux_conf(group,
				TEGRA_PINCONF_PARAM_SLEW_RATE_RISING,
				confs[i]->drives[j].slew_rising);
		}
	}
}

static int tegra_board_pinmux_bus_notify(struct notifier_block *nb,
					 unsigned long event, void *vdev)
{
	static bool had_gpio;
	static bool had_pinmux;

	struct device *dev = vdev;
	const char *devname;

	if (event != BUS_NOTIFY_BOUND_DRIVER)
		return NOTIFY_DONE;

	devname = dev_name(dev);

	if (!had_gpio && !strcmp(devname, GPIO_DEV)) {
		tegra_board_pinmux_setup_gpios();
		had_gpio = true;
	} else if (!had_pinmux && !strcmp(devname, PINMUX_DEV)) {
		tegra_board_pinmux_setup_pinmux();
		had_pinmux = true;
	}

	if (had_gpio && had_pinmux)
		return NOTIFY_STOP_MASK;
	else
		return NOTIFY_DONE;
}

static struct notifier_block nb = {
	.notifier_call = tegra_board_pinmux_bus_notify,
};

static struct platform_device *devices[] = {
	&tegra_gpio_device,
	&tegra_pinmux_device,
};

void tegra_board_pinmux_init(struct tegra_board_pinmux_conf *conf_a,
			     struct tegra_board_pinmux_conf *conf_b)
{
	int i;

	confs[0] = conf_a;
	confs[1] = conf_b;

	for (i = 0; i < ARRAY_SIZE(confs); i++) {
		if (!confs[i])
			continue;

		pinmux_register_mappings(confs[i]->maps, confs[i]->map_count);
	}

	bus_register_notifier(&platform_bus_type, &nb);

	if (!of_machine_is_compatible("nvidia,tegra20"))
		platform_add_devices(devices, ARRAY_SIZE(devices));
}
