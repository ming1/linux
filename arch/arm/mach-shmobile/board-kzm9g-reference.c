/*
 * KZM-A9-GT board support - Reference Device Tree Implementation
 *
 * Copyright (C) 2012	Horms Solutions Ltd.
 *
 * Based on board-kzm9g.c
 * Copyright (C) 2012	Kuninori Morimoto <kuninori.morimoto.gx@renesas.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/input.h>
#include <linux/of_platform.h>
#include <mach/sh73a0.h>
#include <mach/common.h>
#include <asm/hardware/cache-l2x0.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>

static void __init kzm_init(void)
{
	/* enable SCIFA4 */
	gpio_request(GPIO_FN_SCIFA4_TXD, NULL);
	gpio_request(GPIO_FN_SCIFA4_RXD, NULL);
	gpio_request(GPIO_FN_SCIFA4_RTS_, NULL);
	gpio_request(GPIO_FN_SCIFA4_CTS_, NULL);

	/* enable MMCIF */
	gpio_request(GPIO_FN_MMCCLK0,		NULL);
	gpio_request(GPIO_FN_MMCCMD0_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_0_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_1_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_2_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_3_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_4_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_5_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_6_PU,	NULL);
	gpio_request(GPIO_FN_MMCD0_7_PU,	NULL);

	/* I2C 3 */
	gpio_request(GPIO_FN_PORT27_I2C_SCL3, NULL);
	gpio_request(GPIO_FN_PORT28_I2C_SDA3, NULL);

#ifdef CONFIG_CACHE_L2X0
	/* Early BRESP enable, Shared attribute override enable, 64K*8way */
	l2x0_init(IOMEM(0xf0100000), 0x40460000, 0x82000fff);
#endif

	sh73a0_add_standard_devices_dt();
}

static void kzm9g_restart(char mode, const char *cmd)
{
#define RESCNT2 IOMEM(0xe6188020)
	/* Do soft power on reset */
	writel((1 << 31), RESCNT2);
}

static const char *kzm9g_boards_compat_dt[] __initdata = {
	"renesas,kzm9g-reference",
	NULL,
};

/* Please note that the clock initialisation shcheme used in
 * sh73a0_add_early_devices_dt() and sh73a0_add_standard_devices_dt()
 * does not work with SMP as there is a yet to be resolved lock-up in
 * workqueue initialisation.
 *
 * CONFIG_SMP should be disabled when using this code.
 */
DT_MACHINE_START(KZM9G_DT, "kzm9g-reference")
	.smp		= smp_ops(sh73a0_smp_ops),
	.map_io		= sh73a0_map_io,
	.init_early	= sh73a0_add_early_devices_dt,
	.nr_irqs	= NR_IRQS_LEGACY,
	.init_irq	= sh73a0_init_irq_dt,
	.init_machine	= kzm_init,
	.init_late	= shmobile_init_late,
	.init_time	= shmobile_timer_init,
	.restart	= kzm9g_restart,
	.dt_compat	= kzm9g_boards_compat_dt,
MACHINE_END
