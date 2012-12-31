/*
 * mackerel board support - Reference Device Tree Implementation
 *
 * Copyright (C) 2012 Renesas Solutions Corp.
 *
 * Copyright (C) 2010 Kuninori Morimoto <kuninori.morimoto.gx@renesas.com>
 *
 * based on ap4evb
 * Copyright (C) 2010  Magnus Damm
 * Copyright (C) 2008  Yoshihiro Shimoda
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
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/gpio.h>

#include <mach/common.h>
#include <mach/irqs.h>
#include <mach/sh7372.h>

#include <asm/mach/arch.h>

#define IRQ7 evt2irq(0x02e0)
#define IRQ21 evt2irq(0x32a0)

static void __init mackerel_init(void)
{
	sh7372_add_standard_devices_dt();

	/* External clock source */
	clk_set_rate(&sh7372_dv_clki_clk, 27000000);

	sh7372_pinmux_init();

	/* enable SCIFA0 */
	gpio_request(GPIO_FN_SCIFA0_TXD, NULL);
	gpio_request(GPIO_FN_SCIFA0_RXD, NULL);

	/* enable SMSC911X */
	gpio_request(GPIO_FN_CS5A,	NULL);
	gpio_request(GPIO_FN_IRQ6_39,	NULL);

	/* enable Touchscreen */
	gpio_request(GPIO_FN_IRQ7_40,	NULL);
	irq_set_irq_type(IRQ7, IRQ_TYPE_LEVEL_LOW);

	/* enable Accelerometer */
	gpio_request(GPIO_FN_IRQ21,	NULL);
	irq_set_irq_type(IRQ21, IRQ_TYPE_LEVEL_HIGH);

	/* enable SDHI0 */
	gpio_request(GPIO_FN_SDHIWP0, NULL);
	gpio_request(GPIO_FN_SDHICMD0, NULL);
	gpio_request(GPIO_FN_SDHICLK0, NULL);
	gpio_request(GPIO_FN_SDHID0_3, NULL);
	gpio_request(GPIO_FN_SDHID0_2, NULL);
	gpio_request(GPIO_FN_SDHID0_1, NULL);
	gpio_request(GPIO_FN_SDHID0_0, NULL);

	/* SDHI0 PORT172 card-detect IRQ26 */
	gpio_request(GPIO_FN_IRQ26_172, NULL);

	/* enable SDHI1 */
	gpio_request(GPIO_FN_SDHICMD1, NULL);
	gpio_request(GPIO_FN_SDHICLK1, NULL);
	gpio_request(GPIO_FN_SDHID1_3, NULL);
	gpio_request(GPIO_FN_SDHID1_2, NULL);
	gpio_request(GPIO_FN_SDHID1_1, NULL);
	gpio_request(GPIO_FN_SDHID1_0, NULL);

	/* enable SDHI2 */
	gpio_request(GPIO_FN_SDHICMD2, NULL);
	gpio_request(GPIO_FN_SDHICLK2, NULL);
	gpio_request(GPIO_FN_SDHID2_3, NULL);
	gpio_request(GPIO_FN_SDHID2_2, NULL);
	gpio_request(GPIO_FN_SDHID2_1, NULL);
	gpio_request(GPIO_FN_SDHID2_0, NULL);

	/* card detect pin for microSD slot (CN23) */
	gpio_request(GPIO_PORT162, NULL);
	gpio_direction_input(GPIO_PORT162);

	/* MMCIF */
	gpio_request(GPIO_FN_MMCD0_0, NULL);
	gpio_request(GPIO_FN_MMCD0_1, NULL);
	gpio_request(GPIO_FN_MMCD0_2, NULL);
	gpio_request(GPIO_FN_MMCD0_3, NULL);
	gpio_request(GPIO_FN_MMCD0_4, NULL);
	gpio_request(GPIO_FN_MMCD0_5, NULL);
	gpio_request(GPIO_FN_MMCD0_6, NULL);
	gpio_request(GPIO_FN_MMCD0_7, NULL);
	gpio_request(GPIO_FN_MMCCMD0, NULL);
	gpio_request(GPIO_FN_MMCCLK0, NULL);
}

static const char *mackerel_compat_dt[] __initdata = {
	"renesas,mackerel-reference",
	NULL,
};

DT_MACHINE_START(MACKEREL, "mackerel-reference")
	.map_io		= sh7372_map_io,
	.init_early	= sh7372_add_early_devices_dt,
	.init_irq	= sh7372_init_irq_of,
	.handle_irq	= shmobile_handle_irq_intc,
	.init_machine	= mackerel_init,
	.init_late	= sh7372_pm_init_late,
	.timer		= &shmobile_timer,
	.dt_compat	= mackerel_compat_dt,
MACHINE_END
