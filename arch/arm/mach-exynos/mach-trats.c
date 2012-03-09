/*
 * linux/arch/arm/mach-exynos/board-trats.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/platform_device.h>
#include <linux/serial_core.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/fixed.h>
#include <linux/mfd/max8997.h>
#include <linux/mfd/max8997-private.h>
#include <linux/mmc/host.h>

#include <asm/mach/arch.h>
#include <asm/hardware/gic.h>
#include <asm/mach-types.h>

#include <plat/regs-serial.h>
#include <plat/cpu.h>
#include <plat/devs.h>
#include <plat/sdhci.h>
#include <plat/clock.h>
#include <plat/gpio-cfg.h>
#include <plat/iic.h>

#include <mach/map.h>

#include "common.h"

/* Following are default values for UCON, ULCON and UFCON UART registers */
#define TRATS_UCON_DEFAULT	(S3C2410_UCON_TXILEVEL |	\
				 S3C2410_UCON_RXILEVEL |	\
				 S3C2410_UCON_TXIRQMODE |	\
				 S3C2410_UCON_RXIRQMODE |	\
				 S3C2410_UCON_RXFIFO_TOI |	\
				 S3C2443_UCON_RXERR_IRQEN)

#define TRATS_ULCON_DEFAULT	S3C2410_LCON_CS8

#define TRATS_UFCON_DEFAULT	(S3C2410_UFCON_FIFOMODE |	\
				 S5PV210_UFCON_TXTRIG256 |	\
				 S5PV210_UFCON_RXTRIG256)

enum fixed_regulator_id {
	FIXED_REG_ID_MMC = 0,
};

static struct s3c2410_uartcfg trats_uartcfgs[] __initdata = {
	{
		.hwport		= 0,
		.ucon		= TRATS_UCON_DEFAULT,
		.ulcon		= TRATS_ULCON_DEFAULT,
		.ufcon		= TRATS_UFCON_DEFAULT,
	},
	{
		.hwport		= 1,
		.ucon		= TRATS_UCON_DEFAULT,
		.ulcon		= TRATS_ULCON_DEFAULT,
		.ufcon		= TRATS_UFCON_DEFAULT,
	},
	{
		.hwport		= 2,
		.ucon		= TRATS_UCON_DEFAULT,
		.ulcon		= TRATS_ULCON_DEFAULT,
		.ufcon		= TRATS_UFCON_DEFAULT,
	},
	{
		.hwport		= 3,
		.ucon		= TRATS_UCON_DEFAULT,
		.ulcon		= TRATS_ULCON_DEFAULT,
		.ufcon		= TRATS_UFCON_DEFAULT,
	},
};

/* eMMC */
static struct s3c_sdhci_platdata trats_hsmmc0_data __initdata = {
	.max_width		= 8,
	.host_caps		= (MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA |
				MMC_CAP_MMC_HIGHSPEED | MMC_CAP_SD_HIGHSPEED |
				MMC_CAP_DISABLE | MMC_CAP_ERASE),
	.cd_type		= S3C_SDHCI_CD_PERMANENT,
	.clk_type		= S3C_SDHCI_CLK_DIV_EXTERNAL,
};

static struct regulator_consumer_supply emmc_supplies[] = {
	REGULATOR_SUPPLY("vmmc", "s3c-sdhci.0"),
};

static struct regulator_init_data emmc_fixed_voltage_init_data = {
	.constraints		= {
		.name		= "VMEM_VDD_2.8V",
		.valid_ops_mask	= REGULATOR_CHANGE_STATUS,
	},
	.num_consumer_supplies	= ARRAY_SIZE(emmc_supplies),
	.consumer_supplies	= emmc_supplies,
};

static struct fixed_voltage_config emmc_fixed_voltage_config = {
	.supply_name		= "MASSMEMORY_EN",
	.microvolts		= 2800000,
	.gpio			= EXYNOS4_GPK0(2),
	.enable_high		= true,
	.init_data		= &emmc_fixed_voltage_init_data,
};

static struct platform_device emmc_fixed_voltage = {
	.name			= "reg-fixed-voltage",
	.id			= FIXED_REG_ID_MMC,
	.dev			= {
		.platform_data	= &emmc_fixed_voltage_config,
	},
};

static void __init trats_sdhci_init(void)
{
	s3c_sdhci0_set_platdata(&trats_hsmmc0_data);
}

static struct regulator_consumer_supply __initdata max8997_buck1_[] = {
	REGULATOR_SUPPLY("vdd_arm", NULL), /* CPUFREQ */
};
static struct regulator_consumer_supply __initdata max8997_buck2_[] = {
	REGULATOR_SUPPLY("vdd_int", NULL), /* CPUFREQ */
};

static struct regulator_init_data __initdata max8997_ldo2_data = {
	.constraints	= {
		.name		= "VALIVE_1.1V_C210",
		.min_uV		= 1100000,
		.max_uV		= 1100000,
		.apply_uV	= 1,
		.always_on	= 1,
		.state_mem	= {
			.enabled	= 1,
		},
	},
};

static struct regulator_init_data __initdata max8997_ldo6_data = {
	.constraints	= {
		.name		= "VCC_1.8V_PDA",
		.min_uV		= 1800000,
		.max_uV		= 1800000,
		.apply_uV	= 1,
		.always_on	= 1,
		.state_mem	= {
			.enabled	= 1,
		},
	},
};

static struct regulator_init_data __initdata max8997_ldo9_data = {
	.constraints	= {
		.name		= "VCC_2.8V_PDA",
		.min_uV		= 2800000,
		.max_uV		= 2800000,
		.apply_uV	= 1,
		.always_on	= 1,
		.state_mem	= {
			.enabled	= 1,
		},
	},
};

static struct regulator_init_data __initdata max8997_ldo10_data = {
	.constraints	= {
		.name		= "VPLL_1.1V_C210",
		.min_uV		= 1100000,
		.max_uV		= 1100000,
		.apply_uV	= 1,
		.always_on	= 1,
		.state_mem	= {
			.disabled	= 1,
		},
	},
};

static struct regulator_init_data __initdata max8997_buck1_data = {
	.constraints	= {
		.name		= "VARM_1.2V_C210",
		.min_uV		= 900000,
		.max_uV		= 1350000,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE,
		.always_on	= 1,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies = ARRAY_SIZE(max8997_buck1_),
	.consumer_supplies = max8997_buck1_,
};

static struct regulator_init_data __initdata max8997_buck2_data = {
	.constraints	= {
		.name		= "VINT_1.1V_C210",
		.min_uV		= 900000,
		.max_uV		= 1100000,
		.valid_ops_mask	= REGULATOR_CHANGE_VOLTAGE,
		.always_on	= 1,
		.state_mem	= {
			.disabled	= 1,
		},
	},
	.num_consumer_supplies = ARRAY_SIZE(max8997_buck2_),
	.consumer_supplies = max8997_buck2_,
};

static struct regulator_init_data __initdata max8997_buck5_data = {
	.constraints	= {
		.name		= "VMEM_1.2V_C210",
		.min_uV		= 1200000,
		.max_uV		= 1200000,
		.apply_uV	= 1,
		.always_on	= 1,
		.state_mem	= {
			.enabled	= 1,
		},
	},
};

static struct regulator_init_data __initdata max8997_buck6_data = {
	.constraints	= {
		.name		= "V_BAT",
		.min_uV		= 2800000,
		.max_uV		= 2800000,
		.always_on	= 1,
		.state_mem	= {
			.enabled	= 1,
		},
	},
};

static struct max8997_regulator_data __initdata trats_max8997_regulators[] = {
	{ MAX8997_LDO2, &max8997_ldo2_data },
	{ MAX8997_LDO6, &max8997_ldo6_data },
	{ MAX8997_LDO9, &max8997_ldo9_data },
	{ MAX8997_LDO10, &max8997_ldo10_data },

	{ MAX8997_BUCK1, &max8997_buck1_data },
	{ MAX8997_BUCK2, &max8997_buck2_data },
	{ MAX8997_BUCK5, &max8997_buck5_data },
	{ MAX8997_BUCK6, &max8997_buck6_data },
};

static struct max8997_platform_data __initdata trats_max8997_pdata = {
	.wakeup			= 1,

	.num_regulators		= ARRAY_SIZE(trats_max8997_regulators),
	.regulators		= trats_max8997_regulators,

	.buck125_gpios = { EXYNOS4_GPX0(5), EXYNOS4_GPX0(6), EXYNOS4_GPL0(0) },

	.buck1_voltage[0] = 1350000, /* 1.35V */
	.buck1_voltage[1] = 1300000, /* 1.3V */
	.buck1_voltage[2] = 1250000, /* 1.25V */
	.buck1_voltage[3] = 1200000, /* 1.2V */
	.buck1_voltage[4] = 1150000, /* 1.15V */
	.buck1_voltage[5] = 1100000, /* 1.1V */
	.buck1_voltage[6] = 1000000, /* 1.0V */
	.buck1_voltage[7] = 950000, /* 0.95V */

	.buck2_voltage[0] = 1100000, /* 1.1V */
	.buck2_voltage[1] = 1000000, /* 1.0V */
	.buck2_voltage[2] = 950000, /* 0.95V */
	.buck2_voltage[3] = 900000, /* 0.9V */
	.buck2_voltage[4] = 1100000, /* 1.1V */
	.buck2_voltage[5] = 1000000, /* 1.0V */
	.buck2_voltage[6] = 950000, /* 0.95V */
	.buck2_voltage[7] = 900000, /* 0.9V */

	.buck5_voltage[0] = 1200000, /* 1.2V */
	.buck5_voltage[1] = 1200000, /* 1.2V */
	.buck5_voltage[2] = 1200000, /* 1.2V */
	.buck5_voltage[3] = 1200000, /* 1.2V */
	.buck5_voltage[4] = 1200000, /* 1.2V */
	.buck5_voltage[5] = 1200000, /* 1.2V */
	.buck5_voltage[6] = 1200000, /* 1.2V */
	.buck5_voltage[7] = 1200000, /* 1.2V */
};

/* I2C 5 (PMIC) */
enum { I2C5_MAX8997 };
static struct i2c_board_info i2c5_devs[] __initdata = {
	[I2C5_MAX8997] = {
		I2C_BOARD_INFO("max8997", 0xCC >> 1),
		.platform_data	= &trats_max8997_pdata,
	},
};

static void __init trats_power_init(void)
{
	int gpio;

	gpio = EXYNOS4_GPX0(7);
	gpio_request(gpio, "AP_PMIC_IRQ");
	s3c_gpio_cfgpin(gpio, S3C_GPIO_SFN(0xf));
	s3c_gpio_setpull(gpio, S3C_GPIO_PULL_NONE);
}

static struct platform_device *trats_devices[] __initdata = {
	/* Samsung Platform Devices */
	&s3c_device_i2c5, /* PMIC should initialize first */
	&emmc_fixed_voltage,
	&s3c_device_hsmmc0,
	&s3c_device_wdt,
};

static void __init trats_map_io(void)
{
	exynos_init_io(NULL, 0);
	s3c24xx_init_clocks(24000000);
	s3c24xx_init_uarts(trats_uartcfgs, ARRAY_SIZE(trats_uartcfgs));
}

static void __init trats_machine_init(void)
{
	trats_sdhci_init();
	trats_power_init();

	s3c_i2c5_set_platdata(NULL);
	i2c5_devs[I2C5_MAX8997].irq = gpio_to_irq(EXYNOS4_GPX0(7));
	i2c_register_board_info(5, i2c5_devs, ARRAY_SIZE(i2c5_devs));

	/* Last */
	platform_add_devices(trats_devices, ARRAY_SIZE(trats_devices));
}

MACHINE_START(TRATS, "TRATS")
	/* Maintainer: Kyungmin Park <kyungmin.park@samsung.com> */
	.atag_offset	= 0x100,
	.init_irq	= exynos4_init_irq,
	.map_io		= trats_map_io,
	.handle_irq	= gic_handle_irq,
	.init_machine	= trats_machine_init,
	.timer		= &exynos4_timer,
	.restart	= exynos4_restart,
MACHINE_END
