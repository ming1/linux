/*
 * Technologic Systems TS-5500 board - SBC info layer
 *
 * Copyright (c) 2010-2011 Savoir-faire Linux Inc.
 *	Alexandre Savard <alexandre.savard@savoirfairelinux.com>
 *	Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>
 *	Vivien Didelot <vivien.didelot@savoirfairelinux.com>
 *
 * Portions originate from ts_sbcinfo.c (c) Technologic Systems
 *	Liberty Young <liberty@embeddedx86.com>
 *
 * These functions add sysfs platform entries to display information about
 * the Technologic Systems TS-5500 Single Board Computer (SBC).
 *
 * For further information about sysfs entries, see
 * Documentation/ABI/testing/sysfs-platform-ts5500
 */

#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <asm/processor.h>
#include <linux/leds.h>
#include <linux/gpio.h>
#include "ts5500_gpio.h"
#include "ts5500_adc.h"

/* Hardware info for pre-detection */
#define AMD_ELAN_FAMILY			4
#define AMD_ELAN_SC520			9

/* Product code register */
#define TS5500_PRODUCT_CODE_REG		0x74
#define TS5500_PRODUCT_CODE		0x60	/* TS-5500 product code */

/* SRAM/RS-485/ADC options, and RS-485 RTS/Automatic RS-485 flags register */
#define TS5500_SRAM_RS485_ADC_REG	0x75
#define TS5500_SRAM_OPT			0x01	/* SRAM option */
#define TS5500_RS485_OPT		0x02	/* RS-485 option */
#define TS5500_ADC_OPT			0x04	/* A/D converter option */
#define TS5500_RS485_RTS_MASK		0x40	/* RTS for RS-485 */
#define TS5500_RS485_AUTO_MASK		0x80	/* Automatic RS-485 */

/* External Reset/Industrial Temperature Range options register */
#define TS5500_ERESET_ITR_REG		0x76
#define TS5500_ERESET_OPT		0x01	/*  External Reset option */
#define TS5500_ITR_OPT			0x02	/* Indust. Temp. Range option */

/* LED/Jumpers register */
#define TS5500_LED_JMPRS_REG		0x77
#define TS5500_LED_MASK			0x01	/* LED flag */
#define TS5500_JP1			0x02	/* Automatic CMOS */
#define TS5500_JP2			0x04	/* Enable Serial Console */
#define TS5500_JP3			0x08	/* Write Enable Drive A */
#define TS5500_JP4			0x10	/* Fast Console (115K baud) */
#define TS5500_JP5			0x20	/* User Jumper */
#define TS5500_JP6			0x40	/* Console on COM1 (req. JP2) */
#define TS5500_JP7			0x80	/* Undocumented (Unused) */

/**
 * struct ts5500_sbc - TS-5500 SBC main structure
 * @lock:		Read/Write mutex.
 * @board_id:		Board name.
 * @sram:		Check SRAM option.
 * @rs485:		Check RS-485 option.
 * @adc:		Check Analogic/Digital converter option.
 * @ereset:		Check External Reset option.
 * @itr:		Check Industrial Temperature Range option.
 * @jumpers:		States of jumpers 1-7.
 */
struct ts5500_sbc {
	struct mutex		lock;
	int			board_id;
	bool			sram;
	bool			rs485;
	bool			adc;
	bool			ereset;
	bool			itr;
	u8			jumpers;
};

/* Current platform */
struct ts5500_sbc *ts5500;

/**
 * ts5500_pre_detect_hw() - check for TS-5500 specific hardware
 */
static __init int ts5500_pre_detect_hw(void)
{
	/* Check for AMD ElanSC520 Microcontroller */
	if (cpu_info.x86_vendor != X86_VENDOR_AMD ||
	    cpu_info.x86 != AMD_ELAN_FAMILY	  ||
	    cpu_info.x86_model != AMD_ELAN_SC520)
		return -ENODEV;

	return 0;
}

/* BIOS signatures */
static struct {
	const unsigned char *string;
	const ssize_t offset;
} signatures[] __initdata = {
	{"TS-5x00 AMD Elan", 0xb14}
};

/**
 * ts5500_bios_signature() - find board signature in BIOS shadow RAM.
 */
static __init int ts5500_bios_signature(void)
{
	void __iomem *bios = ioremap(0xF0000, 0x10000);
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(signatures); i++)
		if (check_signature(bios + signatures[i].offset,
				    signatures[i].string,
				    strlen(signatures[i].string)))
			goto found;
		else
			pr_notice("Technologic Systems BIOS signature "
				  "'%s' not found at offset %zd\n",
				  signatures[i].string, signatures[i].offset);
	ret = -ENODEV;
found:
	iounmap(bios);
	return ret;
}

/**
 * ts5500_detect_config() - detect the TS board
 * @sbc:		Structure where to store the detected board's details.
 */
static int ts5500_detect_config(struct ts5500_sbc *sbc)
{
	u8 tmp;
	int ret = 0;

	if (!request_region(TS5500_PRODUCT_CODE_REG, 4, "ts5500"))
		return -EBUSY;

	mutex_lock(&ts5500->lock);
	tmp = inb(TS5500_PRODUCT_CODE_REG);
	if (tmp != TS5500_PRODUCT_CODE) {
		pr_err("This platform is not a TS-5500 (found ID 0x%x)\n", tmp);
		ret = -ENODEV;
		goto error;
	}
	sbc->board_id = tmp;

	tmp = inb(TS5500_SRAM_RS485_ADC_REG);
	ts5500->sram = !!(tmp & TS5500_SRAM_OPT);
	ts5500->rs485 = !!(tmp & TS5500_RS485_OPT);
	ts5500->adc = !!(tmp & TS5500_ADC_OPT);

	tmp = inb(TS5500_ERESET_ITR_REG);
	ts5500->ereset = !!(tmp & TS5500_ERESET_OPT);
	ts5500->itr = !!(tmp & TS5500_ITR_OPT);

	tmp = inb(TS5500_LED_JMPRS_REG);
	sbc->jumpers = tmp & 0xFE;	/* All bits except the first (LED) */

error:
	mutex_unlock(&ts5500->lock);
	release_region(TS5500_PRODUCT_CODE_REG, 4);
	return ret;
}

#define TS5500_IS_JP_SET(sbc, jmp) (!!(sbc->jumpers & TS5500_JP##jmp))

#ifdef CONFIG_TS5500_LED
static struct led_info ts5500_led_info = {
	.name = "ts5500_led",
	.default_trigger = "ts5500_led",
	.flags = TS5500_LED_MASK
};

static struct led_platform_data ts5500_led_platform_data = {
	.num_leds = 1,
	.leds = &ts5500_led_info
};

static struct resource ts5500_led_resources[] = {
	{
		.name = "ts5500_led",
		.start = TS5500_LED_JMPRS_REG,
		.end = TS5500_LED_JMPRS_REG,
		.flags = IORESOURCE_IO
	}
};

static void ts5500_led_release(struct device *dev)
{
	/* noop */
}

static struct platform_device ts5500_led_device = {
	.name = "ts5500_led",
	.resource = ts5500_led_resources,
	.num_resources = ARRAY_SIZE(ts5500_led_resources),
	.id = -1,
	.dev = {
		.platform_data = &ts5500_led_platform_data,
		.release = ts5500_led_release
	}
};
#endif

#ifdef CONFIG_TS5500_GPIO
/* Callback for releasing resources */
static void ts5500_gpio_device_release(struct device *dev)
{
	/* noop */
}

static struct platform_device ts5500_gpio_device = {
	.name = "ts5500_gpio",
	.id = -1,
	.dev = {
		.release = ts5500_gpio_device_release,
	}
};
#endif

#ifdef CONFIG_TS5500_ADC
static void ts5500_adc_release(struct device *dev)
{
	/* noop */
}

static struct resource ts5500_adc_resources[] = {
	{
		.name  = "ts5500_adc" "-data",
		.start = TS5500_ADC_INIT_LSB_REG,
		.end   = TS5500_ADC_MSB_REG,
		.flags = IORESOURCE_IO,
	},
	{
		.name  = "ts5500_adc" "-ctrl",
		.start = TS5500_ADC_CTRL_REG,
		.end   = TS5500_ADC_CTRL_REG,
		.flags = IORESOURCE_IO,
	}
};

static struct ts5500_adc_platform_data ts5500_adc_platform_data = {
	.name = TS5500_ADC_NAME,
	.ioaddr = {
		.data = TS5500_ADC_INIT_LSB_REG,
		.ctrl = TS5500_ADC_CTRL_REG,
	},
	.read = {
		.delay     = TS5500_ADC_READ_DELAY,
		.busy_mask = TS5500_ADC_READ_BUSY_MASK,
	},
	.ctrl = {
		{ TS5500_ADC_UNIPOLAR | TS5500_ADC_RANGE_5V,
		  TS5500_ADC_UNIPOLAR | TS5500_ADC_RANGE_10V },
		{ TS5500_ADC_BIPOLAR  | TS5500_ADC_RANGE_5V,
		  TS5500_ADC_BIPOLAR  | TS5500_ADC_RANGE_10V },
	},
	.ranges = {
		.min = {
			{  0,     0 },
			{ -5000, -10000 },
		},
		.max = {
			{  5000,  10000 },
			{  5000,  10000 },
		},
	},
	.scale = {
		{ 12207, 24414 },
		{ 24414, 48828 },
	},
};

static struct platform_device ts5500_adc_device = {
	.name = "ts5500_adc",
	.id = -1,
	.resource = ts5500_adc_resources,
	.num_resources = ARRAY_SIZE(ts5500_adc_resources),
	.dev = {
		.platform_data = &ts5500_adc_platform_data,
		.release = ts5500_adc_release,
	},
};
#endif
static struct platform_device *ts5500_devices[] __initdata = {
#ifdef CONFIG_TS5500_LED
	&ts5500_led_device,
#endif
#ifdef CONFIG_TS5500_GPIO
	&ts5500_gpio_device,
#endif
};

static ssize_t ts5500_show_id(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "0x%x\n", sbc->board_id);
}

static ssize_t ts5500_show_sram(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", sbc->sram);
}

static ssize_t ts5500_show_rs485(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", sbc->rs485);
}

static ssize_t ts5500_show_adc(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", sbc->adc);
}

static ssize_t ts5500_show_ereset(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", sbc->ereset);
}

static ssize_t ts5500_show_itr(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct ts5500_sbc *sbc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", sbc->itr);
}

#define TS5500_SHOW_JP(jp)						\
	static ssize_t ts5500_show_jp##jp(struct device *dev,		\
					  struct device_attribute *attr,\
					  char *buf)			\
	{								\
		struct ts5500_sbc *sbc = dev_get_drvdata(dev);		\
		return sprintf(buf, "%d\n", TS5500_IS_JP_SET(sbc, jp)); \
	}

TS5500_SHOW_JP(1)
TS5500_SHOW_JP(2)
TS5500_SHOW_JP(3)
TS5500_SHOW_JP(4)
TS5500_SHOW_JP(5)
TS5500_SHOW_JP(6)

static DEVICE_ATTR(id, S_IRUGO, ts5500_show_id, NULL);
static DEVICE_ATTR(sram, S_IRUGO, ts5500_show_sram, NULL);
static DEVICE_ATTR(rs485, S_IRUGO, ts5500_show_rs485, NULL);
static DEVICE_ATTR(adc, S_IRUGO, ts5500_show_adc, NULL);
static DEVICE_ATTR(ereset, S_IRUGO, ts5500_show_ereset, NULL);
static DEVICE_ATTR(itr, S_IRUGO, ts5500_show_itr, NULL);
static DEVICE_ATTR(jp1, S_IRUGO, ts5500_show_jp1, NULL);
static DEVICE_ATTR(jp2, S_IRUGO, ts5500_show_jp2, NULL);
static DEVICE_ATTR(jp3, S_IRUGO, ts5500_show_jp3, NULL);
static DEVICE_ATTR(jp4, S_IRUGO, ts5500_show_jp4, NULL);
static DEVICE_ATTR(jp5, S_IRUGO, ts5500_show_jp5, NULL);
static DEVICE_ATTR(jp6, S_IRUGO, ts5500_show_jp6, NULL);

static struct attribute *ts5500_attributes[] = {
	&dev_attr_id.attr,
	&dev_attr_sram.attr,
	&dev_attr_rs485.attr,
	&dev_attr_adc.attr,
	&dev_attr_ereset.attr,
	&dev_attr_itr.attr,
	&dev_attr_jp1.attr,
	&dev_attr_jp2.attr,
	&dev_attr_jp3.attr,
	&dev_attr_jp4.attr,
	&dev_attr_jp5.attr,
	&dev_attr_jp6.attr,
	NULL
};

static const struct attribute_group ts5500_attr_group = {
	.attrs = ts5500_attributes
};

static int __init ts5500_init(void)
{
	int ret;
	struct platform_device *pdev;

	/*
	 * There is no DMI available, or PCI bridge subvendor info,
	 * only the BIOS provides a 16-bit identification call.
	 * It is safer to check for a TS-5500 specific hardware
	 * such as the processor, then find a signature in the BIOS.
	 */
	ret = ts5500_pre_detect_hw();
	if (ret)
		return ret;

	ret = ts5500_bios_signature();
	if (ret)
		return ret;

	ts5500 = kzalloc(sizeof(struct ts5500_sbc), GFP_KERNEL);
	if (!ts5500)
		return -ENOMEM;
	mutex_init(&ts5500->lock);

	ret = ts5500_detect_config(ts5500);
	if (ret)
		goto release_mem;

	pdev = platform_device_register_simple("ts5500", -1, NULL, 0);
	if (IS_ERR(pdev)) {
		ret = PTR_ERR(pdev);
		goto release_mem;
	}
	platform_set_drvdata(pdev, ts5500);

	ret = platform_add_devices(ts5500_devices, ARRAY_SIZE(ts5500_devices));
	if (ret)
		goto release_pdev;

#ifdef CONFIG_TS5500_ADC
	if (ts5500->adc) {
		ret = platform_device_register(&ts5500_adc_device);
		if (ret)
			goto release_pdev;
	}
#endif

	ret = sysfs_create_group(&pdev->dev.kobj,
				 &ts5500_attr_group);
	if (ret)
		goto release_pdev;

	return 0;

release_pdev:
	platform_device_unregister(pdev);
release_mem:
	kfree(ts5500);

	return ret;
}
postcore_initcall(ts5500_init);

MODULE_AUTHOR("Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>");
MODULE_AUTHOR("Alexandre Savard <alexandre.savard@savoirfairelinux.com>");
MODULE_AUTHOR("Vivien Didelot <vivien.didelot@savoirfairelinux.com>");
MODULE_DESCRIPTION("Technologic Systems TS-5500 Board's platform driver");
MODULE_LICENSE("GPL");
