/*
 * GPIO (DIO) driver for Technologic Systems TS-5500
 *
 * Copyright (c) 2010 Savoir-faire Linux Inc.
 *	Jerome Oufella <jerome.oufella@savoirfairelinux.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * TS-5500 board has 38 GPIOs referred to as DIOs in the product's literature.
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/io.h>
#include "ts5500_gpio.h"

static void port_bit_set(u8 addr, int bit)
{
	u8 var;
	var = inb(addr);
	var |= (1 << bit);
	outb(var, addr);
}

static void port_bit_clear(u8 addr, int bit)
{
	u8 var;
	var = inb(addr);
	var &= ~(1 << bit);
	outb(var, addr);
}

/* "DIO" line to IO port mapping table for line's value */
static const unsigned long line_to_port_map[] = {
	0x7B, 0x7B, 0x7B, 0x7B, 0x7B, 0x7B, 0x7B, 0x7B,		/* DIO1_0~7  */
	0x7C, 0x7C, 0x7C, 0x7C, 0x7C, 0x7C,			/* DIO1_8~13 */
	0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x7E, 0x7E,		/* DIO2_0~7  */
	0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,			/* DIO2_8~13 */
	0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72, 0x72,		/* LCD_0~7   */
	0x73, 0x73, 0x73			   /* LCD_EN, LCD_RS, LCD_WR */
};

/* "DIO" line to IO port's bit map for line's value */
static const int line_to_bit_map[] = {
	0, 1, 2, 3, 4, 5, 6, 7,		/* DIO1_0~7  */
	0, 1, 2, 3, 4, 5,		/* DIO1_8~13 */
	0, 1, 2, 3, 4, 5, 6, 7,		/* DIO2_0~7  */
	0, 1, 2, 3, 4, 5,		/* DIO2_8~13 */
	0, 1, 2, 3, 4, 5, 6, 7,		/* LCD_0~7   */
	0, 7, 6				/* LCD_EN, LCD_RS, LCD_WR */
};

/* "DIO" line's direction control mapping table */
static const unsigned long line_to_dir_map[] = {
	0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A,		/* DIO1_0~7  */
	0x7A, 0x7A, 0x7A, 0x7A, 0, 0,				/* DIO1_8~13 */
	0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D,		/* DIO2_0~7  */
	0x7D, 0x7D, 0x7D, 0x7D, 0, 0,				/* DIO2_8~13 */
	0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D, 0x7D,		/* LCD_0~7   */
	0, 0, 0					   /* LCD_EN, LCD_RS, LCD_WR */
};

/* "DIO" line's direction control bit-mapping table */
static const int line_to_dir_bit_map[] = {
	0, 0, 0, 0,  1,  1, 1, 1,	/* DIO1_0~7  */
	5, 5, 5, 5, -1, -1,		/* DIO1_8~13 */
	0, 0, 0, 0,  1,  1, 1, 1,	/* DIO2_0~7  */
	5, 5, 5, 5, -1, -1,		/* DIO2_8~13 */
	2, 2, 2, 2,  3,  3, 3, 3,	/* LCD_0~7   */
	-1, -1, -1			/* LCD_EN, LCD_RS, LCD_WR */
};

/* This array is used to track requests for our GPIO lines */
static int requested_gpios[TS5500_LCD_WR + 1];

static int dio1_irq = 1;
module_param(dio1_irq, int, 0644);
MODULE_PARM_DESC(dio1_irq,
		 "Enable usage of IRQ7 for any DIO1 line (default 1).");

static int dio2_irq = 0;
module_param(dio2_irq, int, 0644);
MODULE_PARM_DESC(dio2_irq,
		 "Enable usage of IRQ6 for any DIO2 line (default 0).");

static int lcd_irq = 0;
module_param(lcd_irq, int, 0644);
MODULE_PARM_DESC(lcd_irq, "Enable usage of IRQ1 for any LCD line (default 0).");

static int use_lcdio = 0;
module_param(use_lcdio, int, 0644);
MODULE_PARM_DESC(use_lcdio, "Enable usage of the LCD header for DIO operation"
		 " (default 0).");

/**
 * struct ts5500_drvdata - Driver data
 * @master:		Device.
 * @gpio_chip:		GPIO chip.
 * @gpio_lock:		Read/Write Mutex.
 */
struct ts5500_drvdata {
	struct device *master;
	struct gpio_chip gpio_chip;
	struct mutex gpio_lock;
};

static int ts5500_gpio_request(struct gpio_chip *chip, unsigned offset)
{
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	mutex_lock(&drvdata->gpio_lock);
	if (requested_gpios[offset]) {
		mutex_unlock(&drvdata->gpio_lock);
		return -EBUSY;
	}
	requested_gpios[offset] = 1;
	mutex_unlock(&drvdata->gpio_lock);

	return 0;
}

static void ts5500_gpio_free(struct gpio_chip *chip, unsigned offset)
{
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	mutex_lock(&drvdata->gpio_lock);
	requested_gpios[offset] = 0;
	mutex_unlock(&drvdata->gpio_lock);
}

static int ts5500_gpio_get(struct gpio_chip *chip, unsigned offset)
{
	unsigned long ioaddr;
	u8 byte;
	int bitno;
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	/* Some lines are output-only and cannot be read */
	if (offset == TS5500_LCD_EN || offset > chip->ngpio)
		return -ENXIO;

	ioaddr = line_to_port_map[offset];
	bitno = line_to_bit_map[offset];
	byte = inb(ioaddr);

	return (byte >> bitno) & 0x1;
}

static void ts5500_gpio_set(struct gpio_chip *chip, unsigned offset, int val)
{
	int bitno;
	unsigned long ioaddr;
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	/* Some lines just can't be set */
	switch (offset) {
	case TS5500_DIO1_12:
	case TS5500_DIO1_13:
	case TS5500_DIO2_13:
	case TS5500_LCD_RS:
	case TS5500_LCD_WR:
		return;
	default:
		if (offset > chip->ngpio)
			return;
		break;
	}

	/* Get io port and bit for 'offset' */
	ioaddr = line_to_port_map[offset];
	bitno = line_to_bit_map[offset];

	mutex_lock(&drvdata->gpio_lock);
	if (val == 0)
		port_bit_clear(ioaddr, bitno);
	else
		port_bit_set(ioaddr, bitno);
	mutex_unlock(&drvdata->gpio_lock);
}

static int ts5500_gpio_to_irq(struct gpio_chip *chip, unsigned offset)
{
	/* Only a few lines are IRQ-Capable */
	switch (offset) {
	case TS5500_DIO1_13:
		return TS5500_DIO1_13_IRQ;
	case TS5500_DIO2_13:
		return TS5500_DIO2_13_IRQ;
	case TS5500_LCD_RS:
		return TS5500_LCD_RS_IRQ;
	default:
		break;
	}

	/*
	 * Handle the case where the user bridged the IRQ line with another
	 * DIO line from the same header.
	 */
	if (dio1_irq && offset >= TS5500_DIO1_0 && offset < TS5500_DIO1_13)
		return TS5500_DIO1_13_IRQ;

	if (dio2_irq && offset >= TS5500_DIO2_0 && offset < TS5500_DIO2_13)
		return TS5500_DIO2_13_IRQ;

	if (lcd_irq && offset >= TS5500_LCD_0 && offset <= TS5500_LCD_WR)
		return TS5500_LCD_RS_IRQ;

	return -ENXIO;
}

static int ts5500_gpio_direction_input(struct gpio_chip *chip, unsigned offset)
{
	unsigned long dir_reg;
	int dir_bit;
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	/* Some lines cannot be set as inputs */
	switch (offset) {
	case TS5500_LCD_EN:
		return -ENXIO;
	default:
		if (offset > chip->ngpio)
			return -ENXIO;
		break;
	}

	dir_reg = line_to_dir_map[offset];
	dir_bit = line_to_dir_bit_map[offset];

	mutex_lock(&drvdata->gpio_lock);
	port_bit_clear(dir_reg, dir_bit);
	mutex_unlock(&drvdata->gpio_lock);

	return 0;
}

static int ts5500_gpio_direction_output(struct gpio_chip *chip, unsigned offset,
					int val)
{
	unsigned long dir_reg, ioaddr;
	int dir_bit, bitno;
	struct ts5500_drvdata *drvdata;

	drvdata = container_of(chip, struct ts5500_drvdata, gpio_chip);

	/* Some lines cannot be set as outputs */
	switch (offset) {
	case TS5500_DIO1_12:
	case TS5500_DIO1_13:
	case TS5500_DIO2_13:
	case TS5500_LCD_RS:
	case TS5500_LCD_WR:
		return -ENXIO;
	default:
		if (offset > chip->ngpio)
			return -ENXIO;
		break;
	}

	/* Get direction and value registers infos */
	dir_reg = line_to_dir_map[offset];
	dir_bit = line_to_dir_bit_map[offset];
	ioaddr = line_to_port_map[offset];
	bitno = line_to_bit_map[offset];

	mutex_lock(&drvdata->gpio_lock);
	if (val == 0)
		port_bit_clear(ioaddr, bitno); /* Set initial line value */
	else
		port_bit_set(ioaddr, bitno);
	port_bit_set(dir_reg, dir_bit); /* Set output direction for line */

	/*
	 * Confirm initial line output value
	 * (might have been changed by input)
	 */
	if (val == 0)
		port_bit_clear(ioaddr, bitno);
	else
		port_bit_set(ioaddr, bitno);
	mutex_unlock(&drvdata->gpio_lock);

	return 0;
}

static int __devinit ts5500_gpio_probe(struct platform_device *pdev)
{
	struct ts5500_drvdata *drvdata;
	struct gpio_chip *chip;
	int ret;

	if (pdev == NULL) {
		dev_err(&pdev->dev, "Platform device not available!\n");
		return -ENODEV;
	}

	/* Request DIO1 */
	if (!request_region(0x7A, 3, "ts5500-gpio-DIO1")) {
		dev_err(&pdev->dev, "Cannot request I/O port 0x7A-7C\n");
		goto err_req_dio1;
	}

	/* Request DIO2 */
	if (!request_region(0x7D, 3, "ts5500-gpio-DIO2")) {
		dev_err(&pdev->dev, "Cannot request I/O port 0x7D-7F\n");
		goto err_req_dio2;
	}

	/* Request LCDIO if wanted */
	if (use_lcdio && !request_region(0x72, 2, "ts5500-gpio-LCD")) {
		dev_err(&pdev->dev, "Cannot request I/O port 0x72-73\n");
		goto err_req_lcdio;
	}

	/* Setup the gpio_chip structure */
	drvdata = kzalloc(sizeof(struct ts5500_drvdata), GFP_KERNEL);
	if (drvdata == NULL)
		goto err_alloc_dev;

	memset(requested_gpios, 0, sizeof(requested_gpios));
	mutex_init(&drvdata->gpio_lock);

	drvdata->master = pdev->dev.parent;
	chip = &drvdata->gpio_chip;
	chip->request = ts5500_gpio_request;
	chip->free = ts5500_gpio_free;
	chip->to_irq = ts5500_gpio_to_irq;
	chip->direction_input = ts5500_gpio_direction_input;
	chip->direction_output = ts5500_gpio_direction_output;
	chip->get = ts5500_gpio_get;
	chip->set = ts5500_gpio_set;
	chip->can_sleep = 0;
	chip->base = TS5500_DIO1_0;
	chip->label = pdev->name;
	chip->ngpio = (use_lcdio ? TS5500_LCD_WR + 1 : TS5500_DIO2_13 + 1);

	/* Enable IRQ generation */
	mutex_lock(&drvdata->gpio_lock);
	port_bit_set(0x7A, 7); /* DIO1_13 on IRQ7 */
	port_bit_set(0x7D, 7); /* DIO2_13 on IRQ6 */
	if (use_lcdio) {
		port_bit_clear(0x7D, 4); /* Enable LCD header usage as DIO */
		port_bit_set(0x7D, 6);   /* LCD_RS on IRQ1 */
	}
	mutex_unlock(&drvdata->gpio_lock);

	/* Register chip */
	ret = gpiochip_add(&drvdata->gpio_chip);
	if (ret)
		goto err_gpiochip_add;

	platform_set_drvdata(pdev, drvdata);

	return 0;

err_gpiochip_add:
	dev_err(&pdev->dev, "Failed to register the gpio chip.\n");
	kfree(drvdata);

err_alloc_dev:
	if (use_lcdio)
		release_region(0x72, 2);	/* Release LCD's region */

err_req_lcdio:
	release_region(0x7D, 3);		/* Release DIO2's region */

err_req_dio2:
	release_region(0x7A, 3);		/* Release DIO1's region */

err_req_dio1:
	ret = -EBUSY;

	return ret;
}

static struct platform_driver ts5500_gpio_driver = {
	.driver = {
		.name = "ts5500_gpio",
		.owner = THIS_MODULE,
	},
	.probe = ts5500_gpio_probe
};

static const struct platform_device_id ts5500_devices[] = {
	{ "ts5500_gpio", 0 },
	{}
};
MODULE_DEVICE_TABLE(platform, ts5500_devices);

static int __init ts5500_gpio_init(void)
{
	return platform_driver_register(&ts5500_gpio_driver);
}
module_init(ts5500_gpio_init);

MODULE_AUTHOR("Jerome Oufella <jerome.oufella@savoirfairelinux.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Technologic Systems TS-5500, GPIO/DIO driver");
