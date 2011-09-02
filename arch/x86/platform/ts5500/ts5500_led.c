/*
 * Technologic Systems TS-5500 boards - LED driver
 *
 * Copyright (c) 2010 Savoir-faire Linux Inc.
 *	Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>
 *
 * Portions Copyright (c) 2008 Compulab, Ltd.
 *	Mike Rapoport <mike@compulab.co.il>
 *
 * Portions Copyright (c) 2006-2008 Marvell International Ltd.
 *	Eric Miao <eric.miao@marvell.com>
 *
 * Based on drivers/leds/leds-da903x.c from linux-2.6.32.8.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/leds.h>

/**
 * struct ts5500_led - LED structure
 * @cdev:		LED class device structure.
 * @ioaddr:		LED I/O address.
 */
struct ts5500_led {
	struct led_classdev	cdev;
	int			ioaddr;
	int			bit;
};

static void ts5500_led_set(struct led_classdev *led_cdev,
			   enum led_brightness value)
{
	struct ts5500_led *led = container_of(led_cdev, struct ts5500_led,
					      cdev);
	outb(!!value, led->ioaddr);
}

static int __devinit ts5500_led_probe(struct platform_device *pdev)
{
	struct led_platform_data *pdata = pdev->dev.platform_data;
	struct ts5500_led *led;
	struct resource *res;
	int ret;

	if (pdata == NULL || !pdata->num_leds) {
		dev_err(&pdev->dev, "No platform data available\n");
		return -ENODEV;
	}

	res = platform_get_resource(pdev, IORESOURCE_IO, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get I/O resource\n");
		return -EBUSY;
	}

	led = kzalloc(sizeof(struct ts5500_led), GFP_KERNEL);
	if (led == NULL) {
		dev_err(&pdev->dev, "Failed to alloc memory for LED device\n");
		return -ENOMEM;
	}

	led->cdev.name = pdata->leds[0].name;
	led->cdev.default_trigger = pdata->leds[0].default_trigger;
	led->cdev.brightness_set = ts5500_led_set;
	led->cdev.brightness = LED_OFF;

	led->ioaddr = res->start;
	led->bit = pdata->leds[0].flags;

	ret = led_classdev_register(pdev->dev.parent, &led->cdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register LED\n");
		goto err;
	}

	platform_set_drvdata(pdev, led);
	return 0;

err:
	kfree(led);
	return ret;
}

static struct platform_driver ts5500_led_driver = {
	.driver = {
		.name = "ts5500_led",
		.owner = THIS_MODULE
	},
	.probe = ts5500_led_probe
};

static const struct platform_device_id ts5500_devices[] = {
	{ "ts5500_led", 0 },
	{}
};
MODULE_DEVICE_TABLE(platform, ts5500_devices);

static int __init ts5500_led_init(void)
{
	return platform_driver_register(&ts5500_led_driver);
}
module_init(ts5500_led_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>");
MODULE_DESCRIPTION("LED driver for Technologic Systems TS-5500");
