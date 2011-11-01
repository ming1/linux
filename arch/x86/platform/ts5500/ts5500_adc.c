/*
 * Technologic Systems TS-5500 boards - Mapped MAX197 ADC driver
 *
 * Copyright (c) 2010 Savoir-faire Linux Inc.
 *          Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>
 *
 * Portions Copyright (C) 2008 Marc Pignat <marc.pignat@hevs.ch>
 *
 * The driver uses direct access for communication with the ADC.
 * Should work unchanged with the MAX199 chip.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * The TS-5500 uses a CPLD to abstract the interface to a MAX197.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/err.h>
#include <linux/sysfs.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/io.h>
#include "ts5500_adc.h"

#define ts5500_adc_test_bit(bit, map)	(test_bit(bit, map) != 0)

/**
 * struct ts5500_adc_chip
 * @hwmon_dev:		The hwmon device.
 * @lock:		Read/Write mutex.
 * @spec:		The mapped MAX197 platform data.
 * @polarity:		bitmap for polarity.
 * @range:		bitmap for range.
 */
struct ts5500_adc_chip {
	struct device *hwmon_dev;
	struct mutex lock;
	struct ts5500_adc_platform_data spec;
	DECLARE_BITMAP(polarity, TS5500_ADC_CHANNELS_MAX);
	DECLARE_BITMAP(range, TS5500_ADC_CHANNELS_MAX);
};

static s32 ts5500_adc_scale(struct ts5500_adc_chip *chip, s16 raw,
			    int polarity, int range)
{
	s32 scaled = raw;

	scaled *= chip->spec.scale[polarity][range];
	scaled /= 10000;

	return scaled;
}

static int ts5500_adc_range(struct ts5500_adc_chip *chip, int is_min,
			       int polarity, int range)
{
	if (is_min)
		return chip->spec.ranges.min[polarity][range];
	return chip->spec.ranges.max[polarity][range];
}

static int ts5500_adc_strtol(const char *buf, long *value, int range1,
				int range2)
{
	if (strict_strtol(buf, 10, value))
		return -EINVAL;

	if (range1 < range2)
		*value = SENSORS_LIMIT(*value, range1, range2);
	else
		*value = SENSORS_LIMIT(*value, range2, range1);

	return 0;
}

static struct ts5500_adc_chip *ts5500_adc_get_drvdata(struct device *dev)
{
	return platform_get_drvdata(to_platform_device(dev));
}

/**
 * ts5500_adc_show_range() - Display range on user output
 *
 * Function called on read access on
 * /sys/devices/platform/ts5500-adc/in{0,1,2,3,4,5,6,7}_{min,max}
 */
static ssize_t ts5500_adc_show_range(struct device *dev,
				 struct device_attribute *devattr, char *buf)
{
	struct ts5500_adc_chip *chip = ts5500_adc_get_drvdata(dev);
	struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
	int is_min = attr->nr != 0;
	int polarity, range;

	if (mutex_lock_interruptible(&chip->lock))
		return -ERESTARTSYS;

	polarity = ts5500_adc_test_bit(attr->index, chip->polarity);
	range = ts5500_adc_test_bit(attr->index, chip->range);

	mutex_unlock(&chip->lock);

	return sprintf(buf, "%d\n",
		       ts5500_adc_range(chip, is_min, polarity, range));
}

/**
 * ts5500_adc_store_range() - Write range from user input
 *
 * Function called on write access on
 * /sys/devices/platform/ts5500-adc/in{0,1,2,3,4,5,6,7}_{min,max}
 */
static ssize_t ts5500_adc_store_range(struct device *dev,
				  struct device_attribute *devattr,
				  const char *buf, size_t count)
{
	struct ts5500_adc_chip *chip = ts5500_adc_get_drvdata(dev);
	struct sensor_device_attribute_2 *attr = to_sensor_dev_attr_2(devattr);
	int is_min = attr->nr != 0;
	int range1 = ts5500_adc_range(chip, is_min, 0, 0);
	int range2 = ts5500_adc_range(chip, is_min, 1, 1);
	long value;

	if (ts5500_adc_strtol(buf, &value, range1, range2))
		return -EINVAL;

	if (mutex_lock_interruptible(&chip->lock))
		return -ERESTARTSYS;

	if (abs(value) > 5000)
		set_bit(attr->index, chip->range);
	else
		clear_bit(attr->index, chip->range);

	if (is_min) {
		if (value < 0)
			set_bit(attr->index, chip->polarity);
		else
			clear_bit(attr->index, chip->polarity);
	}

	mutex_unlock(&chip->lock);

	return count;
}

/**
 * ts5500_adc_show_input() - Show channel input
 *
 * Function called on read access on
 * /sys/devices/platform/ts5500-adc/in{0,1,2,3,4,5,6,7}_input
 */
static ssize_t ts5500_adc_show_input(struct device *dev,
				     struct device_attribute *devattr,
				     char *buf)
{
	struct ts5500_adc_chip *chip = ts5500_adc_get_drvdata(dev);
	struct sensor_device_attribute *attr = to_sensor_dev_attr(devattr);
	int polarity, range;
	int ret;
	u8 command;

	if (mutex_lock_interruptible(&chip->lock))
		return -ERESTARTSYS;

	polarity = ts5500_adc_test_bit(attr->index, chip->polarity);
	range = ts5500_adc_test_bit(attr->index, chip->range);

	command = attr->index | chip->spec.ctrl[polarity][range];

	outb(command, chip->spec.ioaddr.data);

	udelay(chip->spec.read.delay);
	ret = inb(chip->spec.ioaddr.ctrl);

	if (ret & chip->spec.read.busy_mask) {
		dev_err(dev, "device not ready (ret=0x0%x, try=%d)\n", ret,
			range);
		ret = -EIO;
	} else {
		/* LSB of conversion is at 0x196 and MSB is at 0x197 */
		u8 lsb = inb(chip->spec.ioaddr.data);
		u8 msb = inb(chip->spec.ioaddr.data + 1);
		s16 raw = (msb << 8) | lsb;
		s32 scaled = ts5500_adc_scale(chip, raw, polarity, range);

		ret = sprintf(buf, "%d\n", scaled);
	}

	mutex_unlock(&chip->lock);
	return ret;
}

static ssize_t ts5500_adc_show_name(struct device *dev,
	struct device_attribute *devattr, char *buf)
{
	return sprintf(buf, "%s\n", ts5500_adc_get_drvdata(dev)->spec.name);
}

#define TS5500_ADC_HWMON_CHANNEL(chan)				\
	SENSOR_DEVICE_ATTR(in##chan##_input, S_IRUGO,		\
			   ts5500_adc_show_input, NULL, chan);	\
	SENSOR_DEVICE_ATTR_2(in##chan##_max, S_IRUGO | S_IWUSR,	\
			     ts5500_adc_show_range,		\
			     ts5500_adc_store_range, 0, chan);	\
	SENSOR_DEVICE_ATTR_2(in##chan##_min, S_IRUGO | S_IWUSR,	\
			     ts5500_adc_show_range,		\
			     ts5500_adc_store_range, 1, chan)	\

#define TS5500_ADC_SYSFS_CHANNEL(chan)				\
	&sensor_dev_attr_in##chan##_input.dev_attr.attr,	\
	&sensor_dev_attr_in##chan##_max.dev_attr.attr,		\
	&sensor_dev_attr_in##chan##_min.dev_attr.attr

static DEVICE_ATTR(name, S_IRUGO, ts5500_adc_show_name, NULL);

static TS5500_ADC_HWMON_CHANNEL(0);
static TS5500_ADC_HWMON_CHANNEL(1);
static TS5500_ADC_HWMON_CHANNEL(2);
static TS5500_ADC_HWMON_CHANNEL(3);
static TS5500_ADC_HWMON_CHANNEL(4);
static TS5500_ADC_HWMON_CHANNEL(5);
static TS5500_ADC_HWMON_CHANNEL(6);
static TS5500_ADC_HWMON_CHANNEL(7);

static const struct attribute_group ts5500_adc_sysfs_group = {
	.attrs = (struct attribute *[]) {
		&dev_attr_name.attr,
		TS5500_ADC_SYSFS_CHANNEL(0),
		TS5500_ADC_SYSFS_CHANNEL(1),
		TS5500_ADC_SYSFS_CHANNEL(2),
		TS5500_ADC_SYSFS_CHANNEL(3),
		TS5500_ADC_SYSFS_CHANNEL(4),
		TS5500_ADC_SYSFS_CHANNEL(5),
		TS5500_ADC_SYSFS_CHANNEL(6),
		TS5500_ADC_SYSFS_CHANNEL(7),
		NULL
	}
};

static int __devinit ts5500_adc_probe(struct platform_device *pdev)
{
	struct ts5500_adc_platform_data *pdata = pdev->dev.platform_data;
	struct ts5500_adc_chip *chip;
	int ret;

	if (pdata == NULL)
		return -ENODEV;

	chip = kzalloc(sizeof *chip, GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->spec = *pdata;

	mutex_init(&chip->lock);
	mutex_lock(&chip->lock);

	ret = sysfs_create_group(&pdev->dev.kobj, &ts5500_adc_sysfs_group);
	if (ret) {
		dev_err(&pdev->dev, "sysfs_create_group failed.\n");
		goto error_unlock_and_free;
	}

	chip->hwmon_dev = hwmon_device_register(&pdev->dev);
	if (IS_ERR(chip->hwmon_dev)) {
		dev_err(&pdev->dev, "hwmon_device_register failed.\n");
		ret = PTR_ERR(chip->hwmon_dev);
		goto error_unregister_device;
	}

	platform_set_drvdata(pdev, chip);
	mutex_unlock(&chip->lock);
	return 0;

error_unregister_device:
	sysfs_remove_group(&pdev->dev.kobj, &ts5500_adc_sysfs_group);

error_unlock_and_free:
	mutex_unlock(&chip->lock);
	kfree(chip);
	return ret;
}

static struct platform_driver ts5500_adc_driver = {
	.driver	= {
		.name	= "ts5500_adc",
		.owner	= THIS_MODULE,
	},
	.probe	= ts5500_adc_probe
};

static const struct platform_device_id ts5500_devices[] = {
	{ "ts5500_adc", 0 },
	{}
};
MODULE_DEVICE_TABLE(platform, ts5500_devices);

static int __init ts5500_adc_init(void)
{
	return platform_driver_register(&ts5500_adc_driver);
}
module_init(ts5500_adc_init);

MODULE_DESCRIPTION("TS-5500 mapped MAX197 ADC device driver");
MODULE_AUTHOR("Jonas Fonseca <jonas.fonseca@savoirfairelinux.com>");
MODULE_LICENSE("GPL");
