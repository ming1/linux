/*
 * Copyright (c) 2012 Guenter Roeck <linux@roeck-us.net>
 *
 * based on max1668.c
 * Copyright (c) 2011 David George <david.george@ska.ac.za>
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
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/i2c.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/of.h>

#include <linux/platform_data/max6697.h>

enum chips { max6581, max6602, max6622, max6636, max6689, max6693, max6694,
	     max6697, max6698, max6699 };

/* Report local sensor as temp1 */

static const u8 MAX6697_REG_TEMP[] = { 7, 1, 2, 3, 4, 5, 6, 8 };
static const u8 MAX6697_REG_TEMP_EXT[] = {
			0x57, 0x09, 0x52, 0x53, 0x54, 0x55, 0x56, 0 };
static const u8 MAX6697_REG_MAX[] = {
			0x17, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x18 };
static const u8 MAX6697_REG_CRIT[] = {
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27 };

#define MAX6697_REG_STAT(n)		(0x44 + (n))

#define MAX6697_REG_CONFIG		0x41
#define MAX6581_CONF_EXTENDED		(1 << 1)
#define MAX6697_CONF_RESISTANCE		(1 << 3)
#define MAX6697_CONF_TIMEOUT		(1 << 5)
#define MAX6697_REG_ALERT_MASK		0x42
#define MAX6697_REG_OVERT_MASK		0x43

#define MAX6581_REG_RESISTANCE		0x4a
#define MAX6581_REG_IDEALITY		0x4b
#define MAX6581_REG_IDEALITY_SELECT	0x4c
#define MAX6581_REG_OFFSET		0x4d
#define MAX6581_REG_OFFSET_SELECT	0x4e

struct max6697_chip_data {
	int channels;
	u32 have_ext;
	u32 have_crit;
	u32 have_fault;
	const u8 *alarm_map;
};

struct max6697_data {
	struct device *hwmon_dev;

	enum chips type;
	const struct max6697_chip_data *chip;

	struct mutex update_lock;
	unsigned long last_updated;	/* In jiffies */
	bool valid;		/* true if following fields are valid */

	/* 1x local and up to 7x remote */
	u8 temp[8][4];		/* [nr][0]=temp [1]=ext [2]=max [3]=crit */
	u32 alarms;
};

/* Diode fault status bits on MAX6581 are right shifted by one bit */
static const u8 max6581_alarm_map[] = {
	 0, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15,
	 16, 17, 18, 19, 20, 21, 22, 23 };

static const struct max6697_chip_data max6697_chip_data[] = {
	[max6581] = {
		.channels = 8,
		.have_crit = 0xff,
		.have_ext = 0xfe,
		.have_fault = 0xfe,
		.alarm_map = max6581_alarm_map,
	},
	[max6602] = {
		.channels = 5,
		.have_crit = 0x12,
		.have_ext = 0x02,
		.have_fault = 0x1e,
	},
	[max6636] = {
		.channels = 7,
		.have_crit = 0x72,
		.have_ext = 0x02,
		.have_fault = 0x7e,
	},
	[max6622] = {
		.channels = 5,
		.have_crit = 0x12,
		.have_ext = 0x02,
		.have_fault = 0x1e,
	},
	[max6689] = {
		.channels = 7,
		.have_crit = 0x72,
		.have_ext = 0x02,
		.have_fault = 0x7e,
	},
	[max6693] = {
		.channels = 7,
		.have_crit = 0x72,
		.have_ext = 0x02,
		.have_fault = 0x7e,
	},
	[max6694] = {
		.channels = 5,
		.have_crit = 0x12,
		.have_ext = 0x02,
		.have_fault = 0x1e,
	},
	[max6697] = {
		.channels = 7,
		.have_crit = 0x72,
		.have_ext = 0x02,
		.have_fault = 0x7e,
	},
	[max6698] = {
		.channels = 7,
		.have_crit = 0x72,
		.have_ext = 0x02,
		.have_fault = 0x0e,
	},
	[max6699] = {
		.channels = 5,
		.have_crit = 0x12,
		.have_ext = 0x02,
		.have_fault = 0x1e,
	},
};

static struct max6697_data *max6697_update_device(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct max6697_data *data = i2c_get_clientdata(client);
	struct max6697_data *ret = data;
	int val;
	int i;

	mutex_lock(&data->update_lock);

	if (data->valid &&
	    !time_after(jiffies, data->last_updated + HZ + HZ / 2))
		goto abort;

	for (i = 0; i < data->chip->channels; i++) {
		if (data->chip->have_ext & (1 << i)) {
			val = i2c_smbus_read_byte_data(client,
						       MAX6697_REG_TEMP_EXT[i]);
			if (unlikely(val < 0)) {
				ret = ERR_PTR(val);
				goto abort;
			}
			data->temp[i][1] = val;
		}

		val = i2c_smbus_read_byte_data(client, MAX6697_REG_TEMP[i]);
		if (unlikely(val < 0)) {
			ret = ERR_PTR(val);
			goto abort;
		}
		data->temp[i][0] = val;

		val = i2c_smbus_read_byte_data(client, MAX6697_REG_MAX[i]);
		if (unlikely(val < 0)) {
			ret = ERR_PTR(val);
			goto abort;
		}
		data->temp[i][2] = val;

		if (data->chip->have_crit & (1 << i)) {
			val = i2c_smbus_read_byte_data(client,
						       MAX6697_REG_CRIT[i]);
			if (unlikely(val < 0)) {
				ret = ERR_PTR(val);
				goto abort;
			}
			data->temp[i][3] = val;
		}
	}

	data->alarms = 0;
	for (i = 0; i < 3; i++) {
		val = i2c_smbus_read_byte_data(client, MAX6697_REG_STAT(i));
		if (unlikely(val < 0)) {
			ret = ERR_PTR(val);
			goto abort;
		}
		data->alarms = (data->alarms << 8) | val;
	}

	data->last_updated = jiffies;
	data->valid = true;
abort:
	mutex_unlock(&data->update_lock);

	return ret;
}

static ssize_t show_temp11(struct device *dev,
			   struct device_attribute *devattr, char *buf)
{
	int nr = to_sensor_dev_attr_2(devattr)->nr;
	int index = to_sensor_dev_attr_2(devattr)->index;
	struct max6697_data *data = max6697_update_device(dev);

	if (IS_ERR(data))
		return PTR_ERR(data);

	return sprintf(buf, "%d\n",
		       ((data->temp[nr][index] << 3) |
			(data->temp[nr][index + 1] >> 5)) * 125);
}

static ssize_t show_temp(struct device *dev,
			 struct device_attribute *devattr, char *buf)
{
	int nr = to_sensor_dev_attr_2(devattr)->nr;
	int index = to_sensor_dev_attr_2(devattr)->index;
	struct max6697_data *data = max6697_update_device(dev);

	if (IS_ERR(data))
		return PTR_ERR(data);

	return sprintf(buf, "%d\n", data->temp[nr][index] * 1000);
}

static ssize_t show_alarm(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	int index = to_sensor_dev_attr(attr)->index;
	struct max6697_data *data = max6697_update_device(dev);

	if (IS_ERR(data))
		return PTR_ERR(data);

	if (data->chip->alarm_map)
		index = data->chip->alarm_map[index];

	return sprintf(buf, "%u\n", (data->alarms >> index) & 0x1);
}

static ssize_t set_temp(struct device *dev,
			struct device_attribute *devattr,
			const char *buf, size_t count)
{
	int nr = to_sensor_dev_attr_2(devattr)->nr;
	int index = to_sensor_dev_attr_2(devattr)->index;
	struct i2c_client *client = to_i2c_client(dev);
	struct max6697_data *data = i2c_get_clientdata(client);
	long temp;
	int ret;

	ret = kstrtol(buf, 10, &temp);
	if (ret < 0)
		return ret;

	mutex_lock(&data->update_lock);
	data->temp[nr][index] = clamp_val(temp / 1000, 0, 127);
	ret = i2c_smbus_write_byte_data(client,
					index == 2 ? MAX6697_REG_MAX[nr]
						   : MAX6697_REG_CRIT[nr],
					data->temp[nr][index]);
	if (ret < 0)
		count = ret;
	mutex_unlock(&data->update_lock);

	return count;
}

static SENSOR_DEVICE_ATTR_2(temp1_input, S_IRUGO, show_temp11, NULL, 0, 0);
static SENSOR_DEVICE_ATTR_2(temp1_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    0, 2);
static SENSOR_DEVICE_ATTR_2(temp1_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    0, 3);

static SENSOR_DEVICE_ATTR_2(temp2_input, S_IRUGO, show_temp11, NULL, 1, 0);
static SENSOR_DEVICE_ATTR_2(temp2_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    1, 2);
static SENSOR_DEVICE_ATTR_2(temp2_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    1, 3);

static SENSOR_DEVICE_ATTR_2(temp3_input, S_IRUGO, show_temp11, NULL, 2, 0);
static SENSOR_DEVICE_ATTR_2(temp3_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    2, 2);
static SENSOR_DEVICE_ATTR_2(temp3_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    2, 3);

static SENSOR_DEVICE_ATTR_2(temp4_input, S_IRUGO, show_temp11, NULL, 3, 0);
static SENSOR_DEVICE_ATTR_2(temp4_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    3, 2);
static SENSOR_DEVICE_ATTR_2(temp4_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    3, 3);

static SENSOR_DEVICE_ATTR_2(temp5_input, S_IRUGO, show_temp11, NULL, 4, 0);
static SENSOR_DEVICE_ATTR_2(temp5_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    4, 2);
static SENSOR_DEVICE_ATTR_2(temp5_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    4, 3);

static SENSOR_DEVICE_ATTR_2(temp6_input, S_IRUGO, show_temp11, NULL, 5, 0);
static SENSOR_DEVICE_ATTR_2(temp6_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    5, 2);
static SENSOR_DEVICE_ATTR_2(temp6_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    5, 3);

static SENSOR_DEVICE_ATTR_2(temp7_input, S_IRUGO, show_temp11, NULL, 6, 0);
static SENSOR_DEVICE_ATTR_2(temp7_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    6, 2);
static SENSOR_DEVICE_ATTR_2(temp7_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    6, 3);

static SENSOR_DEVICE_ATTR_2(temp8_input, S_IRUGO, show_temp11, NULL, 7, 0);
static SENSOR_DEVICE_ATTR_2(temp8_max, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    7, 2);
static SENSOR_DEVICE_ATTR_2(temp8_crit, S_IRUGO | S_IWUSR, show_temp, set_temp,
			    7, 3);

static SENSOR_DEVICE_ATTR(temp1_max_alarm, S_IRUGO, show_alarm, NULL, 22);
static SENSOR_DEVICE_ATTR(temp2_max_alarm, S_IRUGO, show_alarm, NULL, 16);
static SENSOR_DEVICE_ATTR(temp3_max_alarm, S_IRUGO, show_alarm, NULL, 17);
static SENSOR_DEVICE_ATTR(temp4_max_alarm, S_IRUGO, show_alarm, NULL, 18);
static SENSOR_DEVICE_ATTR(temp5_max_alarm, S_IRUGO, show_alarm, NULL, 19);
static SENSOR_DEVICE_ATTR(temp6_max_alarm, S_IRUGO, show_alarm, NULL, 20);
static SENSOR_DEVICE_ATTR(temp7_max_alarm, S_IRUGO, show_alarm, NULL, 21);
static SENSOR_DEVICE_ATTR(temp8_max_alarm, S_IRUGO, show_alarm, NULL, 23);

static SENSOR_DEVICE_ATTR(temp1_crit_alarm, S_IRUGO, show_alarm, NULL, 14);
static SENSOR_DEVICE_ATTR(temp2_crit_alarm, S_IRUGO, show_alarm, NULL, 8);
static SENSOR_DEVICE_ATTR(temp3_crit_alarm, S_IRUGO, show_alarm, NULL, 9);
static SENSOR_DEVICE_ATTR(temp4_crit_alarm, S_IRUGO, show_alarm, NULL, 10);
static SENSOR_DEVICE_ATTR(temp5_crit_alarm, S_IRUGO, show_alarm, NULL, 11);
static SENSOR_DEVICE_ATTR(temp6_crit_alarm, S_IRUGO, show_alarm, NULL, 12);
static SENSOR_DEVICE_ATTR(temp7_crit_alarm, S_IRUGO, show_alarm, NULL, 13);
static SENSOR_DEVICE_ATTR(temp8_crit_alarm, S_IRUGO, show_alarm, NULL, 15);

static SENSOR_DEVICE_ATTR(temp1_fault, S_IRUGO, show_alarm, NULL, 0);
static SENSOR_DEVICE_ATTR(temp2_fault, S_IRUGO, show_alarm, NULL, 1);
static SENSOR_DEVICE_ATTR(temp3_fault, S_IRUGO, show_alarm, NULL, 2);
static SENSOR_DEVICE_ATTR(temp4_fault, S_IRUGO, show_alarm, NULL, 3);
static SENSOR_DEVICE_ATTR(temp5_fault, S_IRUGO, show_alarm, NULL, 4);
static SENSOR_DEVICE_ATTR(temp6_fault, S_IRUGO, show_alarm, NULL, 5);
static SENSOR_DEVICE_ATTR(temp7_fault, S_IRUGO, show_alarm, NULL, 6);
static SENSOR_DEVICE_ATTR(temp8_fault, S_IRUGO, show_alarm, NULL, 7);

static struct attribute *max6697_attributes[] = {
	&sensor_dev_attr_temp1_input.dev_attr.attr,
	&sensor_dev_attr_temp1_max.dev_attr.attr,
	&sensor_dev_attr_temp1_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp1_crit.dev_attr.attr,
	&sensor_dev_attr_temp1_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp1_fault.dev_attr.attr,

	&sensor_dev_attr_temp2_input.dev_attr.attr,
	&sensor_dev_attr_temp2_max.dev_attr.attr,
	&sensor_dev_attr_temp2_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp2_crit.dev_attr.attr,
	&sensor_dev_attr_temp2_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp2_fault.dev_attr.attr,

	&sensor_dev_attr_temp3_input.dev_attr.attr,
	&sensor_dev_attr_temp3_max.dev_attr.attr,
	&sensor_dev_attr_temp3_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp3_crit.dev_attr.attr,
	&sensor_dev_attr_temp3_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp3_fault.dev_attr.attr,

	&sensor_dev_attr_temp4_input.dev_attr.attr,
	&sensor_dev_attr_temp4_max.dev_attr.attr,
	&sensor_dev_attr_temp4_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp4_crit.dev_attr.attr,
	&sensor_dev_attr_temp4_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp4_fault.dev_attr.attr,

	&sensor_dev_attr_temp5_input.dev_attr.attr,
	&sensor_dev_attr_temp5_max.dev_attr.attr,
	&sensor_dev_attr_temp5_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp5_crit.dev_attr.attr,
	&sensor_dev_attr_temp5_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp5_fault.dev_attr.attr,

	&sensor_dev_attr_temp6_input.dev_attr.attr,
	&sensor_dev_attr_temp6_max.dev_attr.attr,
	&sensor_dev_attr_temp6_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp6_crit.dev_attr.attr,
	&sensor_dev_attr_temp6_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp6_fault.dev_attr.attr,

	&sensor_dev_attr_temp7_input.dev_attr.attr,
	&sensor_dev_attr_temp7_max.dev_attr.attr,
	&sensor_dev_attr_temp7_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp7_crit.dev_attr.attr,
	&sensor_dev_attr_temp7_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp7_fault.dev_attr.attr,

	&sensor_dev_attr_temp8_input.dev_attr.attr,
	&sensor_dev_attr_temp8_max.dev_attr.attr,
	&sensor_dev_attr_temp8_max_alarm.dev_attr.attr,
	&sensor_dev_attr_temp8_crit.dev_attr.attr,
	&sensor_dev_attr_temp8_crit_alarm.dev_attr.attr,
	&sensor_dev_attr_temp8_fault.dev_attr.attr,

	NULL
};

static const struct attribute_group max6697_group = {
	.attrs = max6697_attributes,
};

static void max6697_get_config_of(struct device_node *node,
				  struct max6697_platform_data *pdata)
{
	int len;
	const __be32 *prop;

	prop = of_get_property(node, "smbus-timeout-disable", &len);
	if (prop)
		pdata->smbus_timeout_disable = true;
	prop = of_get_property(node, "extended_range_enable", &len);
	if (prop)
		pdata->extended_range_enable = true;
	prop = of_get_property(node, "alert-mask", &len);
	if (prop && len == sizeof(u32))
		pdata->alert_mask = be32_to_cpu(prop[0]);
	prop = of_get_property(node, "over-temperature-mask", &len);
	if (prop && len == sizeof(u32))
		pdata->over_temperature_mask = be32_to_cpu(prop[0]);
	prop = of_get_property(node, "resistance-cancellation", &len);
	if (prop) {
		if (len == sizeof(u32))
			pdata->resistance_cancellation = be32_to_cpu(prop[0]);
		else
			pdata->resistance_cancellation = 0xff;
	}
	prop = of_get_property(node, "transistor-ideality", &len);
	if (prop && len == 2 * sizeof(u32)) {
			pdata->ideality_mask = be32_to_cpu(prop[0]);
			pdata->ideality_value = be32_to_cpu(prop[1]);
	}
}

static int max6697_init_chip(struct i2c_client *client)
{
	struct max6697_data *data = i2c_get_clientdata(client);
	struct max6697_platform_data *pdata = dev_get_platdata(&client->dev);
	struct max6697_platform_data p;
	int ret;
	u8 reg;

	/*
	 * Don't touch configuration if neither platform data nor of
	 * configuration was specified.
	 */
	if (!pdata && !client->dev.of_node)
		return 0;

	if (!pdata || client->dev.of_node) {
		memset(&p, 0, sizeof(p));
		max6697_get_config_of(client->dev.of_node, &p);
		pdata = &p;
	}

	reg = 0;
	if (pdata->smbus_timeout_disable)
		reg |= MAX6697_CONF_TIMEOUT;
	if (pdata->extended_range_enable && data->type == max6581)
		reg |= MAX6581_CONF_EXTENDED;
	if (pdata->resistance_cancellation && data->type != max6581)
		reg |= MAX6697_CONF_RESISTANCE;

	ret = i2c_smbus_write_byte_data(client, MAX6697_REG_CONFIG, reg);
	if (ret < 0)
		return ret;

	ret = i2c_smbus_write_byte_data(client, MAX6697_REG_ALERT_MASK,
					pdata->alert_mask);
	if (ret < 0)
		return ret;

	ret = i2c_smbus_write_byte_data(client, MAX6697_REG_OVERT_MASK,
					pdata->over_temperature_mask);
	if (ret < 0)
		return ret;

	if (data->type == max6581) {
		ret = i2c_smbus_write_byte_data(client, MAX6581_REG_RESISTANCE,
						pdata->resistance_cancellation);
		if (ret < 0)
			return ret;
		ret = i2c_smbus_write_byte_data(client, MAX6581_REG_IDEALITY,
						pdata->ideality_mask);
		if (ret < 0)
			return ret;
		ret = i2c_smbus_write_byte_data(client,
						MAX6581_REG_IDEALITY_SELECT,
						pdata->ideality_value);
		if (ret < 0)
			return ret;
	}
	return ret;
}

static int max6697_probe(struct i2c_client *client,
			 const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = client->adapter;
	struct device *dev = &client->dev;
	struct max6697_data *data;
	int i, err;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE_DATA))
		return -ENODEV;

	data = devm_kzalloc(dev, sizeof(struct max6697_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->type = id->driver_data;
	data->chip = &max6697_chip_data[data->type];

	i2c_set_clientdata(client, data);
	mutex_init(&data->update_lock);

	err = max6697_init_chip(client);
	if (err)
		return err;

	/* Register sysfs hooks */

	for (i = 0; i < data->chip->channels; i++) {
		err = sysfs_create_file(&dev->kobj,
					max6697_attributes[i * 6]);
		if (err)
			goto error;
		err = sysfs_create_file(&dev->kobj,
					max6697_attributes[i * 6 + 1]);
		if (err)
			goto error;
		err = sysfs_create_file(&dev->kobj,
					max6697_attributes[i * 6 + 2]);
		if (err)
			goto error;

		if (data->chip->have_crit & (1 << i)) {
			err = sysfs_create_file(&dev->kobj,
						max6697_attributes[i * 6 + 3]);
			if (err)
				goto error;
			err = sysfs_create_file(&dev->kobj,
						max6697_attributes[i * 6 + 4]);
			if (err)
				goto error;
		}
		if (data->chip->have_fault & (1 << i)) {
			err = sysfs_create_file(&dev->kobj,
						max6697_attributes[i * 6 + 5]);
			if (err)
				goto error;
		}
	}

	data->hwmon_dev = hwmon_device_register(dev);
	if (IS_ERR(data->hwmon_dev)) {
		err = PTR_ERR(data->hwmon_dev);
		goto error;
	}

	return 0;

error:
	sysfs_remove_group(&dev->kobj, &max6697_group);
	return err;
}

static int max6697_remove(struct i2c_client *client)
{
	struct max6697_data *data = i2c_get_clientdata(client);

	hwmon_device_unregister(data->hwmon_dev);
	sysfs_remove_group(&client->dev.kobj, &max6697_group);

	return 0;
}

static const struct i2c_device_id max6697_id[] = {
	{ "max6581", max6581 },
	{ "max6602", max6602 },
	{ "max6622", max6622 },
	{ "max6636", max6636 },
	{ "max6689", max6689 },
	{ "max6693", max6693 },
	{ "max6694", max6694 },
	{ "max6697", max6697 },
	{ "max6698", max6698 },
	{ "max6699", max6699 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, max6697_id);

/* This is the driver that will be inserted */
static struct i2c_driver max6697_driver = {
	.class = I2C_CLASS_HWMON,
	.driver = {
		  .name	= "max6697",
		  },
	.probe = max6697_probe,
	.remove	= max6697_remove,
	.id_table = max6697_id,
};

module_i2c_driver(max6697_driver);

MODULE_AUTHOR("Guenter Roeck <linux@roeck-us.net>");
MODULE_DESCRIPTION("MAX6697 temperature sensor driver");
MODULE_LICENSE("GPL");
