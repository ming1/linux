/*
 * Simple driver for Texas Instruments LM3556 LED Flash driver chip (Rev0x03)
 * Copyright (C) 2012 Texas Instruments
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/leds-lm3556.h>

#define	REG_FILT_TIME			(0x0)
#define	REG_IVFM_MODE			(0x1)
#define	REG_NTC				(0x2)
#define	REG_INDIC_TIME			(0x3)
#define	REG_INDIC_BLINK			(0x4)
#define	REG_INDIC_PERIOD		(0x5)
#define	REG_TORCH_TIME			(0x6)
#define	REG_CONF			(0x7)
#define	REG_FLASH			(0x8)
#define	REG_I_CTRL			(0x9)
#define	REG_ENABLE			(0xA)
#define	REG_FLAG			(0xB)
#define	REG_MAX				(0xC)

#define	IVFM_FILTER_TIME_SHIFT		(3)
#define	UVLO_EN_SHIFT			(7)
#define	HYSTERSIS_SHIFT			(5)
#define	IVM_D_TH_SHIFT			(2)
#define	IVFM_ADJ_MODE_SHIFT		(0)
#define	NTC_EVENT_LVL_SHIFT		(5)
#define	NTC_TRIP_TH_SHIFT		(2)
#define	NTC_BIAS_I_LVL_SHIFT		(0)
#define	INDIC_RAMP_UP_TIME_SHIFT	(3)
#define	INDIC_RAMP_DN_TIME_SHIFT	(0)
#define	INDIC_N_BLANK_SHIFT		(4)
#define	INDIC_PULSE_TIME_SHIFT		(0)
#define	INDIC_N_PERIOD_SHIFT		(0)
#define	TORCH_RAMP_UP_TIME_SHIFT	(3)
#define	TORCH_RAMP_DN_TIME_SHIFT	(0)
#define	STROBE_USUAGE_SHIFT		(7)
#define	STROBE_PIN_POLARITY_SHIFT	(6)
#define	TORCH_PIN_POLARITY_SHIFT	(5)
#define	TX_PIN_POLARITY_SHIFT		(4)
#define	TX_EVENT_LVL_SHIFT		(3)
#define	IVFM_EN_SHIFT			(2)
#define	NTC_MODE_SHIFT			(1)
#define	INDIC_MODE_SHIFT		(0)
#define	INDUCTOR_I_LIMIT_SHIFT		(6)
#define	FLASH_RAMP_TIME_SHIFT		(3)
#define	FLASH_TOUT_TIME_SHIFT		(0)
#define	TORCH_I_SHIFT			(4)
#define	FLASH_I_SHIFT			(0)
#define	NTC_EN_SHIFT			(7)
#define	TX_PIN_EN_SHIFT			(6)
#define	STROBE_PIN_EN_SHIFT		(5)
#define	TORCH_PIN_EN_SHIFT		(4)
#define	PRECHG_MODE_EN_SHIFT		(3)
#define	PASS_MODE_ONLY_EN_SHIFT		(2)
#define	MODE_BITS_SHIFT			(0)

#define	IVFM_FILTER_TIME_MASK		(0x3)
#define	UVLO_EN_MASK			(0x1)
#define	HYSTERSIS_MASK			(0x3)
#define	IVM_D_TH_MASK			(0x7)
#define	IVFM_ADJ_MODE_MASK		(0x3)
#define	NTC_EVENT_LVL_MASK		(0x1)
#define	NTC_TRIP_TH_MASK		(0x7)
#define	NTC_BIAS_I_LVL_MASK		(0x3)
#define	INDIC_RAMP_UP_TIME_MASK		(0x7)
#define	INDIC_RAMP_DN_TIME_MASK		(0x7)
#define	INDIC_N_BLANK_MASK		(0x7)
#define	INDIC_PULSE_TIME_MASK		(0x7)
#define	INDIC_N_PERIOD_MASK		(0x7)
#define	TORCH_RAMP_UP_TIME_MASK		(0x7)
#define	TORCH_RAMP_DN_TIME_MASK		(0x7)
#define	STROBE_USUAGE_MASK		(0x1)
#define	STROBE_PIN_POLARITY_MASK	(0x1)
#define	TORCH_PIN_POLARITY_MASK		(0x1)
#define	TX_PIN_POLARITY_MASK		(0x1)
#define	TX_EVENT_LVL_MASK		(0x1)
#define	IVFM_EN_MASK			(0x1)
#define	NTC_MODE_MASK			(0x1)
#define	INDIC_MODE_MASK			(0x1)
#define	INDUCTOR_I_LIMIT_MASK		(0x3)
#define	FLASH_RAMP_TIME_MASK		(0x7)
#define	FLASH_TOUT_TIME_MASK		(0x7)
#define	TORCH_I_MASK			(0x7)
#define	FLASH_I_MASK			(0xF)
#define	NTC_EN_MASK			(0x1)
#define	TX_PIN_EN_MASK			(0x1)
#define	STROBE_PIN_EN_MASK		(0x1)
#define	TORCH_PIN_EN_MASK		(0x1)
#define	PRECHG_MODE_EN_MASK		(0x1)
#define	PASS_MODE_ONLY_EN_MASK		(0x1)
#define	MODE_BITS_MASK			(0x13)
#define EX_PIN_CONTROL_MASK		(0xF1)
#define EX_PIN_ENABLE_MASK		(0x70)


#define INDIC_PATTERN_SIZE 4

struct indicator {
	u8 blinking;
	u8 period_cnt;
};

struct lm3556_chip_data {
	struct i2c_client *client;

	struct led_classdev cdev_flash;
	struct led_classdev cdev_torch;
	struct led_classdev cdev_indicator;

	struct lm3556_platform_data *pdata;
	struct mutex lock;

	u8 last_flag;
};

/*Indicator Pattern*/
static struct indicator indicator_pattern[INDIC_PATTERN_SIZE] = {
	[0] = {(INDIC_N_BLANK_0 << INDIC_N_BLANK_SHIFT)
	       | PULSE_TIME_0_MS, INDIC_PERIOD_0},
	[1] = {(INDIC_N_BLANK_15 << INDIC_N_BLANK_SHIFT)
	       | PULSE_TIME_32_MS, INDIC_PERIOD_1},
	[2] = {(INDIC_N_BLANK_10 << INDIC_N_BLANK_SHIFT)
	       | PULSE_TIME_32_MS, INDIC_PERIOD_4},
	[3] = {(INDIC_N_BLANK_5 << INDIC_N_BLANK_SHIFT)
	       | PULSE_TIME_32_MS, INDIC_PERIOD_7},
};

/* i2c access*/
int lm3556_read_reg(struct i2c_client *client, u8 reg, u8 * val)
{
	int ret;
	struct lm3556_chip_data *chip = i2c_get_clientdata(client);

	mutex_lock(&chip->lock);
	ret = i2c_smbus_read_byte_data(client, reg);
	mutex_unlock(&chip->lock);

	if (ret < 0) {
		printk(KERN_ERR "[LM3556]reading fail at 0x%02x error %d\n",
		       reg, ret);
		return ret;
	}
	*val = ret & 0xff;
	return 0;
}
EXPORT_SYMBOL_GPL(lm3556_read_reg);

int lm3556_write_reg(struct i2c_client *client, u8 reg, u8 val)
{
	int ret = 0;
	struct lm3556_chip_data *chip = i2c_get_clientdata(client);

	mutex_lock(&chip->lock);
	ret = i2c_smbus_write_byte_data(client, reg, val);
	mutex_unlock(&chip->lock);

	if (ret < 0)
		printk(KERN_ERR"[LM3556] writting fail at 0x%02x\n", reg);
	return ret;
}
EXPORT_SYMBOL_GPL(lm3556_write_reg);

int lm3556_write_bits(struct i2c_client *client,
		      u8 reg, u8 val, u8 mask, u8 shift)
{
	int ret;
	u8 reg_val;

	ret = lm3556_read_reg(client, reg, &reg_val);
	if (ret < 0)
		return ret;
	reg_val &= (~(mask << shift));
	reg_val |= ((val & mask) << shift);

	ret = lm3556_write_reg(client, reg, reg_val);
	return ret;
}
EXPORT_SYMBOL_GPL(lm3556_write_bits);

/* chip initialize*/
static int lm3556_chip_init(struct lm3556_chip_data *chip)
{
	u8 reg_val;
	int ret = 0;
	struct i2c_client *client = chip->client;
	struct lm3556_platform_data *pdata = chip->pdata;

	/*Set Config Register for external PINs depended by HW*/
	ret = lm3556_read_reg(client, REG_CONF, &reg_val);
	reg_val &= ~EX_PIN_CONTROL_MASK;
	reg_val |= ((pdata->torch_pin_polarity & 0x01)
		    << TORCH_PIN_POLARITY_SHIFT);
	reg_val |= ((pdata->strobe_usuage & 0x01) << STROBE_USUAGE_SHIFT);
	reg_val |= ((pdata->strobe_pin_polarity & 0x01)
		    << STROBE_PIN_POLARITY_SHIFT);
	reg_val |= ((pdata->tx_pin_polarity & 0x01) << TX_PIN_POLARITY_SHIFT);
	reg_val |= ((pdata->indicator_mode & 0x01) << INDIC_MODE_SHIFT);
	ret |= lm3556_write_reg(client, REG_CONF, reg_val);

	/*Set Enable Register for external PINs depended by HW*/
	ret = lm3556_read_reg(client, REG_ENABLE, &reg_val);
	reg_val &= ~EX_PIN_ENABLE_MASK;
	reg_val |= ((pdata->torch_pin_en & 0x01) << TORCH_PIN_EN_SHIFT);
	reg_val |= ((pdata->strobe_pin_en & 0x01) << STROBE_PIN_EN_SHIFT);
	reg_val |= ((pdata->tx_pin_en & 0x01) << TX_PIN_EN_SHIFT);
	ret |= lm3556_write_reg(client, REG_ENABLE, reg_val);
	return ret;
}

/* chip control*/
static void lm3556_control(struct lm3556_chip_data *chip,
			   u8 brightness, enum lm3556_mode opmode)
{
	struct i2c_client *client = chip->client;
	struct lm3556_platform_data *pdata = chip->pdata;

	lm3556_read_reg(client, REG_FLAG, &chip->last_flag);
	if (chip->last_flag)
		printk(KERN_INFO"[LM3556] Last FLAG is 0x%x\n",
		       chip->last_flag);

	/*Brightness 0 means off-state*/
	if (!brightness)
		opmode = MODES_STASNDBY;

	switch (opmode) {
	case MODES_TORCH:
		lm3556_write_bits(client, REG_I_CTRL,
				  brightness - 1, TORCH_I_MASK, TORCH_I_SHIFT);

		if (pdata->torch_pin_en)
			opmode |= (TORCH_PIN_EN_MASK << TORCH_PIN_EN_SHIFT);
		break;

	case MODES_FLASH:
		lm3556_write_bits(client, REG_I_CTRL,
				  brightness - 1, FLASH_I_MASK, FLASH_I_SHIFT);

		if (pdata->strobe_pin_en)
			opmode |= (STROBE_PIN_EN_MASK << STROBE_PIN_EN_SHIFT);
		if (pdata->tx_pin_en)
			opmode |= (TX_PIN_EN_MASK << TX_PIN_EN_SHIFT);
		break;

	case MODES_INDIC:
		lm3556_write_bits(client, REG_I_CTRL,
				  brightness - 1, TORCH_I_MASK, TORCH_I_SHIFT);

		if (pdata->indicator_mode)
			opmode |= (TORCH_PIN_EN_MASK << TORCH_PIN_EN_SHIFT);
		break;

	case MODES_STASNDBY:
		if (pdata->torch_pin_en)
			opmode |= (TORCH_PIN_EN_MASK << TORCH_PIN_EN_SHIFT);
		break;

	default:
		return;
	}
	lm3556_write_bits(client, REG_ENABLE,
			  opmode, MODE_BITS_MASK, MODE_BITS_SHIFT);

	return;
}

/*torch */
static void lm3556_torch_brightness_set(struct led_classdev *cdev,
					enum led_brightness brightness)
{
	struct lm3556_chip_data *chip =
	    container_of(cdev, struct lm3556_chip_data, cdev_torch);

	lm3556_control(chip, (u8) brightness, MODES_TORCH);
	return;
}

/* flash */
static void lm3556_strobe_brightness_set(struct led_classdev *cdev,
					 enum led_brightness brightness)
{
	struct lm3556_chip_data *chip =
	    container_of(cdev, struct lm3556_chip_data, cdev_flash);

	lm3556_control(chip, (u8) brightness, MODES_FLASH);
	return;
}

/* indicator */
static void lm3556_indicator_brightness_set(struct led_classdev *cdev,
					    enum led_brightness brightness)
{
	struct lm3556_chip_data *chip =
	    container_of(cdev, struct lm3556_chip_data, cdev_indicator);

	lm3556_control(chip, (u8) brightness, MODES_INDIC);
	return;
}

static ssize_t lm3556_indicator_pattern_store(struct device *dev,
					      struct device_attribute *devAttr,
					      const char *buf, size_t size)
{
	char *after;
	ssize_t ret = -EINVAL;
	struct i2c_client *client = container_of(dev->parent,
						 struct i2c_client, dev);
	unsigned long state = simple_strtoul(buf, &after, 10);
	size_t count = after - buf;

	if (isspace(*after))
		count++;

	if (count == size) {
		ret = count;

		if (state > INDIC_PATTERN_SIZE - 1)
			state = INDIC_PATTERN_SIZE - 1;
		lm3556_write_reg(client, REG_INDIC_BLINK,
				 indicator_pattern[state].blinking);
		lm3556_write_reg(client, REG_INDIC_PERIOD,
				 indicator_pattern[state].period_cnt);
	}
	return ret;
}

static DEVICE_ATTR(pattern, 0644, NULL, lm3556_indicator_pattern_store);

/* Module Initialize */
static int lm3556_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct lm3556_platform_data *pdata = client->dev.platform_data;
	struct lm3556_chip_data *chip;

	int err = -ENODEV;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		printk(KERN_ERR"[LM3556]i2c functionality check fail.\n");
		return err;
	}

	if (pdata == NULL) {
		printk(KERN_ERR"[LM3556] Needs Platform Data.\n");
		return err;
	}

	chip = kzalloc(sizeof(struct lm3556_chip_data), GFP_KERNEL);
	chip->client = client;
	chip->pdata = pdata;

	mutex_init(&chip->lock);
	i2c_set_clientdata(client, chip);

	if (lm3556_chip_init(chip) < 0)
		goto err_chip_init;

	/*flash*/
	chip->cdev_flash.name = "flash";
	chip->cdev_flash.max_brightness = 16;
	chip->cdev_flash.brightness_set = lm3556_strobe_brightness_set;
	if (led_classdev_register((struct device *)
				  &client->dev, &chip->cdev_flash) < 0)
		goto err_create_flash_file;
	/*torch*/
	chip->cdev_torch.name = "torch";
	chip->cdev_torch.max_brightness = 8;
	chip->cdev_torch.brightness_set = lm3556_torch_brightness_set;
	if (led_classdev_register((struct device *)
				  &client->dev, &chip->cdev_torch) < 0)
		goto err_create_torch_file;
	/*indicator*/
	chip->cdev_indicator.name = "indicator";
	chip->cdev_indicator.max_brightness = 8;
	chip->cdev_indicator.brightness_set = lm3556_indicator_brightness_set;
	if (led_classdev_register((struct device *)
				  &client->dev, &chip->cdev_indicator) < 0)
		goto err_create_indicator_file;

	if (device_create_file(chip->cdev_indicator.dev, &dev_attr_pattern) < 0)
		goto err_create_pattern_file;

	return 0;

err_create_pattern_file:
	led_classdev_unregister(&chip->cdev_indicator);
err_create_indicator_file:
	led_classdev_unregister(&chip->cdev_torch);
err_create_torch_file:
	led_classdev_unregister(&chip->cdev_flash);
err_create_flash_file:
err_chip_init:
	i2c_set_clientdata(client, NULL);
	kfree(chip);
	printk(KERN_ERR"[LM3556] probe func. returns failed\n");
	return -ENODEV;
}

static int lm3556_remove(struct i2c_client *client)
{
	struct lm3556_chip_data *chip = i2c_get_clientdata(client);

	device_remove_file(chip->cdev_indicator.dev, &dev_attr_pattern);
	led_classdev_unregister(&chip->cdev_indicator);
	led_classdev_unregister(&chip->cdev_torch);
	led_classdev_unregister(&chip->cdev_flash);
	lm3556_write_reg(client, REG_ENABLE, 0);

	kfree(chip);
	printk(KERN_INFO "[LM3556] Removing is done");
	return 0;
}

static const struct i2c_device_id lm3556_id[] = {
	{LM3556_NAME, 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, lm3556_id);

static struct i2c_driver lm3556_i2c_driver = {
	.driver = {
		   .name = LM3556_NAME,
		   .owner = THIS_MODULE,
		   .pm = NULL,
		   },
	.probe = lm3556_probe,
	.remove = __devexit_p(lm3556_remove),
	.id_table = lm3556_id,
};

static int __init lm3556_init(void)
{
	return i2c_add_driver(&lm3556_i2c_driver);
}

static void __exit lm3556_exit(void)
{
	i2c_del_driver(&lm3556_i2c_driver);
}

module_init(lm3556_init);
module_exit(lm3556_exit);

MODULE_DESCRIPTION("Texas Instruments Flash Lighting driver for LM3556");
MODULE_AUTHOR
	("Geon Si Jeong <daniel.jeong@ti.com>, Woogyom Kim <milo.kim@ti.com>");
MODULE_LICENSE("GPL v2");
