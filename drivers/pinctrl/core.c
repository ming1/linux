/*
 * Core driver for the pin control subsystem
 *
 * Copyright (C) 2011 ST-Ericsson SA
 * Written on behalf of Linaro for ST-Ericsson
 * Based on bits of regulator core, gpio core and clk core
 *
 * Author: Linus Walleij <linus.walleij@linaro.org>
 *
 * License terms: GNU General Public License (GPL) version 2
 */
#define pr_fmt(fmt) "pinctrl core: " fmt

#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/machine.h>
#include "core.h"
#include "pinmux.h"

/* Global list of pin control devices */
static DEFINE_MUTEX(pinctrldev_list_mutex);
static LIST_HEAD(pinctrldev_list);

/* sysfs interaction */
static ssize_t pinctrl_name_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct pinctrl_dev *pctldev = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", pctldev_get_name(pctldev));
}

static void pinctrl_dev_release(struct device *dev)
{
	struct pinctrl_dev *pctldev = dev_get_drvdata(dev);
	kfree(pctldev);
}

static DEVICE_ATTR(name, S_IRUGO, pinctrl_name_show, NULL);

static struct attribute *pinctrl_dev_attrs[] = {
	&dev_attr_name.attr,
	NULL
};

static struct attribute_group pinctrl_dev_attr_group = {
	.attrs = pinctrl_dev_attrs,
};

static const struct attribute_group *pinctrl_dev_attr_groups[] = {
	&pinctrl_dev_attr_group,
	NULL
};

static struct bus_type pinctrl_bus = {
	.name = "pinctrl",
};

static struct device_type pinctrl_type = {
	.groups = pinctrl_dev_attr_groups,
	.release = pinctrl_dev_release,
};

const char *pctldev_get_name(struct pinctrl_dev *pctldev)
{
	/* We're not allowed to register devices without name */
	return pctldev->desc->name;
}
EXPORT_SYMBOL_GPL(pctldev_get_name);

void *pctldev_get_drvdata(struct pinctrl_dev *pctldev)
{
	return pctldev->driver_data;
}
EXPORT_SYMBOL_GPL(pctldev_get_drvdata);

/**
 * Looks up a pin control device matching a certain device name or
 * pure device pointer.
 */
struct pinctrl_dev *get_pctldev_from_dev(struct device *dev,
					 const char *devname)
{
	struct pinctrl_dev *pctldev = NULL;
	bool found = false;

	mutex_lock(&pinctrldev_list_mutex);
	list_for_each_entry(pctldev, &pinctrldev_list, node) {
		if (dev &&  &pctldev->dev == dev) {
			/* Matched on device pointer */
			found = true;
			break;
		}

		if (devname &&
		    !strcmp(dev_name(&pctldev->dev), devname)) {
			/* Matched on device name */
			found = true;
			break;
		}
	}
	mutex_unlock(&pinctrldev_list_mutex);

	if (found)
		return pctldev;

	return NULL;
}

struct pin_desc *pin_desc_get(struct pinctrl_dev *pctldev, int pin)
{
	struct pin_desc *pindesc;
	unsigned long flags;

	spin_lock_irqsave(&pctldev->pin_desc_tree_lock, flags);
	pindesc = radix_tree_lookup(&pctldev->pin_desc_tree, pin);
	spin_unlock_irqrestore(&pctldev->pin_desc_tree_lock, flags);

	return pindesc;
}

/**
 * Tell us whether a certain pin exist on a certain pin controller
 * or not. Pin lists may be sparse, so some pins may not exist.
 * @pctldev: the pin control device to check the pin on
 * @pin: pin to check, use the local pin controller index number
 */
bool pin_is_valid(struct pinctrl_dev *pctldev, int pin)
{
	struct pin_desc *pindesc;

	if (pin < 0)
		return false;

	pindesc = pin_desc_get(pctldev, pin);
	if (pindesc == NULL)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(pin_is_valid);

/* Deletes a range of pin descriptors */
static void pinctrl_free_pindescs(struct pinctrl_dev *pctldev,
				  const struct pinctrl_pin_desc *pins,
				  unsigned num_pins)
{
	int i;

	spin_lock(&pctldev->pin_desc_tree_lock);
	for (i = 0; i < num_pins; i++) {
		struct pin_desc *pindesc;

		pindesc = radix_tree_lookup(&pctldev->pin_desc_tree,
					    pins[i].number);
		if (pindesc != NULL) {
			radix_tree_delete(&pctldev->pin_desc_tree,
					  pins[i].number);
		}
		kfree(pindesc);
	}
	spin_unlock(&pctldev->pin_desc_tree_lock);
}

static int pinctrl_register_one_pin(struct pinctrl_dev *pctldev,
				    unsigned number, const char *name)
{
	struct pin_desc *pindesc;

	pindesc = pin_desc_get(pctldev, number);
	if (pindesc != NULL) {
		pr_err("pin %d already registered on %s\n", number,
		       pctldev->desc->name);
		return -EINVAL;
	}

	pindesc = kzalloc(sizeof(*pindesc), GFP_KERNEL);
	if (pindesc == NULL)
		return -ENOMEM;
	spin_lock_init(&pindesc->lock);

	/* Set owner */
	pindesc->pctldev = pctldev;

	/* Copy optional basic pin info */
	if (name)
		strlcpy(pindesc->name, name, sizeof(pindesc->name));

	spin_lock(&pctldev->pin_desc_tree_lock);
	radix_tree_insert(&pctldev->pin_desc_tree, number, pindesc);
	spin_unlock(&pctldev->pin_desc_tree_lock);
	pr_debug("registered pin %d (%s) on %s\n",
		 number, name ? name : "(unnamed)", pctldev->desc->name);
	return 0;
}

static int pinctrl_register_pins(struct pinctrl_dev *pctldev,
				 struct pinctrl_pin_desc const *pins,
				 unsigned num_descs)
{
	unsigned i;
	int ret = 0;

	for (i = 0; i < num_descs; i++) {
		ret = pinctrl_register_one_pin(pctldev,
					       pins[i].number, pins[i].name);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * pinctrl_match_gpio_range() - check if a certain GPIO pin is in the range of
 * a certain pin controller, return the range or NULL
 */
static struct pinctrl_gpio_range *
pinctrl_match_gpio_range(struct pinctrl_dev *pctldev, unsigned gpio)
{
	struct pinctrl_gpio_range *range = NULL;

	/* Loop over the ranges */
	mutex_lock(&pctldev->gpio_ranges_lock);
	list_for_each_entry(range, &pctldev->gpio_ranges, node) {
		/* Check if we're in the valid range */
		if (gpio >= range->base &&
		    gpio < range->base + range->npins) {
			mutex_unlock(&pctldev->gpio_ranges_lock);
			return range;
		}
	}
	mutex_unlock(&pctldev->gpio_ranges_lock);

	return NULL;
}

/**
 * pinctrl_get_device_gpio_range() - find the pin controller handling a certain
 * pin from the pinspace in the GPIO subsystem, return the device and the
 * matching GPIO range. Returns negative if the GPIO range could not be found
 * in any device
 * @gpio: the pin to locate the pin controller for
 * @outdev: the pin control device if found
 * @outrange: the GPIO range if found
 */
int pinctrl_get_device_gpio_range(unsigned gpio,
				struct pinctrl_dev **outdev,
				struct pinctrl_gpio_range **outrange)
{
	struct pinctrl_dev *pctldev = NULL;

	/* Loop over the pin controllers */
	mutex_lock(&pinctrldev_list_mutex);
	list_for_each_entry(pctldev, &pinctrldev_list, node) {
		struct pinctrl_gpio_range *range;

		range = pinctrl_match_gpio_range(pctldev, gpio);
		if (range != NULL) {
			*outdev = pctldev;
			*outrange = range;
			return 0;
		}
	}
	mutex_unlock(&pinctrldev_list_mutex);

	return -EINVAL;
}

/**
 * pinctrl_add_gpio_range() - this adds a range of GPIOs to be handled
 * by a certain pin controller. Call this to register handled ranges after
 * registering your pin controller.
 * @pctldev: pin controller device to add the range to
 * @range: the GPIO range to add
 */
void pinctrl_add_gpio_range(struct pinctrl_dev *pctldev,
			    struct pinctrl_gpio_range *range)
{
	mutex_lock(&pctldev->gpio_ranges_lock);
	list_add(&range->node, &pctldev->gpio_ranges);
	mutex_unlock(&pctldev->gpio_ranges_lock);
}

/**
 * pinctrl_remove_gpio_range() - removes a range of GPIOs fro a pin controller
 * @pctldev: pin controller device to remove the range from
 * @range: the GPIO range to remove
 */
void pinctrl_remove_gpio_range(struct pinctrl_dev *pctldev,
			       struct pinctrl_gpio_range *range)
{
	mutex_lock(&pctldev->gpio_ranges_lock);
	list_del(&range->node);
	mutex_unlock(&pctldev->gpio_ranges_lock);
}

#ifdef CONFIG_DEBUG_FS

static int pinctrl_pins_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev = s->private;
	const struct pinctrl_ops *ops = pctldev->desc->pctlops;
	unsigned pin;

	seq_printf(s, "registered pins: %d\n", pctldev->desc->npins);
	seq_printf(s, "max pin number: %d\n", pctldev->desc->maxpin);

	/* The highest pin number need to be included in the loop, thus <= */
	for (pin = 0; pin <= pctldev->desc->maxpin; pin++) {
		struct pin_desc *desc;

		desc = pin_desc_get(pctldev, pin);
		/* Pin space may be sparse */
		if (desc == NULL)
			continue;

		seq_printf(s, "pin %d (%s) ", pin,
			   desc->name ? desc->name : "unnamed");

		/* Driver-specific info per pin */
		if (ops->pin_dbg_show)
			ops->pin_dbg_show(pctldev, s, pin);

		seq_puts(s, "\n");
	}

	return 0;
}

static int pinctrl_groups_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev = s->private;
	const struct pinctrl_ops *ops = pctldev->desc->pctlops;
	unsigned selector = 0;

	/* No grouping */
	if (!ops)
		return 0;

	seq_puts(s, "registered pin groups:\n");
	while (ops->list_groups(pctldev, selector) >= 0) {
		unsigned *pins;
		unsigned num_pins;
		const char *gname = ops->get_group_name(pctldev, selector);
		int ret;
		int i;

		ret = ops->get_group_pins(pctldev, selector,
					  &pins, &num_pins);
		if (ret)
			seq_printf(s, "%s [ERROR GETTING PINS]\n",
				   gname);
		else {
			seq_printf(s, "group: %s, pins = [ ", gname);
			for (i = 0; i < num_pins; i++)
				seq_printf(s, "%d ", pins[i]);
			seq_puts(s, "]\n");
		}
		selector++;
	}


	return 0;
}

static int pinctrl_gpioranges_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev = s->private;
	struct pinctrl_gpio_range *range = NULL;

	seq_puts(s, "GPIO ranges handled:\n");

	/* Loop over the ranges */
	mutex_lock(&pctldev->gpio_ranges_lock);
	list_for_each_entry(range, &pctldev->gpio_ranges, node) {
		seq_printf(s, "%u: %s [%u - %u]\n", range->id, range->name,
			   range->base, (range->base + range->npins - 1));
	}
	mutex_unlock(&pctldev->gpio_ranges_lock);

	return 0;
}

static int pinctrl_devices_show(struct seq_file *s, void *what)
{
	struct pinctrl_dev *pctldev;

	seq_puts(s, "name [pinmux]\n");
	mutex_lock(&pinctrldev_list_mutex);
	list_for_each_entry(pctldev, &pinctrldev_list, node) {
		seq_printf(s, "%s ", pctldev->desc->name);
		if (pctldev->desc->pmxops)
			seq_puts(s, "yes");
		else
			seq_puts(s, "no");
		seq_puts(s, "\n");
	}
	mutex_unlock(&pinctrldev_list_mutex);

	return 0;
}

static int pinctrl_pins_open(struct inode *inode, struct file *file)
{
	return single_open(file, pinctrl_pins_show, inode->i_private);
}

static int pinctrl_groups_open(struct inode *inode, struct file *file)
{
	return single_open(file, pinctrl_groups_show, inode->i_private);
}

static int pinctrl_gpioranges_open(struct inode *inode, struct file *file)
{
	return single_open(file, pinctrl_gpioranges_show, inode->i_private);
}

static int pinctrl_devices_open(struct inode *inode, struct file *file)
{
	return single_open(file, pinctrl_devices_show, NULL);
}

static const struct file_operations pinctrl_pins_ops = {
	.open		= pinctrl_pins_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations pinctrl_groups_ops = {
	.open		= pinctrl_groups_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations pinctrl_gpioranges_ops = {
	.open		= pinctrl_gpioranges_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static const struct file_operations pinctrl_devices_ops = {
	.open		= pinctrl_devices_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static struct dentry *debugfs_root;

static void pinctrl_init_device_debugfs(struct pinctrl_dev *pctldev)
{
	static struct dentry *device_root;

	device_root = debugfs_create_dir(dev_name(&pctldev->dev),
					 debugfs_root);
	if (IS_ERR(device_root) || !device_root) {
		pr_warn("failed to create debugfs directory for %s\n",
			dev_name(&pctldev->dev));
		return;
	}
	debugfs_create_file("pins", S_IFREG | S_IRUGO,
			    device_root, pctldev, &pinctrl_pins_ops);
	debugfs_create_file("pingroups", S_IFREG | S_IRUGO,
			    device_root, pctldev, &pinctrl_groups_ops);
	debugfs_create_file("gpio-ranges", S_IFREG | S_IRUGO,
			    device_root, pctldev, &pinctrl_gpioranges_ops);
	pinmux_init_device_debugfs(device_root, pctldev);
}

static void pinctrl_init_debugfs(void)
{
	debugfs_root = debugfs_create_dir("pinctrl", NULL);
	if (IS_ERR(debugfs_root) || !debugfs_root) {
		pr_warn("failed to create debugfs directory\n");
		debugfs_root = NULL;
		return;
	}

	debugfs_create_file("pinctrl-devices", S_IFREG | S_IRUGO,
			    debugfs_root, NULL, &pinctrl_devices_ops);
	pinmux_init_debugfs(debugfs_root);
}

#else /* CONFIG_DEBUG_FS */

static void pinctrl_init_device_debugfs(struct pinctrl_dev *pctldev)
{
}

static void pinctrl_init_debugfs(void)
{
}

#endif

/**
 * pinctrl_register() - register a pin controller device
 * @pctldesc: descriptor for this pin controller
 * @dev: parent device for this pin controller
 * @driver_data: private pin controller data for this pin controller
 */
struct pinctrl_dev *pinctrl_register(struct pinctrl_desc *pctldesc,
				    struct device *dev, void *driver_data)
{
	static atomic_t pinmux_no = ATOMIC_INIT(0);
	struct pinctrl_dev *pctldev;
	int ret;

	if (pctldesc == NULL)
		return ERR_PTR(-EINVAL);
	if (pctldesc->name == NULL)
		return ERR_PTR(-EINVAL);

	/* If we're implementing pinmuxing, check the ops for sanity */
	if (pctldesc->pmxops) {
		ret = pinmux_check_ops(pctldesc->pmxops);
		if (ret) {
			pr_err("%s pinmux ops lacks necessary functions\n",
			       pctldesc->name);
			return ERR_PTR(ret);
		}
	}

	pctldev = kzalloc(sizeof(struct pinctrl_dev), GFP_KERNEL);
	if (pctldev == NULL)
		return ERR_PTR(-ENOMEM);

	/* Initialize pin control device struct */
	pctldev->owner = pctldesc->owner;
	pctldev->desc = pctldesc;
	pctldev->driver_data = driver_data;
	INIT_RADIX_TREE(&pctldev->pin_desc_tree, GFP_KERNEL);
	spin_lock_init(&pctldev->pin_desc_tree_lock);
	INIT_LIST_HEAD(&pctldev->gpio_ranges);
	mutex_init(&pctldev->gpio_ranges_lock);

	/* Register device with sysfs */
	pctldev->dev.parent = dev;
	pctldev->dev.bus = &pinctrl_bus;
	pctldev->dev.type = &pinctrl_type;
	dev_set_name(&pctldev->dev, "pinctrl.%d",
		     atomic_inc_return(&pinmux_no) - 1);
	ret = device_register(&pctldev->dev);
	if (ret != 0) {
		pr_err("error in device registration\n");
		put_device(&pctldev->dev);
		kfree(pctldev);
		goto out_err;
	}
	dev_set_drvdata(&pctldev->dev, pctldev);

	/* Register all the pins */
	pr_debug("try to register %d pins on %s...\n",
		 pctldesc->npins, pctldesc->name);
	ret = pinctrl_register_pins(pctldev, pctldesc->pins, pctldesc->npins);
	if (ret) {
		pr_err("error during pin registration\n");
		pinctrl_free_pindescs(pctldev, pctldesc->pins,
				      pctldesc->npins);
		goto out_err;
	}

	pinctrl_init_device_debugfs(pctldev);
	mutex_lock(&pinctrldev_list_mutex);
	list_add(&pctldev->node, &pinctrldev_list);
	mutex_unlock(&pinctrldev_list_mutex);
	pinmux_hog_maps(pctldev);
	return pctldev;

out_err:
	put_device(&pctldev->dev);
	kfree(pctldev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(pinctrl_register);

/**
 * pinctrl_unregister() - unregister pinmux
 * @pctldev: pin controller to unregister
 *
 * Called by pinmux drivers to unregister a pinmux.
 */
void pinctrl_unregister(struct pinctrl_dev *pctldev)
{
	if (pctldev == NULL)
		return;

	pinmux_unhog_maps(pctldev);
	/* TODO: check that no pinmuxes are still active? */
	mutex_lock(&pinctrldev_list_mutex);
	list_del(&pctldev->node);
	mutex_unlock(&pinctrldev_list_mutex);
	device_unregister(&pctldev->dev);
	/* Destroy descriptor tree */
	pinctrl_free_pindescs(pctldev, pctldev->desc->pins,
			      pctldev->desc->npins);
	kfree(pctldev);
}
EXPORT_SYMBOL_GPL(pinctrl_unregister);

static int __init pinctrl_init(void)
{
	int ret;

	ret = bus_register(&pinctrl_bus);
	if (ret) {
		pr_crit("could not register pinctrl bus\n");
		return ret;
	}

	pr_info("initialized pinctrl subsystem\n");
	pinctrl_init_debugfs();
	return 0;
}

/* init early since many drivers really need to initialized pinmux early */
core_initcall(pinctrl_init);
