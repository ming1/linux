/*
 * Copyright (C) ST-Ericsson AB 2011
 * Author: Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/xshm/xshm_dev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sjur Brændland <sjur.brandeland@stericsson.com>");

static int xshm_dev_match(struct device *_dv, struct device_driver *_dr)
{
	struct xshm_dev *dev = container_of(_dv, struct xshm_dev, dev);
	struct xshm_driver *drv = container_of(_dr, struct xshm_driver, driver);

	return drv->mode ==  (drv->mode & dev->cfg.mode);
}

static int xshm_dev_probe(struct device *_d)
{
	struct xshm_dev *dev = container_of(_d, struct xshm_dev, dev);
	struct xshm_driver *drv = container_of(dev->dev.driver,
						 struct xshm_driver, driver);
	return drv->probe(dev);
}

static int xshm_dev_remove(struct device *_d)
{
	struct xshm_dev *dev = container_of(_d, struct xshm_dev, dev);
	struct xshm_driver *drv = container_of(dev->dev.driver,
						 struct xshm_driver, driver);
	drv->remove(dev);
	return 0;
}

static struct bus_type xshm_bus = {
	.name  = "xshm",
	.match = xshm_dev_match,
	.probe = xshm_dev_probe,
	.remove = xshm_dev_remove,
};

struct xshm_iter_data {
	void *data;
	void (*fn)(struct xshm_dev *, void *);
};

int xshm_iter(struct device *_dev, void *data)
{
	struct xshm_dev *dev = container_of(_dev, struct xshm_dev, dev);
	struct xshm_iter_data *iter_data = data;

	iter_data->fn(dev, iter_data->data);
	return 0;
}

void xshm_foreach_dev(void fn(struct xshm_dev *, void *), void *data)
{
	struct xshm_iter_data iter = {
		.data = data,
		.fn = fn
	};

	bus_for_each_dev(&xshm_bus, NULL, &iter, xshm_iter);
}
EXPORT_SYMBOL_GPL(xshm_foreach_dev);

int xshm_register_driver(struct xshm_driver *driver)
{
	driver->driver.bus = &xshm_bus;
	return driver_register(&driver->driver);
}
EXPORT_SYMBOL_GPL(xshm_register_driver);

void xshm_unregister_driver(struct xshm_driver *driver)
{
	driver_unregister(&driver->driver);
}
EXPORT_SYMBOL_GPL(xshm_unregister_driver);

int xshm_register_device(struct xshm_dev *dev)
{
	int err;

	dev->dev.bus = &xshm_bus;
	err = device_register(&dev->dev);
	return err;
}
EXPORT_SYMBOL_GPL(xshm_register_device);

void xshm_unregister_device(struct xshm_dev *dev)
{
	device_unregister(&dev->dev);
}
EXPORT_SYMBOL_GPL(xshm_unregister_device);

static int xshm_bus_init(void)
{
	if (bus_register(&xshm_bus) != 0)
		panic("xshm bus registration failed");
	return 0;
}

static void __exit xshm_bus_exit(void)
{
	bus_unregister(&xshm_bus);
}

core_initcall(xshm_bus_init);
module_exit(xshm_bus_exit);
