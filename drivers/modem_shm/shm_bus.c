/*
 * Copyright (C) ST-Ericsson AB 2012
 * Author: Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/modem_shm/shm_dev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sjur Brændland <sjur.brandeland@stericsson.com>");

static int shm_dev_match(struct device *_dv, struct device_driver *_dr)
{
	struct shm_dev *dev = container_of(_dv, struct shm_dev, dev);
	struct shm_driver *drv = container_of(_dr, struct shm_driver, driver);

	return drv->mode ==  (drv->mode & dev->cfg.mode);
}

static int shm_dev_probe(struct device *_d)
{
	struct shm_dev *dev = container_of(_d, struct shm_dev, dev);
	struct shm_driver *drv = container_of(dev->dev.driver,
						 struct shm_driver, driver);
	return drv->probe(dev);
}

static int shm_dev_remove(struct device *_d)
{
	struct shm_dev *dev = container_of(_d, struct shm_dev, dev);
	struct shm_driver *drv = container_of(dev->dev.driver,
						 struct shm_driver, driver);
	drv->remove(dev);
	return 0;
}

static struct bus_type shm_bus = {
	.name  = "modem_shm",
	.match = shm_dev_match,
	.probe = shm_dev_probe,
	.remove = shm_dev_remove,
};

struct shm_iter_data {
	void *data;
	void (*fn)(struct shm_dev *, void *);
};

int shm_iter(struct device *_dev, void *data)
{
	struct shm_dev *dev = container_of(_dev, struct shm_dev, dev);
	struct shm_iter_data *iter_data = data;

	iter_data->fn(dev, iter_data->data);
	return 0;
}

void modem_shm_foreach_dev(void fn(struct shm_dev *, void *), void *data)
{
	struct shm_iter_data iter = {
		.data = data,
		.fn = fn
	};

	bus_for_each_dev(&shm_bus, NULL, &iter, shm_iter);
}
EXPORT_SYMBOL_GPL(modem_shm_foreach_dev);

int modem_shm_register_driver(struct shm_driver *driver)
{
	driver->driver.bus = &shm_bus;
	return driver_register(&driver->driver);
}
EXPORT_SYMBOL_GPL(modem_shm_register_driver);

void modem_shm_unregister_driver(struct shm_driver *driver)
{
	driver_unregister(&driver->driver);
}
EXPORT_SYMBOL_GPL(modem_shm_unregister_driver);

int modem_shm_register_device(struct shm_dev *dev)
{
	int err;

	dev->dev.bus = &shm_bus;
	err = device_register(&dev->dev);
	return err;
}
EXPORT_SYMBOL_GPL(modem_shm_register_device);

void modem_shm_unregister_device(struct shm_dev *dev)
{
	device_unregister(&dev->dev);
}
EXPORT_SYMBOL_GPL(modem_shm_unregister_device);

static int shm_bus_init(void)
{
	if (bus_register(&shm_bus) != 0)
		panic("shm bus registration failed");
	return 0;
}

static void __exit shm_bus_exit(void)
{
	bus_unregister(&shm_bus);
}

core_initcall(shm_bus_init);
module_exit(shm_bus_exit);
