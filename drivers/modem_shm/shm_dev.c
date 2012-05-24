/*
 * Copyright (C) ST-Ericsson AB 2012
 * Author: Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ":" fmt
#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/firmware.h>
#include <linux/c2c_genio.h>
#include <linux/modem_shm/shm_dev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sjur Brændland <sjur.brandeland@stericsson.com>");

static int shm_inactivity_timeout = 1000;
module_param(shm_inactivity_timeout, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(shm_inactivity_timeout, "Inactivity timeout, ms.");

struct shm_parent {
	struct device dev;
	bool ready_for_ipc;
	bool ready_for_caif;
	spinlock_t timer_lock;
	int inactivity_timeout;
	struct timer_list inactivity_timer;
	bool power_on;
};

struct shm_parent *parent_dev;

#define mdev_dbg(dev, fmt, arg...) dev_dbg(&dev->dev, pr_fmt(fmt), ##arg)
#define mdev_vdbg(dev, fmt, arg...) dev_vdbg(&dev->dev, pr_fmt(fmt), ##arg)

static void inactivity_tout(unsigned long arg)
{
	unsigned long flags;
	pr_devel("enter\n");
	spin_lock_irqsave(&parent_dev->timer_lock, flags);
	/*
	 * This is paranoia, but if timer is reactivated
	 * before this tout function is scheduled,
	 * we just ignore this timeout.
	 */
	if (timer_pending(&parent_dev->inactivity_timer))
		goto out;

	if (parent_dev->power_on) {
		pr_devel("genio power req(off)\n");
		genio_power_req(false);
		parent_dev->power_on = false;
	}
out:
	spin_unlock_irqrestore(&parent_dev->timer_lock, flags);
}

static void activity(void)
{
	unsigned long flags;

	spin_lock_irqsave(&parent_dev->timer_lock, flags);
	if (!parent_dev->power_on) {
		pr_devel("genio power req(on)\n");
		genio_power_req(true);
		parent_dev->power_on = true;
	}
	mod_timer(&parent_dev->inactivity_timer,
			jiffies + parent_dev->inactivity_timeout);
	spin_unlock_irqrestore(&parent_dev->timer_lock, flags);
}

static void reset_activity_tout(void)
{
	unsigned long flags;
	pr_devel("enter\n");
	spin_lock_irqsave(&parent_dev->timer_lock, flags);
	if (parent_dev->power_on) {
		genio_power_req(false);
		parent_dev->power_on = false;
	}
	del_timer_sync(&parent_dev->inactivity_timer);
	spin_unlock_irqrestore(&parent_dev->timer_lock, flags);
}

static int shmdev_ipc_tx(struct shm_dev *dev)
{
	mdev_vdbg(dev, "call genio_set_bit(%d)\n", dev->cfg.tx.xfer_bit);
	activity();
	return genio_set_bit(dev->cfg.tx.xfer_bit);
}

static int shmdev_ipc_rx_release(struct shm_dev *dev, bool more)
{
	mdev_vdbg(dev, "call genio_set_bit(%d)\n", dev->cfg.tx.xfer_bit);
	activity();
	return genio_set_bit(dev->cfg.rx.xfer_done_bit);
}

static int do_open(struct shm_dev *dev)
{
	int err;

	err = dev->open_cb(dev->driver_data);
	if (err < 0) {
		mdev_dbg(dev, "Error - open_cb failed\n");

		/* Make sure ring-buffer is empty i RX and TX direction */
		*dev->cfg.rx.read = *dev->cfg.rx.write;
		*dev->cfg.tx.write = *dev->cfg.tx.read;
		*dev->cfg.tx.state = cpu_to_le32(SHM_CLOSED);
		mdev_vdbg(dev, "set state = SHM_DEV_CLOSED\n");
		dev->state = SHM_DEV_CLOSED;
		return err;
	}

	/* Check is we already have any data in the pipe */
	if (*dev->cfg.rx.write != *dev->cfg.rx.read) {
		mdev_vdbg(dev, "Received data during opening\n");
		dev->ipc_rx_cb(dev->driver_data);
	}

	return err;
}

static void genio_rx_cb(void *data)
{
	struct shm_dev *dev = data;

	if (likely(dev->state == SHM_DEV_OPEN)) {
		if (unlikely(!parent_dev->ready_for_ipc)) {
			mdev_vdbg(dev, "ready_for_ipc is not yet set\n");
			return;
		}

		if (dev->ipc_rx_cb) {
			int err = dev->ipc_rx_cb(dev->driver_data);
			if (unlikely(err < 0))
				goto remote_close;
		}

	} else if (*dev->cfg.rx.state == cpu_to_le32(SHM_OPEN)) {
		dev->state = SHM_DEV_OPEN;
		if (!parent_dev->ready_for_ipc) {
			mdev_vdbg(dev, "ready_for_ipc is not yet set\n");
			return;
		}
		if (do_open(dev) < 0)
			goto open_fail;
	}
	return;
open_fail:
	/* Make sure ring-buffer is empty i RX and TX direction */
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
remote_close:
	*dev->cfg.tx.state = cpu_to_le32(SHM_CLOSED);
	dev->state = SHM_DEV_CLOSED;
	dev->close_cb(dev->driver_data);
}

static void genio_tx_release_cb(void *data)
{
	struct shm_dev *dev = data;

	if (!parent_dev->ready_for_ipc) {
		mdev_vdbg(dev, "not ready_for_ipc\n");
		return;
	}
	if (dev->ipc_tx_release_cb)
		dev->ipc_tx_release_cb(dev->driver_data);
}

struct shm_xgroup {
	bool prohibit;
	u32 group;
};

static void check_exclgroup(struct shm_dev *dev, void *data)
{
	struct shm_xgroup *x = data;
	if (dev->state == SHM_DEV_OPEN &&
		dev->cfg.excl_group != x->group) {
		x->prohibit = true;
		mdev_dbg(dev, "Exclusive group "
				"prohibits device open\n");
	}
}

static int shmdev_open(struct shm_dev *dev)
{
	int err = -EINVAL;
	struct shm_xgroup x = {
		.prohibit = false,
		.group = dev->cfg.excl_group
	};


	if (WARN_ON(dev->ipc_rx_cb == NULL) ||
			WARN_ON(dev->ipc_tx_release_cb == NULL) ||
			WARN_ON(dev->open_cb == NULL) ||
			WARN_ON(dev->close_cb == NULL))
		goto err;

	modem_shm_foreach_dev(check_exclgroup, &x);
	if (x.prohibit) {
		mdev_dbg(dev, "Exclusive group prohibits device open\n");
		err = -EPERM;
		goto err;
	}

	mdev_vdbg(dev, "call genio_subscribe(%d)\n", dev->cfg.rx.xfer_bit);
	err = genio_subscribe(dev->cfg.rx.xfer_bit, genio_rx_cb, dev);
	if (err)
		goto err;

	mdev_vdbg(dev, "call genio_subscribe(%d)\n", dev->cfg.tx.xfer_done_bit);
	err = genio_subscribe(dev->cfg.tx.xfer_done_bit,
			genio_tx_release_cb, dev);
	if (err)
		goto err;

	/* Indicate that our side is open and ready for action */
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
	*dev->cfg.tx.state = cpu_to_le32(SHM_OPEN);

	if (parent_dev->ready_for_ipc)
		err = shmdev_ipc_tx(dev);

	if (err < 0) {
		mdev_dbg(dev, "can't update geno\n");
		goto err;
	}
	/* If other side is ready as well we're ready to role */
	if (*dev->cfg.rx.state == cpu_to_le32(SHM_OPEN) &&
			parent_dev->ready_for_ipc) {

		if (do_open(dev) < 0)
			goto err;
		dev->state = SHM_DEV_OPEN;
	}

	return 0;
err:
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
	*dev->cfg.tx.state = cpu_to_le32(SHM_CLOSED);
	return err;
}

static void shmdev_close(struct shm_dev *dev)
{
	dev->state = SHM_DEV_CLOSED;
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.state = cpu_to_le32(SHM_CLOSED);
	shmdev_ipc_tx(dev);
	if (dev->close_cb)
		dev->close_cb(dev->driver_data);

	mdev_vdbg(dev, "call genio_unsubscribe(%d)\n", dev->cfg.rx.xfer_bit);
	genio_unsubscribe(dev->cfg.rx.xfer_bit);
	mdev_vdbg(dev, "call genio_unsubscribe(%d)\n",
			dev->cfg.tx.xfer_done_bit);
	genio_unsubscribe(dev->cfg.tx.xfer_done_bit);
}

static void shmdev_release(struct device *dev)
{
	struct shm_dev *shm = container_of(dev, struct shm_dev, dev);
	kfree(shm);
}

int modem_shm_register_devices(struct shm_channel *channel[], int channels)
{

	int i, err;
	struct shm_dev *dev;

	for (i = 0; i < channels; i++) {
		dev = kzalloc(sizeof(*dev), GFP_KERNEL);
		if (dev == NULL)
			return -ENOMEM;
		dev_set_name(&dev->dev, "shm%u", i);
		dev->dev.release = shmdev_release;

		dev->state = SHM_DEV_CLOSED;
		dev->open = shmdev_open;
		dev->close = shmdev_close;
		dev->ipc_rx_release = shmdev_ipc_rx_release;
		dev->ipc_tx = shmdev_ipc_tx;
		mdev_vdbg(dev, "register SHM device %s\n",
				dev_name(&dev->dev));
		dev->dev.parent = &parent_dev->dev;
		dev->cfg = *channel[i];

		err = modem_shm_register_device(dev);
		if (err) {
			mdev_dbg(dev, "registration failed (%d)\n", err);
			return err;
		}
	}
	return 0;
}
EXPORT_SYMBOL(modem_shm_register_devices);

/* sysfs: ipc_ready file */
static ssize_t caif_ready_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", parent_dev->ready_for_caif);
}

static DEVICE_ATTR(caif_ready, S_IRUSR | S_IRUGO, caif_ready_show, NULL);

/* sysfs: notification on change of caif_ready to user space */
void shm_caif_ready(void)
{
	sysfs_notify(&parent_dev->dev.kobj, NULL,
			dev_attr_caif_ready.attr.name);
}

/* sysfs: ipc_ready file */
static ssize_t ipc_ready_show(struct device *dev, struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", parent_dev->ready_for_ipc);
}

static DEVICE_ATTR(ipc_ready, S_IRUSR | S_IRUGO, ipc_ready_show, NULL);

/* sysfs: notification on change of ipc_ready to user space */
void shm_ipc_ready(void)
{
	sysfs_notify(&parent_dev->dev.kobj, NULL, dev_attr_ipc_ready.attr.name);
}

static void genio_caif_ready_cb(bool ready)
{
	pr_devel("enter\n");
	/* Set global variable ready_for_caif true */
	if (parent_dev->ready_for_caif != ready) {
		parent_dev->ready_for_caif = ready;
		shm_caif_ready();
	}
}

static void genio_errhandler(int errno)
{
	/* Fake CAIF_READY low to trigger modem restart */
	pr_warn("Driver reported error:%d\n", errno);
	parent_dev->ready_for_caif = 0;
	shm_caif_ready();
}

struct shm_bits {
	u32 setter;
	u32 getter;
};

static void collect_bits(struct shm_dev *dev, void *data)
{
	struct shm_bits *bits = data;
	bits->setter |= 1 << dev->cfg.tx.xfer_bit;
	bits->setter |= 1 << dev->cfg.rx.xfer_done_bit;
	bits->getter |= 1 << dev->cfg.rx.xfer_bit;
	bits->getter |= 1 << dev->cfg.tx.xfer_done_bit;
}

static void handle_open(struct shm_dev *dev, void *data)
{
		if (dev->cfg.rx.state != NULL && dev->cfg.tx.state != NULL &&
				*dev->cfg.rx.state == cpu_to_le32(SHM_OPEN) &&
				*dev->cfg.tx.state == cpu_to_le32(SHM_OPEN)) {
			dev->state = SHM_DEV_OPEN;
			do_open(dev);
		}
}

void genio_ipc_ready_cb(void)
{
	int err;
	struct shm_bits bits = {0, 0};

	pr_devel("enter\n");
	/* Set global variable ready_for_ipc true */
#ifdef DEBUG
	/*
	 * In real life ready_for_ipc doesn't change, but it's
	 * convenient for testing.
	 */
	parent_dev->ready_for_ipc = !parent_dev->ready_for_ipc;
#else
	parent_dev->ready_for_ipc = true;
#endif

	shm_ipc_ready();

	genio_register_errhandler(genio_errhandler);

	pr_devel("call genio_subscribe_caif_ready()\n");
	err = genio_subscribe_caif_ready(genio_caif_ready_cb);
	if (err < 0)
		pr_debug("genio_subscribe_caif_ready failed:%d\n", err);

	/* Collect the bit-mask for GENIO bits */
	modem_shm_foreach_dev(collect_bits, &bits);
	pr_devel("call genio_bit_alloc(%x,%x)\n", bits.setter, bits.getter);
	err = genio_bit_alloc(bits.setter, bits.getter);
	if (err < 0)
		pr_debug("genio_bit_alloc failed:%d\n", err);
	modem_shm_foreach_dev(handle_open, NULL);
}
EXPORT_SYMBOL(genio_ipc_ready_cb);

int modem_shm_request_firmware(void *context, struct module *mod,
		const char *img_name,
		void (*cb)(const struct firmware *, void *))
{
	pr_debug("firmware request\n");
	return request_firmware_nowait(mod,
			FW_ACTION_NOHOTPLUG,
			img_name,
			&parent_dev->dev,
			GFP_KERNEL,
			context,
			cb);
}
EXPORT_SYMBOL(modem_shm_request_firmware);

static void parent_release(struct device *dev)
{
	struct shm_parent *parent = container_of(dev, struct shm_parent, dev);
	WARN_ON(parent_dev != parent);
	kfree(parent);
	parent_dev = NULL;
}

static int __init shm_init(void)
{
	int err;

	pr_devel("Initializing\n");

	parent_dev = kzalloc(sizeof(*parent_dev), GFP_KERNEL);
	if (parent_dev  == NULL)
		return -ENOMEM;

	dev_set_name(&parent_dev->dev, "modem_shm");
	parent_dev->dev.release = parent_release;

	/* Pre-calculate inactivity timeout. */
	if (shm_inactivity_timeout != -1) {
		parent_dev->inactivity_timeout =
				shm_inactivity_timeout * HZ / 1000;
		if (parent_dev->inactivity_timeout == 0)
			parent_dev->inactivity_timeout = 1;
		else if (parent_dev->inactivity_timeout > NEXT_TIMER_MAX_DELTA)
			parent_dev->inactivity_timeout = NEXT_TIMER_MAX_DELTA;
	} else
		parent_dev->inactivity_timeout = NEXT_TIMER_MAX_DELTA;

	spin_lock_init(&parent_dev->timer_lock);
	init_timer(&parent_dev->inactivity_timer);
	parent_dev->inactivity_timer.data = 0L;
	parent_dev->inactivity_timer.function = inactivity_tout;

	err = device_register(&parent_dev->dev);
	if (err)
		goto err;

	err = device_create_file(&parent_dev->dev, &dev_attr_ipc_ready);
	if (err)
		goto err_unreg;
	err = device_create_file(&parent_dev->dev, &dev_attr_caif_ready);
	if (err)
		goto err_unreg;

	return err;
err_unreg:
	pr_debug("initialization failed\n");
	device_unregister(&parent_dev->dev);
err:
	return err;
}

static void handle_close(struct shm_dev *dev, void *data)
{
	if (dev->close_cb)
		dev->close_cb(dev->driver_data);
}

void close_devices(void)
{
	modem_shm_foreach_dev(handle_close, NULL);
}

static void handle_reset(struct shm_dev *dev, void *data)
{
	if (dev->close_cb)
		dev->close_cb(dev->driver_data);
	modem_shm_unregister_device(dev);
}

void modem_shm_reset(void)
{
	parent_dev->ready_for_ipc = false;
	parent_dev->ready_for_caif = false;
	modem_shm_foreach_dev(handle_reset, NULL);
	reset_activity_tout();
	genio_reset();
}
EXPORT_SYMBOL(modem_shm_reset);

static void __exit shm_exit(void)
{
	modem_shm_reset();
	device_unregister(&parent_dev->dev);
	genio_unsubscribe(READY_FOR_IPC_BIT);
	genio_unsubscribe(READY_FOR_CAIF_BIT);
}

module_init(shm_init);
module_exit(shm_exit);
