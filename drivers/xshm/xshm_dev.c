/*
 * Copyright (C) ST-Ericsson AB 2010
 * Author: Sjur Brendeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": %s :" fmt, __func__
#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/c2c_genio.h>
#include <linux/xshm/xshm_ipctoc.h>
#include <linux/xshm/xshm_pdev.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sjur Brændland <sjur.brandeland@stericsson.com>");
MODULE_DESCRIPTION("External Shared Memory - Supporting direct boot and IPC");
MODULE_VERSION("XSHM 0.5 : " __DATE__);

static int xshm_inactivity_timeout = 1000;
module_param(xshm_inactivity_timeout, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xshm_inactivity_timeout, "Inactivity timeout, ms.");

bool ready_for_ipc;
bool ready_for_caif;
static spinlock_t list_lock;
static LIST_HEAD(pdev_list);
static spinlock_t timer_lock;
static int inactivity_timeout;
static struct timer_list inactivity_timer;
static bool power_on;

#if 1
#define xdev_dbg(dev, fmt, arg...) printk(KERN_DEBUG "%s%d: %s - " fmt, \
			dev->pdev.name, dev->pdev.id, __func__, ##arg)
#define xdev_devl(dev, fmt, arg...) printk(KERN_DEBUG "%s%d: %s - " fmt, \
			dev->pdev.name, dev->pdev.id, __func__, ##arg)
#define pr_xshmstate(dev, str) \
	pr_devel("xshm%d: %s: %s STATE: %s txch:%s(%p) rxch:%s(%p)\n",	\
			dev->pdev.id, __func__, str,			\
			dev->state == XSHM_DEV_OPEN ? "open" : "close", \
			*dev->cfg.tx.state == cpu_to_le32(XSHM_OPEN) ?	\
			"open" : "close",				\
			dev->cfg.tx.state,				\
			*dev->cfg.rx.state == cpu_to_le32(XSHM_OPEN) ?	\
			"open" : "close",				\
			dev->cfg.rx.state)
#else
#define xdev_dbg(...)
#define xdev_devl(...)
#undef pr_debug
#undef pr_devel
#define pr_debug(...)
#define pr_devel(...)
#define pr_xshmstate(...)
#endif

static void inactivity_tout(unsigned long arg)
{
	unsigned long flags;
	pr_devel("enter\n");
	spin_lock_irqsave(&timer_lock, flags);
	/*
	 * This is paranoia, but if timer is reactivated
	 * before this tout function is scheduled,
	 * we just ignore this timeout.
	 */
	if (timer_pending(&inactivity_timer))
		goto out;

	if (power_on) {
		pr_devel("genio power req(off)\n");
		genio_power_req(false);
		power_on = false;
	}
out:
	spin_unlock_irqrestore(&timer_lock, flags);
}

static void activity(void)
{
	unsigned long flags;
	pr_devel("enter\n");
	spin_lock_irqsave(&timer_lock, flags);
	if (!power_on) {
		pr_devel("genio power req(on)\n");
		genio_power_req(true);
		power_on = true;
	}
	mod_timer(&inactivity_timer,
			jiffies + inactivity_timeout);
	spin_unlock_irqrestore(&timer_lock, flags);
}

static void reset_activity_tout(void)
{
	unsigned long flags;
	pr_devel("enter\n");
	spin_lock_irqsave(&timer_lock, flags);
	if (power_on) {
		genio_power_req(false);
		power_on = false;
	}
	del_timer_sync(&inactivity_timer);
	spin_unlock_irqrestore(&timer_lock, flags);
}

static int xshmdev_ipc_tx(struct xshm_dev *dev)
{
	xdev_devl(dev, "call genio_set_bit(%d)\n", dev->cfg.tx.xfer_bit);
	activity();
	return genio_set_bit(dev->cfg.tx.xfer_bit);
}

static int xshmdev_ipc_rx_release(struct xshm_dev *dev, bool more)
{
	xdev_devl(dev, "call genio_set_bit(%d)\n", dev->cfg.tx.xfer_bit);
	activity();
	return genio_set_bit(dev->cfg.rx.xfer_done_bit);
}

static int do_open(struct xshm_dev *dev)
{
	int err;

	pr_xshmstate(dev, "enter");
	err = dev->open_cb(dev->driver_data);
	if (err < 0) {
		xdev_dbg(dev, "Error - open_cb failed\n");

		/* Make sure ring-buffer is empty i RX and TX direction */
		*dev->cfg.rx.read = *dev->cfg.rx.write;
		*dev->cfg.tx.write = *dev->cfg.tx.read;
		*dev->cfg.tx.state = cpu_to_le32(XSHM_CLOSED);
		xdev_devl(dev, "set state = XSHM_DEV_CLOSED\n");
		dev->state = XSHM_DEV_CLOSED;
		return err;
	}

	/* Check is we already have any data in the pipe */
	if (*dev->cfg.rx.write != *dev->cfg.rx.read) {
		pr_devel("Received data during opening\n");
		dev->ipc_rx_cb(dev->driver_data);
	}

	return err;
}

static void genio_rx_cb(void *data)
{
	struct xshm_dev *dev = data;

	pr_xshmstate(dev, "Enter");

	if (likely(dev->state == XSHM_DEV_OPEN)) {
		if (unlikely(!ready_for_ipc)) {
			xdev_devl(dev, "ready_for_ipc is not yet set\n");
			return;
		}

		if (dev->ipc_rx_cb) {
			int err = dev->ipc_rx_cb(dev->driver_data);
			if (unlikely(err < 0))
				goto remote_close;
		}

	} else if (*dev->cfg.rx.state == cpu_to_le32(XSHM_OPEN)) {
		pr_xshmstate(dev, "");
		dev->state = XSHM_DEV_OPEN;
		if (!ready_for_ipc) {
			xdev_devl(dev, "ready_for_ipc is not yet set\n");
			return;
		}
		if (do_open(dev) < 0)
			goto open_fail;
	}
	return;
open_fail:
	pr_xshmstate(dev, "exit open failed");
	/* Make sure ring-buffer is empty i RX and TX direction */
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
remote_close:
	*dev->cfg.tx.state = cpu_to_le32(XSHM_CLOSED);
	dev->state = XSHM_DEV_CLOSED;
	dev->close_cb(dev->driver_data);
}

static void genio_tx_release_cb(void *data)
{
	struct xshm_dev *dev = data;

	pr_xshmstate(dev, "Enter");
	if (!ready_for_ipc) {
		xdev_devl(dev, "not ready_for_ipc\n");
		return;
	}
	if (dev->ipc_tx_release_cb)
		dev->ipc_tx_release_cb(dev->driver_data);
}

static int xshmdev_open(struct xshm_dev *dev)
{
	int err = -EINVAL;
	struct list_head *node;
	struct list_head *n;

	pr_xshmstate(dev, "Enter");
	if (WARN_ON(dev->ipc_rx_cb == NULL) ||
			WARN_ON(dev->ipc_tx_release_cb == NULL) ||
			WARN_ON(dev->open_cb == NULL) ||
			WARN_ON(dev->close_cb == NULL))
		goto err;

	list_for_each_safe(node, n, &pdev_list) {
		struct xshm_dev *dev2;
		dev2 = list_entry(node, struct xshm_dev, node);
		if (dev2 == dev)
			continue;

		if (dev2->state == XSHM_DEV_OPEN &&
				dev2->cfg.excl_group != dev->cfg.excl_group) {
			xdev_dbg(dev, "Exclusive group "
					"prohibits device open\n");
			err = -EPERM;
			goto err;
		}
	}
	pr_devel("call genio_subscribe(%d)\n", dev->cfg.rx.xfer_bit);
	err = genio_subscribe(dev->cfg.rx.xfer_bit, genio_rx_cb, dev);
	if (err)
		goto err;

	pr_devel("call genio_subscribe(%d)\n", dev->cfg.tx.xfer_done_bit);
	err = genio_subscribe(dev->cfg.tx.xfer_done_bit,
			genio_tx_release_cb, dev);
	if (err)
		goto err;

	/* Indicate that our side is open and ready for action */
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
	*dev->cfg.tx.state = cpu_to_le32(XSHM_OPEN);

	if (ready_for_ipc)
		err = xshmdev_ipc_tx(dev);

	if (err < 0) {
		xdev_dbg(dev, "can't update geno\n");
		goto err;
	}
	/* If other side is ready as well we're ready to role */
	if (*dev->cfg.rx.state == cpu_to_le32(XSHM_OPEN) && ready_for_ipc) {
		if (do_open(dev) < 0)
			goto err;
		dev->state = XSHM_DEV_OPEN;
	}

	return 0;
err:
	pr_xshmstate(dev, "exit error");
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.write = *dev->cfg.tx.read;
	*dev->cfg.tx.state = cpu_to_le32(XSHM_CLOSED);
	return err;
}

static void xshmdev_close(struct xshm_dev *dev)
{
	pr_xshmstate(dev, "enter");

	dev->state = XSHM_DEV_CLOSED;
	*dev->cfg.rx.read = *dev->cfg.rx.write;
	*dev->cfg.tx.state = cpu_to_le32(XSHM_CLOSED);
	xshmdev_ipc_tx(dev);
	if (dev->close_cb)
		dev->close_cb(dev->driver_data);

	pr_devel("call genio_unsubscribe(%d)\n", dev->cfg.rx.xfer_bit);
	genio_unsubscribe(dev->cfg.rx.xfer_bit);
	pr_devel("call genio_unsubscribe(%d)\n", dev->cfg.tx.xfer_done_bit);
	genio_unsubscribe(dev->cfg.tx.xfer_done_bit);
}

int xshm_register_dev(struct xshm_dev *dev)
{
	int err;
	unsigned long flags;

	dev->state = XSHM_DEV_CLOSED;
	dev->open = xshmdev_open;
	dev->close = xshmdev_close;
	dev->ipc_rx_release = xshmdev_ipc_rx_release;
	dev->ipc_tx = xshmdev_ipc_tx;
	/* Driver should only use this when platform_data is set */
	dev->pdev.dev.platform_data = dev;
	xdev_devl(dev, "re-register SHM platform device %s\n", dev->pdev.name);
	err = platform_device_register(&dev->pdev);
	if (err) {
		xdev_dbg(dev, "registration failed (%d)\n", err);
		goto clean;
	}
	spin_lock_irqsave(&list_lock, flags);
	list_add_tail(&dev->node, &pdev_list);
	spin_unlock_irqrestore(&list_lock, flags);

	return err;
clean:
	kfree(dev);
	return err;
}

static void genio_caif_ready_cb(bool ready)
{
	pr_devel("enter\n");
	/* Set global variable ready_for_caif true */
	if (ready_for_caif != ready) {
		ready_for_caif = ready;
		xshm_caif_ready();
	}
}

static void genio_errhandler(int errno)
{
	/* Fake CAIF_READY low to trigger modem restart */
	pr_warn("Driver reported error:%d\n", errno);
	ready_for_caif = 0;
	xshm_caif_ready();
}

void genio_ipc_ready_cb(void)
{
	struct xshm_dev *dev, *tmp;
	unsigned long flags;
	int err;
	u32 getter = 0;
	u32 setter = 0;

	pr_devel("enter\n");
	/* Set global variable ready_for_ipc true */
#ifdef DEBUG
	/*
	 * In real life read_for_ipc doesn't change, but it's
	 * convenient for testing.
	 */
	ready_for_ipc = !ready_for_ipc;
#else
	ready_for_ipc = true;
#endif

	xshm_ipc_ready();

	genio_register_errhandler(genio_errhandler);

	pr_devel("call genio_subscribe_caif_ready()\n");
	err = genio_subscribe_caif_ready(genio_caif_ready_cb);
	if (err < 0)
		pr_debug("genio_subscribe_caif_ready failed:%d\n", err);

	/* Take a refcount to the device so it doesn't go away */
	spin_lock_irqsave(&list_lock, flags);
	list_for_each_entry_safe(dev, tmp, &pdev_list, node)
		get_device(&dev->pdev.dev);
	spin_unlock_irqrestore(&list_lock, flags);

	/* Collect the bit-mask for GENIO bits */
	list_for_each_entry_safe(dev, tmp, &pdev_list, node) {
		setter |= 1 << dev->cfg.tx.xfer_bit;
		setter |= 1 << dev->cfg.rx.xfer_done_bit;
		getter |= 1 << dev->cfg.rx.xfer_bit;
		getter |= 1 << dev->cfg.tx.xfer_done_bit;
	}
	pr_devel("call genio_bit_alloc(%x,%x)\n", setter, getter);
	err = genio_bit_alloc(setter, getter);
	if (err < 0)
		pr_debug("genio_bit_alloc failed:%d\n", err);

	list_for_each_entry_safe(dev, tmp, &pdev_list, node) {
		if (dev->cfg.rx.state != NULL && dev->cfg.tx.state != NULL &&
				*dev->cfg.rx.state == cpu_to_le32(XSHM_OPEN) &&
				*dev->cfg.tx.state == cpu_to_le32(XSHM_OPEN)) {
			dev->state = XSHM_DEV_OPEN;
			do_open(dev);
		}
		put_device(&dev->pdev.dev);
	}
}

static int __init xshm_init(void)
{
	int err;

	pr_devel("Initializing\n");

	/* Pre-calculate inactivity timeout. */
	if (xshm_inactivity_timeout != -1) {
		inactivity_timeout =
				xshm_inactivity_timeout * HZ / 1000;
		if (inactivity_timeout == 0)
			inactivity_timeout = 1;
		else if (inactivity_timeout > NEXT_TIMER_MAX_DELTA)
			inactivity_timeout = NEXT_TIMER_MAX_DELTA;
	} else
		inactivity_timeout = NEXT_TIMER_MAX_DELTA;

	spin_lock_init(&list_lock);
	INIT_LIST_HEAD(&pdev_list);

	spin_lock_init(&timer_lock);
	init_timer(&inactivity_timer);
	inactivity_timer.data = 0L;
	inactivity_timer.function = inactivity_tout;

	pr_devel("call genio_init()\n");

	err = xshm_boot_init();
	if (err)
		goto err;

	return err;
err:
	pr_devel("call genio_exit()\n");
	return err;
}

void close_devices(void)
{
	struct xshm_dev *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &pdev_list, node)
		if (dev->close_cb)
			dev->close_cb(dev->driver_data);
}

void xshm_reset(void)
{
	struct xshm_dev *dev, *tmp;
	unsigned long flags;

	list_for_each_entry_safe(dev, tmp, &pdev_list, node) {
		get_device(&dev->pdev.dev);
		if (dev->close_cb)
			dev->close_cb(dev->driver_data);
		platform_device_unregister(&dev->pdev);
		spin_lock_irqsave(&list_lock, flags);
		dev->pdev.dev.platform_data = NULL;
		list_del(&dev->node);
		spin_unlock_irqrestore(&list_lock, flags);
		put_device(&dev->pdev.dev);
	}

	reset_activity_tout();
	genio_reset();
}

static void __exit xshm_exit(void)
{
	xshm_reset();
	genio_unsubscribe(READY_FOR_IPC_BIT);
	genio_unsubscribe(READY_FOR_CAIF_BIT);
	xshm_boot_exit();
}

module_init(xshm_init);
module_exit(xshm_exit);
