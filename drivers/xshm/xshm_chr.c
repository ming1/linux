/*
 * Copyright (C) ST-Ericsson AB 2010
 * Author:	Per Sigmond / Per.Sigmond@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ":%s :" fmt, __func__
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/xshm/xshm_pdev.h>
#include <linux/err.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
static LIST_HEAD(xshmchr_chrdev_list);
static spinlock_t list_lock;

#define xdev_dbg(dev, fmt, arg...) printk(KERN_DEBUG "%s: %s - " fmt, \
			dev ? dev->misc.name : "?", __func__, ##arg)
#define xdev_devl(dev, fmt, arg...) printk(KERN_DEBUG "%s: %s - " fmt, \
			dev ? dev->misc.name : "?" , __func__, ##arg)
#define pr_xchrstate(dev, str) \
	xdev_devl(dev, "State: %s %s %s\n", str,	\
		STATE_IS_PENDING(dev) ? "pending" : "", \
		STATE_IS_OPEN(dev) ? "open" : "close")

#define OPEN_TOUT			(25 * HZ)
#define CONN_STATE_OPEN_BIT		0
#define CONN_STATE_PENDING_BIT		1
#define CONN_REMOTE_TEARDOWN_BIT	2
#define CONN_EOF_BIT			4

#define STATE_IS_OPEN(dev) test_bit(CONN_STATE_OPEN_BIT, \
					(void *) &(dev)->conn_state)
#define STATE_IS_REMOTE_TEARDOWN(dev) test_bit(CONN_REMOTE_TEARDOWN_BIT, \
					(void *) &(dev)->conn_state)
#define STATE_IS_PENDING(dev) test_bit(CONN_STATE_PENDING_BIT, \
					(void *) &(dev)->conn_state)
#define SET_STATE_OPEN(dev) (set_bit(CONN_STATE_OPEN_BIT,	\
			(void *) &(dev)->conn_state), \
			pr_devel("SET_STATE_OPEN:%d\n", dev->conn_state))
#define SET_STATE_CLOSED(dev) (clear_bit(CONN_STATE_OPEN_BIT,	\
			(void *) &(dev)->conn_state), \
			pr_devel("SET_STATE_CLOSED:%d\n", dev->conn_state))
#define SET_PENDING_ON(dev) (set_bit(CONN_STATE_PENDING_BIT,	\
			(void *) &(dev)->conn_state), \
			pr_devel("SET_PENDING_ON:%d\n", dev->conn_state))
#define SET_PENDING_OFF(dev) (clear_bit(CONN_STATE_PENDING_BIT, \
			(void *) &(dev)->conn_state), \
			pr_devel("SET_PENDING_OFF:%d\n", dev->conn_state))
#define SET_REMOTE_TEARDOWN(dev) (set_bit(CONN_REMOTE_TEARDOWN_BIT,	\
			(void *) &(dev)->conn_state), \
			pr_devel("SET_REMOTE_TEARDOWN:%d\n", dev->conn_state))
#define CLEAR_REMOTE_TEARDOWN(dev) (clear_bit(CONN_REMOTE_TEARDOWN_BIT, \
			(void *) &(dev)->conn_state), \
			pr_devel("CLEAR_REMOTE_TEARDOWN:%d\n", dev->conn_state))
#define SET_EOF(dev) (set_bit(CONN_EOF_BIT,	\
			(void *) &(dev)->conn_state), \
			pr_devel("SET_EOF:%d\n", dev->conn_state))
#define CLEAR_EOF(dev) (clear_bit(CONN_EOF_BIT, \
			(void *) &(dev)->conn_state), \
			pr_devel("CLEAR_EOF:%d\n", dev->conn_state))
#define STATE_IS_EOF(dev) test_bit(CONN_EOF_BIT, \
					(void *) &(dev)->conn_state)

#define CHR_READ_FLAG 0x01
#define CHR_WRITE_FLAG 0x02

#ifdef CONFIG_DEBUG_FS
static struct dentry *debugfsdir;
#include <linux/debugfs.h>
#define	dbfs_atomic_inc(a) atomic_inc(a)
#define	dbfs_atomic_add(v, a) atomic_add_return(v, a)
#else
#define	dbfs_atomic_inc(a) 0
#define	dbfs_atomic_add(v, a) 0
#endif

struct ringbuf {
	__le32 *ri;	/* Pointer to read-index in shared memory.*/
	__le32 *wi;	/* Pointer to write-index in shared memory */
	unsigned int size;/* Size of buffer */
	void *data;	/* Buffer data in shared memory */
};

struct xshmchr_char_dev {
	struct xshm_dev *xshm;
	struct kref kref;
	struct ringbuf rx, tx;
	u32 conn_state;
	char name[256];
	struct miscdevice misc;
	int file_mode;

	/* Access to this struct and below layers */
	struct mutex mutex;
	wait_queue_head_t mgmt_wq;
	/* List of misc test devices */
	struct list_head list_field;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_device_dir;
	atomic_t num_open;
	atomic_t num_close;
	atomic_t num_read;
	atomic_t num_read_block;
	atomic_t num_read_bytes;

	atomic_t num_write;
	atomic_t num_write_block;
	atomic_t num_write_bytes;

	atomic_t num_init;
	atomic_t num_init_resp;
	atomic_t num_deinit;
	atomic_t num_deinit_resp;
	atomic_t num_remote_teardown_ind;

#endif
};

static void xshm_release(struct kref *kref)
{
	struct xshmchr_char_dev *dev;
	dev = container_of(kref, struct xshmchr_char_dev, kref);
	xdev_devl(dev, "Freeing device\n");
	kfree(dev);
}

static void xshmchr_get(struct xshmchr_char_dev *dev)
{
	kref_get(&dev->kref);
}

static void xshmchr_put(struct xshmchr_char_dev *dev)
{
	kref_put(&dev->kref, xshm_release);
}

static inline unsigned int ringbuf_empty(struct ringbuf *rb)
{
	return *rb->wi == *rb->ri;
}

static inline unsigned int ringbuf_full(struct ringbuf *rb)
{
	return (le32_to_cpu(*rb->wi) + 1) % rb->size == le32_to_cpu(*rb->ri);
}

static int insert_ringbuf(struct ringbuf *rb, const char __user *from,
		u32 len)
{
	u32 wi = le32_to_cpu(*rb->wi);
	u32 ri = le32_to_cpu(*rb->ri);
	u32 cpylen, cpylen2 = 0, notcpy;

	pr_devel("insert: wi:%d ri:%d len:%d\n", wi, ri, len);
	if (wi >= ri) {
		len = min(len, rb->size - 1 - wi + ri);
		cpylen = min(rb->size, wi + len) - wi;

		/* Write is ahead of read, copy 'cpylen' data from 'wi' */
		notcpy = copy_from_user(rb->data + wi, from, cpylen);
		if (cpylen > 0 && notcpy == cpylen)
			return -EIO;

		if (cpylen < len && notcpy == 0) {
			cpylen2 = min(ri - 1 , len - cpylen);

			/* We have wrapped copy 'cpylen2' from start */
			notcpy = copy_from_user(rb->data, from + cpylen,
					cpylen2);
		}
	} else {
		cpylen = min(ri - 1 - wi , len);

		/* Read is ahead of write, copy from wi to (ri - 1) */
		notcpy = copy_from_user(rb->data + wi, from, cpylen);
		if (cpylen > 0 && notcpy == cpylen)
			return -EIO;

	}
	/* Do write barrier before updating index */
	smp_wmb();
	*rb->wi = cpu_to_le32((wi + cpylen + cpylen2 - notcpy) % rb->size);
	pr_devel("write ringbuf: wi: %d->%d l:%d\n",
			wi, le32_to_cpu(*rb->wi), cpylen + cpylen2);
	return cpylen + cpylen2 - notcpy;
}

static int extract_ringbuf(struct ringbuf *rb, void __user *to, u32 len)
{
	u32 wi = le32_to_cpu(*rb->wi);
	u32 ri = le32_to_cpu(*rb->ri);
	u32 cpylen = 0, cpylen2 = 0, notcpy;

	pr_devel("extract: wi:%d ri:%d len:%d\n", wi, ri, len);
	if (ri <= wi) {
		len = min(wi - ri, len);

		/* Read is ahead of write, copy 'len' data from 'ri' */
		notcpy = copy_to_user(to, rb->data + ri, len);
		if (len > 0 && notcpy == len)
			return -EIO;

		/* Do write barrier before updating index */
		smp_wmb();
		*rb->ri = cpu_to_le32(ri + len - notcpy);
		pr_devel("read ringbuf: ri: %d->%d len:%d\n",
			ri, le32_to_cpu(*rb->ri), len - notcpy);

		return len - notcpy;
	} else {
		/* wr >= ri */
		cpylen = min(rb->size - ri, len);

		/* Write is ahead, copy 'cpylen' data from ri until end */
		notcpy = copy_to_user(to, rb->data + ri, cpylen);
		if (cpylen > 0 && notcpy == cpylen)
			return -EIO;
		if (cpylen < len && notcpy == 0) {
			cpylen2 = min(wi , len - cpylen);
			/* we have wrapped copy from [0 .. cpylen2] */
			notcpy = copy_to_user(to + cpylen, rb->data, cpylen2);
		}
		/* Do write barrier before updating index */
		smp_wmb();

		*rb->ri = cpu_to_le32((ri + cpylen + cpylen2 - notcpy)
						% rb->size);
		pr_devel("read ringbuf: ri: %d->%d cpylen:%d\n",
			ri, le32_to_cpu(*rb->ri), cpylen + cpylen2 - notcpy);

		return cpylen + cpylen2 - notcpy;
	}
}

static void drain_ringbuf(struct xshmchr_char_dev *dev)
{
	/* Empty the ringbuf. */
	*dev->xshm->cfg.rx.read = *dev->xshm->cfg.rx.write;
	*dev->xshm->cfg.tx.write = *dev->xshm->cfg.tx.read;
}

static int open_cb(void *drv)
{
	struct xshmchr_char_dev *dev = drv;

	pr_xchrstate(dev, "enter");
	dbfs_atomic_inc(&dev->num_init_resp);
	/* Signal reader that data is available. */
	WARN_ON(!STATE_IS_OPEN(dev));
	SET_PENDING_OFF(dev);
	wake_up_interruptible_all(&dev->mgmt_wq);
	pr_xchrstate(dev, "exit");
	return 0;
}

static void close_cb(void *drv)
{
	struct xshmchr_char_dev *dev = drv;

	pr_xchrstate(dev, "enter");
	dbfs_atomic_inc(&dev->num_remote_teardown_ind);
	if (STATE_IS_PENDING(dev) && !STATE_IS_OPEN(dev)) {
		/* Normal close sequence */
		SET_PENDING_OFF(dev);
		CLEAR_REMOTE_TEARDOWN(dev);
		SET_EOF(dev);
		drain_ringbuf(dev);
		dev->file_mode = 0;
	} else {
		/* Remote teardown, close should be called from user-space */
		SET_REMOTE_TEARDOWN(dev);
		SET_PENDING_OFF(dev);
	}

	wake_up_interruptible_all(&dev->mgmt_wq);
	pr_xchrstate(dev, "exit");
}

static int ipc_rx_cb(void *drv)
{
	struct xshmchr_char_dev *dev = drv;

	xdev_devl(dev, "Enter\n");

	if (unlikely(*dev->xshm->cfg.rx.state == cpu_to_le32(XSHM_CLOSED)))
		return -ESHUTDOWN;

	/*
	 * Performance could perhaps be improved by having a WAIT
	 * flag, similar to SOCK_ASYNC_WAITDATA, and only do wake up
	 * when it's actually needed.
	 */
	wake_up_interruptible_all(&dev->mgmt_wq);
	return 0;
}

static int ipc_tx_release_cb(void *drv)
{
	struct xshmchr_char_dev *dev = drv;

	xdev_devl(dev, "Enter\n");
	wake_up_interruptible_all(&dev->mgmt_wq);
	return 0;
}

/* Device Read function called from Linux kernel */
static ssize_t xshmchr_chrread(struct file *filp, char __user *buf,
	 size_t count, loff_t *f_pos)
{
	unsigned int len = 0;
	int result;
	struct xshmchr_char_dev *dev = filp->private_data;
	ssize_t ret = -EIO;

	if (dev == NULL) {
		xdev_dbg(dev, "private_data not set!\n");
		return -EBADFD;
	}

	/* I want to be alone on dev (except status and queue) */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		return -ERESTARTSYS;
	}
	xshmchr_get(dev);

	if (!STATE_IS_OPEN(dev)) {
		/* Device is closed or closing. */
		if (!STATE_IS_PENDING(dev)) {
			xdev_dbg(dev, "device is closed (by remote)\n");
			ret = -ECONNRESET;
		} else {
			xdev_dbg(dev, "device is closing...\n");
			ret = -EBADF;
		}
		goto read_error;
	}

	dbfs_atomic_inc(&dev->num_read);

	/* Device is open or opening. */
	if (STATE_IS_PENDING(dev)) {
		xdev_devl(dev, "device is opening...\n");

		dbfs_atomic_inc(&dev->num_read_block);
		if (filp->f_flags & O_NONBLOCK) {
			/* We can't block. */
			xdev_dbg(dev, "exit: state pending and O_NONBLOCK\n");
			ret = -EAGAIN;
			goto read_error;
		}

		/*
		 * To reach here client must do blocking open,
		 * and start read() before open completes. This is
		 * quite quirky, but let's handle it anyway.
		 */
		result =
		    wait_event_interruptible(dev->mgmt_wq,
					!STATE_IS_PENDING(dev) ||
				    STATE_IS_REMOTE_TEARDOWN(dev));

		if (result == -ERESTARTSYS) {
			xdev_dbg(dev, "wait_event_interruptible"
				 " woken by a signal (1)\n");
			ret = -ERESTARTSYS;
			goto read_error;
		}
		if (STATE_IS_REMOTE_TEARDOWN(dev)) {
			xdev_dbg(dev, "received remote_shutdown indication (1)\n");
			ret = -ESHUTDOWN;
			goto read_error;
		}
	}

	/* Block if we don't have any received buffers.
	 * The queue has its own lock.
	 */
	while (ringbuf_empty(&dev->rx)) {

		if (filp->f_flags & O_NONBLOCK) {
			xdev_devl(dev, "exit: O_NONBLOCK\n");
			ret = -EAGAIN;
			goto read_error;
		}

		/* Let writers in. */
		mutex_unlock(&dev->mutex);

		xdev_devl(dev, "%s:wait for data\n", dev->name);
		/* Block reader until data arrives or device is closed. */
		if (wait_event_interruptible(dev->mgmt_wq,
				!ringbuf_empty(&dev->rx)
				|| STATE_IS_REMOTE_TEARDOWN(dev)
				|| !STATE_IS_OPEN(dev)) == -ERESTARTSYS) {
			xdev_devl(dev, "event_interruptible woken by "
				 "a signal, signal_pending(current) = %d\n",
				signal_pending(current));
			return -ERESTARTSYS;
		}

		xdev_devl(dev, "%s:wakeup readq\n", dev->name);

		if (STATE_IS_REMOTE_TEARDOWN(dev) && ringbuf_empty(&dev->rx)) {
			if (!STATE_IS_EOF(dev)) {
				xdev_dbg(dev, "First EOF OK\n");
				SET_EOF(dev);
				ret = 0;
				goto error_nolock;
			}
			xdev_dbg(dev, "2'nd EOF - remote_shutdown\n");
			ret = -ECONNRESET;
			goto error_nolock;
		}

		/* I want to be alone on dev (except status and queue). */
		if (mutex_lock_interruptible(&dev->mutex)) {
			xdev_dbg(dev, "mutex_lock_interruptible"
					" got signalled\n");
			return -ERESTARTSYS;
		}

		if (!STATE_IS_OPEN(dev)) {
			/* Someone closed the link, report error. */
			xdev_dbg(dev, "remote end shutdown!\n");
			ret = -EBADF;
			goto read_error;
		}
	}

	xdev_devl(dev, "%s:copy data\n", dev->name);
	len = extract_ringbuf(&dev->rx, buf, count);
	if (len <= 0) {
		xdev_dbg(dev, "Extracting from ringbuf failed\n");
		ret = -EINVAL;
		goto read_error;
	}

	/* Signal to modem that data is read from ringbuf */

	dev->xshm->ipc_rx_release(dev->xshm, false);

	dbfs_atomic_add(len, &dev->num_read_bytes);
	/* Let the others in. */
	mutex_unlock(&dev->mutex);
	xshmchr_put(dev);
	return len;

read_error:
	mutex_unlock(&dev->mutex);
error_nolock:
	xshmchr_put(dev);
	return ret;
}

/* Device write function called from Linux kernel (misc device) */
static ssize_t xshmchr_chrwrite(struct file *filp, const char __user *buf,
		      size_t count, loff_t *f_pos)
{
	struct xshmchr_char_dev *dev = filp->private_data;
	ssize_t ret = -EIO;
	int result;
	uint len = 0;

	if (dev == NULL) {
		xdev_dbg(dev, "private_data not set!\n");
		ret = -EBADFD;
		goto write_error_no_unlock;
	}

	pr_xchrstate(dev, "Enter");

	/* I want to be alone on dev (except status and queue). */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		ret = -ERESTARTSYS;
		goto write_error_no_unlock;
	}
	xshmchr_get(dev);

	dbfs_atomic_inc(&dev->num_write);
	if (!STATE_IS_OPEN(dev)) {
		/* Device is closed or closing. */
		if (!STATE_IS_PENDING(dev)) {
			xdev_dbg(dev, "device is closed (by remote)\n");
			ret = -EPIPE;
		} else {
			xdev_dbg(dev, "device is closing...\n");
			ret = -EBADF;
		}
		goto write_error;
	}

	/* Device is open or opening. */
	if (STATE_IS_PENDING(dev)) {
		xdev_dbg(dev, "device is opening...\n");

		dbfs_atomic_inc(&dev->num_write_block);
		if (filp->f_flags & O_NONBLOCK) {
			/* We can't block */
			xdev_dbg(dev, "exit: state pending and O_NONBLOCK\n");
			ret = -EAGAIN;
			goto write_error;
		}

		/* Blocking mode; state is pending and we need to wait
		 * for its conclusion. (Shutdown_ind set pending off.)
		 */
		result =
		    wait_event_interruptible(dev->mgmt_wq,
					!STATE_IS_PENDING(dev) ||
					STATE_IS_REMOTE_TEARDOWN(dev));
		if (result == -ERESTARTSYS) {
			xdev_dbg(dev, "wait_event_interruptible"
				 " woken by a signal (1)\n");
			ret = -ERESTARTSYS;
			goto write_error;
		}
	}
	if (STATE_IS_REMOTE_TEARDOWN(dev)) {
		xdev_dbg(dev, "received remote_shutdown indication\n");
		ret = -EPIPE;
		goto write_error;
	}

	while (ringbuf_full(&dev->tx)) {
		/* Flow is off. Check non-block flag. */
		if (filp->f_flags & O_NONBLOCK) {
			xdev_dbg(dev, "exit: O_NONBLOCK and tx flow off");
			ret = -EAGAIN;
			goto write_error;
		}

		/* Let readers in. */
		mutex_unlock(&dev->mutex);

		xdev_devl(dev, "wait for write space\n");
		/* Wait until flow is on or device is closed. */
		if (wait_event_interruptible(dev->mgmt_wq,
					!ringbuf_full(&dev->tx)
					|| !STATE_IS_OPEN(dev)
					|| STATE_IS_REMOTE_TEARDOWN(dev)
					) == -ERESTARTSYS) {
			xdev_dbg(dev, "wait_event_interruptible"
				 " woken by a signal (1)\n");
			ret = -ERESTARTSYS;
			goto write_error_no_unlock;
		}

		/* I want to be alone on dev (except status and queue). */
		if (mutex_lock_interruptible(&dev->mutex)) {
			xdev_dbg(dev, "mutex_lock_interruptible "
					"got signalled\n");
			ret = -ERESTARTSYS;
			goto write_error_no_unlock;
		}

		xdev_devl(dev, "wakeup got write space\n");
		if (!STATE_IS_OPEN(dev)) {
			/* Someone closed the link, report error. */
			xdev_dbg(dev, "remote end shutdown!\n");
			ret = -EPIPE;
			goto write_error;
		}
		if (STATE_IS_REMOTE_TEARDOWN(dev)) {
			xdev_dbg(dev, "received remote_shutdown indication\n");
			ret = -ESHUTDOWN;
			goto write_error;
		}
	}
	len = insert_ringbuf(&dev->tx, buf, count);
	xdev_devl(dev, "inserted %d bytes\n", len);
	if (len <= 0) {
		xdev_dbg(dev, "transmit failed, error = %d\n",
				(int) ret);
		goto write_error;
	}

	dbfs_atomic_add(len, &dev->num_write_bytes);

	/* Signal to modem that data is put in ringbuf */
	dev->xshm->ipc_tx(dev->xshm);

	mutex_unlock(&dev->mutex);
	xshmchr_put(dev);
	return len;

write_error:
	mutex_unlock(&dev->mutex);
write_error_no_unlock:
	xshmchr_put(dev);
	return ret;
}

static unsigned int xshmchr_chrpoll(struct file *filp, poll_table *waittab)
{
	struct xshmchr_char_dev *dev = filp->private_data;
	unsigned int mask = 0;

	if (dev == NULL) {
		xdev_dbg(dev, "private_data not set!\n");
		return -EBADFD;
	}

	/* I want to be alone on dev (except status and queue). */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		mask |= POLLERR;
		goto out;
	}
	xshmchr_get(dev);

	if (STATE_IS_REMOTE_TEARDOWN(dev)) {
		xdev_dbg(dev, "not open\n");
		mask |= POLLRDHUP | POLLHUP;
		goto out;
	}

	xdev_devl(dev, "%s: poll wait\n", dev->name);
	poll_wait(filp, &dev->mgmt_wq, waittab);

	if (STATE_IS_OPEN(dev) && STATE_IS_PENDING(dev))
		goto out;

	if (!ringbuf_empty(&dev->rx))
		mask |= (POLLIN | POLLRDNORM);

	if (!ringbuf_full(&dev->tx))
		mask |= (POLLOUT | POLLWRNORM);

out:
	mutex_unlock(&dev->mutex);
	xdev_devl(dev, "poll return mask=0x%04x\n", mask);
	xshmchr_put(dev);
	return mask;
}

/* Usage:
 * minor >= 0 : find from minor
 * minor < 0 and name == name : find from name
 * minor < 0 and name == NULL : get first
 */

static struct xshmchr_char_dev *find_device(int minor, char *name,
					 int remove_from_list)
{
	struct list_head *list_node;
	struct list_head *n;
	struct xshmchr_char_dev *dev = NULL;
	struct xshmchr_char_dev *tmp;
	spin_lock(&list_lock);
	xdev_devl(dev, "start looping \n");
	list_for_each_safe(list_node, n, &xshmchr_chrdev_list) {
		tmp = list_entry(list_node, struct xshmchr_char_dev,
				list_field);
		if (minor >= 0) {	/* find from minor */
			if (tmp->misc.minor == minor)
				dev = tmp;

		} else if (name) {	/* find from name */
			if (!strncmp(tmp->name, name, sizeof(tmp->name)))
				dev = tmp;
		} else {	/* take first */
			dev = tmp;
		}

		if (dev) {
			xdev_devl(dev, "match %d, %s \n",
				      minor, name);
			if (remove_from_list)
				list_del(list_node);
			break;
		}
	}
	spin_unlock(&list_lock);
	return dev;
}

static int xshmchr_chropen(struct inode *inode, struct file *filp)
{
	struct xshmchr_char_dev *dev = NULL;
	int result = -1;
	int minor = iminor(inode);
	int mode = 0;
	int ret = -EIO;

	dev = find_device(minor, NULL, 0);
	pr_xchrstate(dev, "ENTER");

	if (dev == NULL) {
		xdev_dbg(dev, "Could not find device\n");
		return -EBADF;
	}

	/* I want to be alone on dev (except status and queue). */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		return -ERESTARTSYS;
	}

	xshmchr_get(dev);
	dbfs_atomic_inc(&dev->num_open);
	filp->private_data = dev;

	switch (filp->f_flags & O_ACCMODE) {
	case O_RDONLY:
		mode = CHR_READ_FLAG;
		break;
	case O_WRONLY:
		mode = CHR_WRITE_FLAG;
		break;
	case O_RDWR:
		mode = CHR_READ_FLAG | CHR_WRITE_FLAG;
		break;
	}

	/* If device is not open, make sure device is in fully closed state. */
	if (!STATE_IS_OPEN(dev)) {
		/* Has link close response been received
		 * (if we ever sent it)?
		 */
		if (STATE_IS_PENDING(dev)) {
			/* Still waiting for close response from remote.
			 * If opened non-blocking, report "would block".
			 */
			if (filp->f_flags & O_NONBLOCK) {
				xdev_devl(dev, "%s: exit: "
						"O_NONBLOCK && close pending\n",
						dev->name);
				ret = -EAGAIN;
				goto open_error;
			}

			xdev_devl(dev, "%s:WAIT for close response"
					"from remote\n", dev->name);

			/*
			 * Blocking mode; close is pending and we need to wait
			 * for its conclusion. However modem may be dead,
			 * or resureccted and alive waiting for
			 * an open ack.
			 * It's hard to get this rigth - if state is
			 * pending. We have missed a state update,
			 * let's just wait for ack, and then proceede
			 * with watever state we have.
			 */
			result =
			    wait_event_interruptible_timeout(dev->mgmt_wq,
					    !STATE_IS_PENDING(dev) ||
					    STATE_IS_REMOTE_TEARDOWN(dev),
					    OPEN_TOUT);

			if (result == -ERESTARTSYS) {
				xdev_dbg(dev, "%s:wait_event_interruptible"
					" woken by a signal (1)\n", dev->name);
				ret = -ERESTARTSYS;
				goto open_error;
			}

			if (result == 0) {
				SET_PENDING_OFF(dev);
				pr_xchrstate(dev, "Timeout -pending close;"
						"Clear pending");
			} else
				pr_xchrstate(dev, "wakeup (wait for close)");
		}
	}

	/* Device is now either closed, pending open or open */
	if (STATE_IS_OPEN(dev) && !STATE_IS_PENDING(dev)) {
		/* Open */
		xdev_devl(dev, "%s:Device is already opened (dev=%p) check"
				"access f_flags = 0x%x file_mode = 0x%x\n",
				dev->name, dev, mode, dev->file_mode);

		if (mode & dev->file_mode) {
			xdev_devl(dev, "%s:Access mode already in use 0x%x\n",
					dev->name, mode);
			ret = -EBUSY;
			goto open_error;
		}
	} else {

		/* We are closed or pending open.
		 * If closed:	    send link setup
		 * If pending open: link setup already sent (we could have been
		 *		    interrupted by a signal last time)
		 */
		if (!STATE_IS_OPEN(dev)) {
			/* First opening of file; do connect */

			SET_STATE_OPEN(dev);
			SET_PENDING_ON(dev);
			CLEAR_EOF(dev);
			/* Send "open" by resetting indexes */
			result = dev->xshm->open(dev->xshm);

			if (result < 0) {
				xdev_dbg(dev, "%s:can't open channel\n",
						dev->name);
				ret = -EIO;
				SET_STATE_CLOSED(dev);
				SET_PENDING_OFF(dev);
				goto open_error;
			}
			dbfs_atomic_inc(&dev->num_init);
		}

		/* If opened non-blocking, report "success".
		 */
		if (filp->f_flags & O_NONBLOCK) {
			xdev_devl(dev, "%s: EXIT: O_NONBLOCK success\n",
					dev->name);
			ret = 0;
			goto open_success;
		}

		xdev_devl(dev, "%s:WAIT for connect response\n", dev->name);
		/*
		 * misc_open holds a global mutex anyway so there is no
		 * reason to release our own while waiting
		 */
		result =
		    wait_event_interruptible_timeout(dev->mgmt_wq,
				    !STATE_IS_PENDING(dev) ||
				    STATE_IS_REMOTE_TEARDOWN(dev),
				    OPEN_TOUT);
		if (result == 0) {
			xdev_dbg(dev, "%s:wait_event_interruptible "
					"timed out (1)\n", dev->name);
			ret = -ETIMEDOUT;
			goto open_error;
		}
		if (result == -ERESTARTSYS) {
			xdev_dbg(dev, "%s:wait_event_interruptible"
					" woken by a signal (2)\n", dev->name);
			ret = -ERESTARTSYS;
			goto open_error;
		}
		if (STATE_IS_REMOTE_TEARDOWN(dev)) {
			xdev_dbg(dev, "received remote_shutdown indication\n");
			ret = -ESHUTDOWN;
			goto open_error;
		}

		pr_xchrstate(dev, "wakeup (wait for open)");
		if (!STATE_IS_OPEN(dev)) {
			/* Lower layers said "no". */
			xdev_dbg(dev, "%s:xshmchr_chropen: Closed received\n",
					dev->name);
			ret = -EPIPE;
			goto open_error;
		}

		xdev_devl(dev, "%s: connect received\n", dev->name);
	}
open_success:
	/* Open is OK. */
	dev->file_mode |= mode;

	xdev_devl(dev, "%s: file mode = %x\n",
			dev->name, dev->file_mode);
	pr_xchrstate(dev, "EXIT");

	mutex_unlock(&dev->mutex);
	xshmchr_put(dev);
	return 0;

open_error:
	SET_STATE_CLOSED(dev);
	SET_PENDING_OFF(dev);
	mutex_unlock(&dev->mutex);
	xshmchr_put(dev);
	return ret;
}

static int xshmchr_chrrelease(struct inode *inode, struct file *filp)
{
	struct xshmchr_char_dev *dev = NULL;
	int minor = iminor(inode);
	int mode = 0;


	dev = find_device(minor, NULL, 0);
	if (dev == NULL) {
		xdev_dbg(dev, "Could not find device\n");
		return -EBADF;
	}

	pr_xchrstate(dev, "enter");

	/* I want to be alone on dev (except status queue). */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		return -ERESTARTSYS;
	}

	xshmchr_get(dev);
	dbfs_atomic_inc(&dev->num_close);

	/* Is the device open? */
	if (!STATE_IS_OPEN(dev)) {
		xdev_devl(dev, "Device not open (dev=%p) \n",
			      dev);
		mutex_unlock(&dev->mutex);
		xshmchr_put(dev);
		return 0;
	}

	switch (filp->f_flags & O_ACCMODE) {
	case O_RDONLY:
		mode = CHR_READ_FLAG;
		break;
	case O_WRONLY:
		mode = CHR_WRITE_FLAG;
		break;
	case O_RDWR:
		mode = CHR_READ_FLAG | CHR_WRITE_FLAG;
		break;
	}

	dev->file_mode &= ~mode;
	if (dev->file_mode) {
		xdev_devl(dev, "Device is kept open by someone else, "
			 " don't close. XSHMCHR connection - file_mode = %x\n",
			 dev->file_mode);
		mutex_unlock(&dev->mutex);
		xshmchr_put(dev);
		return 0;
	}

	/* IS_CLOSED have double meaning:
	 * 1) Spontanous Remote Shutdown Request.
	 * 2) Ack on a channel teardown(disconnect)
	 * Must clear bit, in case we previously received
	 * a remote shudown request.
	 */

	SET_STATE_CLOSED(dev);
	SET_PENDING_ON(dev);
	CLEAR_REMOTE_TEARDOWN(dev);
	SET_EOF(dev);

	dev->xshm->close(dev->xshm);

	dbfs_atomic_inc(&dev->num_deinit);

	/* Empty the ringbuf */
	drain_ringbuf(dev);
	dev->file_mode = 0;

	mutex_unlock(&dev->mutex);
	pr_xchrstate(dev, "exit");
	xshmchr_put(dev);
	return 0;
}

static const struct file_operations xshmchr_chrfops = {
	.owner = THIS_MODULE,
	.read = xshmchr_chrread,
	.write = xshmchr_chrwrite,
	.open = xshmchr_chropen,
	.release = xshmchr_chrrelease,
	.poll = xshmchr_chrpoll,
};

static int cfshm_probe(struct platform_device *pdev)

{
	struct xshmchr_char_dev *dev = NULL;
	int result;
	struct xshm_dev *xshm = pdev->dev.platform_data;
	xdev_devl(dev, "cfshm_probe called\n");

	if (xshm == NULL)
		return 0;

	/* Allocate device */
	dev = kmalloc(sizeof(*dev), GFP_KERNEL);

	if (!dev) {
		pr_err("kmalloc failed.\n");
		return -ENOMEM;
	}

	memset(dev, 0, sizeof(*dev));
	kref_init(&dev->kref);

	dev->xshm = xshm;
	mutex_init(&dev->mutex);
	init_waitqueue_head(&dev->mgmt_wq);

	/* Fill in some information concerning the misc device. */
	dev->misc.minor = MISC_DYNAMIC_MINOR;
	if (strlen(xshm->cfg.name) == 0) {
		xdev_dbg(dev, "Platform device does not have a name\n");
		return -EINVAL;
	}
	sprintf(dev->name, "%s", xshm->cfg.name);
	dev->misc.name = dev->name;
	dev->misc.fops = &xshmchr_chrfops;

	dev->tx.ri = xshm->cfg.tx.read;
	dev->tx.wi = xshm->cfg.tx.write;
	dev->tx.data = xshm->cfg.tx.addr;
	dev->tx.size = xshm->cfg.tx.ch_size - 1;

	dev->rx.ri = xshm->cfg.rx.read;
	dev->rx.wi = xshm->cfg.rx.write;
	dev->rx.data = xshm->cfg.rx.addr;
	dev->rx.size = xshm->cfg.rx.ch_size - 1;
	if (dev->rx.size < 2 || dev->tx.size < 2) {
		dev->rx.size = 0;
		dev->tx.size = 0;
		xdev_dbg(dev, "dev:%s error - channel size too small\n",
				dev->name);
		return -EINVAL;
	}
	dev->xshm->ipc_rx_cb = ipc_rx_cb;
	dev->xshm->ipc_tx_release_cb = ipc_tx_release_cb;
	dev->xshm->open_cb = open_cb;
	dev->xshm->close_cb = close_cb;
	dev->xshm->driver_data = dev;

	xdev_devl(dev, "register pdev:%s chr=%s(%s) dev=%p\n", xshm->pdev.name,
			dev->name, xshm->cfg.name, dev);

	/* Register the device. */
	dev->misc.parent = &xshm->pdev.dev;
	result = misc_register(&dev->misc);

	/* Lock in order to try to stop someone from opening the device
	 * too early. The misc device has its own lock. We cannot take our
	 * lock until misc_register() is finished, because in open() the
	 * locks are taken in this order (misc first and then dev).
	 * So anyone managing to open the device between the misc_register
	 * and the mutex_lock will get a "device not found" error. Don't
	 * think it can be avoided.
	 */
	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		return -ERESTARTSYS;
	}

	if (result < 0) {
		pr_warn("XSHMCHR: chnl_chr: error - %d, can't register misc.\n",
			      result);
		mutex_unlock(&dev->mutex);
		goto err_failed;
	}

	xdev_devl(dev, "XSHMCHR: dev: "
			"Registered dev with name=%s minor=%d, dev=%p\n",
			dev->misc.name, dev->misc.minor, dev->misc.this_device);

	SET_STATE_CLOSED(dev);
	SET_PENDING_OFF(dev);
	CLEAR_REMOTE_TEARDOWN(dev);
	CLEAR_EOF(dev);

	/* Add the device. */
	spin_lock(&list_lock);
	list_add(&dev->list_field, &xshmchr_chrdev_list);
	spin_unlock(&list_lock);

#ifdef CONFIG_DEBUG_FS
	if (debugfsdir != NULL) {
		dev->debugfs_device_dir =
		    debugfs_create_dir(dev->misc.name, debugfsdir);
		debugfs_create_u32("conn_state", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir, &dev->conn_state);
		debugfs_create_u32("num_open", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_open);
		debugfs_create_u32("num_close", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_close);
		debugfs_create_u32("num_init", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_init);
		debugfs_create_u32("num_init_resp", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_init_resp);
		debugfs_create_u32("num_deinit", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_deinit);
		debugfs_create_u32("num_deinit_resp", S_IRUSR | S_IWUSR,
				   dev->debugfs_device_dir,
				   (u32 *) &dev->num_deinit_resp);
		debugfs_create_u32("num_remote_teardown_ind",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_remote_teardown_ind);
		debugfs_create_u32("num_read",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_read);
		debugfs_create_u32("num_read_block",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_read_block);
		debugfs_create_u32("num_read_bytes",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_read_bytes);
		debugfs_create_u32("num_write",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_write);
		debugfs_create_u32("num_write_block",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_write_block);
		debugfs_create_u32("num_write_bytes",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				   (u32 *) &dev->num_write_bytes);

		debugfs_create_u32("rx_write_index",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.rx.write);
		debugfs_create_u32("rx_read_index",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.rx.read);
		debugfs_create_u32("rx_state",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.rx.state);
		debugfs_create_u32("tx_write_index",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.tx.write);
		debugfs_create_u32("tx_read_index",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.tx.read);
		debugfs_create_u32("tx_state",
				   S_IRUSR | S_IWUSR, dev->debugfs_device_dir,
				(u32 *) dev->xshm->cfg.tx.state);

	}
#endif
	mutex_unlock(&dev->mutex);
	return 0;
err_failed:
	xshmchr_put(dev);
	return result;
}

static int chrdev_remove(struct xshmchr_char_dev *dev)
{
	if (!dev)
		return -EBADF;

	if (STATE_IS_OPEN(dev)) {
		xdev_dbg(dev, "Device is opened "
			 "(dev=%p) file_mode = 0x%x\n",
			 dev, dev->file_mode);
		SET_STATE_CLOSED(dev);
		SET_PENDING_OFF(dev);
		wake_up_interruptible_all(&dev->mgmt_wq);
	}

	if (mutex_lock_interruptible(&dev->mutex)) {
		xdev_dbg(dev, "mutex_lock_interruptible got signalled\n");
		xshmchr_put(dev);
		return -ERESTARTSYS;
	}

	drain_ringbuf(dev);

	misc_deregister(&dev->misc);

	/* Remove from list. */
	list_del(&dev->list_field);

#ifdef CONFIG_DEBUG_FS
	if (dev->debugfs_device_dir != NULL)
		debugfs_remove_recursive(dev->debugfs_device_dir);
#endif

	mutex_unlock(&dev->mutex);
	xshmchr_put(dev);
	return 0;
}

static int cfshm_remove(struct platform_device *pdev)
{
	int err;
	struct xshm_dev *xshm = pdev->dev.platform_data;

	if (xshm == NULL)
		return 0;
	pr_devel("unregister pdev:%s chr=%s pdev=%p\n", xshm->pdev.name,
			xshm->cfg.name, pdev);

	err = chrdev_remove(xshm->driver_data);
	if (err)
		pr_debug("removing char-dev:%s failed.%d\n",
					xshm->cfg.name, err);

	xshm->ipc_rx_cb = NULL;
	xshm->ipc_tx_release_cb = NULL;
	xshm->open_cb = NULL;
	xshm->close_cb = NULL;
	xshm->driver_data = NULL;
	return err;
}

static struct platform_driver cfshm_plat_drv = {
	.probe = cfshm_probe,
	.remove = cfshm_remove,
	.driver = {
		   .name = "xshms",
		   .owner = THIS_MODULE,
		   },
};


static int __init xshmchr_chrinit_module(void)
{
	int err;
	pr_devel("xshm init\n");
	spin_lock_init(&list_lock);

	/* Register platform driver. */
	err = platform_driver_register(&cfshm_plat_drv);
	if (err) {
		printk(KERN_ERR "Could not register platform SHM driver: %d.\n",
			err);
		goto err_dev_register;
	}

#ifdef CONFIG_DEBUG_FS
	debugfsdir = debugfs_create_dir("xshm_chr", NULL);
#endif

 err_dev_register:
	return err;

}

static void __exit xshmchr_chrexit_module(void)
{
	int result;
	struct xshmchr_char_dev *dev = NULL;

	/* Unregister platform driver. */
	platform_driver_unregister(&cfshm_plat_drv);

	do {
		/* Remove any device (the first in the list). */
		dev = find_device(-1, NULL, 0);
		result = chrdev_remove(dev);
	} while (result == 0);

#ifdef CONFIG_DEBUG_FS
	if (debugfsdir != NULL)
		debugfs_remove_recursive(debugfsdir);
#endif

}

module_init(xshmchr_chrinit_module);
module_exit(xshmchr_chrexit_module);
