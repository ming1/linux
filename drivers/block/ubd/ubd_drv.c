// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Userspace block device - block device which IO is implemented from userspace
 *
 * Take full use of io_uring passthrough command for communicating with
 * userspace for handling basic IO request.
 *
 * Copyright 2022 Ming Lei <ming.lei@redhat.com>
 *
 * (part of code stolen from loop.c)
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/writeback.h>
#include <linux/completion.h>
#include <linux/highmem.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/miscdevice.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/ioprio.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/io_uring.h>
#include <linux/blk-mq.h>

#define UBD_MINORS		(1U << MINORBITS)

#define UBD_QUEUE_DEPTH		128
#define UBD_MAX_SECTORS		(128 * 1024 / 512)

struct ubd_cmd {
	unsigned char data[16];
};

struct ubd_device {
	struct gendisk		*ub_disk;
	struct request_queue	*ub_queue;
	int			ub_number;
	struct blk_mq_tag_set	tag_set;

	struct cdev		cdev;
};

static dev_t ubd_chr_devt;
static DEFINE_IDR(ubd_index_idr);
static DEFINE_MUTEX(ubd_ctl_mutex);

static int ubd_open(struct block_device *bdev, fmode_t mode)
{
	return 0;
}

static void ubd_release(struct gendisk *disk, fmode_t mode)
{
}

static const struct block_device_operations ub_fops = {
	.owner =	THIS_MODULE,
	.open =		ubd_open,
	.release =	ubd_release,
};

static blk_status_t ubd_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	return BLK_STS_OK;
}

static void ubd_complete_rq(struct request *rq)
{
}

static const struct blk_mq_ops ubd_mq_ops = {
	.queue_rq       = ubd_queue_rq,
	.complete	= ubd_complete_rq,
};

static int ubd_ch_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int ubd_ch_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static int ubd_ch_async_cmd(struct io_uring_cmd *ucmd)
{
	return 0;
}

static const struct file_operations ubd_ch_fops = {
        .owner = THIS_MODULE,
        .open = ubd_ch_open,
        .release = ubd_ch_release,
        .llseek = no_llseek,
	.async_cmd = ubd_ch_async_cmd,
};

static int ubd_add_chdev(struct ubd_device *ub)
{
	cdev_init(&ub->cdev, &ubd_ch_fops);

	return cdev_add(&ub->cdev, MKDEV(ubd_chr_devt, ub->ub_number), 1);
}

static int ubd_add(int i)
{
	struct ubd_device *ub;
	struct gendisk *disk;
	int err;

	err = -ENOMEM;
	ub = kzalloc(sizeof(*ub), GFP_KERNEL);
	if (!ub)
		goto out;

	err = mutex_lock_killable(&ubd_ctl_mutex);
	if (err)
		goto out_free_dev;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&ubd_index_idr, ub, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&ubd_index_idr, ub, 0, 0, GFP_KERNEL);
	}
	mutex_unlock(&ubd_ctl_mutex);
	if (err < 0)
		goto out_free_dev;

	i = err;
	ub->ub_number		= i;

	if (ubd_add_chdev(ub))
		goto out_free_idr;

	ub->tag_set.ops = &ubd_mq_ops;
	ub->tag_set.nr_hw_queues = 1;
	ub->tag_set.queue_depth = 128;
	ub->tag_set.numa_node = NUMA_NO_NODE;
	ub->tag_set.cmd_size = sizeof(struct ubd_cmd);
	ub->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_STACKING |
		BLK_MQ_F_NO_SCHED_BY_DEFAULT;
	ub->tag_set.driver_data = ub;

	err = blk_mq_alloc_tag_set(&ub->tag_set);
	if (err)
		goto out_free_cdev;

	disk = ub->ub_disk = blk_mq_alloc_disk(&ub->tag_set, ub);
	if (IS_ERR(disk)) {
		err = PTR_ERR(disk);
		goto out_cleanup_tags;
	}
	ub->ub_queue = ub->ub_disk->queue;

	blk_queue_max_hw_sectors(ub->ub_queue, UBD_MAX_SECTORS);

	disk->fops		= &ub_fops;
	disk->private_data	= ub;
	disk->queue		= ub->ub_queue;
	sprintf(disk->disk_name, "ubdb%d", i);
	/* Make this loop device reachable from pathname. */
	err = add_disk(disk);
	if (err)
		goto out_cleanup_disk;

	return i;

out_cleanup_disk:
	blk_cleanup_disk(disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&ub->tag_set);
out_free_cdev:
	cdev_del(&ub->cdev);
out_free_idr:
	mutex_lock(&ubd_ctl_mutex);
	idr_remove(&ubd_index_idr, i);
	mutex_unlock(&ubd_ctl_mutex);
out_free_dev:
	kfree(ub);
out:
	return err;
}

static void ubd_remove(struct ubd_device *ub)
{
	/* Make this loop device unreachable from pathname. */
	del_gendisk(ub->ub_disk);
	blk_cleanup_disk(ub->ub_disk);
	cdev_del(&ub->cdev);
	blk_mq_free_tag_set(&ub->tag_set);
	mutex_lock(&ubd_ctl_mutex);
	idr_remove(&ubd_index_idr, ub->ub_number);
	mutex_unlock(&ubd_ctl_mutex);
	kfree(ub);
}

static int ubd_control_remove(int idx)
{
	struct ubd_device *ub;
	int ret;

	if (idx < 0) {
		pr_warn_once("deleting an unspecified ubd device is not supported.\n");
		return -EINVAL;
	}

	/* Hide this loop device for serialization. */
	ret = mutex_lock_killable(&ubd_ctl_mutex);
	if (ret)
		return ret;
	ub = idr_find(&ubd_index_idr, idx);
	if (!ub)
		ret = -ENODEV;
	mutex_unlock(&ubd_ctl_mutex);
	if (ret)
		return ret;

	ubd_remove(ub);
	return 0;
}

static int ubd_ctrl_async_cmd(struct io_uring_cmd *cmd)
{
	io_uring_cmd_done(cmd, 0x05);

	return -EIOCBQUEUED;
}

static const struct file_operations ubd_ctl_fops = {
	.open		= nonseekable_open,
	.async_cmd      = ubd_ctrl_async_cmd,
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

static struct miscdevice ubd_misc = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "ubd-control",
	.fops		= &ubd_ctl_fops,
};

static int __init ubd_init(void)
{
	int ret;

	ret = misc_register(&ubd_misc);
	if (ret)
		return ret;

	ret = alloc_chrdev_region(&ubd_chr_devt, 0, UBD_MINORS, "ubdc");
	if (ret)
		return ret;
	return ret;
}

static void __exit ubd_exit(void)
{
	struct ubd_device *ub;
	int id;

	misc_deregister(&ubd_misc);

	idr_for_each_entry(&ubd_index_idr, ub, id)
		ubd_remove(ub);

	idr_destroy(&ubd_index_idr);
	unregister_chrdev_region(ubd_chr_devt, UBD_MINORS);
}

module_init(ubd_init);
module_exit(ubd_exit);

MODULE_AUTHOR("Ming Lei <ming.lei@redhat.com>");
MODULE_LICENSE("GPL");
