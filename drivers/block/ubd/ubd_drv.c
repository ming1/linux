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

#include "ubd_cmd.h"

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

	/*
	 * kmalloc() is used for allocate cmd buffer, and we need to
	 * make it aligned with PAGE_SIZE, then map it to ubdserv
	 * daemon.
	 */
	void			*cmd_buf_alloc_addr;

	struct blk_mq_tag_set	tag_set;

	struct cdev		cdev;
	struct device		cdev_dev;

	struct ubdsrv_ctrl_dev_info	dev_info;

	atomic_t		ch_open_cnt;
};

static dev_t ubd_chr_devt;
static struct class *ubd_chr_class;

static DEFINE_IDR(ubd_index_idr);
static DEFINE_MUTEX(ubd_ctl_mutex);

static struct miscdevice ubd_misc;

/* kmalloc buffer is often not aligned with PAGE_SIZE */
static inline char *ubd_get_cmd_buf(struct ubd_device *ub)
{
	return ub->cmd_buf_alloc_addr;
}

static int ubd_cmd_buf_size(struct ubd_device *ub)
{
	int len = ub->dev_info.nr_hw_queues * ub->dev_info.queue_depth;

	return round_up(len * sizeof(struct ubdsrv_io_desc), PAGE_SIZE);
}

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
	struct ubd_device *ub = container_of(inode->i_cdev,
			struct ubd_device, cdev);

	if (atomic_cmpxchg(&ub->ch_open_cnt, 0, 1) == 0) {
		filp->private_data = ub;
		return 0;
	}

	return -EBUSY;
}

static int ubd_ch_release(struct inode *inode, struct file *filp)
{
	struct ubd_device *ub = filp->private_data;

	while (atomic_cmpxchg(&ub->ch_open_cnt, 1, 0) != 1) {
		cpu_relax();
	}
	filp->private_data = NULL;
	return 0;
}

static int ubd_ch_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct ubd_device *ub = filp->private_data;
	size_t sz = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (vma->vm_pgoff != UBDSRV_CMD_BUF_OFFSET)
		return -EINVAL;

	if (sz != ubd_cmd_buf_size(ub))
		return -EINVAL;

	pfn = virt_to_phys(ubd_get_cmd_buf(ub)) >> PAGE_SHIFT;
	return remap_pfn_range(vma, vma->vm_start, pfn, sz, vma->vm_page_prot);
}

static int ubd_ch_async_cmd(struct io_uring_cmd *cmd)
{
	struct ubd_device *ub = cmd->file->private_data;

	return 0;
}

static const struct file_operations ubd_ch_fops = {
	.owner = THIS_MODULE,
	.open = ubd_ch_open,
	.release = ubd_ch_release,
	.llseek = no_llseek,
	.async_cmd = ubd_ch_async_cmd,
	.mmap = ubd_ch_mmap,
};

static int ubd_alloc_cmd_buf(struct ubd_device *ub)
{
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO;
	int size = ubd_cmd_buf_size(ub);
	void *ptr = (void *) __get_free_pages(gfp_flags, get_order(size));

	if (!ptr)
		return -ENOMEM;

	/*
	 * check in ubdsrv side, so we can make sure that cmd buf is setup
	 * successfully
	 */
	strcpy(ptr, "UBD");
	ub->cmd_buf_alloc_addr = ptr;
	return 0;
}

static void ubd_free_cmd_buf(struct ubd_device *ub)
{
	int size = ubd_cmd_buf_size(ub);

	free_pages((unsigned long)ub->cmd_buf_alloc_addr, get_order(size));
}

static void ubd_cdev_rel(struct device *dev)
{
	struct ubd_device *ub = container_of(dev, struct ubd_device, cdev_dev);

	blk_mq_free_tag_set(&ub->tag_set);
	mutex_lock(&ubd_ctl_mutex);
	idr_remove(&ubd_index_idr, ub->ub_number);
	mutex_unlock(&ubd_ctl_mutex);

	ubd_free_cmd_buf(ub);

	kfree(ub);
}

static int ubd_add_chdev(struct ubd_device *ub)
{
	struct device *dev = &ub->cdev_dev;
	int minor = ub->ub_number;
	int ret;

	dev->parent = ubd_misc.this_device;
	ret = dev_set_name(dev, "ubdc%d", minor);
	if (ret)
		return ret;

	dev->devt = MKDEV(MAJOR(ubd_chr_devt), minor);
	dev->class = ubd_chr_class;
	dev->release = ubd_cdev_rel;
	device_initialize(dev);

	cdev_init(&ub->cdev, &ubd_ch_fops);
	ret = cdev_device_add(&ub->cdev, dev);
	if (ret) {
		put_device(dev);
		return -1;
	}
	return 0;
}

/* add disk & cdev */
static int ubd_add_dev(struct ubd_device *ub)
{
	struct gendisk *disk;
	int err = -ENOMEM;
	int bsize;

	ub->tag_set.ops = &ubd_mq_ops;
	ub->tag_set.nr_hw_queues = ub->dev_info.nr_hw_queues;
	ub->tag_set.queue_depth = ub->dev_info.queue_depth;
	ub->tag_set.numa_node = NUMA_NO_NODE;
	ub->tag_set.cmd_size = sizeof(struct ubd_cmd);
	ub->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
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

	bsize = ub->dev_info.block_size;
	blk_queue_logical_block_size(ub->ub_queue, bsize);
	blk_queue_physical_block_size(ub->ub_queue, bsize);
	blk_queue_io_min(ub->ub_queue, bsize);

	blk_queue_max_hw_sectors(ub->ub_queue, ub->dev_info.rq_max_blocks);
	set_capacity(ub->ub_disk, ub->dev_info.dev_blocks);

	ub->ub_queue->limits.discard_granularity = 0;


	disk->fops		= &ub_fops;
	disk->private_data	= ub;
	disk->queue		= ub->ub_queue;
	sprintf(disk->disk_name, "ubdb%d", ub->ub_number);

	if (ubd_alloc_cmd_buf(ub))
		goto out_cleanup_disk;

	/* add char dev so that ubdsrv daemon can be setup */
	err = ubd_add_chdev(ub);
	if (err)
		goto out_free_cmd_buf;

	/* don't expose disk now until we got start command from cdev */

	return 0;

out_free_cmd_buf:
	ubd_free_cmd_buf(ub);
out_cleanup_disk:
	blk_cleanup_disk(ub->ub_disk);
out_cleanup_tags:
	blk_mq_free_tag_set(&ub->tag_set);
out_free_cdev:
	cdev_del(&ub->cdev);
	return err;
}

static void ubd_remove(struct ubd_device *ub)
{
	/* we may not start disk yet*/
	if (disk_live(ub->ub_disk))
		del_gendisk(ub->ub_disk);
	blk_cleanup_disk(ub->ub_disk);
	cdev_device_del(&ub->cdev, &ub->cdev_dev);
	put_device(&ub->cdev_dev);
}

static struct ubd_device *ubd_find_device(int idx)
{
	struct ubd_device *ub = NULL;

	if (idx < 0) {
		pr_warn_once("deleting an unspecified ubd device is not supported.\n");
		return NULL;
	}

	if (mutex_lock_killable(&ubd_ctl_mutex))
		return NULL;
	ub = idr_find(&ubd_index_idr, idx);
	mutex_unlock(&ubd_ctl_mutex);

	return ub;
}

static int __ubd_alloc_dev_number(struct ubd_device *ub, int idx)
{
	int i = idx;
	int err;

	/* allocate id, if @id >= 0, we're requesting that specific id */
	if (i >= 0) {
		err = idr_alloc(&ubd_index_idr, ub, i, i + 1, GFP_KERNEL);
		if (err == -ENOSPC)
			err = -EEXIST;
	} else {
		err = idr_alloc(&ubd_index_idr, ub, 0, 0, GFP_KERNEL);
	}

	if (err >= 0)
		ub->ub_number = err;

	return err;
}

static struct ubd_device *ubd_find_or_create_dev(int idx)
{
	struct ubd_device *ub = NULL;
	struct ubd_device *ub_new;
	int ret;

	ub_new = kzalloc(sizeof(*ub), GFP_KERNEL);

	ret = mutex_lock_killable(&ubd_ctl_mutex);
	if (ret) {
		kfree(ub_new);
		return NULL;
	}

	if (idx >= 0)
		ub = idr_find(&ubd_index_idr, idx);

	if (ub) {
		kfree(ub_new);
		goto out;
	}

	if (!ub_new)
		goto out;

	ub = ub_new;
	ret = __ubd_alloc_dev_number(ub, idx);
	if (ret < 0) {
		kfree(ub_new);
		ub = NULL;
	}
 out:
	mutex_unlock(&ubd_ctl_mutex);
	return ub;
}

static void ubd_dump(struct io_uring_cmd *cmd)
{
	struct ubdsrv_ctrl_dev_info *info = (struct ubdsrv_ctrl_dev_info *)cmd->cmd;

	printk("%s: cmd_op %x cmd_len %d, dev id %d\n",
			__func__, cmd->cmd_op, cmd->cmd_len, info->dev_id);

	printk("\t nr_hw_queues %d queue_depth %d block size %d dev_capacity %lld\n",
			info->nr_hw_queues, info->queue_depth,
			info->block_size, info->dev_blocks);
}

static bool ubd_ctrl_cmd_validate(struct io_uring_cmd *cmd)
{
	/* Fix me: validate all ctrl commands */
	return  true;
}

static int ubd_ctrl_async_cmd(struct io_uring_cmd *cmd)
{
	struct ubdsrv_ctrl_dev_info *info = (struct ubdsrv_ctrl_dev_info *)cmd->cmd;
	unsigned ret = UBD_CTRL_CMD_RES_FAILED;
	u32 cmd_op = cmd->cmd_op;
	struct ubd_device *ub;

	ubd_dump(cmd);

	if (!ubd_ctrl_cmd_validate(cmd))
		goto out;

	switch (cmd_op) {
	case UBD_CMD_START_DEV:
		break;
	case UBD_CMD_STOP_DEV:
		break;
	case UBD_CMD_GET_DEV_INFO:
		ub = ubd_find_device(info->dev_id);
		if (ub) {
			if (info->len < sizeof(*info))
				goto out;

			if (!copy_to_user((void __user *)info->addr,
						(void *)&ub->dev_info,
						sizeof(*info)))
				ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	case UBD_CMD_ADD_DEV:
		ub = ubd_find_or_create_dev(info->dev_id);
		if (ub) {
			memcpy(&ub->dev_info, info, sizeof(*info));

			/* update device id */
			ub->dev_info.dev_id = ub->ub_number;

			if (ubd_add_dev(ub))
				ubd_remove(ub);
			else
				ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	case UBD_CMD_DEL_DEV:
		ub = ubd_find_device(info->dev_id);
		if (ub) {
			ubd_remove(ub);
			ret = UBD_CTRL_CMD_RES_OK;
		}
		break;
	default:
		break;
	};
 out:
	io_uring_cmd_done(cmd, ret);
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

	ret = alloc_chrdev_region(&ubd_chr_devt, 0, UBD_MINORS, "ubd-char");
	if (ret)
		goto unregister_mis;

	ubd_chr_class = class_create(THIS_MODULE, "ubd-char");
	if (IS_ERR(ubd_chr_class)) {
		ret = PTR_ERR(ubd_chr_class);
		goto free_chrdev_region;
	}
	return 0;

free_chrdev_region:
	unregister_chrdev_region(ubd_chr_devt, UBD_MINORS);
unregister_mis:
	misc_deregister(&ubd_misc);
	return ret;
}

static void __exit ubd_exit(void)
{
	struct ubd_device *ub;
	int id;

	class_destroy(ubd_chr_class);

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
