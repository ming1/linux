/*
 * CUSE: Character device in Userspace
 *
 * Copyright (C) 2008-2009  SUSE Linux Products GmbH
 * Copyright (C) 2008-2009  Tejun Heo <tj@kernel.org>
 *
 * This file is released under the GPLv2.
 *
 * CUSE enables character devices to be implemented from userland much
 * like FUSE allows filesystems.  On initialization /dev/cuse is
 * created.  By opening the file and replying to the CUSE_INIT request
 * userland CUSE server can create a character device.  After that the
 * operation is very similar to FUSE.
 *
 * A CUSE instance involves the following objects.
 *
 * cuse_conn	: contains fuse_conn and serves as bonding structure
 * channel	: file handle connected to the userland CUSE server
 * cdev		: the implemented character device
 * dev		: generic device for cdev
 *
 * Note that 'channel' is what 'dev' is in FUSE.  As CUSE deals with
 * devices, it's called 'channel' to reduce confusion.
 *
 * channel determines when the character device dies.  When channel is
 * closed, everything begins to destruct.  The cuse_conn is taken off
 * the lookup table preventing further access from cdev, cdev and
 * generic device are removed and the base reference of cuse_conn is
 * put.
 *
 * On each open, the matching cuse_conn is looked up and if found an
 * additional reference is taken which is released when the file is
 * closed.
 */

#include <linux/fuse.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/pagemap.h>

#include "fuse_i.h"

#define CUSE_CONNTBL_LEN	64

struct cuse_conn {
	struct list_head	list;	/* linked on cuse_conntbl */
	struct fuse_conn	fc;	/* fuse connection */
	struct cdev		*cdev;	/* associated character device */
	struct device		*dev;	/* device representing @cdev */

	/* init parameters, set once during initialization */
	bool			unrestricted_ioctl;
};

static DEFINE_SPINLOCK(cuse_lock);		/* protects cuse_conntbl */
static struct list_head cuse_conntbl[CUSE_CONNTBL_LEN];
static struct class *cuse_class;

static struct cuse_conn *fc_to_cc(struct fuse_conn *fc)
{
	return container_of(fc, struct cuse_conn, fc);
}

static struct list_head *cuse_conntbl_head(dev_t devt)
{
	return &cuse_conntbl[(MAJOR(devt) + MINOR(devt)) % CUSE_CONNTBL_LEN];
}


/**************************************************************************
 * CUSE frontend operations
 *
 * These are file operations for the character device.
 *
 * On open, CUSE opens a file from the FUSE mnt and stores it to
 * private_data of the open file.  All other ops call FUSE ops on the
 * FUSE file.
 */

static ssize_t cuse_read(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	loff_t pos = 0;

	return fuse_direct_io(file, buf, count, &pos, 0);
}

static ssize_t cuse_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	loff_t pos = 0;
	/*
	 * No locking or generic_write_checks(), the server is
	 * responsible for locking and sanity checks.
	 */
	return fuse_direct_io(file, buf, count, &pos, 1);
}

static int cuse_open(struct inode *inode, struct file *file)
{
	dev_t devt = inode->i_cdev->dev;
	struct cuse_conn *cc = NULL, *pos;
	int rc;

	/* look up and get the connection */
	spin_lock(&cuse_lock);
	list_for_each_entry(pos, cuse_conntbl_head(devt), list)
		if (pos->dev->devt == devt) {
			fuse_conn_get(&pos->fc);
			cc = pos;
			break;
		}
	spin_unlock(&cuse_lock);

	/* dead? */
	if (!cc)
		return -ENODEV;

	/*
	 * Generic permission check is already done against the chrdev
	 * file, proceed to open.
	 */
	rc = fuse_do_open(&cc->fc, 0, file, 0);
	if (rc)
		fuse_conn_put(&cc->fc);
	return rc;
}

static int cuse_release(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;

	fuse_sync_release(ff, file->f_flags);
	fuse_conn_put(fc);

	return 0;
}

static long cuse_file_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct fuse_file *ff = file->private_data;
	struct cuse_conn *cc = fc_to_cc(ff->fc);
	unsigned int flags = 0;

	if (cc->unrestricted_ioctl)
		flags |= FUSE_IOCTL_UNRESTRICTED;

	return fuse_do_ioctl(file, cmd, arg, flags);
}

static long cuse_file_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct fuse_file *ff = file->private_data;
	struct cuse_conn *cc = fc_to_cc(ff->fc);
	unsigned int flags = FUSE_IOCTL_COMPAT;

	if (cc->unrestricted_ioctl)
		flags |= FUSE_IOCTL_UNRESTRICTED;

	return fuse_do_ioctl(file, cmd, arg, flags);
}

struct fuse_dmmap_region {
	u64 mapid;
	u64 size;
	pgoff_t nr_pages;
	struct page **pages;
	struct list_head list;
	atomic_t ref;
};

/*
 * fuse_dmmap_vm represents the result of a single mmap() call, which
 * can be shared by multiple client vmas created by forking.
 */
struct fuse_dmmap_vm {
	atomic_t open_count;
	struct fuse_dmmap_region *region;
};

static void fuse_dmmap_region_put(struct fuse_conn *fc,
				  struct fuse_dmmap_region *fdr)
{
	if (atomic_dec_and_lock(&fdr->ref, &fc->lock)) {
		pgoff_t idx;

		list_del(&fdr->list);
		spin_unlock(&fc->lock);

		for (idx = 0; idx < fdr->nr_pages; idx++)
			if (fdr->pages[idx])
				put_page(fdr->pages[idx]);

		kfree(fdr->pages);
		kfree(fdr);
	}
}

static void fuse_dmmap_vm_open(struct vm_area_struct *vma)
{
	struct fuse_dmmap_vm *fdvm = vma->vm_private_data;

	/* vma copied */
	atomic_inc(&fdvm->open_count);
}

static void fuse_dmmap_vm_close(struct vm_area_struct *vma)
{
	struct fuse_dmmap_vm *fdvm = vma->vm_private_data;
	struct fuse_file *ff = vma->vm_file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_req *req;
	struct fuse_munmap_in *inarg;

	if (!atomic_dec_and_test(&fdvm->open_count))
		return;
	/*
	 * Notify server that the mmap region has been unmapped.
	 * Failing this might lead to resource leak in server, don't
	 * fail.
	 */
	req = fuse_get_req_nofail(fc, vma->vm_file);
	inarg = &req->misc.munmap_in;

	inarg->fh = ff->fh;
	inarg->mapid = fdvm->region->mapid;
	inarg->size = fdvm->region->size;

	req->in.h.opcode = FUSE_MUNMAP;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;

	fuse_request_send(fc, req);
	fuse_dmmap_region_put(fc, fdvm->region);
	kfree(fdvm);
}

static struct page *fuse_dmmap_find_or_create_page(struct fuse_conn *fc,
					   struct fuse_dmmap_region *fdr,
					   pgoff_t index)
{
	struct page *new_page = NULL;
	struct page *page;

	BUG_ON(index >= fdr->nr_pages);

	spin_lock(&fc->lock);
	page = fdr->pages[index];
	if (!page) {
		spin_unlock(&fc->lock);
		/* need to allocate and install a new page */
		new_page = alloc_page(GFP_HIGHUSER | __GFP_ZERO);
		if (!new_page)
			return NULL;

		/* try to install, check whether someone else already did it */
		spin_lock(&fc->lock);
		page = fdr->pages[index];
		if (!page) {
			page = fdr->pages[index] = new_page;
			new_page = NULL;
		}
	}
	get_page(page);
	spin_unlock(&fc->lock);

	if (new_page)
		put_page(new_page);

	return page;
}

static int fuse_dmmap_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct fuse_dmmap_vm *fdvm = vma->vm_private_data;
	struct fuse_dmmap_region *fdr = fdvm->region;
	struct fuse_file *ff = vma->vm_file->private_data;
	struct fuse_conn *fc = ff->fc;

	if (vmf->pgoff >= fdr->nr_pages)
		return VM_FAULT_SIGBUS;

	vmf->page = fuse_dmmap_find_or_create_page(fc, fdr, vmf->pgoff);
	if (!vmf->page)
		return VM_FAULT_OOM;

	return 0;
}

static const struct vm_operations_struct fuse_dmmap_vm_ops = {
	.open		= fuse_dmmap_vm_open,
	.close		= fuse_dmmap_vm_close,
	.fault		= fuse_dmmap_vm_fault,
};

static struct fuse_dmmap_region *fuse_dmmap_find_locked(struct fuse_conn *fc,
							u64 mapid)
{
	struct fuse_dmmap_region *curr;
	struct fuse_dmmap_region *fdr = NULL;

	list_for_each_entry(curr, &fc->dmmap_list, list) {
		if (curr->mapid == mapid) {
			fdr = curr;
			atomic_inc(&fdr->ref);
			break;
		}
	}

	return fdr;
}

static struct fuse_dmmap_region *fuse_dmmap_find(struct fuse_conn *fc,
						 u64 mapid)
{
	struct fuse_dmmap_region *fdr;

	spin_lock(&fc->lock);
	fdr = fuse_dmmap_find_locked(fc, mapid);
	spin_unlock(&fc->lock);

	return fdr;
}

static struct fuse_dmmap_region *fuse_dmmap_get(struct fuse_conn *fc,
						u64 mapid, u64 size)
{
	struct fuse_dmmap_region *fdr;
	pgoff_t nr_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if ((loff_t) (nr_pages << PAGE_SHIFT) < size)
		return ERR_PTR(-EIO);

	fdr = fuse_dmmap_find(fc, mapid);
	if (fdr) {
		if (fdr->size != size) {
			fuse_dmmap_region_put(fc, fdr);
			return ERR_PTR(-EIO);
		}
	} else {
		struct fuse_dmmap_region *tmp;

		fdr = kzalloc(sizeof(struct fuse_dmmap_region), GFP_KERNEL);
		if (!fdr)
			return ERR_PTR(-ENOMEM);

		atomic_set(&fdr->ref, 1);
		fdr->mapid = mapid;
		fdr->size = size;
		fdr->nr_pages = nr_pages;

		fdr->pages = kzalloc(sizeof(struct page *) * nr_pages,
				     GFP_KERNEL);
		if (!fdr->pages) {
			kfree(fdr);
			return ERR_PTR(-ENOMEM);
		}

		spin_lock(&fc->lock);
		tmp = fuse_dmmap_find_locked(fc, mapid);
		if (tmp) {
			kfree(fdr->pages);
			kfree(fdr);
			fdr = tmp;
		} else {
			list_add(&fdr->list, &fc->dmmap_list);
		}
		spin_unlock(&fc->lock);
	}

	return fdr;
}

static int cuse_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_dmmap_vm *fdvm;
	struct fuse_dmmap_region *fdr;
	struct fuse_req *req = NULL;
	struct fuse_mmap_in inarg;
	struct fuse_mmap_out outarg;
	int err;

	if (fc->no_dmmap)
		return -ENOSYS;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	/* ask server whether this mmap is okay and what the offset should be */
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.addr = vma->vm_start;
	inarg.len = vma->vm_end - vma->vm_start;
	inarg.prot = ((vma->vm_flags & VM_READ) ? PROT_READ : 0) |
		     ((vma->vm_flags & VM_WRITE) ? PROT_WRITE : 0) |
		     ((vma->vm_flags & VM_EXEC) ? PROT_EXEC : 0);
	inarg.flags = ((vma->vm_flags & VM_GROWSDOWN) ? MAP_GROWSDOWN : 0) |
		      ((vma->vm_flags & VM_DENYWRITE) ? MAP_DENYWRITE : 0) |
		      ((vma->vm_flags & VM_EXECUTABLE) ? MAP_EXECUTABLE : 0) |
		      ((vma->vm_flags & VM_LOCKED) ? MAP_LOCKED : 0);
	inarg.offset = (loff_t)vma->vm_pgoff << PAGE_SHIFT;

	req->in.h.opcode = FUSE_MMAP;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;

	fuse_request_send(fc, req);
	err = req->out.h.error;
	if (err) {
		if (err == -ENOSYS)
			fc->no_dmmap = 1;
		goto free_req;
	}

	fdr = fuse_dmmap_get(fc, outarg.mapid, outarg.size);
	err = PTR_ERR(fdr);
	if (IS_ERR(fdr))
		goto free_req;

	err = -ENOMEM;
	fdvm = kzalloc(sizeof(*fdvm), GFP_KERNEL);
	if (!fdvm) {
		fuse_dmmap_region_put(fc, fdr);
		goto free_req;
	}
	atomic_set(&fdvm->open_count, 1);
	fdvm->region = fdr;

	vma->vm_ops = &fuse_dmmap_vm_ops;
	vma->vm_private_data = fdvm;
	vma->vm_flags |= VM_DONTEXPAND;		/* disallow expansion for now */
	err = 0;

free_req:
	fuse_put_request(fc, req);
	return err;
}

static int fuse_notify_store_to_dmmap(struct fuse_conn *fc,
				      struct fuse_copy_state *cs,
				      u64 nodeid, u32 size, u64 pos)
{
	struct fuse_dmmap_region *fdr;
	pgoff_t index;
	unsigned int off;
	int err;

	fdr = fuse_dmmap_find(fc, nodeid);
	if (!fdr)
		return -ENOENT;

	index = pos >> PAGE_SHIFT;
	off = pos & ~PAGE_MASK;
	if (pos > fdr->size)
		size = 0;
	else if (size > fdr->size - pos)
		size = fdr->size - pos;

	while (size) {
		struct page *page;
		unsigned int this_num;

		err = -ENOMEM;
		page = fuse_dmmap_find_or_create_page(fc, fdr, index);
		if (!page)
			goto out_iput;

		this_num = min_t(unsigned, size, PAGE_SIZE - off);
		err = fuse_copy_page(cs, &page, off, this_num, 0);
		put_page(page);

		if (err)
			goto out_iput;

		size -= this_num;
		off = 0;
		index++;
	}

	err = 0;

out_iput:
	fuse_dmmap_region_put(fc, fdr);

	return err;
}

static void fuse_retrieve_dmmap_end(struct fuse_conn *fc, struct fuse_req *req)
{
	release_pages(req->pages, req->num_pages, 0);
}

static int fuse_notify_retrieve_from_dmmap(struct fuse_conn *fc,
				struct fuse_notify_retrieve_out *outarg)
{
	struct fuse_dmmap_region *fdr;
	struct fuse_req *req;
	pgoff_t index;
	unsigned int num;
	unsigned int offset;
	size_t total_len = 0;
	int err;

	fdr = fuse_dmmap_find(fc, outarg->nodeid);
	if (!fdr)
		return -ENOENT;

	req = fuse_get_req(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out_put_region;

	offset = outarg->offset & ~PAGE_MASK;

	req->in.h.opcode = FUSE_NOTIFY_REPLY;
	req->in.h.nodeid = outarg->nodeid;
	req->in.numargs = 2;
	req->in.argpages = 1;
	req->page_offset = offset;
	req->end = fuse_retrieve_dmmap_end;

	index = outarg->offset >> PAGE_SHIFT;
	num = outarg->size;
	if (outarg->offset > fdr->size)
		num = 0;
	else if (outarg->offset + num > fdr->size)
		num = fdr->size - outarg->offset;

	while (num && req->num_pages < FUSE_MAX_PAGES_PER_REQ) {
		struct page *page;
		unsigned int this_num;

		BUG_ON(index >= fdr->nr_pages);
		spin_lock(&fc->lock);
		page = fdr->pages[index];
		if (!page)
			page = ZERO_PAGE(0);
		get_page(page);
		spin_unlock(&fc->lock);

		this_num = min_t(unsigned, num, PAGE_SIZE - offset);
		req->pages[req->num_pages] = page;
		req->num_pages++;

		num -= this_num;
		total_len += this_num;
		index++;
	}
	req->misc.retrieve_in.offset = outarg->offset;
	req->misc.retrieve_in.size = total_len;
	req->in.args[0].size = sizeof(req->misc.retrieve_in);
	req->in.args[0].value = &req->misc.retrieve_in;
	req->in.args[1].size = total_len;

	err = fuse_request_send_notify_reply(fc, req, outarg->notify_unique);
	if (err)
		fuse_retrieve_dmmap_end(fc, req);

out_put_region:
	fuse_dmmap_region_put(fc, fdr);

	return err;
}


static const struct file_operations cuse_frontend_fops = {
	.owner			= THIS_MODULE,
	.read			= cuse_read,
	.write			= cuse_write,
	.open			= cuse_open,
	.release		= cuse_release,
	.unlocked_ioctl		= cuse_file_ioctl,
	.compat_ioctl		= cuse_file_compat_ioctl,
	.poll			= fuse_file_poll,
	.llseek			= noop_llseek,
	.mmap			= cuse_mmap,
};


/**************************************************************************
 * CUSE channel initialization and destruction
 */

struct cuse_devinfo {
	const char		*name;
};

/**
 * cuse_parse_one - parse one key=value pair
 * @pp: i/o parameter for the current position
 * @end: points to one past the end of the packed string
 * @keyp: out parameter for key
 * @valp: out parameter for value
 *
 * *@pp points to packed strings - "key0=val0\0key1=val1\0" which ends
 * at @end - 1.  This function parses one pair and set *@keyp to the
 * start of the key and *@valp to the start of the value.  Note that
 * the original string is modified such that the key string is
 * terminated with '\0'.  *@pp is updated to point to the next string.
 *
 * RETURNS:
 * 1 on successful parse, 0 on EOF, -errno on failure.
 */
static int cuse_parse_one(char **pp, char *end, char **keyp, char **valp)
{
	char *p = *pp;
	char *key, *val;

	while (p < end && *p == '\0')
		p++;
	if (p == end)
		return 0;

	if (end[-1] != '\0') {
		printk(KERN_ERR "CUSE: info not properly terminated\n");
		return -EINVAL;
	}

	key = val = p;
	p += strlen(p);

	if (valp) {
		strsep(&val, "=");
		if (!val)
			val = key + strlen(key);
		key = strstrip(key);
		val = strstrip(val);
	} else
		key = strstrip(key);

	if (!strlen(key)) {
		printk(KERN_ERR "CUSE: zero length info key specified\n");
		return -EINVAL;
	}

	*pp = p;
	*keyp = key;
	if (valp)
		*valp = val;

	return 1;
}

/**
 * cuse_parse_dev_info - parse device info
 * @p: device info string
 * @len: length of device info string
 * @devinfo: out parameter for parsed device info
 *
 * Parse @p to extract device info and store it into @devinfo.  String
 * pointed to by @p is modified by parsing and @devinfo points into
 * them, so @p shouldn't be freed while @devinfo is in use.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int cuse_parse_devinfo(char *p, size_t len, struct cuse_devinfo *devinfo)
{
	char *end = p + len;
	char *key, *val;
	int rc;

	while (true) {
		rc = cuse_parse_one(&p, end, &key, &val);
		if (rc < 0)
			return rc;
		if (!rc)
			break;
		if (strcmp(key, "DEVNAME") == 0)
			devinfo->name = val;
		else
			printk(KERN_WARNING "CUSE: unknown device info \"%s\"\n",
			       key);
	}

	if (!devinfo->name || !strlen(devinfo->name)) {
		printk(KERN_ERR "CUSE: DEVNAME unspecified\n");
		return -EINVAL;
	}

	return 0;
}

static void cuse_gendev_release(struct device *dev)
{
	kfree(dev);
}

/**
 * cuse_process_init_reply - finish initializing CUSE channel
 *
 * This function creates the character device and sets up all the
 * required data structures for it.  Please read the comment at the
 * top of this file for high level overview.
 */
static void cuse_process_init_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	struct cuse_conn *cc = fc_to_cc(fc);
	struct cuse_init_out *arg = req->out.args[0].value;
	struct page *page = req->pages[0];
	struct cuse_devinfo devinfo = { };
	struct device *dev;
	struct cdev *cdev;
	dev_t devt;
	int rc;

	if (req->out.h.error ||
	    arg->major != FUSE_KERNEL_VERSION || arg->minor < 11) {
		goto err;
	}

	fc->minor = arg->minor;
	fc->max_read = max_t(unsigned, arg->max_read, 4096);
	fc->max_write = max_t(unsigned, arg->max_write, 4096);

	/* parse init reply */
	cc->unrestricted_ioctl = arg->flags & CUSE_UNRESTRICTED_IOCTL;

	rc = cuse_parse_devinfo(page_address(page), req->out.args[1].size,
				&devinfo);
	if (rc)
		goto err;

	/* determine and reserve devt */
	devt = MKDEV(arg->dev_major, arg->dev_minor);
	if (!MAJOR(devt))
		rc = alloc_chrdev_region(&devt, MINOR(devt), 1, devinfo.name);
	else
		rc = register_chrdev_region(devt, 1, devinfo.name);
	if (rc) {
		printk(KERN_ERR "CUSE: failed to register chrdev region\n");
		goto err;
	}

	/* devt determined, create device */
	rc = -ENOMEM;
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto err_region;

	device_initialize(dev);
	dev_set_uevent_suppress(dev, 1);
	dev->class = cuse_class;
	dev->devt = devt;
	dev->release = cuse_gendev_release;
	dev_set_drvdata(dev, cc);
	dev_set_name(dev, "%s", devinfo.name);

	rc = device_add(dev);
	if (rc)
		goto err_device;

	/* register cdev */
	rc = -ENOMEM;
	cdev = cdev_alloc();
	if (!cdev)
		goto err_device;

	cdev->owner = THIS_MODULE;
	cdev->ops = &cuse_frontend_fops;

	rc = cdev_add(cdev, devt, 1);
	if (rc)
		goto err_cdev;

	cc->dev = dev;
	cc->cdev = cdev;

	/* make the device available */
	spin_lock(&cuse_lock);
	list_add(&cc->list, cuse_conntbl_head(devt));
	spin_unlock(&cuse_lock);

	/* announce device availability */
	dev_set_uevent_suppress(dev, 0);
	kobject_uevent(&dev->kobj, KOBJ_ADD);
out:
	kfree(arg);
	__free_page(page);
	return;

err_cdev:
	cdev_del(cdev);
err_device:
	put_device(dev);
err_region:
	unregister_chrdev_region(devt, 1);
err:
	fc->conn_error = 1;
	goto out;
}

static int cuse_send_init(struct cuse_conn *cc)
{
	int rc;
	struct fuse_req *req;
	struct page *page;
	struct fuse_conn *fc = &cc->fc;
	struct cuse_init_in *arg;
	void *outarg;

	BUILD_BUG_ON(CUSE_INIT_INFO_MAX > PAGE_SIZE);

	req = fuse_get_req(fc);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		goto err;
	}

	rc = -ENOMEM;
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto err_put_req;

	outarg = kzalloc(sizeof(struct cuse_init_out), GFP_KERNEL);
	if (!outarg)
		goto err_free_page;

	arg = &req->misc.cuse_init_in;
	arg->major = FUSE_KERNEL_VERSION;
	arg->minor = FUSE_KERNEL_MINOR_VERSION;
	arg->flags |= CUSE_UNRESTRICTED_IOCTL;
	req->in.h.opcode = CUSE_INIT;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct cuse_init_in);
	req->in.args[0].value = arg;
	req->out.numargs = 2;
	req->out.args[0].size = sizeof(struct cuse_init_out);
	req->out.args[0].value = outarg;
	req->out.args[1].size = CUSE_INIT_INFO_MAX;
	req->out.argvar = 1;
	req->out.argpages = 1;
	req->pages[0] = page;
	req->num_pages = 1;
	req->end = cuse_process_init_reply;
	fuse_request_send_background(fc, req);

	return 0;

err_free_page:
	__free_page(page);
err_put_req:
	fuse_put_request(fc, req);
err:
	return rc;
}

static void cuse_fc_release(struct fuse_conn *fc)
{
	struct cuse_conn *cc = fc_to_cc(fc);
	kfree(cc);
}

static const struct fuse_conn_operations cuse_ops = {
	.release = cuse_fc_release,
	.notify_store = fuse_notify_store_to_dmmap,
	.notify_retrieve = fuse_notify_retrieve_from_dmmap,
};

/**
 * cuse_channel_open - open method for /dev/cuse
 * @inode: inode for /dev/cuse
 * @file: file struct being opened
 *
 * Userland CUSE server can create a CUSE device by opening /dev/cuse
 * and replying to the initialization request kernel sends.  This
 * function is responsible for handling CUSE device initialization.
 * Because the fd opened by this function is used during
 * initialization, this function only creates cuse_conn and sends
 * init.  The rest is delegated to a kthread.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int cuse_channel_open(struct inode *inode, struct file *file)
{
	struct cuse_conn *cc;
	int rc;

	/* set up cuse_conn */
	cc = kzalloc(sizeof(*cc), GFP_KERNEL);
	if (!cc)
		return -ENOMEM;

	fuse_conn_init(&cc->fc);

	INIT_LIST_HEAD(&cc->list);
	cc->fc.ops = &cuse_ops;

	cc->fc.connected = 1;
	cc->fc.blocked = 0;
	rc = cuse_send_init(cc);
	if (rc) {
		fuse_conn_put(&cc->fc);
		return rc;
	}
	file->private_data = &cc->fc;	/* channel owns base reference to cc */

	return 0;
}

/**
 * cuse_channel_release - release method for /dev/cuse
 * @inode: inode for /dev/cuse
 * @file: file struct being closed
 *
 * Disconnect the channel, deregister CUSE device and initiate
 * destruction by putting the default reference.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int cuse_channel_release(struct inode *inode, struct file *file)
{
	struct cuse_conn *cc = fc_to_cc(file->private_data);
	int rc;

	/* remove from the conntbl, no more access from this point on */
	spin_lock(&cuse_lock);
	list_del_init(&cc->list);
	spin_unlock(&cuse_lock);

	/* remove device */
	if (cc->dev)
		device_unregister(cc->dev);
	if (cc->cdev) {
		unregister_chrdev_region(cc->cdev->dev, 1);
		cdev_del(cc->cdev);
	}

	/* kill connection and shutdown channel */
	fuse_conn_kill(&cc->fc);
	rc = fuse_dev_release(inode, file);	/* puts the base reference */

	return rc;
}

static struct file_operations cuse_channel_fops; /* initialized during init */


/**************************************************************************
 * Misc stuff and module initializatiion
 *
 * CUSE exports the same set of attributes to sysfs as fusectl.
 */

static ssize_t cuse_class_waiting_show(struct device *dev,
				       struct device_attribute *attr, char *buf)
{
	struct cuse_conn *cc = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", atomic_read(&cc->fc.num_waiting));
}

static ssize_t cuse_class_abort_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct cuse_conn *cc = dev_get_drvdata(dev);

	fuse_abort_conn(&cc->fc);
	return count;
}

static struct device_attribute cuse_class_dev_attrs[] = {
	__ATTR(waiting, S_IFREG | 0400, cuse_class_waiting_show, NULL),
	__ATTR(abort, S_IFREG | 0200, NULL, cuse_class_abort_store),
	{ }
};

static struct miscdevice cuse_miscdev = {
	.minor		= MISC_DYNAMIC_MINOR,
	.name		= "cuse",
	.fops		= &cuse_channel_fops,
};

static int __init cuse_init(void)
{
	int i, rc;

	/* init conntbl */
	for (i = 0; i < CUSE_CONNTBL_LEN; i++)
		INIT_LIST_HEAD(&cuse_conntbl[i]);

	/* inherit and extend fuse_dev_operations */
	cuse_channel_fops		= fuse_dev_operations;
	cuse_channel_fops.owner		= THIS_MODULE;
	cuse_channel_fops.open		= cuse_channel_open;
	cuse_channel_fops.release	= cuse_channel_release;

	cuse_class = class_create(THIS_MODULE, "cuse");
	if (IS_ERR(cuse_class))
		return PTR_ERR(cuse_class);

	cuse_class->dev_attrs = cuse_class_dev_attrs;

	rc = misc_register(&cuse_miscdev);
	if (rc) {
		class_destroy(cuse_class);
		return rc;
	}

	return 0;
}

static void __exit cuse_exit(void)
{
	misc_deregister(&cuse_miscdev);
	class_destroy(cuse_class);
}

module_init(cuse_init);
module_exit(cuse_exit);

MODULE_AUTHOR("Tejun Heo <tj@kernel.org>");
MODULE_DESCRIPTION("Character device in Userspace");
MODULE_LICENSE("GPL");
