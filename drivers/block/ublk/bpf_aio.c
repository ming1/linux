// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Red Hat */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpf_mem_alloc.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>

#include "bpf_aio.h"

static int __bpf_aio_submit(struct bpf_aio *aio);

static struct kmem_cache *bpf_aio_cachep;
static struct kmem_cache *bpf_aio_work_cachep;
static struct workqueue_struct *bpf_aio_wq;

static inline bool bpf_aio_is_rw(int op)
{
	return op == BPF_AIO_OP_FS_READ || op == BPF_AIO_OP_FS_WRITE;
}

/* check if it is short read */
static bool bpf_aio_is_short_read(const struct bpf_aio *aio, long ret)
{
	return ret >= 0 && ret < aio->bytes &&
		bpf_aio_get_op(aio) == BPF_AIO_OP_FS_READ;
}

/* zeroing the remained bytes starting from `off` to end */
static void bpf_aio_zero_remained(const struct bpf_aio *aio, long off)
{
	struct iov_iter iter;

	iov_iter_bvec(&iter, ITER_DEST, aio->buf.bvec, aio->buf.nr_bvec, aio->bytes);
	iter.iov_offset = aio->buf.bvec_off;

	iov_iter_advance(&iter, off);
	iov_iter_zero(aio->bytes - off, &iter);
}

static void bpf_aio_do_completion(struct bpf_aio *aio)
{
	if (aio->iocb.ki_filp)
		fput(aio->iocb.ki_filp);
	if (aio->work)
		kmem_cache_free(bpf_aio_work_cachep, aio->work);
}

/* ->ki_complete callback */
static void bpf_aio_complete(struct kiocb *iocb, long ret)
{
	struct bpf_aio *aio = container_of(iocb, struct bpf_aio, iocb);

	if (unlikely(ret == -EAGAIN)) {
		aio->opf |= BPF_AIO_FORCE_WQ;
		ret = __bpf_aio_submit(aio);
		if (!ret)
			return;
	}

	/* zero the remained bytes in case of short read */
	if (bpf_aio_is_short_read(aio, ret))
		bpf_aio_zero_remained(aio, ret);

	bpf_aio_do_completion(aio);
	aio->ops->bpf_aio_complete_cb(aio, ret);
}

static void bpf_aio_prep_rw(struct bpf_aio *aio, unsigned int rw,
		struct iov_iter *iter)
{
	iov_iter_bvec(iter, rw, aio->buf.bvec, aio->buf.nr_bvec, aio->bytes);
	iter->iov_offset = aio->buf.bvec_off;

	if (unlikely(aio->opf & BPF_AIO_FORCE_WQ)) {
		aio->iocb.ki_flags &= ~IOCB_NOWAIT;
		aio->iocb.ki_complete = NULL;
	} else {
		aio->iocb.ki_flags |= IOCB_NOWAIT;
		aio->iocb.ki_complete = bpf_aio_complete;
	}
}

static int bpf_aio_do_submit(struct bpf_aio *aio)
{
	int op = bpf_aio_get_op(aio);
	struct iov_iter iter;
	struct file *file = aio->iocb.ki_filp;
	int ret;

	switch (op) {
	case BPF_AIO_OP_FS_READ:
		bpf_aio_prep_rw(aio, ITER_DEST, &iter);
		if (file->f_op->read_iter)
			ret = file->f_op->read_iter(&aio->iocb, &iter);
		else
			ret = -EOPNOTSUPP;
		break;
	case BPF_AIO_OP_FS_WRITE:
		bpf_aio_prep_rw(aio, ITER_SOURCE, &iter);
		if (file->f_op->write_iter)
			ret = file->f_op->write_iter(&aio->iocb, &iter);
		else
			ret = -EOPNOTSUPP;
		break;
	case BPF_AIO_OP_FS_FSYNC:
		ret = vfs_fsync_range(aio->iocb.ki_filp, aio->iocb.ki_pos,
				aio->iocb.ki_pos + aio->bytes - 1, 0);
		if (unlikely(ret && ret != -EINVAL))
			ret = -EIO;
		break;
	case BPF_AIO_OP_FS_FALLOCATE:
		ret = vfs_fallocate(aio->iocb.ki_filp, aio->iocb.ki_flags,
				aio->iocb.ki_pos, aio->bytes);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret == -EIOCBQUEUED) {
		ret = 0;
	} else if (ret != -EAGAIN) {
		bpf_aio_complete(&aio->iocb, ret);
		ret = 0;
	}

	return ret;
}

static void bpf_aio_submit_work(struct work_struct *work)
{
	struct bpf_aio_work *aio_work = container_of(work, struct bpf_aio_work, work);

	bpf_aio_do_submit(aio_work->aio);
}

static int __bpf_aio_submit(struct bpf_aio *aio)
{
	struct work_struct *work;

do_submit:
	if (likely(!(aio->opf & BPF_AIO_FORCE_WQ))) {
		int ret = bpf_aio_do_submit(aio);

		/* retry via workqueue in case of -EAGAIN */
		if (ret != -EAGAIN)
			return ret;
		aio->opf |= BPF_AIO_FORCE_WQ;
	}

	if (!aio->work) {
		bool in_irq = in_interrupt();
		gfp_t gfpflags = in_irq ? GFP_ATOMIC : GFP_NOIO;

		aio->work = kmem_cache_alloc(bpf_aio_work_cachep, gfpflags);
		if (unlikely(!aio->work)) {
			if (in_irq)
				return -ENOMEM;
			aio->opf &= ~BPF_AIO_FORCE_WQ;
			goto do_submit;
		}
	}

	aio->work->aio = aio;
	work = &aio->work->work;
	INIT_WORK(work, bpf_aio_submit_work);
	queue_work(bpf_aio_wq, work);

	return 0;
}

static struct bpf_aio *__bpf_aio_alloc(gfp_t gfpflags, unsigned op,
				       enum bpf_aio_flag aio_flags)
{
	struct bpf_aio *aio;

	if (op >= BPF_AIO_OP_LAST)
		return NULL;

	if (aio_flags & BPF_AIO_OP_MASK)
		return NULL;

	aio = kmem_cache_alloc(bpf_aio_cachep, gfpflags);
	if (!aio)
		return NULL;

	memset(aio, 0, sizeof(*aio));
	aio->opf = op | (unsigned int)aio_flags;
	return aio;
}

__bpf_kfunc struct bpf_aio *bpf_aio_alloc(unsigned int op, enum bpf_aio_flag aio_flags)
{
	return __bpf_aio_alloc(GFP_ATOMIC, op, aio_flags);
}

__bpf_kfunc struct bpf_aio *bpf_aio_alloc_sleepable(unsigned int op, enum bpf_aio_flag aio_flags)
{
	return __bpf_aio_alloc(GFP_NOIO, op, aio_flags);
}

__bpf_kfunc void bpf_aio_release(struct bpf_aio *aio)
{
	kmem_cache_free(bpf_aio_cachep, aio);
}

/* Submit AIO from bpf prog */
__bpf_kfunc int bpf_aio_submit(struct bpf_aio *aio, int fd, loff_t pos,
		unsigned bytes, unsigned io_flags)
{
	unsigned op = bpf_aio_get_op(aio);
	struct file *file;

	/*
	 * ->ops has to assigned by kfunc of consumer subsystem because
	 * bpf prog lifetime is aligned with the consumer subsystem
	 */
	if (!aio->ops)
		return -EINVAL;

	if (unlikely((bytes > aio->buf_size) && bpf_aio_is_rw(op)))
		return -EINVAL;

	file = fget(fd);
	if (!file)
		return -EINVAL;

	/* we could be called from io completion handler */
	if (in_interrupt())
		aio->opf |= BPF_AIO_FORCE_WQ;

	aio->iocb.ki_pos = pos;
	aio->iocb.ki_filp = file;
	aio->iocb.ki_flags = io_flags;
	aio->bytes = bytes;
	if (bpf_aio_is_rw(op)) {
		if (file->f_flags & O_DIRECT)
			aio->iocb.ki_flags |= IOCB_DIRECT;
		else
			aio->opf |= BPF_AIO_FORCE_WQ;
		aio->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
	} else {
		aio->opf |= BPF_AIO_FORCE_WQ;
	}

	return __bpf_aio_submit(aio);
}

int __init bpf_aio_init(void)
{
	int err;

	bpf_aio_cachep = KMEM_CACHE(bpf_aio, SLAB_PANIC);
	bpf_aio_work_cachep = KMEM_CACHE(bpf_aio_work, SLAB_PANIC);
	bpf_aio_wq = alloc_workqueue("bpf_aio", WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);

	err = bpf_aio_struct_ops_init();
	if (err) {
		pr_warn("error while initializing bpf aio struct_ops: %d", err);
		return err;
	}
	return 0;
}
