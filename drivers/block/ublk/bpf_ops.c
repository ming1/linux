// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Red Hat */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/xarray.h>

#include "ublk.h"
#include "bpf.h"

static DEFINE_XARRAY(ublk_ops);
static DEFINE_MUTEX(ublk_bpf_ops_lock);

static bool ublk_bpf_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int ublk_bpf_ops_btf_struct_access(struct bpf_verifier_log *log,
					   const struct bpf_reg_state *reg,
					   int off, int size)
{
	/* ublk prog can change nothing */
	if (size > 0)
		return -EACCES;

	return NOT_INIT;
}

static const struct bpf_verifier_ops ublk_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = ublk_bpf_ops_is_valid_access,
	.btf_struct_access = ublk_bpf_ops_btf_struct_access,
};

static int ublk_bpf_ops_init(struct btf *btf)
{
	return 0;
}

static int ublk_bpf_ops_check_member(const struct btf_type *t,
				      const struct btf_member *member,
				      const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct ublk_bpf_ops, queue_io_cmd):
	case offsetof(struct ublk_bpf_ops, release_io_cmd):
		if (prog->sleepable)
			return -EINVAL;
	case offsetof(struct ublk_bpf_ops, queue_io_cmd_daemon):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int ublk_bpf_ops_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	const struct ublk_bpf_ops *uops;
	struct ublk_bpf_ops *kops;
	u32 moff;

	uops = (const struct ublk_bpf_ops *)udata;
	kops = (struct ublk_bpf_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct ublk_bpf_ops, id):
		/* For dev_id, this function has to copy it and return 1 to
		 * indicate that the data has been handled by the struct_ops
		 * type, or the verifier will reject the map if the value of
		 * those fields is not zero.
		 */
		kops->id = uops->id;
		return 1;
	}
	return 0;
}

static int ublk_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct ublk_bpf_ops *ops = kdata;
	struct ublk_bpf_ops *curr;
	int ret = -EBUSY;

	mutex_lock(&ublk_bpf_ops_lock);
	if (!xa_load(&ublk_ops, ops->id)) {
		curr = kmalloc(sizeof(*curr), GFP_KERNEL);
		if (curr) {
			*curr = *ops;
			bpf_prog_provider_init(&curr->provider);
			ret = xa_err(xa_store(&ublk_ops, ops->id, curr, GFP_KERNEL));
		} else {
			ret = -ENOMEM;
		}
	}
	mutex_unlock(&ublk_bpf_ops_lock);

	return ret;
}

static void ublk_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct ublk_bpf_ops *ops = kdata;
	struct ublk_bpf_ops *curr;
	LIST_HEAD(consumer_list);
	struct bpf_prog_consumer *consumer, *tmp;

	mutex_lock(&ublk_bpf_ops_lock);
	curr = xa_erase(&ublk_ops, ops->id);
	if (curr)
		list_splice_init(&curr->provider.list, &consumer_list);
	mutex_unlock(&ublk_bpf_ops_lock);

	list_for_each_entry_safe(consumer, tmp, &consumer_list, node)
		bpf_prog_consumer_detach(consumer, true);
	kfree(curr);
}

int ublk_bpf_prog_attach(struct bpf_prog_consumer *consumer)
{
	unsigned id = consumer->prog_id;
	struct ublk_bpf_ops *ops;
	int ret = -EINVAL;

	mutex_lock(&ublk_bpf_ops_lock);
	ops = xa_load(&ublk_ops, id);
	if (ops && ops->id == id)
		ret = bpf_prog_consumer_attach(consumer, &ops->provider);
	mutex_unlock(&ublk_bpf_ops_lock);

	return ret;
}

void ublk_bpf_prog_detach(struct bpf_prog_consumer *consumer)
{
	mutex_lock(&ublk_bpf_ops_lock);
	bpf_prog_consumer_detach(consumer, false);
	mutex_unlock(&ublk_bpf_ops_lock);
}


static void ublk_bpf_prep_io(struct ublk_bpf_io *io,
		const struct ublksrv_io_desc *iod)
{
	io->flags = 0;
	io->res = 0;
	io->iod = iod;
	__set_bit(UBLK_BPF_IO_PREP, &io->flags);
	/* one is for submission, another is for completion */
	refcount_set(&io->ref, 2);
}

/* Return true if io cmd is queued, otherwise forward it to userspace */
bool ublk_run_bpf_handler(struct ublk_queue *ubq, struct request *req,
			  queue_io_cmd_t cb)
{
	ublk_bpf_return_t ret;
	struct ublk_rq_data *data = blk_mq_rq_to_pdu(req);
	struct ublksrv_io_desc *iod = ublk_get_iod(ubq, req->tag);
	struct ublk_bpf_io *bpf_io = &data->bpf_data;
	const unsigned long total = iod->nr_sectors << 9;
	unsigned int done = 0;
	bool res = true;
	int err;

	if (!test_bit(UBLK_BPF_IO_PREP, &bpf_io->flags))
		ublk_bpf_prep_io(bpf_io, iod);

	do {
		enum ublk_bpf_disposition rc;
		unsigned int bytes;

		ret = cb(bpf_io, done);
		rc = ublk_bpf_get_disposition(ret);

		if (rc == UBLK_BPF_IO_QUEUED)
			goto exit;

		if (rc == UBLK_BPF_IO_REDIRECT)
			break;

		if (unlikely(rc != UBLK_BPF_IO_CONTINUE)) {
			printk_ratelimited(KERN_ERR "%s: unknown rc code %d\n",
					__func__, rc);
			err = -EINVAL;
			goto fail;
		}

		bytes = ublk_bpf_get_return_bytes(ret);
		if (unlikely((bytes & 511) || !bytes)) {
			err = -EREMOTEIO;
			goto fail;
		} else if (unlikely(bytes > total - done)) {
			err = -ENOSPC;
			goto fail;
		} else {
			done += bytes;
		}
	} while (done < total);

	/*
	 * If any bytes are queued, we can't forward to userspace
	 * immediately because it is too complicated to support two side
	 * completion.
	 *
	 * But the request will be updated and retried after the queued
	 * part is completed, then it can be forwarded to userspace too.
	 */
	res = done > 0;
	if (!res) {
		/* will redirect to userspace, so forget bpf handling */
		__clear_bit(UBLK_BPF_IO_PREP, &bpf_io->flags);
		refcount_dec(&bpf_io->ref);
	}
	goto exit;
fail:
	res = true;
	ublk_bpf_complete_io_cmd(bpf_io, err);
exit:
	ublk_bpf_io_dec_ref(bpf_io);
	return res;
}

static ublk_bpf_return_t ublk_bpf_run_io_task(struct ublk_bpf_io *io,
						   unsigned int offset)
{
	return ublk_bpf_return_val(UBLK_BPF_IO_REDIRECT, 0);
}

static ublk_bpf_return_t ublk_bpf_queue_io_cmd(struct ublk_bpf_io *io,
						    unsigned int offset)
{
	return ublk_bpf_return_val(UBLK_BPF_IO_REDIRECT, 0);
}

static void ublk_bpf_release_io_cmd(struct ublk_bpf_io *io)
{
}

static int ublk_bpf_attach_dev(int dev_id)
{
	return 0;
}

static void ublk_bpf_detach_dev(int dev_id)
{
}

static struct ublk_bpf_ops __bpf_ublk_bpf_ops = {
	.queue_io_cmd = ublk_bpf_queue_io_cmd,
	.queue_io_cmd_daemon = ublk_bpf_run_io_task,
	.release_io_cmd = ublk_bpf_release_io_cmd,
	.attach_dev	= ublk_bpf_attach_dev,
	.detach_dev	= ublk_bpf_detach_dev,
};

static struct bpf_struct_ops bpf_ublk_bpf_ops = {
	.verifier_ops = &ublk_bpf_verifier_ops,
	.init = ublk_bpf_ops_init,
	.check_member = ublk_bpf_ops_check_member,
	.init_member = ublk_bpf_ops_init_member,
	.reg = ublk_bpf_reg,
	.unreg = ublk_bpf_unreg,
	.name = "ublk_bpf_ops",
	.cfi_stubs = &__bpf_ublk_bpf_ops,
	.owner = THIS_MODULE,
};

int __init ublk_bpf_struct_ops_init(void)
{
	int err;

	err = register_bpf_struct_ops(&bpf_ublk_bpf_ops, ublk_bpf_ops);
	if (err)
		pr_warn("error while registering ublk bpf struct ops: %d", err);

	return 0;
}
