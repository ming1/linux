// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Red Hat */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <uapi/linux/io_uring.h>
#include "io_uring.h"
#include "register.h"
#include "bpf_op.h"

static inline unsigned char uring_bpf_get_op(u32 op_flags)
{
	return (unsigned char)(op_flags >> IORING_BPF_OP_SHIFT);
}

static inline unsigned int uring_bpf_get_flags(u32 op_flags)
{
	return op_flags & ((1U << IORING_BPF_OP_SHIFT) - 1);
}

int io_uring_bpf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct uring_bpf_data *data = io_kiocb_to_cmd(req, struct uring_bpf_data);
	u32 opf = READ_ONCE(sqe->bpf_op_flags);
	unsigned char bpf_op = uring_bpf_get_op(opf);
	struct uring_bpf_ops_kern *ops_kern;
	const struct uring_bpf_ops *ops;
	int ret;

	if (unlikely(!(req->ctx->flags & IORING_SETUP_BPF_OP)))
		goto fail;

	if (bpf_op >= IO_RING_MAX_BPF_OPS)
		return -EINVAL;

	ops_kern = &req->ctx->bpf_ops[bpf_op];
	ops = ops_kern->ops;
	if (!ops || !ops->prep_fn || !ops_kern->refcount)
		goto fail;

	data->opf = opf;
	data->ops = ops;
	ret = ops->prep_fn(data, sqe);
	if (!ret) {
		/* Only increment refcount on success (uring_lock already held) */
		req->flags |= REQ_F_NEED_CLEANUP;
		ops_kern->refcount++;
	}
	return ret;
fail:
	return -EOPNOTSUPP;
}

static int __io_uring_bpf_issue(struct io_kiocb *req)
{
	struct uring_bpf_data *data = io_kiocb_to_cmd(req, struct uring_bpf_data);
	const struct uring_bpf_ops *ops = data->ops;
	int ret = 0;

	if (ops && ops->issue_fn) {
		ret = ops->issue_fn(data);
		if (ret == IOU_ISSUE_SKIP_COMPLETE)
			return -EINVAL;
	}
	return ret;
}

int io_uring_bpf_issue(struct io_kiocb *req, unsigned int issue_flags)
{
	return __io_uring_bpf_issue(req);
}

void io_uring_bpf_fail(struct io_kiocb *req)
{
	struct uring_bpf_data *data = io_kiocb_to_cmd(req, struct uring_bpf_data);
	const struct uring_bpf_ops *ops = data->ops;

	if (ops && ops->fail_fn)
		ops->fail_fn(data);
}

void io_uring_bpf_cleanup(struct io_kiocb *req)
{
	struct uring_bpf_data *data = io_kiocb_to_cmd(req, struct uring_bpf_data);
	const struct uring_bpf_ops *ops = data->ops;
	struct uring_bpf_ops_kern *ops_kern;
	unsigned char bpf_op;

	if (ops && ops->cleanup_fn)
		ops->cleanup_fn(data);

	bpf_op = uring_bpf_get_op(data->opf);
	ops_kern = &req->ctx->bpf_ops[bpf_op];

	/* Decrement refcount after cleanup (uring_lock already held) */
	if (--ops_kern->refcount == 0)
		wake_up(&req->ctx->bpf_wq);
}

static const struct btf_type *uring_bpf_data_type;

static int uring_bpf_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t != uring_bpf_data_type) {
		bpf_log(log, "only read is supported\n");
		return -EACCES;
	}

	if (off < offsetof(struct uring_bpf_data, pdu) ||
			off + size > sizeof(struct uring_bpf_data))
		return -EACCES;

	return NOT_INIT;
}

static const struct bpf_verifier_ops io_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_tracing_btf_ctx_access,
	.btf_struct_access = uring_bpf_ops_btf_struct_access,
};

static int uring_bpf_ops_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "uring_bpf_data", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	uring_bpf_data_type = btf_type_by_id(btf, type_id);
	return 0;
}

static int uring_bpf_ops_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	/*
	 * All io_uring BPF ops callbacks are called in non-sleepable
	 * context, so reject sleepable BPF programs.
	 */
	if (prog->sleepable)
		return -EINVAL;

	return 0;
}

static int uring_bpf_ops_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	const struct uring_bpf_ops *uuring_bpf_ops;
	struct uring_bpf_ops *kuring_bpf_ops;
	u32 moff;

	uuring_bpf_ops = udata;
	kuring_bpf_ops = kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct uring_bpf_ops, id):
		/* For id, this function has to copy it and return 1 to
		 * indicate that the data has been handled by the struct_ops
		 * type, or the verifier will reject the map if the value of
		 * those fields is not zero.
		 */
		kuring_bpf_ops->id = uuring_bpf_ops->id;
		return 1;
	case offsetof(struct uring_bpf_ops, ring_fd):
		kuring_bpf_ops->ring_fd = uuring_bpf_ops->ring_fd;
		return 1;
	}
	return 0;
}

static int io_bpf_reg_unreg(struct uring_bpf_ops *ops, bool reg)
{
	struct uring_bpf_ops_kern *ops_kern;
	struct io_ring_ctx *ctx;
	struct file *file;
	int ret = -EINVAL;

	if (ops->id >= IO_RING_MAX_BPF_OPS)
		return -EINVAL;

	file = io_uring_register_get_file(ops->ring_fd, false);
	if (IS_ERR(file))
		return PTR_ERR(file);

	ctx = file->private_data;
	if (!(ctx->flags & IORING_SETUP_BPF_OP))
		goto out;

	ops_kern = &ctx->bpf_ops[ops->id];

	mutex_lock(&ctx->uring_lock);
	if (reg) {
		/* Registration: set refcount to 1 and store ops */
		if (ops_kern->ops) {
			ret = -EBUSY;
		} else {
			ops_kern->ops = ops;
			ops_kern->refcount = 1;
			ret = 0;
		}
	} else {
		/* Unregistration */
		if (!ops_kern->ops) {
			ret = -EINVAL;
		} else {
			ops_kern->refcount--;
retry:
			if (ops_kern->refcount == 0) {
				ops_kern->ops = NULL;
				ret = 0;
			} else {
				mutex_unlock(&ctx->uring_lock);
				wait_event(ctx->bpf_wq, ops_kern->refcount == 0);
				mutex_lock(&ctx->uring_lock);
				goto retry;
			}
		}
	}
	mutex_unlock(&ctx->uring_lock);

out:
	fput(file);
	return ret;
}

static int io_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct uring_bpf_ops *ops = kdata;

	return io_bpf_reg_unreg(ops, true);
}

static void io_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct uring_bpf_ops *ops = kdata;

	io_bpf_reg_unreg(ops, false);
}

static int io_bpf_prep_io(struct uring_bpf_data *data, const struct io_uring_sqe *sqe)
{
	return 0;
}

static int io_bpf_issue_io(struct uring_bpf_data *data)
{
	return 0;
}

static void io_bpf_fail_io(struct uring_bpf_data *data)
{
}

static void io_bpf_cleanup_io(struct uring_bpf_data *data)
{
}

static struct uring_bpf_ops __bpf_uring_bpf_ops = {
	.prep_fn	= io_bpf_prep_io,
	.issue_fn	= io_bpf_issue_io,
	.fail_fn	= io_bpf_fail_io,
	.cleanup_fn	= io_bpf_cleanup_io,
};

static struct bpf_struct_ops bpf_uring_bpf_ops = {
	.verifier_ops = &io_bpf_verifier_ops,
	.init = uring_bpf_ops_init,
	.check_member = uring_bpf_ops_check_member,
	.init_member = uring_bpf_ops_init_member,
	.reg = io_bpf_reg,
	.unreg = io_bpf_unreg,
	.name = "uring_bpf_ops",
	.cfi_stubs = &__bpf_uring_bpf_ops,
	.owner = THIS_MODULE,
};

__bpf_kfunc_start_defs();
__bpf_kfunc void uring_bpf_set_result(struct uring_bpf_data *data, int res)
{
	struct io_kiocb *req = cmd_to_io_kiocb(data);

	if (res < 0)
		req_set_fail(req);
	io_req_set_res(req, res, 0);
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(uring_bpf_kfuncs)
BTF_ID_FLAGS(func, uring_bpf_set_result)
BTF_KFUNCS_END(uring_bpf_kfuncs)

static const struct btf_kfunc_id_set uring_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &uring_bpf_kfuncs,
};

int io_bpf_alloc(struct io_ring_ctx *ctx)
{
	init_waitqueue_head(&ctx->bpf_wq);

	if (!(ctx->flags & IORING_SETUP_BPF_OP))
		return 0;

	ctx->bpf_ops = kcalloc(IO_RING_MAX_BPF_OPS,
			sizeof(struct uring_bpf_ops_kern), GFP_KERNEL);
	if (!ctx->bpf_ops)
		return -ENOMEM;

	return 0;
}

void io_bpf_free(struct io_ring_ctx *ctx)
{
	kfree(ctx->bpf_ops);
	ctx->bpf_ops = NULL;
}

static int __init io_bpf_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &uring_kfunc_set);
	if (err) {
		pr_warn("error while setting io_uring BPF kfuncs: %d\n", err);
		return err;
	}

	err = register_bpf_struct_ops(&bpf_uring_bpf_ops, uring_bpf_ops);
	if (err)
		pr_warn("error while registering io_uring BPF struct ops: %d\n", err);

	return err;
}
__initcall(io_bpf_init);
