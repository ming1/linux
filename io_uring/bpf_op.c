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
#include <linux/uio.h>
#include <uapi/linux/io_uring.h>
#include "io_uring.h"
#include "register.h"
#include "rsrc.h"
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
	data->issue_flags = 0;
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
	struct uring_bpf_data *data = io_kiocb_to_cmd(req, struct uring_bpf_data);
	int ret;

	data->issue_flags = issue_flags;
	ret = __io_uring_bpf_issue(req);
	data->issue_flags = 0;
	return ret;
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

/*
 * Helper to copy data between two iov_iters using page extraction.
 * Extracts pages from source iterator and copies them to destination.
 * Returns number of bytes copied or negative error code.
 */
static ssize_t io_bpf_copy_iters(struct iov_iter *src, struct iov_iter *dst,
				 size_t len)
{
#define MAX_PAGES_PER_LOOP 32
	struct page *pages[MAX_PAGES_PER_LOOP];
	size_t total_copied = 0;
	bool need_unpin;

	need_unpin = iov_iter_extract_will_pin(src);

	while (len > 0) {
		struct page **page_array = pages;
		size_t offset, copied = 0;
		ssize_t extracted;
		unsigned int nr_pages;
		size_t chunk_len;
		int i;

		chunk_len = min_t(size_t, len, MAX_PAGES_PER_LOOP * PAGE_SIZE);
		extracted = iov_iter_extract_pages(src, &page_array, chunk_len,
						   MAX_PAGES_PER_LOOP, 0, &offset);
		if (extracted <= 0) {
			if (total_copied > 0)
				break;
			return extracted < 0 ? extracted : -EFAULT;
		}

		nr_pages = DIV_ROUND_UP(offset + extracted, PAGE_SIZE);

		for (i = 0; i < nr_pages && copied < extracted; i++) {
			size_t page_offset = (i == 0) ? offset : 0;
			size_t page_len = min_t(size_t, extracted - copied,
						PAGE_SIZE - page_offset);
			size_t n;

			n = copy_page_to_iter(page_array[i], page_offset, page_len, dst);
			copied += n;
			if (n < page_len)
				break;
		}

		if (need_unpin)
			unpin_user_pages(page_array, nr_pages);

		total_copied += copied;
		len -= copied;

		if (copied < extracted)
			break;
	}

	return total_copied;
#undef MAX_PAGES_PER_LOOP
}

/*
 * Helper to import fixed buffer (FIXED or KFIXED).
 * Must be called with submit lock held.
 *
 * FIXED: addr is absolute userspace address within buffer
 * KFIXED: addr is offset from buffer start
 *
 * Returns node with incremented refcount on success, ERR_PTR on failure.
 */
static struct io_rsrc_node *io_bpf_import_fixed_buf(struct io_ring_ctx *ctx,
						    struct iov_iter *iter,
						    const struct io_bpf_buf_desc *desc,
						    int ddir)
{
	struct io_rsrc_node *node;
	struct io_mapped_ubuf *imu;
	int ret;

	node = io_rsrc_node_lookup(&ctx->buf_table, desc->buf_index);
	if (!node)
		return ERR_PTR(-EFAULT);

	imu = node->buf;
	if (!(imu->dir & (1 << ddir)))
		return ERR_PTR(-EFAULT);

	node->refs++;

	ret = io_import_fixed(ddir, iter, imu, desc->addr, desc->len);
	if (ret) {
		node->refs--;
		return ERR_PTR(ret);
	}

	return node;
}

/*
 * Helper to import registered vectored buffer (KVEC).
 * Must be called with submit lock held.
 *
 * addr: userspace iovec pointer
 * len: number of iovecs
 * buf_index: registered buffer index
 *
 * Returns node with incremented refcount on success, ERR_PTR on failure.
 * Caller must call io_vec_free(vec) after use.
 */
static struct io_rsrc_node *io_bpf_import_reg_vec(struct io_ring_ctx *ctx,
						   struct iov_iter *iter,
						   const struct io_bpf_buf_desc *desc,
						   int ddir, struct iou_vec *vec)
{
	struct io_rsrc_node *node;
	struct io_mapped_ubuf *imu;
	int ret;

	node = io_rsrc_node_lookup(&ctx->buf_table, desc->buf_index);
	if (!node)
		return ERR_PTR(-EFAULT);

	imu = node->buf;
	if (!(imu->dir & (1 << ddir)))
		return ERR_PTR(-EFAULT);

	node->refs++;

	/* Prepare iovec from userspace */
	ret = __io_prep_reg_iovec(vec, u64_to_user_ptr(desc->addr),
				  desc->len, ctx->compat, NULL);
	if (ret)
		goto err;

	/* Import vectored buffer from registered buffer */
	ret = __io_import_reg_vec(ddir, iter, imu, vec, desc->len, NULL);
	if (ret)
		goto err;

	return node;
err:
	node->refs--;
	return ERR_PTR(ret);
}

/*
 * Helper to import a vectored user buffer (VEC) into iou_vec.
 * Allocates space in vec and copies iovec from userspace.
 *
 * Returns 0 on success, negative error code on failure.
 * Caller must call io_vec_free(vec) after use.
 */
static int io_bpf_import_vec_buf(struct io_ring_ctx *ctx,
				 struct iov_iter *iter,
				 const struct io_bpf_buf_desc *desc,
				 int ddir, struct iou_vec *vec)
{
	unsigned nr_vecs = desc->len;
	struct iovec *iov;
	size_t total_len = 0;
	void *res;
	int ret, i;

	if (nr_vecs > vec->nr) {
		ret = io_vec_realloc(vec, nr_vecs);
		if (ret)
			return ret;
	}

	iov = vec->iovec;
	res = iovec_from_user(u64_to_user_ptr(desc->addr), nr_vecs,
			      nr_vecs, iov, ctx->compat);
	if (IS_ERR(res))
		return PTR_ERR(res);

	for (i = 0; i < nr_vecs; i++)
		total_len += iov[i].iov_len;

	iov_iter_init(iter, ddir, iov, nr_vecs, total_len);
	return 0;
}

/*
 * Helper to import a buffer into an iov_iter based on io_bpf_buf_desc.
 * Supports all 5 buffer types: USER, FIXED, VEC, KFIXED, KVEC.
 * Must be called with submit lock held for FIXED/KFIXED/KVEC types.
 *
 * @ctx: ring context
 * @iter: output iterator
 * @desc: buffer descriptor
 * @ddir: direction (ITER_SOURCE for source, ITER_DEST for destination)
 * @vec: iou_vec for VEC/KVEC types (caller must call io_vec_free after use)
 *
 * Returns node pointer (may be NULL for USER/VEC), or ERR_PTR on failure.
 * Caller must drop node reference when done if non-NULL.
 */
static struct io_rsrc_node *io_bpf_import_buffer(struct io_ring_ctx *ctx,
						 struct iov_iter *iter,
						 const struct io_bpf_buf_desc *desc,
						 int ddir, struct iou_vec *vec)
{
	int ret;

	switch (desc->type) {
	case IO_BPF_BUF_USER:
		/* Plain user buffer */
		ret = import_ubuf(ddir, u64_to_user_ptr(desc->addr),
				  desc->len, iter);
		return ret ? ERR_PTR(ret) : NULL;

	case IO_BPF_BUF_FIXED:
	case IO_BPF_BUF_KFIXED:
		/* FIXED: addr is absolute address within buffer */
		/* KFIXED: addr is offset from buffer start */
		return io_bpf_import_fixed_buf(ctx, iter, desc, ddir);

	case IO_BPF_BUF_VEC:
		/* Vectored user buffer - addr is iovec ptr, len is nr_vecs */
		ret = io_bpf_import_vec_buf(ctx, iter, desc, ddir, vec);
		return ret ? ERR_PTR(ret) : NULL;

	case IO_BPF_BUF_REG_VEC:
		/* Registered vectored buffer */
		return io_bpf_import_reg_vec(ctx, iter, desc, ddir, vec);

	default:
		return ERR_PTR(-EINVAL);
	}
}

__bpf_kfunc_start_defs();
__bpf_kfunc void uring_bpf_set_result(struct uring_bpf_data *data, int res)
{
	struct io_kiocb *req = cmd_to_io_kiocb(data);

	if (res < 0)
		req_set_fail(req);
	io_req_set_res(req, res, 0);
}

/**
 * uring_bpf_memcpy - Copy data between io_uring BPF buffers
 * @data: BPF request data containing request context
 * @dst: Destination buffer descriptor
 * @src: Source buffer descriptor
 *
 * Copies data from source buffer to destination buffer.
 * Supports all 5 buffer types: USER, FIXED, VEC, KFIXED, REG_VEC.
 * The copy length is min of actual buffer sizes (for VEC types,
 * total bytes across all vectors, not nr_vecs).
 *
 * Returns: Number of bytes copied on success, negative error code on failure
 */
__bpf_kfunc ssize_t uring_bpf_memcpy(const struct uring_bpf_data *data,
				     struct io_bpf_buf_desc *dst,
				     struct io_bpf_buf_desc *src)
{
	struct io_kiocb *req = cmd_to_io_kiocb((void *)data);
	struct io_ring_ctx *ctx = req->ctx;
	unsigned int issue_flags = data->issue_flags;
	struct io_rsrc_node *src_node, *dst_node;
	struct iov_iter src_iter, dst_iter;
	struct iou_vec src_vec = {};
	struct iou_vec dst_vec = {};
	ssize_t ret;
	size_t len;

	/* Validate buffer types */
	if (src->type > IO_BPF_BUF_REG_VEC || dst->type > IO_BPF_BUF_REG_VEC)
		return -EINVAL;

	io_ring_submit_lock(ctx, issue_flags);

	/* Import source buffer */
	src_node = io_bpf_import_buffer(ctx, &src_iter, src, ITER_SOURCE,
					&src_vec);
	if (IS_ERR(src_node)) {
		ret = PTR_ERR(src_node);
		goto unlock;
	}

	/* Import destination buffer */
	dst_node = io_bpf_import_buffer(ctx, &dst_iter, dst, ITER_DEST,
					&dst_vec);
	if (IS_ERR(dst_node)) {
		ret = PTR_ERR(dst_node);
		goto put_src;
	}

	/*
	 * Calculate copy length from actual iterator sizes.
	 * For VEC types, desc->len is nr_vecs, not total bytes.
	 */
	len = min(iov_iter_count(&src_iter), iov_iter_count(&dst_iter));
	if (!len) {
		ret = 0;
		goto put_dst;
	}
	if (len > MAX_RW_COUNT) {
		ret = -EINVAL;
		goto put_dst;
	}

	/* Copy data between iterators */
	ret = io_bpf_copy_iters(&src_iter, &dst_iter, len);

put_dst:
	io_vec_free(&dst_vec);
	if (dst_node)
		io_put_rsrc_node(ctx, dst_node);
put_src:
	io_vec_free(&src_vec);
	if (src_node)
		io_put_rsrc_node(ctx, src_node);
unlock:
	io_ring_submit_unlock(ctx, issue_flags);
	return ret;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(uring_bpf_kfuncs)
BTF_ID_FLAGS(func, uring_bpf_set_result)
BTF_ID_FLAGS(func, uring_bpf_memcpy)
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
