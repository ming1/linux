// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "uring_cmd.h"
#include "xpipe.h"

static inline const struct io_uring_bvec_buf *xbuf_to_bbuf(
		struct io_uring_xpipe_buf *xbuf)
{
	return &xbuf->__buf;
}

static inline unsigned long io_xbuf_key(u16 xpipe_id, u32 xbuf_key)
{
	return ((unsigned long)xpipe_id << 32) | xbuf_key;
}

static void io_xpipe_remove_buf(struct io_ring_ctx *ctx,
		struct io_uring_xpipe_buf *xbuf)
{
	unsigned long key = io_xbuf_key(xbuf->xpipe_id, xbuf->xbuf_key);

	xbuf->flags |= IO_URING_XBUF_KILLED;
	xa_erase(&ctx->xpipe, key);
	xbuf->buf_release_fn(xbuf);
}

void io_xpipe_destroy(struct io_ring_ctx *ctx)
{
	struct io_uring_xpipe_buf *xbuf;
	unsigned long index;

	xa_for_each(&ctx->xpipe, index, xbuf)
		io_xpipe_remove_buf(ctx, xbuf);
}

/* ->uring_lock covers load & erase */
int io_xpipe_put_buf(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_xpipe_buf *xbuf = req->xbuf;

	if (unlikely(!xbuf || !(req->flags & REQ_F_XPIPE_BUF)))
		return -EINVAL;

	io_ring_submit_lock(req->ctx, issue_flags);
	++xbuf->comp_cnt;
	if (xbuf->flags & IO_URING_XBUF_KILLED) {
		if (xbuf->comp_cnt == xbuf->submit_cnt)
			xbuf->buf_release_fn(xbuf);
	}
	req->xbuf = NULL;
	req->flags &= ~REQ_F_XPIPE_BUF;
	io_ring_submit_unlock(req->ctx, issue_flags);

	return 0;
}

static int io_xpipe_kill_buf(struct io_kiocb *req, u16 xpipe_id, u32 xbuf_key)
{
	unsigned long index = io_xbuf_key(xpipe_id, xbuf_key);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_xpipe_buf *xbuf;

	xbuf = (struct io_uring_xpipe_buf *)xa_load(&ctx->xpipe, index);
	if (!xbuf)
		return -EINVAL;

	if (atomic_dec_return(&xbuf->ref) == 0) {
		xbuf->flags |= IO_URING_XBUF_KILLED;
		__xa_erase(&ctx->xpipe, index);
		if (xbuf->submit_cnt == xbuf->comp_cnt)
			xbuf->buf_release_fn(xbuf);
	}
	return 0;
}

/*
 *  Add one xbuf to xpipe.
 *
 *  Grab one reference of xbuf, and the xbuf doesn't leave xpipe until the
 *  reference drops to zero. So multiple OP_ADD_BUF can work just fine.
 */
int io_uring_produce_xbuf(struct io_uring_cmd *ioucmd,
		struct io_uring_xpipe_buf *xbuf, unsigned xbuf_flags,
		unsigned issue_flags, bool *was_present)
{
	const struct io_uring_bvec_buf *bbuf = xbuf_to_bbuf(xbuf);
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);
	struct io_ring_ctx *ctx = req->ctx;
	unsigned long index;
	int ret = -EINVAL;

	/*
	 * We just call ->buf_release_fn() once after returning back the buffer,
	 * so have to tell producer if the buffer was present or new added
	 */
	if (!was_present)
		return -EINVAL;

	io_ring_submit_lock(ctx, issue_flags);

	if (!xbuf || !xbuf->buf_release_fn)
		goto unlock;

	if (!(xbuf_flags & (IO_URING_XBUF_SOURCE | IO_URING_XBUF_DEST)))
		goto unlock;

	if (!bbuf || !bbuf->bvec || !bbuf->nr_bvecs || !bbuf->len)
		goto unlock;

	atomic_inc(&xbuf->ref);

	index = io_xbuf_key(ioucmd->xpipe_id, ioucmd->xbuf_key);
	ret = __xa_insert(&ctx->xpipe, index, xbuf, GFP_KERNEL);
	if (unlikely(ret))
		goto unlock;

	*was_present = 0;
	xbuf_flags &= ~IO_URING_XBUF_KILLED;
	xbuf->flags = xbuf_flags | IO_URING_XBUF_ACTIVE;
	xbuf->submit_cnt = xbuf->comp_cnt = 0;
	xbuf->xpipe_id = ioucmd->xpipe_id;
	xbuf->xbuf_key = ioucmd->xbuf_key;
unlock:

	/*
	 * If the buffer has been added to xpipe already, let OP_ADD_BUF
	 * return successfully, so userspace still can use this buffer
	 */
	if (ret == -EBUSY) {
		ret = 0;
		*was_present = 1;
	}

	if (ret)
		atomic_dec(&xbuf->ref);

	io_ring_submit_unlock(ctx, issue_flags);

	return ret;
}
EXPORT_SYMBOL_GPL(io_uring_produce_xbuf);

static inline int io_xpipe_req_valid(struct io_uring_cmd *ioucmd, unsigned mask)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);

	if (!(req->ctx->flags & IORING_SETUP_XPIPE))
		return -EINVAL;

	if (req->flags & REQ_F_BUFFER_SELECT)
		return -EINVAL;

	if (ioucmd->flags & ~mask)
		return -EINVAL;

	return 0;
}

int io_xpipe_del_buf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	int ret;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	ret = io_xpipe_req_valid(ioucmd, IORING_URING_CMD_XPIPE);
	if (ret)
		return ret;

	ioucmd->cmd = sqe->cmd;
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);
	ioucmd->xpipe_id = READ_ONCE(sqe->xpipe_id);
	ioucmd->xbuf_key = READ_ONCE(sqe->xbuf_key);

	return 0;
}

int io_xpipe_del_buf(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	u16 xpipe_id = ioucmd->xpipe_id;
	u32 xbuf_key = ioucmd->xbuf_key;
	int ret;

	io_ring_submit_lock(req->ctx, issue_flags);
	ret = io_xpipe_kill_buf(req, xpipe_id, xbuf_key);
	io_ring_submit_unlock(req->ctx, issue_flags);

	return ret;
}

int io_xpipe_add_buf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	int ret;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	ret = io_xpipe_req_valid(ioucmd, IORING_URING_CMD_XPIPE);
	if (ret)
		return ret;

	ioucmd->cmd = sqe->cmd;
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);

	/* The two can only be referred in ->uring_cmd() */
	ioucmd->xpipe_id = READ_ONCE(sqe->xpipe_id);
	ioucmd->xbuf_key = READ_ONCE(sqe->xbuf_key);

	return 0;
}

int io_xpipe_add_buf(struct io_kiocb *req, unsigned int issue_flags)
{
	/*
	 * Only support by ->uring_cmd now, in future if there are more
	 * requirements on xpipe, we can add new fs callback for producing
	 * xpipe buf
	 */
	return io_uring_cmd(req, issue_flags);
}

/*
 * One xbuf in xpipe can be used by more than one OPs, so use ->submit_cnt
 * to track how many users submitted with this xbuf, and use ->comp_cnt
 * to track how many users completed with this xbuf. xbuf can only be
 * killed if there isn't any inflight OPs
 */
int io_xpipe_setup_xbuf(struct io_kiocb *req, unsigned int xbuf_key)
{
	unsigned long key = io_xbuf_key(req->xpipe_id, xbuf_key);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_uring_xpipe_buf *xbuf;

	if (req->xbuf)
		return 0;

	if (unlikely(!(req->flags & REQ_F_XPIPE_BUF)))
		return -EINVAL;

	/* we are using xpipe buf */
	if (unlikely(req->flags & REQ_F_BUFFER_SELECT))
		return -EINVAL;

	xbuf = (struct io_uring_xpipe_buf *)xa_load(&ctx->xpipe, key);
	if (unlikely(!xbuf))
		return -EINVAL;

	if (unlikely(xbuf->flags & IO_URING_XBUF_KILLED))
		return -EINVAL;

	if (unlikely(!(xbuf->flags & IO_URING_XBUF_ACTIVE)))
		return -EINVAL;

	xbuf->submit_cnt += 1;
	req->xbuf = xbuf;
	return 0;
}

static bool io_xpipe_check_buf_dir(struct io_uring_xpipe_buf *xbuf, int op_dir)
{
	if (op_dir == ITER_DEST && (xbuf->flags & IO_URING_XBUF_DEST))
		return true;

	if (op_dir == ITER_SOURCE && (xbuf->flags & IO_URING_XBUF_SOURCE))
		return true;

	return false;
}

/* called from consumer's ->issue() */
int io_xpipe_import_buf(struct io_kiocb *req, u64 addr, unsigned int len,
		int dir, struct iov_iter *iter, unsigned issue_flags)
{
	const struct io_uring_bvec_buf *buf;
	struct io_uring_xpipe_buf *xbuf = req->xbuf;
	unsigned int buf_off = (unsigned int)xbuf_addr_to_off(addr);
	unsigned long offset;

	if (unlikely(!(req->flags & REQ_F_XPIPE_BUF)))
		return -EINVAL;

	if (!xbuf) {
		u32 key = xbuf_addr_to_key(addr);
		int ret = 0;

		io_ring_submit_lock(req->ctx, issue_flags);
		ret = io_xpipe_setup_xbuf(req, key);
		io_ring_submit_unlock(req->ctx, issue_flags);

		if (ret)
			return ret;
		xbuf = req->xbuf;
	}

	if (!xbuf)
		return -EINVAL;

	if (!io_xpipe_check_buf_dir(xbuf, dir))
		return -EACCES;

	buf = xbuf_to_bbuf(xbuf);
	offset = buf->offset;

	if (unlikely(buf_off > buf->len))
		return -EFAULT;

	if (unlikely(len > buf->len - buf_off))
		return -EFAULT;

	/* don't use io_import_fixed which doesn't support multipage bvec */
	offset += buf_off;
	iov_iter_bvec(iter, dir, buf->bvec, buf->nr_bvecs, offset + len);

	if (offset)
		iov_iter_advance(iter, offset);

	return 0;
}
