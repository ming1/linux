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
#include "opdef.h"
#include "uring_cmd.h"
#include "fused_cmd.h"

static bool io_fused_secondary_valid(u8 op)
{
	if (op == IORING_OP_FUSED_CMD)
		return false;

	if (!io_issue_defs[op].fused_secondary)
		return false;

	return true;
}

static int io_fused_prep_provide_buf(struct io_uring_cmd *ioucmd,
		const struct io_uring_sqe *sqe)
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);
	unsigned int sqe_flags = READ_ONCE(sqe->flags);

	/*
	 * Primary command is for providing buffer, non-sense to
	 * set buffer select any more
	 */
	if (sqe_flags & REQ_F_BUFFER_SELECT)
		return -EINVAL;

	req->fused_cmd_kbuf = NULL;
	return 0;
}

int io_fused_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	const struct io_uring_sqe *secondary_sqe = NULL;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *secondary;
	u8 secondary_op;
	int ret;

	if (!(ctx->flags & IORING_SETUP_FUSED_REQ))
		return -EINVAL;

	if (unlikely(sqe->__pad1))
		return -EINVAL;

	/*
	 * Only support single secondary request, in future we may extend to
	 * support multiple secondary requests, which can be covered by
	 * multiple fused command now.
	 */
	if (unlikely(sqe->nr_secondary != 1))
		return -EINVAL;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);

	/* so far, only support plugin of providing buffer */
	if (ioucmd->flags & IORING_FUSED_CMD_BUF)
		ret = io_fused_prep_provide_buf(ioucmd, sqe);
	else
		ret = -EINVAL;
	if (ret)
		return ret;

	if (unlikely(!io_get_secondary_sqe(ctx, &secondary_sqe)))
		return -EINVAL;

	if (unlikely(!secondary_sqe))
		return -EINVAL;

	secondary_op = READ_ONCE(secondary_sqe->opcode);
	if (unlikely(!io_fused_secondary_valid(secondary_op)))
		return -EINVAL;

	ioucmd->cmd = sqe->cmd;
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);

	ret = -ENOMEM;
	if (unlikely(!io_alloc_req(ctx, &secondary)))
		goto fail;

	ret = io_init_secondary_req(ctx, secondary, secondary_sqe,
			REQ_F_FUSED_SECONDARY);
	if (unlikely(ret))
		goto fail_free_req;

	ioucmd->fused.data.__secondary = secondary;

	return 0;

fail_free_req:
	io_free_req(secondary);
fail:
	return ret;
}

int io_fused_cmd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	const struct io_kiocb *secondary = ioucmd->fused.data.__secondary;
	int ret = -EINVAL;

	if (ioucmd->flags & IORING_FUSED_CMD_BUF) {
		/*
		 * Pass buffer direction for driver for validating if the
		 * requested buffer direction is legal
		 */
		if (io_issue_defs[secondary->opcode].buf_dir)
			issue_flags |= IO_URING_F_FUSED_BUF_DEST;
		else
			issue_flags |= IO_URING_F_FUSED_BUF_SRC;
	}

	ret = io_uring_cmd(req, issue_flags);
	if (ret != IOU_ISSUE_SKIP_COMPLETE)
		io_free_req(ioucmd->fused.data.__secondary);

	return ret;
}

/*
 * Called after secondary request is completed,
 *
 * Notify primary request by the saved callback that we are done
 */
void io_fused_cmd_complete_secondary(struct io_kiocb *secondary)
{
	struct io_kiocb *req = secondary->fused_primary_req;
	struct io_uring_cmd *ioucmd;

	if (unlikely(!req || !(secondary->flags & REQ_F_FUSED_SECONDARY)))
		return;

	/* notify primary command that we are done */
	secondary->fused_primary_req = NULL;
	ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	ioucmd->fused.data.__secondary = NULL;

	io_uring_cmd_complete_in_task(ioucmd, ioucmd->task_work_cb);
}

/* only for IORING_FUSED_CMD_BUF */
int io_import_buf_from_fused(unsigned long buf_off, unsigned int len,
		int dir, struct iov_iter *iter, struct io_kiocb *secondary)
{
	struct io_kiocb *req = secondary->fused_primary_req;
	const struct io_uring_bvec_buf *kbuf;
	struct io_uring_cmd *primary;
	unsigned long offset;

	if (unlikely(!(secondary->flags & REQ_F_FUSED_SECONDARY) || !req))
		return -EINVAL;

	if (unlikely(!req->fused_cmd_kbuf))
		return -EINVAL;

	primary = io_kiocb_to_cmd(req, struct io_uring_cmd);
	if (unlikely(!(primary->flags & IORING_FUSED_CMD_BUF)))
		return -EINVAL;

	/* req->fused_cmd_kbuf is immutable */
	kbuf = req->fused_cmd_kbuf;
	offset = kbuf->offset;

	if (!kbuf->bvec)
		return -EINVAL;

	if (unlikely(buf_off > kbuf->len))
		return -EFAULT;

	if (unlikely(len > kbuf->len - buf_off))
		return -EFAULT;

	/* don't use io_import_fixed which doesn't support multipage bvec */
	offset += buf_off;
	iov_iter_bvec(iter, dir, kbuf->bvec, kbuf->nr_bvecs, offset + len);

	if (offset)
		iov_iter_advance(iter, offset);

	return 0;
}

/*
 * Called for starting secondary request after primary command prepared io
 * buffer, only for IORING_FUSED_CMD_BUF
 *
 * Secondary request borrows primary's io buffer for handling the secondary
 * operation, and the buffer is returned back via io_fused_complete_secondary
 * after the secondary request is completed. Meantime the primary command is
 * completed. And driver gets completion notification by the passed callback
 * of @complete_tw_cb.
 */
void io_fused_provide_buf_and_start(struct io_uring_cmd *ioucmd,
		unsigned issue_flags,
		const struct io_uring_bvec_buf *fused_cmd_kbuf,
		void (*complete_tw_cb)(struct io_uring_cmd *, unsigned))
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);
	struct io_kiocb *secondary = ioucmd->fused.data.__secondary;
	struct io_tw_state ts = {
		.locked = !(issue_flags & IO_URING_F_UNLOCKED),
	};

	if (unlikely(!(ioucmd->flags & IORING_FUSED_CMD_BUF)))
		return;

	if (WARN_ON_ONCE(unlikely(!secondary || !(secondary->flags &
						REQ_F_FUSED_SECONDARY))))
		return;

	/*
	 * Once the fused secondary request is completed and the buffer isn't be
	 * used, the driver will be notified by callback of complete_tw_cb
	 */
	ioucmd->task_work_cb = complete_tw_cb;

	/* now we get the buffer */
	req->fused_cmd_kbuf = fused_cmd_kbuf;
	secondary->fused_primary_req = req;

	trace_io_uring_submit_sqe(secondary, true);
	io_req_task_submit(secondary, &ts);
}
EXPORT_SYMBOL_GPL(io_fused_provide_buf_and_start);
