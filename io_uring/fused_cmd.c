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
#include "rsrc.h"
#include "uring_cmd.h"
#include "fused_cmd.h"

static bool io_fused_slave_valid(const struct io_uring_sqe *sqe, u8 op)
{
	unsigned int sqe_flags = READ_ONCE(sqe->flags);

	if (op == IORING_OP_FUSED_CMD || op == IORING_OP_URING_CMD)
		return false;

	if (sqe_flags & REQ_F_BUFFER_SELECT)
		return false;

	if (!io_issue_defs[op].fused_slave)
		return false;

	return true;
}

static inline void io_fused_cmd_update_link_flags(struct io_kiocb *req,
		const struct io_kiocb *slave)
{
	/*
	 * We have to keep slave SQE in order, so update master link flags
	 * with slave request's given master command isn't completed until
	 * the slave request is done
	 */
	if (slave->flags & (REQ_F_LINK | REQ_F_HARDLINK))
		req->flags |= REQ_F_LINK;
}

int io_fused_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	const struct io_uring_sqe *slave_sqe = sqe + 1;
	struct io_ring_ctx *ctx = req->ctx;
	struct io_kiocb *slave;
	u8 slave_op;
	int ret;

	if (unlikely(!(ctx->flags & IORING_SETUP_SQE128)))
		return -EINVAL;

	if (unlikely(sqe->__pad1))
		return -EINVAL;

	ioucmd->flags = READ_ONCE(sqe->uring_cmd_flags);
	if (unlikely(ioucmd->flags))
		return -EINVAL;

	slave_op = READ_ONCE(slave_sqe->opcode);
	if (unlikely(!io_fused_slave_valid(slave_sqe, slave_op)))
		return -EINVAL;

	ioucmd->cmd = sqe->cmd;
	ioucmd->cmd_op = READ_ONCE(sqe->cmd_op);
	req->fused_cmd_kbuf = NULL;

	/* take one extra reference for the slave request */
	io_get_task_refs(1);

	ret = -ENOMEM;
	if (unlikely(!io_alloc_req(ctx, &slave)))
		goto fail;

	ret = io_init_slave_req(ctx, slave, slave_sqe);
	if (unlikely(ret))
		goto fail_free_req;

	/*
	 * The slave request won't be linked to io_uring submission link list,
	 * so it can't be handled by IORING_OP_LINK_TIMEOUT, however, we can do
	 * that on master command directly
	 */
	io_fused_cmd_update_link_flags(req, slave);

	ioucmd->fused.data.__slave = slave;

	return 0;

fail_free_req:
	io_free_req(slave);
fail:
	current->io_uring->cached_refs += 1;
	return ret;
}

int io_fused_cmd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_uring_cmd *ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	const struct io_kiocb *slave = ioucmd->fused.data.__slave;
	int ret = -EINVAL;

	/*
	 * Pass buffer direction for driver to validate if the requested buffer
	 * direction is legal
	 */
	if (io_issue_defs[slave->opcode].buf_dir)
		issue_flags |= IO_URING_F_FUSED_BUF_DEST;
	else
		issue_flags |= IO_URING_F_FUSED_BUF_SRC;

	ret = io_uring_cmd(req, issue_flags);
	if (ret != IOU_ISSUE_SKIP_COMPLETE)
		io_free_req(ioucmd->fused.data.__slave);

	return ret;
}

int io_import_buf_for_slave(unsigned long buf_off, unsigned int len, int dir,
		struct iov_iter *iter, struct io_kiocb *slave)
{
	struct io_kiocb *req = slave->fused_master_req;
	const struct io_uring_bvec_buf *kbuf;
	unsigned long offset;

	if (unlikely(!(slave->flags & REQ_F_FUSED_SLAVE) || !req))
		return -EINVAL;

	if (unlikely(!req->fused_cmd_kbuf))
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
 * Called after slave request is completed,
 *
 * Return back master's fused_cmd kbuf, and notify master request by
 * the saved callback.
 */
void io_fused_cmd_return_buf(struct io_kiocb *slave)
{
	struct io_kiocb *req = slave->fused_master_req;
	struct io_uring_cmd *ioucmd;

	if (unlikely(!req || !(slave->flags & REQ_F_FUSED_SLAVE)))
		return;

	/* return back the buffer */
	slave->fused_master_req = NULL;
	ioucmd = io_kiocb_to_cmd(req, struct io_uring_cmd);
	ioucmd->fused.data.__slave = NULL;

	/*
	 * If slave OP skips CQE, return the result via master command; or
	 * if slave request is failed, REQ_F_CQE_SKIP will be cleared, return
	 * result too
	 */
	if ((slave->flags & REQ_F_CQE_SKIP) || slave->cqe.res < 0)
		ioucmd->fused.data.slave_res = slave->cqe.res;
	else
		ioucmd->fused.data.slave_res = 0;
	io_uring_cmd_complete_in_task(ioucmd, ioucmd->task_work_cb);
}

/*
 * Called for starting slave request after master command prepared io buffer.
 *
 * The io buffer is represented by @fused_cmd_kbuf, which is read only for
 * slave request, however slave request can retrieve any sub-buffer by its
 * sqe->addr(offset) & sqe->len. For slave request, io buffer is imported
 * by io_import_buf_for_slave().
 *
 * Slave request borrows master's io buffer for handling the slave operation,
 * and the buffer is returned back via io_fused_cmd_return_buf after the slave
 * request is completed. Meantime the master command is completed from
 * io_fused_cmd_return_buf(). And driver gets completion notification by
 * the passed callback of @complete_tw_cb.
 */
void io_fused_cmd_start_slave_req(struct io_uring_cmd *ioucmd, bool locked,
		const struct io_uring_bvec_buf *fused_cmd_kbuf,
		void (*complete_tw_cb)(struct io_uring_cmd *))
{
	struct io_kiocb *req = cmd_to_io_kiocb(ioucmd);
	struct io_kiocb *slave = ioucmd->fused.data.__slave;

	if (WARN_ON_ONCE(unlikely(!slave ||
					!(slave->flags & REQ_F_FUSED_SLAVE))))
		return;

	/*
	 * Once the fused slave request is completed and the buffer isn't be
	 * used, the driver will be notified by callback of complete_tw_cb
	 */
	ioucmd->task_work_cb = complete_tw_cb;

	/* now we get the buffer */
	req->fused_cmd_kbuf = fused_cmd_kbuf;
	slave->fused_master_req = req;

	trace_io_uring_submit_sqe(slave, true);
	if (locked)
		io_req_task_submit(slave, &locked);
	else
		io_req_task_queue(slave);
}
EXPORT_SYMBOL_GPL(io_fused_cmd_start_slave_req);
