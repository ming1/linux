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
	if (unlikely(ioucmd->flags))
		return -EINVAL;

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
	int ret = -EINVAL;

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
