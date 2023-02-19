// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FUSED_CMD_H
#define IOU_FUSED_CMD_H

int io_fused_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fused_cmd(struct io_kiocb *req, unsigned int issue_flags);
void io_fused_cmd_complete_secondary(struct io_kiocb *secondary);
int io_import_buf_from_fused(unsigned long buf_off, unsigned int len,
		int dir, struct iov_iter *iter, struct io_kiocb *secondary);

static inline bool io_req_use_fused_buf(struct io_kiocb *req)
{
	return (req->flags & REQ_F_FUSED_SECONDARY) && req->fused_primary_req;
}

#endif
