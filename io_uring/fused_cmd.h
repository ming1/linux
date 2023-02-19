// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FUSED_CMD_H
#define IOU_FUSED_CMD_H

int io_fused_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fused_cmd(struct io_kiocb *req, unsigned int issue_flags);
void io_fused_cmd_return_buf(struct io_kiocb *slave);
int io_import_buf_for_slave(unsigned long buf, unsigned int len, int dir,
		struct iov_iter *iter, struct io_kiocb *slave);

#endif
