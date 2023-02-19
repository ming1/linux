// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FUSED_CMD_H
#define IOU_FUSED_CMD_H

int io_fused_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_fused_cmd(struct io_kiocb *req, unsigned int issue_flags);
void io_fused_cmd_return_kbuf(struct io_kiocb *slave);
int io_import_kbuf_for_slave(u64 buf, unsigned int len, int rw,
		struct iov_iter *iter, struct io_kiocb *slave);

#endif
