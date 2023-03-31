// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_XPIPE_H
#define IOU_XPIPE_H

union xbuf_key_off {
	u64 addr;
	struct {
		u32 xbuf_key;
		u32 xbuf_off;
	};
};

static inline u64 xbuf_addr_to_off(u64 addr)
{
	union xbuf_key_off xk = {
		.addr = addr,
	};

	return (u64)xk.xbuf_off;
}

static inline u32 xbuf_addr_to_key(u64 addr)
{
	union xbuf_key_off xk = {
		.addr = addr,
	};

	return (u64)xk.xbuf_key;
}

int io_xpipe_import_buf(struct io_kiocb *req, u64 addr, unsigned int len,
		int dir, struct iov_iter *iter, unsigned issue_flags);
int io_xpipe_put_buf(struct io_kiocb *req, unsigned int issue_flags);
void io_xpipe_destroy(struct io_ring_ctx *ctx);

int io_xpipe_add_buf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_xpipe_add_buf(struct io_kiocb *req, unsigned int issue_flags);
int io_xpipe_del_buf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_xpipe_del_buf(struct io_kiocb *req, unsigned int issue_flags);

#endif
