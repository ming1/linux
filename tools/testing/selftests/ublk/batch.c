/* SPDX-License-Identifier: MIT */
/*
 * Description: UBLK_F_BATCH_IO implementation
 */

#include "kublk.h"

static inline void *ublk_get_commit_buf(struct ublk_thread *t,
					unsigned short buf_idx)
{
	unsigned idx;

	if (buf_idx < t->commit_buf_start ||
			buf_idx >= t->commit_buf_start + UBLKS_T_COMMIT_BUF_NR)
		return NULL;
	idx = buf_idx - t->commit_buf_start;
	return t->commit_buf + idx * t->commit_buf_size;
}

static inline unsigned short ublk_alloc_commit_buf(struct ublk_thread *t)
{
	int i;

	for (i = 0; i < UBLKS_T_COMMIT_BUF_NR; i++) {
		if (!t->commit_buf_busy[i]) {
			t->commit_buf_busy[i] = 1;
			return i + t->commit_buf_start;
		}
	}
	return -1;
}

static inline void ublk_free_commit_buf(struct ublk_thread *t,
					 unsigned short i)
{
	unsigned short idx = i - t->commit_buf_start;

	assert(idx < UBLKS_T_COMMIT_BUF_NR);
	assert(t->commit_buf_busy[idx]);
	t->commit_buf_busy[idx] = 0;
}

static unsigned char ublk_commit_elem_buf_size(struct ublk_dev *dev)
{
	/* tag(2bytes) + buf_idx(2bytes) + result(4bytes) */
	if (dev->dev_info.flags & (UBLK_F_SUPPORT_ZERO_COPY | UBLK_F_AUTO_BUF_REG))
		return 8;

	/* one extra 8bytes for carrying buffer address */
	return 16;
}

static unsigned ublk_commit_buf_size(struct ublk_thread *t)
{
	struct ublk_dev *dev = t->dev;
	unsigned elem_size = ublk_commit_elem_buf_size(dev);
	unsigned int total = elem_size * dev->dev_info.queue_depth;

	return (total + 64 - 1) & ~(64 - 1);
}

static int alloc_batch_commit_buf(struct ublk_thread *t)
{
	unsigned buf_size = ublk_commit_buf_size(t);
	unsigned int total = buf_size * UBLKS_T_COMMIT_BUF_NR;
	struct iovec iov[UBLKS_T_COMMIT_BUF_NR];
	void *buf = NULL;
	int i;

	posix_memalign(&buf, 64, total);
	if (!buf)
		return -ENOMEM;

	t->commit_buf = buf;
	for (i = 0; i < UBLKS_T_COMMIT_BUF_NR; i++) {
		iov[i].iov_base = buf;
		iov[i].iov_len = buf_size;
		buf += buf_size;
	}

	i = io_uring_register_buffers_update_tag(&t->ring,
			t->commit_buf_start, iov, NULL,
			UBLKS_T_COMMIT_BUF_NR);
	if (i == UBLKS_T_COMMIT_BUF_NR)
		return 0;
	return i;
}

static void ublk_init_batch_cmd(struct ublk_thread *t, struct ublk_queue *q,
				struct io_uring_sqe *sqe, unsigned op,
				unsigned short elem_bytes,
				unsigned short nr_elem,
				unsigned short buf_idx)
{
	struct ublk_batch_io *cmd;
	__u64 user_data;

	cmd = (struct ublk_batch_io *)ublk_get_sqe_cmd(sqe);

	ublk_set_sqe_cmd_op(sqe, op);

	sqe->fd	= 0;	/* dev->fds[0] */
	sqe->opcode	= IORING_OP_URING_CMD;
	sqe->flags	= IOSQE_FIXED_FILE;

	cmd->q_id	= q->q_id;
	cmd->flags	= 0;
	cmd->reserved 	= 0;
	cmd->elem_bytes = elem_bytes;
	cmd->nr_elem	= nr_elem;

	user_data = build_user_data(buf_idx, _IOC_NR(op), 0, q->q_id, 0);
	io_uring_sqe_set_data64(sqe, user_data);

	t->cmd_inflight += 1;

	ublk_dbg(UBLK_DBG_IO_CMD, "%s: thread %u qid %d cmd_op %x data %lx "
			"nr_elem %u elem_bytes %u buf_size %u buf_idx %d "
			"cmd_inflight %u\n",
			__func__, t->idx, q->q_id, op, user_data,
			cmd->nr_elem, cmd->elem_bytes,
			nr_elem * elem_bytes, buf_idx, t->cmd_inflight);
}

static void ublk_setup_commit_sqe(struct ublk_queue *q,
				  struct io_uring_sqe *sqe,
				  unsigned short buf_idx)
{
	struct ublk_batch_io *cmd;

	cmd = (struct ublk_batch_io *)ublk_get_sqe_cmd(sqe);

	sqe->rw_flags= IORING_URING_CMD_FIXED;
	sqe->buf_index = buf_idx;

	if (q->state & UBLKS_Q_AUTO_BUF_REG)
		cmd->flags |= UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK;
	if (!(q->state & UBLKS_Q_NO_BUF))
		cmd->flags |= UBLK_BATCH_F_HAS_BUF_ADDR;
}

int ublk_batch_queue_prep_io_cmds(struct ublk_thread *t, struct ublk_queue *q)
{
	unsigned short nr_elem = ublk_commit_buf_size(t) /
		t->commit_buf_elem_size;
	unsigned short buf_idx = ublk_alloc_commit_buf(t);
	struct io_uring_sqe *sqe;
	void *buf;
	int i;

	assert(buf_idx != UBLKS_T_COMMIT_BUF_INV_IDX);

	ublk_io_alloc_sqes(t, &sqe, 1);

	assert(nr_elem == q->q_depth);
	buf = ublk_get_commit_buf(t, buf_idx);
	for (i = 0; i < nr_elem; i++) {
		struct ublk_batch_elem *elem = (struct ublk_batch_elem *)(
				buf + i * t->commit_buf_elem_size);
		struct ublk_io *io = &q->ios[i];

		elem->tag = io->tag;
		elem->buf_index = io->buf_index;
		elem->result = 0;
		if (!(q->state & UBLKS_Q_NO_BUF))
			elem->buf_addr = (__u64)io->buf_addr;
	}

	sqe->addr = (__u64)buf;
	sqe->len = t->commit_buf_size;

	ublk_init_batch_cmd(t, q, sqe, UBLK_U_IO_PREP_IO_CMDS,
			t->commit_buf_elem_size, nr_elem, buf_idx);
	ublk_setup_commit_sqe(q, sqe, buf_idx);
	return 0;
}

static void ublk_batch_compl_commit_cmd(struct ublk_thread *t,
					const struct io_uring_cqe *cqe,
					unsigned op)
{
	unsigned short buf_idx = user_data_to_tag(cqe->user_data);

	if (op == _IOC_NR(UBLK_U_IO_PREP_IO_CMDS))
		assert(cqe->res == 0);
	else if (op == _IOC_NR(UBLK_U_IO_COMMIT_IO_CMDS))
		;//assert(cqe->res == t->commit_buf_size);
	else
		assert(0);

	ublk_free_commit_buf(t, buf_idx);
}

void ublk_batch_compl_cmd(struct ublk_thread *t, struct ublk_queue *q,
			  const struct io_uring_cqe *cqe)
{
	unsigned op = user_data_to_op(cqe->user_data);

	if (op == _IOC_NR(UBLK_U_IO_PREP_IO_CMDS) ||
			op == _IOC_NR(UBLK_U_IO_COMMIT_IO_CMDS)) {
		ublk_batch_compl_commit_cmd(t, cqe, op);
		return;
	}
}

void ublk_batch_prep_alloc_buf(struct ublk_thread *t)
{
	t->commit_buf_elem_size = ublk_commit_elem_buf_size(t->dev);
	t->commit_buf_size = ublk_commit_buf_size(t);
	t->commit_buf_start = t->nr_bufs;
	t->nr_bufs += UBLKS_T_COMMIT_BUF_NR;
}

int ublk_batch_alloc_buf(struct ublk_thread *t)
{
	return alloc_batch_commit_buf(t);
}

void ublk_batch_free_buf(struct ublk_thread *t)
{
	free(t->commit_buf);
}
