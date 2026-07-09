// SPDX-License-Identifier: GPL-2.0
#include <linux/blk-integrity.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include "ublk.h"

static inline bool ublk_io_evts_empty(const struct ublk_queue *q)
{
	return kfifo_is_empty(&q->evts_fifo);
}

static struct ublk_batch_fetch_cmd *
ublk_batch_alloc_fcmd(struct io_uring_cmd *cmd)
{
	struct ublk_batch_fetch_cmd *fcmd = kzalloc_obj(*fcmd, GFP_NOIO);

	if (fcmd) {
		fcmd->cmd = cmd;
		fcmd->buf_group = READ_ONCE(cmd->sqe->buf_index);
	}
	return fcmd;
}

static void ublk_batch_free_fcmd(struct ublk_batch_fetch_cmd *fcmd)
{
	kfree(fcmd);
}

static void __ublk_release_fcmd(struct ublk_queue *ubq)
{
	WRITE_ONCE(ubq->active_fcmd, NULL);
}

/*
 * Nothing can move on, so clear ->active_fcmd, and the caller should stop
 * dispatching
 */
static void ublk_batch_deinit_fetch_buf(struct ublk_queue *ubq,
					const struct ublk_batch_io_data *data,
					struct ublk_batch_fetch_cmd *fcmd,
					int res)
{
	spin_lock(&ubq->evts_lock);
	list_del_init(&fcmd->node);
	WARN_ON_ONCE(fcmd != ubq->active_fcmd);
	__ublk_release_fcmd(ubq);
	spin_unlock(&ubq->evts_lock);

	io_uring_cmd_done(fcmd->cmd, res, data->issue_flags);
	ublk_batch_free_fcmd(fcmd);
}

static int ublk_batch_fetch_post_cqe(struct ublk_batch_fetch_cmd *fcmd,
				     struct io_br_sel *sel,
				     unsigned int issue_flags)
{
	if (io_uring_mshot_cmd_post_cqe(fcmd->cmd, sel, issue_flags))
		return -ENOBUFS;
	return 0;
}

static ssize_t ublk_batch_copy_io_tags(struct ublk_batch_fetch_cmd *fcmd,
				       void __user *buf, const u16 *tag_buf,
				       unsigned int len)
{
	if (copy_to_user(buf, tag_buf, len))
		return -EFAULT;
	return len;
}

static bool __ublk_batch_prep_dispatch(struct ublk_queue *ubq,
				       const struct ublk_batch_io_data *data,
				       unsigned short tag)
{
	struct ublk_device *ub = data->ub;
	struct ublk_io *io = &ubq->ios[tag];
	struct request *req = blk_mq_tag_to_rq(ub->tag_set.tags[ubq->q_id], tag);
	enum auto_buf_reg_res res = AUTO_BUF_REG_FALLBACK;
	struct io_uring_cmd *cmd = data->cmd;

	if (!ublk_start_io(ubq, req, io))
		return false;

	if (ublk_support_auto_buf_reg(ubq) && blk_rq_has_data(req)) {
		res = ublk_auto_buf_register(ubq, req, io, cmd,
				data->issue_flags);

		if (res == AUTO_BUF_REG_FAIL)
			return false;
	}

	ublk_io_lock(io);
	ublk_auto_buf_io_setup(ubq, req, io, cmd, res);
	ublk_io_unlock(io);

	return true;
}

static bool ublk_batch_prep_dispatch(struct ublk_queue *ubq,
				     const struct ublk_batch_io_data *data,
				     unsigned short *tag_buf,
				     unsigned int len)
{
	bool has_unused = false;
	unsigned int i;

	for (i = 0; i < len; i++) {
		unsigned short tag = tag_buf[i];

		if (!__ublk_batch_prep_dispatch(ubq, data, tag)) {
			tag_buf[i] = UBLK_BATCH_IO_UNUSED_TAG;
			has_unused = true;
		}
	}

	return has_unused;
}

/*
 * Filter out UBLK_BATCH_IO_UNUSED_TAG entries from tag_buf.
 * Returns the new length after filtering.
 */
static noinline unsigned int ublk_filter_unused_tags(unsigned short *tag_buf,
					    unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; i < len; i++) {
		if (tag_buf[i] != UBLK_BATCH_IO_UNUSED_TAG) {
			if (i != j)
				tag_buf[j] = tag_buf[i];
			j++;
		}
	}

	return j;
}

static noinline void ublk_batch_dispatch_fail(struct ublk_queue *ubq,
		const struct ublk_batch_io_data *data,
		unsigned short *tag_buf, size_t len, int ret)
{
	int i, res;

	/*
	 * Undo prep state for all IOs since userspace never received them.
	 * This restores IOs to pre-prepared state so they can be cleanly
	 * re-prepared when tags are pulled from FIFO again.
	 */
	for (i = 0; i < len; i++) {
		struct ublk_io *io = &ubq->ios[tag_buf[i]];
		int index = -1;

		ublk_io_lock(io);
		if (io->flags & UBLK_IO_FLAG_AUTO_BUF_REG)
			index = io->buf.auto_reg.index;
		io->flags &= ~(UBLK_IO_FLAG_OWNED_BY_SRV | UBLK_IO_FLAG_AUTO_BUF_REG);
		io->flags |= UBLK_IO_FLAG_ACTIVE;
		ublk_io_unlock(io);

		if (index != -1)
			io_buffer_unregister_bvec(data->cmd, index,
					data->issue_flags);
	}

	res = kfifo_in_spinlocked_noirqsave(&ubq->evts_fifo,
		tag_buf, len, &ubq->evts_lock);

	pr_warn_ratelimited("%s: copy tags or post CQE failure, move back "
			"tags(%d %zu) ret %d\n", __func__, res, len,
			ret);
}

static int __ublk_batch_dispatch(struct ublk_queue *ubq,
				 const struct ublk_batch_io_data *data,
				 struct ublk_batch_fetch_cmd *fcmd)
{
	const unsigned int tag_sz = sizeof(unsigned short);
	unsigned short tag_buf[MAX_NR_TAG];
	struct io_br_sel sel;
	size_t len = 0;
	bool needs_filter;
	int ret;

	WARN_ON_ONCE(data->cmd != fcmd->cmd);

	sel = io_uring_cmd_buffer_select(fcmd->cmd, fcmd->buf_group, &len,
					 data->issue_flags);
	if (sel.val < 0)
		return sel.val;
	if (!sel.addr)
		return -ENOBUFS;

	/* single reader needn't lock and sizeof(kfifo element) is 2 bytes */
	len = min(len, sizeof(tag_buf)) / tag_sz;
	len = kfifo_out(&ubq->evts_fifo, tag_buf, len);

	needs_filter = ublk_batch_prep_dispatch(ubq, data, tag_buf, len);
	/* Filter out unused tags before posting to userspace */
	if (unlikely(needs_filter)) {
		int new_len = ublk_filter_unused_tags(tag_buf, len);

		/* return actual length if all are failed or requeued */
		if (!new_len) {
			/* release the selected buffer */
			sel.val = 0;
			WARN_ON_ONCE(!io_uring_mshot_cmd_post_cqe(fcmd->cmd,
						&sel, data->issue_flags));
			return len;
		}
		len = new_len;
	}

	sel.val = ublk_batch_copy_io_tags(fcmd, sel.addr, tag_buf, len * tag_sz);
	ret = ublk_batch_fetch_post_cqe(fcmd, &sel, data->issue_flags);
	if (unlikely(ret < 0))
		ublk_batch_dispatch_fail(ubq, data, tag_buf, len, ret);
	return ret;
}

static struct ublk_batch_fetch_cmd *__ublk_acquire_fcmd(
		struct ublk_queue *ubq)
{
	struct ublk_batch_fetch_cmd *fcmd;

	lockdep_assert_held(&ubq->evts_lock);

	/*
	 * Ordering updating ubq->evts_fifo and checking ubq->active_fcmd.
	 *
	 * The pair is the smp_mb() in ublk_batch_dispatch().
	 *
	 * If ubq->active_fcmd is observed as non-NULL, the new added tags
	 * can be visisible in ublk_batch_dispatch() with the barrier pairing.
	 */
	smp_mb();
	if (READ_ONCE(ubq->active_fcmd)) {
		fcmd = NULL;
	} else {
		fcmd = list_first_entry_or_null(&ubq->fcmd_head,
				struct ublk_batch_fetch_cmd, node);
		WRITE_ONCE(ubq->active_fcmd, fcmd);
	}
	return fcmd;
}

static void ublk_batch_dispatch(struct ublk_queue *ubq,
				const struct ublk_batch_io_data *data,
				struct ublk_batch_fetch_cmd *fcmd);

static void ublk_batch_tw_cb(struct io_tw_req tw_req, io_tw_token_t tw)
{
	unsigned int issue_flags = IO_URING_CMD_TASK_WORK_ISSUE_FLAGS;
	struct io_uring_cmd *cmd = io_uring_cmd_from_tw(tw_req);
	struct ublk_uring_cmd_pdu *pdu = ublk_get_uring_cmd_pdu(cmd);
	struct ublk_batch_fetch_cmd *fcmd = pdu->fcmd;
	struct ublk_batch_io_data data = {
		.ub = pdu->ubq->dev,
		.cmd = fcmd->cmd,
		.issue_flags = issue_flags,
	};

	WARN_ON_ONCE(pdu->ubq->active_fcmd != fcmd);

	ublk_batch_dispatch(pdu->ubq, &data, fcmd);
}

static void
ublk_batch_dispatch(struct ublk_queue *ubq,
		    const struct ublk_batch_io_data *data,
		    struct ublk_batch_fetch_cmd *fcmd)
{
	struct ublk_batch_fetch_cmd *new_fcmd;
	unsigned tried = 0;
	int ret = 0;

again:
	while (!ublk_io_evts_empty(ubq)) {
		ret = __ublk_batch_dispatch(ubq, data, fcmd);
		if (ret <= 0)
			break;
	}

	if (ret < 0) {
		ublk_batch_deinit_fetch_buf(ubq, data, fcmd, ret);
		return;
	}

	__ublk_release_fcmd(ubq);
	/*
	 * Order clearing ubq->active_fcmd from __ublk_release_fcmd() and
	 * checking ubq->evts_fifo.
	 *
	 * The pair is the smp_mb() in __ublk_acquire_fcmd().
	 */
	smp_mb();
	if (likely(ublk_io_evts_empty(ubq)))
		return;

	spin_lock(&ubq->evts_lock);
	new_fcmd = __ublk_acquire_fcmd(ubq);
	spin_unlock(&ubq->evts_lock);

	if (!new_fcmd)
		return;

	/* Avoid lockup by allowing to handle at most 32 batches */
	if (new_fcmd == fcmd && tried++ < 32)
		goto again;

	io_uring_cmd_complete_in_task(new_fcmd->cmd, ublk_batch_tw_cb);
}

static void ublk_batch_queue_cmd(struct ublk_queue *ubq, struct request *rq, bool last)
{
	unsigned short tag = rq->tag;
	struct ublk_batch_fetch_cmd *fcmd = NULL;

	spin_lock(&ubq->evts_lock);
	kfifo_put(&ubq->evts_fifo, tag);
	if (last)
		fcmd = __ublk_acquire_fcmd(ubq);
	spin_unlock(&ubq->evts_lock);

	if (fcmd)
		io_uring_cmd_complete_in_task(fcmd->cmd, ublk_batch_tw_cb);
}

static blk_status_t ublk_batch_queue_rq(struct blk_mq_hw_ctx *hctx,
		const struct blk_mq_queue_data *bd)
{
	struct ublk_queue *ubq = hctx->driver_data;
	struct request *rq = bd->rq;
	bool should_queue;
	blk_status_t res;

	res = __ublk_queue_rq_common(ubq, rq, &should_queue);
	if (!should_queue)
		return res;

	if (ublk_has_bpf_ops(ubq)) {
		if (!ublk_bpf_queue_io(ubq, rq, bd->last))
			return BLK_STS_OK;
		/* BPF wants userspace notification, fall through */
	}

	ublk_batch_queue_cmd(ubq, rq, bd->last);
	return BLK_STS_OK;
}

static void ublk_commit_rqs(struct blk_mq_hw_ctx *hctx)
{
	struct ublk_queue *ubq = hctx->driver_data;
	struct ublk_batch_fetch_cmd *fcmd;

	if (ublk_has_bpf_ops(ubq)) {
		ublk_bpf_commit_io_cmds(ubq);
		return;
	}

	spin_lock(&ubq->evts_lock);
	fcmd = __ublk_acquire_fcmd(ubq);
	spin_unlock(&ubq->evts_lock);

	if (fcmd)
		io_uring_cmd_complete_in_task(fcmd->cmd, ublk_batch_tw_cb);
}

static void ublk_batch_queue_cmd_list(struct ublk_queue *ubq, struct rq_list *l)
{
	unsigned short tags[MAX_NR_TAG];
	struct ublk_batch_fetch_cmd *fcmd;
	struct request *rq;
	unsigned cnt = 0;

	spin_lock(&ubq->evts_lock);
	rq_list_for_each(l, rq) {
		tags[cnt++] = (unsigned short)rq->tag;
		if (cnt >= MAX_NR_TAG) {
			kfifo_in(&ubq->evts_fifo, tags, cnt);
			cnt = 0;
		}
	}
	if (cnt)
		kfifo_in(&ubq->evts_fifo, tags, cnt);
	fcmd = __ublk_acquire_fcmd(ubq);
	spin_unlock(&ubq->evts_lock);

	rq_list_init(l);
	if (fcmd)
		io_uring_cmd_complete_in_task(fcmd->cmd, ublk_batch_tw_cb);
}

static void ublk_batch_queue_rqs(struct rq_list *rqlist)
{
	struct rq_list requeue_list = { };
	struct rq_list submit_list = { };
	struct ublk_queue *ubq = NULL;
	struct request *req;

	while ((req = rq_list_pop(rqlist))) {
		struct ublk_queue *this_q = req->mq_hctx->driver_data;

		if (ublk_prep_req(this_q, req, true) != BLK_STS_OK) {
			rq_list_add_tail(&requeue_list, req);
			continue;
		}

		if (ublk_has_bpf_ops(this_q)) {
			struct request *next = rq_list_peek(rqlist);
			/* last for this queue: next request is a different one */
			bool last = !next ||
				    next->mq_hctx->driver_data != this_q;

			if (!ublk_bpf_queue_io(this_q, req, last))
				continue;	/* completed inline, not forwarded */
			/* fall through to forward this request */
		}

		if (ubq && this_q != ubq && !rq_list_empty(&submit_list))
			ublk_batch_queue_cmd_list(ubq, &submit_list);
		ubq = this_q;
		rq_list_add_tail(&submit_list, req);
	}

	if (!rq_list_empty(&submit_list))
		ublk_batch_queue_cmd_list(ubq, &submit_list);
	*rqlist = requeue_list;
}

const struct blk_mq_ops ublk_batch_mq_ops = {
	.commit_rqs	= ublk_commit_rqs,
	.queue_rq       = ublk_batch_queue_rq,
	.queue_rqs      = ublk_batch_queue_rqs,
	.init_hctx	= ublk_init_hctx,
	.timeout	= ublk_timeout,
};

/*
 * Request tag may just be filled to event kfifo, not get chance to
 * dispatch, abort these requests too
 */
void ublk_abort_batch_queue(struct ublk_device *ub,
			    struct ublk_queue *ubq)
{
	unsigned short tag;

	while (kfifo_out(&ubq->evts_fifo, &tag, 1)) {
		struct request *req = blk_mq_tag_to_rq(
				ub->tag_set.tags[ubq->q_id], tag);

		if (!WARN_ON_ONCE(!req || !blk_mq_request_started(req)))
			__ublk_fail_req(ub, &ubq->ios[tag], req);
	}
}

/*
 * Cancel a batch fetch command if it hasn't been claimed by another path.
 *
 * An fcmd can only be cancelled if:
 * 1. It's not the active_fcmd (which is currently being processed)
 * 2. It's still on the list (!list_empty check) - once removed from the list,
 *    the fcmd is considered claimed and will be freed by whoever removed it
 *
 * Use list_del_init() so subsequent list_empty() checks work correctly.
 */
static void ublk_batch_cancel_cmd(struct ublk_queue *ubq,
				  struct ublk_batch_fetch_cmd *fcmd,
				  unsigned int issue_flags)
{
	bool done;

	spin_lock(&ubq->evts_lock);
	done = (READ_ONCE(ubq->active_fcmd) != fcmd) && !list_empty(&fcmd->node);
	if (done)
		list_del_init(&fcmd->node);
	spin_unlock(&ubq->evts_lock);

	if (done) {
		io_uring_cmd_done(fcmd->cmd, UBLK_IO_RES_ABORT, issue_flags);
		ublk_batch_free_fcmd(fcmd);
	}
}

void ublk_batch_cancel_queue(struct ublk_queue *ubq)
{
	struct ublk_batch_fetch_cmd *fcmd;
	LIST_HEAD(fcmd_list);

	spin_lock(&ubq->evts_lock);
	ubq->force_abort = true;
	list_splice_init(&ubq->fcmd_head, &fcmd_list);
	fcmd = READ_ONCE(ubq->active_fcmd);
	if (fcmd)
		list_move(&fcmd->node, &ubq->fcmd_head);
	spin_unlock(&ubq->evts_lock);

	while (!list_empty(&fcmd_list)) {
		fcmd = list_first_entry(&fcmd_list,
				struct ublk_batch_fetch_cmd, node);
		ublk_batch_cancel_cmd(ubq, fcmd, IO_URING_F_UNLOCKED);
	}
}

static void ublk_batch_cancel_fn(struct io_uring_cmd *cmd,
				 unsigned int issue_flags)
{
	struct ublk_uring_cmd_pdu *pdu = ublk_get_uring_cmd_pdu(cmd);
	struct ublk_batch_fetch_cmd *fcmd = pdu->fcmd;
	struct ublk_queue *ubq = pdu->ubq;

	ublk_start_cancel(ubq->dev);

	ublk_batch_cancel_cmd(ubq, fcmd, issue_flags);
}

static inline __u64 ublk_batch_buf_addr(const struct ublk_batch_io *uc,
					const struct ublk_elem_header *elem)
{
	const void *buf = elem;

	if (uc->flags & UBLK_BATCH_F_HAS_BUF_ADDR)
		return *(const __u64 *)(buf + sizeof(*elem));
	return 0;
}

static inline __u64 ublk_batch_zone_lba(const struct ublk_batch_io *uc,
					const struct ublk_elem_header *elem)
{
	const void *buf = elem;

	if (uc->flags & UBLK_BATCH_F_HAS_ZONE_LBA)
		return *(const __u64 *)(buf + sizeof(*elem) +
				8 * !!(uc->flags & UBLK_BATCH_F_HAS_BUF_ADDR));
	return -1;
}

static struct ublk_auto_buf_reg
ublk_batch_auto_buf_reg(const struct ublk_batch_io *uc,
			const struct ublk_elem_header *elem)
{
	struct ublk_auto_buf_reg reg = {
		.index = elem->buf_index,
		.flags = (uc->flags & UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK) ?
			UBLK_AUTO_BUF_REG_FALLBACK : 0,
	};

	return reg;
}

/*
 * 48 can hold any type of buffer element(8, 16 and 24 bytes) because
 * it is the least common multiple(LCM) of 8, 16 and 24
 */
#define UBLK_CMD_BATCH_TMP_BUF_SZ  (48 * 10)
struct ublk_batch_io_iter {
	void __user *uaddr;
	unsigned done, total;
	unsigned char elem_bytes;
	/* copy to this buffer from user space */
	unsigned char buf[UBLK_CMD_BATCH_TMP_BUF_SZ];
};

static inline int
__ublk_walk_cmd_buf(struct ublk_queue *ubq,
		    struct ublk_batch_io_iter *iter,
		    const struct ublk_batch_io_data *data,
		    unsigned bytes,
		    int (*cb)(struct ublk_queue *q,
			    const struct ublk_batch_io_data *data,
			    const struct ublk_elem_header *elem))
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < bytes; i += iter->elem_bytes) {
		const struct ublk_elem_header *elem =
			(const struct ublk_elem_header *)&iter->buf[i];

		if (unlikely(elem->tag >= data->ub->dev_info.queue_depth)) {
			ret = -EINVAL;
			break;
		}

		ret = cb(ubq, data, elem);
		if (unlikely(ret))
			break;
	}

	iter->done += i;
	return ret;
}

static int ublk_walk_cmd_buf(struct ublk_batch_io_iter *iter,
			     const struct ublk_batch_io_data *data,
			     int (*cb)(struct ublk_queue *q,
				     const struct ublk_batch_io_data *data,
				     const struct ublk_elem_header *elem))
{
	struct ublk_queue *ubq = ublk_get_queue(data->ub, data->header.q_id);
	int ret = 0;

	while (iter->done < iter->total) {
		unsigned int len = min(sizeof(iter->buf), iter->total - iter->done);

		if (copy_from_user(iter->buf, iter->uaddr + iter->done, len)) {
			pr_warn("ublk%d: read batch cmd buffer failed\n",
					data->ub->dev_info.dev_id);
			return -EFAULT;
		}

		ret = __ublk_walk_cmd_buf(ubq, iter, data, len, cb);
		if (ret)
			return ret;
	}
	return 0;
}

static int ublk_batch_unprep_io(struct ublk_queue *ubq,
				const struct ublk_batch_io_data *data,
				const struct ublk_elem_header *elem)
{
	struct ublk_io *io = &ubq->ios[elem->tag];

	/*
	 * If queue was ready before this decrement, it won't be anymore,
	 * so we need to decrement the queue ready count and restore the
	 * canceling flag to prevent new requests from being queued.
	 */
	if (ublk_queue_ready(ubq)) {
		data->ub->nr_queue_ready--;
		spin_lock(&ubq->cancel_lock);
		ubq->canceling = true;
		spin_unlock(&ubq->cancel_lock);
	}
	ubq->nr_io_ready--;

	ublk_io_lock(io);
	io->flags = 0;
	ublk_io_unlock(io);
	return 0;
}

static void ublk_batch_revert_prep_cmd(struct ublk_batch_io_iter *iter,
				       const struct ublk_batch_io_data *data)
{
	int ret;

	/* Re-process only what we've already processed, starting from beginning */
	iter->total = iter->done;
	iter->done = 0;

	ret = ublk_walk_cmd_buf(iter, data, ublk_batch_unprep_io);
	WARN_ON_ONCE(ret);
}

static int ublk_batch_prep_io(struct ublk_queue *ubq,
			      const struct ublk_batch_io_data *data,
			      const struct ublk_elem_header *elem)
{
	struct ublk_io *io = &ubq->ios[elem->tag];
	const struct ublk_batch_io *uc = &data->header;
	union ublk_io_buf buf = { 0 };
	int ret;

	if (ublk_dev_support_auto_buf_reg(data->ub))
		buf.auto_reg = ublk_batch_auto_buf_reg(uc, elem);
	else if (ublk_dev_need_map_io(data->ub)) {
		buf.addr = ublk_batch_buf_addr(uc, elem);

		ret = ublk_check_fetch_buf(data->ub, buf.addr);
		if (ret)
			return ret;
	}

	ublk_io_lock(io);
	ret = __ublk_fetch(data->cmd, data->ub, io, ubq->q_id);
	if (!ret)
		io->buf = buf;
	ublk_io_unlock(io);

	if (!ret)
		ublk_mark_io_ready(data->ub, ubq->q_id, io);

	return ret;
}

static int ublk_handle_batch_prep_cmd(const struct ublk_batch_io_data *data)
{
	const struct ublk_batch_io *uc = &data->header;
	struct io_uring_cmd *cmd = data->cmd;
	struct ublk_batch_io_iter iter = {
		.uaddr = u64_to_user_ptr(READ_ONCE(cmd->sqe->addr)),
		.total = uc->nr_elem * uc->elem_bytes,
		.elem_bytes = uc->elem_bytes,
	};
	int ret;

	mutex_lock(&data->ub->mutex);
	ret = ublk_walk_cmd_buf(&iter, data, ublk_batch_prep_io);

	if (ret && iter.done)
		ublk_batch_revert_prep_cmd(&iter, data);
	mutex_unlock(&data->ub->mutex);
	return ret;
}

static int ublk_batch_commit_io_check(const struct ublk_queue *ubq,
				      struct ublk_io *io,
				      union ublk_io_buf *buf)
{
	if (!(io->flags & UBLK_IO_FLAG_OWNED_BY_SRV))
		return -EBUSY;

	/* BATCH_IO doesn't support UBLK_F_NEED_GET_DATA */
	if (ublk_need_map_io(ubq) && !buf->addr)
		return -EINVAL;
	return 0;
}

static int ublk_batch_commit_io(struct ublk_queue *ubq,
				const struct ublk_batch_io_data *data,
				const struct ublk_elem_header *elem)
{
	struct ublk_io *io = &ubq->ios[elem->tag];
	const struct ublk_batch_io *uc = &data->header;
	u16 buf_idx = UBLK_INVALID_BUF_IDX;
	union ublk_io_buf buf = { 0 };
	struct request *req = NULL;
	bool auto_reg = false;
	bool compl = false;
	int ret;

	if (ublk_dev_support_auto_buf_reg(data->ub)) {
		buf.auto_reg = ublk_batch_auto_buf_reg(uc, elem);
		auto_reg = true;
	} else if (ublk_dev_need_map_io(data->ub))
		buf.addr = ublk_batch_buf_addr(uc, elem);

	ublk_io_lock(io);
	ret = ublk_batch_commit_io_check(ubq, io, &buf);
	if (!ret) {
		io->res = elem->result;
		io->buf = buf;
		req = ublk_fill_io_cmd(io, data->cmd);

		if (auto_reg)
			ublk_clear_auto_buf_reg(io, data->cmd, &buf_idx);
		compl = ublk_need_complete_req(data->ub, io);
	}
	ublk_io_unlock(io);

	if (unlikely(ret)) {
		pr_warn_ratelimited("%s: dev %u queue %u io %u: commit failure %d\n",
			__func__, data->ub->dev_info.dev_id, ubq->q_id,
			elem->tag, ret);
		return ret;
	}

	if (buf_idx != UBLK_INVALID_BUF_IDX)
		io_buffer_unregister_bvec(data->cmd, buf_idx, data->issue_flags);
	if (req_op(req) == REQ_OP_ZONE_APPEND)
		req->__sector = ublk_batch_zone_lba(uc, elem);
	if (compl)
		__ublk_complete_rq(req, io, ublk_dev_need_map_io(data->ub), data->iob);
	return 0;
}

static int ublk_handle_batch_commit_cmd(struct ublk_batch_io_data *data)
{
	const struct ublk_batch_io *uc = &data->header;
	struct io_uring_cmd *cmd = data->cmd;
	struct ublk_batch_io_iter iter = {
		.uaddr = u64_to_user_ptr(READ_ONCE(cmd->sqe->addr)),
		.total = uc->nr_elem * uc->elem_bytes,
		.elem_bytes = uc->elem_bytes,
	};
	DEFINE_IO_COMP_BATCH(iob);
	int ret;

	data->iob = &iob;
	ret = ublk_walk_cmd_buf(&iter, data, ublk_batch_commit_io);

	if (iob.complete)
		iob.complete(&iob);

	return iter.done == 0 ? ret : iter.done;
}

static int ublk_check_batch_cmd_flags(const struct ublk_batch_io *uc)
{
	unsigned elem_bytes = sizeof(struct ublk_elem_header);

	if (uc->flags & ~UBLK_BATCH_F_ALL)
		return -EINVAL;

	/* UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK requires buffer index */
	if ((uc->flags & UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK) &&
			(uc->flags & UBLK_BATCH_F_HAS_BUF_ADDR))
		return -EINVAL;

	elem_bytes += (uc->flags & UBLK_BATCH_F_HAS_ZONE_LBA ? sizeof(u64) : 0) +
		(uc->flags & UBLK_BATCH_F_HAS_BUF_ADDR ? sizeof(u64) : 0);
	if (uc->elem_bytes != elem_bytes)
		return -EINVAL;
	return 0;
}

static int ublk_check_batch_cmd(const struct ublk_batch_io_data *data)
{
	const struct ublk_batch_io *uc = &data->header;

	if (uc->q_id >= data->ub->dev_info.nr_hw_queues)
		return -EINVAL;

	if (uc->nr_elem > data->ub->dev_info.queue_depth)
		return -E2BIG;

	if ((uc->flags & UBLK_BATCH_F_HAS_ZONE_LBA) &&
			!ublk_dev_is_zoned(data->ub))
		return -EINVAL;

	if ((uc->flags & UBLK_BATCH_F_HAS_BUF_ADDR) &&
			!ublk_dev_need_map_io(data->ub))
		return -EINVAL;

	if ((uc->flags & UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK) &&
			!ublk_dev_support_auto_buf_reg(data->ub))
		return -EINVAL;

	return ublk_check_batch_cmd_flags(uc);
}

static int ublk_batch_attach(struct ublk_queue *ubq,
			     struct ublk_batch_io_data *data,
			     struct ublk_batch_fetch_cmd *fcmd)
{
	struct ublk_batch_fetch_cmd *new_fcmd = NULL;
	bool free = false;
	struct ublk_uring_cmd_pdu *pdu = ublk_get_uring_cmd_pdu(data->cmd);

	spin_lock(&ubq->evts_lock);
	if (unlikely(ubq->force_abort || ubq->canceling)) {
		free = true;
	} else {
		list_add_tail(&fcmd->node, &ubq->fcmd_head);
		new_fcmd = __ublk_acquire_fcmd(ubq);
	}
	spin_unlock(&ubq->evts_lock);

	if (unlikely(free)) {
		ublk_batch_free_fcmd(fcmd);
		return -ENODEV;
	}

	pdu->ubq = ubq;
	pdu->fcmd = fcmd;
	io_uring_cmd_mark_cancelable(fcmd->cmd, data->issue_flags);

	if (!new_fcmd)
		goto out;

	/*
	 * If the two fetch commands are originated from same io_ring_ctx,
	 * run batch dispatch directly. Otherwise, schedule task work for
	 * doing it.
	 */
	if (io_uring_cmd_ctx_handle(new_fcmd->cmd) ==
			io_uring_cmd_ctx_handle(fcmd->cmd)) {
		data->cmd = new_fcmd->cmd;
		ublk_batch_dispatch(ubq, data, new_fcmd);
	} else {
		io_uring_cmd_complete_in_task(new_fcmd->cmd,
				ublk_batch_tw_cb);
	}
out:
	return -EIOCBQUEUED;
}

static int ublk_handle_batch_fetch_cmd(struct ublk_batch_io_data *data)
{
	struct ublk_queue *ubq = ublk_get_queue(data->ub, data->header.q_id);
	struct ublk_batch_fetch_cmd *fcmd = ublk_batch_alloc_fcmd(data->cmd);

	if (!fcmd)
		return -ENOMEM;

	return ublk_batch_attach(ubq, data, fcmd);
}

static int ublk_validate_batch_fetch_cmd(struct ublk_batch_io_data *data)
{
	const struct ublk_batch_io *uc = &data->header;

	if (uc->q_id >= data->ub->dev_info.nr_hw_queues)
		return -EINVAL;

	if (!(data->cmd->flags & IORING_URING_CMD_MULTISHOT))
		return -EINVAL;

	if (uc->elem_bytes != sizeof(__u16))
		return -EINVAL;

	if (uc->flags != 0)
		return -EINVAL;

	return 0;
}

static int ublk_handle_non_batch_cmd(struct io_uring_cmd *cmd,
				     unsigned int issue_flags)
{
	const struct ublksrv_io_cmd *ub_cmd = io_uring_sqe_cmd(cmd->sqe,
							       struct ublksrv_io_cmd);
	struct ublk_device *ub = cmd->file->private_data;
	unsigned tag = READ_ONCE(ub_cmd->tag);
	unsigned q_id = READ_ONCE(ub_cmd->q_id);
	unsigned index = READ_ONCE(ub_cmd->addr);
	struct ublk_queue *ubq;
	struct ublk_io *io;

	if (cmd->cmd_op == UBLK_U_IO_UNREGISTER_IO_BUF)
		return ublk_unregister_io_buf(cmd, ub, index, issue_flags);

	if (q_id >= ub->dev_info.nr_hw_queues)
		return -EINVAL;

	if (tag >= ub->dev_info.queue_depth)
		return -EINVAL;

	if (cmd->cmd_op != UBLK_U_IO_REGISTER_IO_BUF)
		return -EOPNOTSUPP;

	ubq = ublk_get_queue(ub, q_id);
	io = &ubq->ios[tag];
	return ublk_register_io_buf(cmd, ub, q_id, tag, io, index,
			issue_flags);
}

static int ublk_ch_batch_io_uring_cmd(struct io_uring_cmd *cmd,
				       unsigned int issue_flags)
{
	const struct ublk_batch_io *uc = io_uring_sqe_cmd(cmd->sqe,
							  struct ublk_batch_io);
	struct ublk_device *ub = cmd->file->private_data;
	struct ublk_batch_io_data data = {
		.ub  = ub,
		.cmd = cmd,
		.header = (struct ublk_batch_io) {
			.q_id = READ_ONCE(uc->q_id),
			.flags = READ_ONCE(uc->flags),
			.nr_elem = READ_ONCE(uc->nr_elem),
			.elem_bytes = READ_ONCE(uc->elem_bytes),
		},
		.issue_flags = issue_flags,
	};
	u32 cmd_op = cmd->cmd_op;
	int ret = -EINVAL;

	if (unlikely(issue_flags & IO_URING_F_CANCEL)) {
		ublk_batch_cancel_fn(cmd, issue_flags);
		return 0;
	}

	switch (cmd_op) {
	case UBLK_U_IO_PREP_IO_CMDS:
		ret = ublk_check_batch_cmd(&data);
		if (ret)
			goto out;
		ret = ublk_handle_batch_prep_cmd(&data);
		break;
	case UBLK_U_IO_COMMIT_IO_CMDS:
		ret = ublk_check_batch_cmd(&data);
		if (ret)
			goto out;
		ret = ublk_handle_batch_commit_cmd(&data);
		break;
	case UBLK_U_IO_FETCH_IO_CMDS:
		ret = ublk_validate_batch_fetch_cmd(&data);
		if (ret)
			goto out;
		ret = ublk_handle_batch_fetch_cmd(&data);
		break;
	default:
		ret = ublk_handle_non_batch_cmd(cmd, issue_flags);
		break;
	}
out:
	return ret;
}

const struct file_operations ublk_ch_batch_io_fops = {
	.owner = THIS_MODULE,
	.open = ublk_ch_open,
	.release = ublk_ch_release,
	.read_iter = ublk_ch_read_iter,
	.write_iter = ublk_ch_write_iter,
	.uring_cmd = ublk_ch_batch_io_uring_cmd,
	.mmap = ublk_ch_mmap,
};
