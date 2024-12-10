// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef UBLK_INT_BPF_HEADER
#define UBLK_INT_BPF_HEADER

#include "bpf_reg.h"
#include "bpf_aio.h"

typedef unsigned long ublk_bpf_return_t;
typedef ublk_bpf_return_t (*queue_io_cmd_t)(struct ublk_bpf_io *io, unsigned int);
typedef void (*release_io_cmd_t)(struct ublk_bpf_io *io);
typedef int (*attach_dev_t)(int dev_id);
typedef void (*detach_dev_t)(int dev_id);

#ifdef CONFIG_UBLK_BPF
#include <linux/filter.h>

/*
 * enum ublk_bpf_disposition - how to dispose the bpf io command
 *
 * @UBLK_BPF_IO_QUEUED: io command queued completely by bpf prog, so this
 * 	cmd needn't to be forwarded to ublk daemon any more
 * @UBLK_BPF_IO_REDIRECT: io command can't be queued by bpf prog, so this
 * 	cmd will be forwarded to ublk daemon
 * @UBLK_BPF_IO_CONTINUE: io command is being queued, and can be disposed
 * 	further by bpf prog, so bpf callback will be called further
 */
enum ublk_bpf_disposition {
       UBLK_BPF_IO_QUEUED = 0,
       UBLK_BPF_IO_REDIRECT,
       UBLK_BPF_IO_CONTINUE,
};

/**
 * struct ublk_bpf_ops - A BPF struct_ops of callbacks allowing to implement
 * 			ublk target from bpf program
 * @id: ops id
 * @queue_io_cmd: callback for queuing io command in ublk io context
 * @queue_io_cmd_daemon: callback for queuing io command in ublk daemon
 */
struct ublk_bpf_ops {
	/* struct_ops id, used for ublk device to attach prog */
	unsigned		id;

	/* queue io command from ublk io context, can't be sleepable */
	queue_io_cmd_t		queue_io_cmd;

	/* queue io command from target io daemon context, can be sleepable */
	queue_io_cmd_t		queue_io_cmd_daemon;

	/* called when the io command reference drops to zero, can't be sleepable */
	release_io_cmd_t	release_io_cmd;

	/* called when attaching bpf prog to this ublk dev */
	attach_dev_t		attach_dev;

	/* called when detaching bpf prog from this ublk dev */
	detach_dev_t		detach_dev;

	/* private: don't show in doc, must be the last field */
	struct bpf_prog_provider	provider;
};

#define UBLK_BPF_DISPOSITION_BITS	(4)
#define UBLK_BPF_DISPOSITION_SHIFT	(BITS_PER_LONG - UBLK_BPF_DISPOSITION_BITS)

static inline enum ublk_bpf_disposition ublk_bpf_get_disposition(ublk_bpf_return_t ret)
{
	return ret >> UBLK_BPF_DISPOSITION_SHIFT;
}

static inline unsigned int ublk_bpf_get_return_bytes(ublk_bpf_return_t ret)
{
	return ret & ((1UL << UBLK_BPF_DISPOSITION_SHIFT) - 1);
}

static inline ublk_bpf_return_t ublk_bpf_return_val(enum ublk_bpf_disposition rc,
		unsigned int bytes)
{
	return (ublk_bpf_return_t) ((unsigned long)rc << UBLK_BPF_DISPOSITION_SHIFT) | bytes;
}

static inline struct request *ublk_bpf_get_req(const struct ublk_bpf_io *io)
{
	struct ublk_rq_data *data = container_of(io, struct ublk_rq_data, bpf_data);
	struct request *req = blk_mq_rq_from_pdu(data);

	return req;
}

static inline void ublk_bpf_io_dec_ref(struct ublk_bpf_io *io)
{
	if (refcount_dec_and_test(&io->ref)) {
		struct request *req = ublk_bpf_get_req(io);

		if (req->mq_hctx) {
			const struct ublk_queue *ubq = req->mq_hctx->driver_data;

			if (ubq->bpf_ops && ubq->bpf_ops->release_io_cmd)
				ubq->bpf_ops->release_io_cmd(io);
		}

		if (test_bit(UBLK_BPF_BVEC_ALLOCATED, &io->flags))
			kvfree(io->buf.bvec);

		if (test_bit(UBLK_BPF_IO_COMPLETED, &io->flags)) {
			smp_rmb();
			__clear_bit(UBLK_BPF_IO_PREP, &io->flags);
			__ublk_complete_rq_with_res(req, io->res);
		}
	}
}

static inline void ublk_bpf_complete_io_cmd(struct ublk_bpf_io *io, int res)
{
	io->res = res;
	smp_wmb();
	set_bit(UBLK_BPF_IO_COMPLETED, &io->flags);
	ublk_bpf_io_dec_ref(io);
}


bool ublk_run_bpf_handler(struct ublk_queue *ubq, struct request *req,
			  queue_io_cmd_t cb);

/*
 * Return true if bpf prog handled this io command, otherwise return false
 * so that this io command will be forwarded to userspace
 */
static inline bool ublk_run_bpf_prog(struct ublk_queue *ubq,
				struct request *req,
				queue_io_cmd_t cb,
				bool fail_on_null)
{
	if (likely(cb))
		return ublk_run_bpf_handler(ubq, req, cb);

	/* bpf prog is un-registered */
	if (fail_on_null && !ubq->bpf_ops) {
		__ublk_complete_rq_with_res(req, -EOPNOTSUPP);
		return true;
	}

	return false;
}

static inline queue_io_cmd_t ublk_get_bpf_io_cb(struct ublk_queue *ubq)
{
	return ubq->bpf_ops ? ubq->bpf_ops->queue_io_cmd : NULL;
}

static inline queue_io_cmd_t ublk_get_bpf_io_cb_daemon(struct ublk_queue *ubq)
{
	return ubq->bpf_ops ? ubq->bpf_ops->queue_io_cmd_daemon : NULL;
}

static inline queue_io_cmd_t ublk_get_bpf_any_io_cb(struct ublk_queue *ubq)
{
	if (ublk_get_bpf_io_cb(ubq))
		return ublk_get_bpf_io_cb(ubq);

	return ublk_get_bpf_io_cb_daemon(ubq);
}

static inline bool ublk_support_bpf_aio(const struct ublk_queue *ubq)
{
	return ublk_support_bpf(ubq) && ubq->bpf_aio_ops;
}

int ublk_bpf_init(void);
int ublk_bpf_struct_ops_init(void);
int ublk_bpf_prog_attach(struct bpf_prog_consumer *consumer);
void ublk_bpf_prog_detach(struct bpf_prog_consumer *consumer);
int ublk_bpf_attach(struct ublk_device *ub);
void ublk_bpf_detach(struct ublk_device *ub);

#else

static inline bool ublk_run_bpf_prog(struct ublk_queue *ubq,
				struct request *req,
				queue_io_cmd_t cb,
				bool fail_on_null)
{
	return false;
}

static inline queue_io_cmd_t ublk_get_bpf_io_cb(struct ublk_queue *ubq)
{
	return NULL;
}

static inline queue_io_cmd_t ublk_get_bpf_io_cb_daemon(struct ublk_queue *ubq)
{
	return NULL;
}

static inline queue_io_cmd_t ublk_get_bpf_any_io_cb(struct ublk_queue *ubq)
{
	return NULL;
}

static inline bool ublk_support_bpf_aio(const struct ublk_queue *ubq)
{
	return false;
}

static inline int ublk_bpf_init(void)
{
	return 0;
}

static inline int ublk_bpf_struct_ops_init(void)
{
	return 0;
}

static inline int ublk_bpf_prog_attach(struct bpf_prog_consumer *consumer)
{
	return 0;
}
static inline void ublk_bpf_prog_detach(struct bpf_prog_consumer *consumer)
{
}
static inline int ublk_bpf_attach(struct ublk_device *ub)
{
	return 0;
}
static inline void ublk_bpf_detach(struct ublk_device *ub)
{
}
#endif
#endif
