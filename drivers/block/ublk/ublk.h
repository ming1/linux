// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef UBLK_INTERNAL_HEADER
#define UBLK_INTERNAL_HEADER

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/cdev.h>
#include <uapi/linux/ublk_cmd.h>

#include "bpf_reg.h"

#define UBLK_MINORS		(1U << MINORBITS)

/* private ioctl command mirror */
#define UBLK_CMD_DEL_DEV_ASYNC	_IOC_NR(UBLK_U_CMD_DEL_DEV_ASYNC)

/* All UBLK_F_* have to be included into UBLK_F_ALL */
#define UBLK_F_ALL (UBLK_F_SUPPORT_ZERO_COPY \
		| UBLK_F_URING_CMD_COMP_IN_TASK \
		| UBLK_F_NEED_GET_DATA \
		| UBLK_F_USER_RECOVERY \
		| UBLK_F_USER_RECOVERY_REISSUE \
		| UBLK_F_UNPRIVILEGED_DEV \
		| UBLK_F_CMD_IOCTL_ENCODE \
		| UBLK_F_USER_COPY \
		| UBLK_F_ZONED \
		| UBLK_F_USER_RECOVERY_FAIL_IO \
		| UBLK_F_BPF)

#define UBLK_F_ALL_RECOVERY_FLAGS (UBLK_F_USER_RECOVERY \
		| UBLK_F_USER_RECOVERY_REISSUE \
		| UBLK_F_USER_RECOVERY_FAIL_IO)

/* All UBLK_PARAM_TYPE_* should be included here */
#define UBLK_PARAM_TYPE_ALL                                \
	(UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | \
	 UBLK_PARAM_TYPE_DEVT | UBLK_PARAM_TYPE_ZONED | \
	 UBLK_PARAM_TYPE_BPF)

enum {
	UBLK_BPF_IO_PREP	= 0,
	UBLK_BPF_IO_COMPLETED   = 1,
};

struct ublk_bpf_io {
	const struct ublksrv_io_desc	*iod;
	unsigned long			flags;
	refcount_t                      ref;
	int				res;
};

struct ublk_rq_data {
	struct llist_node node;

	struct kref ref;

#ifdef CONFIG_UBLK_BPF
	struct ublk_bpf_io	bpf_data;
#endif
};

struct ublk_uring_cmd_pdu {
	struct ublk_queue *ubq;
	u16 tag;
};

/*
 * io command is active: sqe cmd is received, and its cqe isn't done
 *
 * If the flag is set, the io command is owned by ublk driver, and waited
 * for incoming blk-mq request from the ublk block device.
 *
 * If the flag is cleared, the io command will be completed, and owned by
 * ublk server.
 */
#define UBLK_IO_FLAG_ACTIVE	0x01

/*
 * IO command is completed via cqe, and it is being handled by ublksrv, and
 * not committed yet
 *
 * Basically exclusively with UBLK_IO_FLAG_ACTIVE, so can be served for
 * cross verification
 */
#define UBLK_IO_FLAG_OWNED_BY_SRV 0x02

/*
 * IO command is aborted, so this flag is set in case of
 * !UBLK_IO_FLAG_ACTIVE.
 *
 * After this flag is observed, any pending or new incoming request
 * associated with this io command will be failed immediately
 */
#define UBLK_IO_FLAG_ABORTED 0x04

/*
 * UBLK_IO_FLAG_NEED_GET_DATA is set because IO command requires
 * get data buffer address from ublksrv.
 *
 * Then, bio data could be copied into this data buffer for a WRITE request
 * after the IO command is issued again and UBLK_IO_FLAG_NEED_GET_DATA is unset.
 */
#define UBLK_IO_FLAG_NEED_GET_DATA 0x08

/* atomic RW with ubq->cancel_lock */
#define UBLK_IO_FLAG_CANCELED	0x80000000

struct ublk_io {
	/* userspace buffer address from io cmd */
	__u64	addr;
	unsigned int flags;
	int res;

	struct io_uring_cmd *cmd;
};

struct ublk_queue {
	int q_id;
	int q_depth;

	unsigned long flags;
	struct task_struct	*ubq_daemon;
	char *io_cmd_buf;

	struct llist_head	io_cmds;

#ifdef CONFIG_UBLK_BPF
	struct ublk_bpf_ops     *bpf_ops;
#endif

	unsigned short force_abort:1;
	unsigned short timeout:1;
	unsigned short canceling:1;
	unsigned short fail_io:1; /* copy of dev->state == UBLK_S_DEV_FAIL_IO */
	unsigned short nr_io_ready;	/* how many ios setup */
	spinlock_t		cancel_lock;
	struct ublk_device *dev;
	struct ublk_io ios[];
};

struct ublk_device {
	struct gendisk		*ub_disk;

	char	*__queues;

	unsigned int	queue_size;
	struct ublksrv_ctrl_dev_info	dev_info;

	struct blk_mq_tag_set	tag_set;

	struct cdev		cdev;
	struct device		cdev_dev;

#define UB_STATE_OPEN		0
#define UB_STATE_USED		1
#define UB_STATE_DELETED	2
	unsigned long		state;
	int			ub_number;

#ifdef CONFIG_UBLK_BPF
	struct bpf_prog_consumer prog;
#endif
	struct mutex		mutex;

	spinlock_t		lock;
	struct mm_struct	*mm;

	struct ublk_params	params;

	struct completion	completion;
	unsigned int		nr_queues_ready;
	unsigned int		nr_privileged_daemon;

	struct work_struct	nosrv_work;
};

/* header of ublk_params */
struct ublk_params_header {
	__u32	len;
	__u32	types;
};

static inline struct ublk_queue *ublk_get_queue(struct ublk_device *dev,
		int qid)
{
       return (struct ublk_queue *)&(dev->__queues[qid * dev->queue_size]);
}

static inline struct ublksrv_io_desc *ublk_get_iod(struct ublk_queue *ubq,
		int tag)
{
	return (struct ublksrv_io_desc *)
		&(ubq->io_cmd_buf[tag * sizeof(struct ublksrv_io_desc)]);
}

static inline bool ublk_support_bpf(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_BPF;
}

static inline bool ublk_dev_support_bpf(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_BPF;
}

struct ublk_device *ublk_get_device(struct ublk_device *ub);
struct ublk_device *ublk_get_device_from_id(int idx);
void ublk_put_device(struct ublk_device *ub);
void __ublk_complete_rq(struct request *req);

static inline void __ublk_complete_rq_with_res(struct request *req, int res)
{
	struct ublk_queue *ubq = req->mq_hctx->driver_data;
	struct ublk_io *io = &ubq->ios[req->tag];

	io->res = res;
	__ublk_complete_rq(req);
}
#endif
