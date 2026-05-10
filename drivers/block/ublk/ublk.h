/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __UBLK_H
#define __UBLK_H

#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/blk-mq.h>
#include <linux/cdev.h>
#include <linux/io_uring/cmd.h>
#include <linux/kfifo.h>
#include <linux/maple_tree.h>
#include <linux/refcount.h>
#include <uapi/linux/ublk_cmd.h>

#define UBLK_MINORS		(1U << MINORBITS)

#define UBLK_INVALID_BUF_IDX	((u16)-1)

/* private ioctl command mirror */
#define UBLK_CMD_DEL_DEV_ASYNC	_IOC_NR(UBLK_U_CMD_DEL_DEV_ASYNC)
#define UBLK_CMD_UPDATE_SIZE	_IOC_NR(UBLK_U_CMD_UPDATE_SIZE)
#define UBLK_CMD_QUIESCE_DEV	_IOC_NR(UBLK_U_CMD_QUIESCE_DEV)
#define UBLK_CMD_TRY_STOP_DEV	_IOC_NR(UBLK_U_CMD_TRY_STOP_DEV)
#define UBLK_CMD_REG_BUF	_IOC_NR(UBLK_U_CMD_REG_BUF)
#define UBLK_CMD_UNREG_BUF	_IOC_NR(UBLK_U_CMD_UNREG_BUF)

/* Default max shmem buffer size: 4GB (may be increased in future) */
#define UBLK_SHMEM_BUF_SIZE_MAX	(1ULL << 32)

#define UBLK_IO_REGISTER_IO_BUF	_IOC_NR(UBLK_U_IO_REGISTER_IO_BUF)
#define UBLK_IO_UNREGISTER_IO_BUF	_IOC_NR(UBLK_U_IO_UNREGISTER_IO_BUF)

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
		| UBLK_F_UPDATE_SIZE \
		| UBLK_F_AUTO_BUF_REG \
		| UBLK_F_QUIESCE \
		| UBLK_F_PER_IO_DAEMON \
		| UBLK_F_BUF_REG_OFF_DAEMON \
		| (IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY) ? UBLK_F_INTEGRITY : 0) \
		| UBLK_F_SAFE_STOP_DEV \
		| UBLK_F_BATCH_IO \
		| UBLK_F_NO_AUTO_PART_SCAN \
		| UBLK_F_SHMEM_ZC)

#define UBLK_F_ALL_RECOVERY_FLAGS (UBLK_F_USER_RECOVERY \
		| UBLK_F_USER_RECOVERY_REISSUE \
		| UBLK_F_USER_RECOVERY_FAIL_IO)

/* All UBLK_PARAM_TYPE_* should be included here */
#define UBLK_PARAM_TYPE_ALL                                \
	(UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DISCARD | \
	 UBLK_PARAM_TYPE_DEVT | UBLK_PARAM_TYPE_ZONED |    \
	 UBLK_PARAM_TYPE_DMA_ALIGN | UBLK_PARAM_TYPE_SEGMENT | \
	 UBLK_PARAM_TYPE_INTEGRITY)

#define UBLK_BATCH_F_ALL  \
	(UBLK_BATCH_F_HAS_ZONE_LBA | \
	 UBLK_BATCH_F_HAS_BUF_ADDR | \
	 UBLK_BATCH_F_AUTO_BUF_REG_FALLBACK)

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
 * UBLK_IO_FLAG_NEED_GET_DATA is set because IO command requires
 * get data buffer address from ublksrv.
 *
 * Then, bio data could be copied into this data buffer for a WRITE request
 * after the IO command is issued again and UBLK_IO_FLAG_NEED_GET_DATA is unset.
 */
#define UBLK_IO_FLAG_NEED_GET_DATA 0x08

/*
 * request buffer is registered automatically, so we have to unregister it
 * before completing this request.
 *
 * io_uring will unregister buffer automatically for us during exiting.
 */
#define UBLK_IO_FLAG_AUTO_BUF_REG	0x10

/* atomic RW with ubq->cancel_lock */
#define UBLK_IO_FLAG_CANCELED	0x80000000

/*
 * Initialize refcount to a large number to include any registered buffers.
 * UBLK_IO_COMMIT_AND_FETCH_REQ will release these references minus those for
 * any buffers registered on the io daemon task.
 */
#define UBLK_REFCOUNT_INIT (REFCOUNT_MAX / 2)

/* used for UBLK_F_BATCH_IO only */
#define UBLK_BATCH_IO_UNUSED_TAG	((unsigned short)-1)

/* ublk batch fetch uring_cmd */
struct ublk_batch_fetch_cmd {
	struct list_head node;
	struct io_uring_cmd *cmd;
	unsigned short buf_group;
};

struct ublk_uring_cmd_pdu {
	/*
	 * Store requests in same batch temporarily for queuing them to
	 * daemon context.
	 *
	 * It should have been stored to request payload, but we do want
	 * to avoid extra pre-allocation, and uring_cmd payload is always
	 * free for us
	 */
	union {
		struct request *req;
		struct request *req_list;
	};

	/*
	 * The following two are valid in this cmd whole lifetime, and
	 * setup in ublk uring_cmd handler
	 */
	struct ublk_queue *ubq;

	union {
		u16 tag;
		struct ublk_batch_fetch_cmd *fcmd; /* batch io only */
	};
};

struct ublk_batch_io_data {
	struct ublk_device *ub;
	struct io_uring_cmd *cmd;
	struct ublk_batch_io header;
	unsigned int issue_flags;
	struct io_comp_batch *iob;
};

union ublk_io_buf {
	__u64	addr;
	struct ublk_auto_buf_reg auto_reg;
};

struct ublk_io {
	union ublk_io_buf buf;
	unsigned int flags;
	int res;

	union {
		/* valid if UBLK_IO_FLAG_ACTIVE is set */
		struct io_uring_cmd *cmd;
		/* valid if UBLK_IO_FLAG_OWNED_BY_SRV is set */
		struct request *req;
	};

	struct task_struct *task;

	/*
	 * The number of uses of this I/O by the ublk server
	 * if user copy or zero copy are enabled:
	 * - UBLK_REFCOUNT_INIT from dispatch to the server
	 *   until UBLK_IO_COMMIT_AND_FETCH_REQ
	 * - 1 for each inflight ublk_ch_{read,write}_iter() call not on task
	 * - 1 for each io_uring registered buffer not registered on task
	 * The I/O can only be completed once all references are dropped.
	 * User copy and buffer registration operations are only permitted
	 * if the reference count is nonzero.
	 */
	refcount_t ref;
	/* Count of buffers registered on task and not yet unregistered */
	unsigned task_registered_buffers;

	void *buf_ctx_handle;
	spinlock_t lock;
} ____cacheline_aligned_in_smp;

struct ublk_queue {
	int q_id;
	int q_depth;

	unsigned long flags;
	struct ublksrv_io_desc *io_cmd_buf;

	bool force_abort;
	bool canceling;
	bool fail_io; /* copy of dev->state == UBLK_S_DEV_FAIL_IO */
	spinlock_t		cancel_lock;
	struct ublk_device *dev;
	u32 nr_io_ready;

	/*
	 * For supporting UBLK_F_BATCH_IO only.
	 *
	 * Inflight ublk request tag is saved in this fifo
	 *
	 * There are multiple writer from ublk_queue_rq() or ublk_queue_rqs(),
	 * so lock is required for storing request tag to fifo
	 *
	 * Make sure just one reader for fetching request from task work
	 * function to ublk server, so no need to grab the lock in reader
	 * side.
	 *
	 * Batch I/O State Management:
	 *
	 * The batch I/O system uses implicit state management based on the
	 * combination of three key variables below.
	 *
	 * - IDLE: list_empty(&fcmd_head) && !active_fcmd
	 *   No fetch commands available, events queue in evts_fifo
	 *
	 * - READY: !list_empty(&fcmd_head) && !active_fcmd
	 *   Fetch commands available but none processing events
	 *
	 * - ACTIVE: active_fcmd
	 *   One fetch command actively processing events from evts_fifo
	 *
	 * Key Invariants:
	 * - At most one active_fcmd at any time (single reader)
	 * - active_fcmd is always from fcmd_head list when non-NULL
	 * - evts_fifo can be read locklessly by the single active reader
	 * - All state transitions require evts_lock protection
	 * - Multiple writers to evts_fifo require lock protection
	 */
	struct {
		DECLARE_KFIFO_PTR(evts_fifo, unsigned short);
		spinlock_t evts_lock;

		/* List of fetch commands available to process events */
		struct list_head fcmd_head;

		/* Currently active fetch command (NULL = none active) */
		struct ublk_batch_fetch_cmd  *active_fcmd;
	}____cacheline_aligned_in_smp;

	struct ublk_io ios[] __counted_by(q_depth);
};

/* Maple tree value: maps a PFN range to buffer location */
struct ublk_buf_range {
	unsigned short buf_index;
	unsigned short flags;
	unsigned int base_offset;	/* byte offset within buffer */
};

struct ublk_device {
	struct gendisk		*ub_disk;

	struct ublksrv_ctrl_dev_info	dev_info;

	struct blk_mq_tag_set	tag_set;

	struct cdev		cdev;
	struct device		cdev_dev;

#define UB_STATE_OPEN		0
#define UB_STATE_USED		1
#define UB_STATE_DELETED	2
	unsigned long		state;
	int			ub_number;

	struct mutex		mutex;

	spinlock_t		lock;
	struct mm_struct	*mm;

	struct ublk_params	params;

	struct completion	completion;
	u32			nr_queue_ready;
	bool 			unprivileged_daemons;
	struct mutex cancel_mutex;
	bool canceling;
	pid_t 	ublksrv_tgid;
	struct delayed_work	exit_work;
	struct work_struct	partition_scan_work;

	bool			block_open; /* protected by open_mutex */

	/* shared memory zero copy */
	struct maple_tree	buf_tree;
	struct ida		buf_ida;

	struct ublk_queue       *queues[];
};

/* header of ublk_params */
struct ublk_params_header {
	__u32	len;
	__u32	types;
};

void ublk_init_iod(struct ublk_queue *ubq, struct request *req,
		   uint8_t ublk_op, uint32_t nr_sectors,
		   uint64_t start_sector);

#ifdef CONFIG_BLK_DEV_ZONED

struct ublk_zoned_report_desc {
	__u64 sector;
	__u32 operation;
	__u32 nr_zones;
};

int ublk_dev_param_zoned_validate(const struct ublk_device *ub);
void ublk_dev_param_zoned_apply(struct ublk_device *ub);
int ublk_revalidate_disk_zones(struct ublk_device *ub);
blk_status_t ublk_setup_iod_zoned(struct ublk_queue *ubq,
				   struct request *req);
int ublk_report_zones(struct gendisk *disk, sector_t sector,
		      unsigned int nr_zones,
		      struct blk_report_zones_args *args);

#else

static inline int ublk_dev_param_zoned_validate(const struct ublk_device *ub)
{
	return -EOPNOTSUPP;
}

static inline void ublk_dev_param_zoned_apply(struct ublk_device *ub)
{
}

static inline int ublk_revalidate_disk_zones(struct ublk_device *ub)
{
	return 0;
}

static inline blk_status_t ublk_setup_iod_zoned(struct ublk_queue *ubq,
						 struct request *req)
{
	return BLK_STS_NOTSUPP;
}

#define ublk_report_zones	(NULL)

#endif

#define UBLK_MAX_UBLKS UBLK_MINORS

#define UBLK_REQUEUE_DELAY_MS	3

#define MAX_NR_TAG 128

static inline struct ublk_queue *ublk_get_queue(struct ublk_device *dev,
		int qid)
{
	return dev->queues[qid];
}

static inline struct ublksrv_io_desc *
ublk_get_iod(const struct ublk_queue *ubq, unsigned tag)
{
	return &ubq->io_cmd_buf[tag];
}

static inline bool ublk_iod_is_shmem_zc(const struct ublk_queue *ubq,
					unsigned int tag)
{
	return ublk_get_iod(ubq, tag)->op_flags & UBLK_IO_F_SHMEM_ZC;
}

static inline struct ublk_uring_cmd_pdu *ublk_get_uring_cmd_pdu(
		struct io_uring_cmd *ioucmd)
{
	return io_uring_cmd_to_pdu(ioucmd, struct ublk_uring_cmd_pdu);
}

static inline void ublk_io_lock(struct ublk_io *io)
{
	spin_lock(&io->lock);
}

static inline void ublk_io_unlock(struct ublk_io *io)
{
	spin_unlock(&io->lock);
}

static inline bool ublk_dev_is_zoned(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_ZONED;
}

static inline bool ublk_queue_is_zoned(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_ZONED;
}

static inline bool ublk_dev_support_batch_io(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_BATCH_IO;
}

static inline bool ublk_support_batch_io(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_BATCH_IO;
}

static inline bool ublk_dev_support_zero_copy(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_SUPPORT_ZERO_COPY;
}

static inline bool ublk_support_zero_copy(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_SUPPORT_ZERO_COPY;
}

static inline bool ublk_dev_support_auto_buf_reg(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_AUTO_BUF_REG;
}

static inline bool ublk_support_auto_buf_reg(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_AUTO_BUF_REG;
}

static inline bool ublk_dev_support_user_copy(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_USER_COPY;
}

static inline bool ublk_support_user_copy(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_USER_COPY;
}

static inline bool ublk_dev_support_shmem_zc(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_SHMEM_ZC;
}

static inline bool ublk_dev_need_map_io(const struct ublk_device *ub)
{
	return !ublk_dev_support_user_copy(ub) &&
	       !ublk_dev_support_zero_copy(ub) &&
	       !ublk_dev_support_auto_buf_reg(ub);
}

static inline bool ublk_need_map_io(const struct ublk_queue *ubq)
{
	return !ublk_support_user_copy(ubq) && !ublk_support_zero_copy(ubq) &&
		!ublk_support_auto_buf_reg(ubq);
}

static inline bool ublk_dev_need_req_ref(const struct ublk_device *ub)
{
	return ublk_dev_support_user_copy(ub) ||
	       ublk_dev_support_zero_copy(ub) ||
	       ublk_dev_support_auto_buf_reg(ub);
}

static inline bool ublk_need_req_ref(const struct ublk_queue *ubq)
{
	/*
	 * read()/write() is involved in user copy, so request reference
	 * has to be grabbed
	 *
	 * for zero copy, request buffer need to be registered to io_uring
	 * buffer table, so reference is needed
	 *
	 * For auto buffer register, ublk server still may issue
	 * UBLK_IO_COMMIT_AND_FETCH_REQ before one registered buffer is used up,
	 * so reference is required too.
	 */
	return ublk_support_user_copy(ubq) || ublk_support_zero_copy(ubq) ||
		ublk_support_auto_buf_reg(ubq);
}

static inline bool ublk_need_get_data(const struct ublk_queue *ubq)
{
	return ubq->flags & UBLK_F_NEED_GET_DATA;
}

static inline bool ublk_dev_need_get_data(const struct ublk_device *ub)
{
	return ub->dev_info.flags & UBLK_F_NEED_GET_DATA;
}

/*
 * Should I/O outstanding to the ublk server when it exits be reissued?
 * If not, outstanding I/O will get errors.
 */
static inline bool ublk_nosrv_should_reissue_outstanding(struct ublk_device *ub)
{
	return (ub->dev_info.flags & UBLK_F_USER_RECOVERY) &&
	       (ub->dev_info.flags & UBLK_F_USER_RECOVERY_REISSUE);
}

/*
 * Should I/O issued while there is no ublk server queue? If not, I/O
 * issued while there is no ublk server will get errors.
 */
static inline bool ublk_nosrv_dev_should_queue_io(struct ublk_device *ub)
{
	return (ub->dev_info.flags & UBLK_F_USER_RECOVERY) &&
	       !(ub->dev_info.flags & UBLK_F_USER_RECOVERY_FAIL_IO);
}

/*
 * Should ublk devices be stopped (i.e. no recovery possible) when the
 * ublk server exits? If not, devices can be used again by a future
 * incarnation of a ublk server via the start_recovery/end_recovery
 * commands.
 */
static inline bool ublk_nosrv_should_stop_dev(struct ublk_device *ub)
{
	return !(ub->dev_info.flags & UBLK_F_USER_RECOVERY);
}

static inline bool ublk_queue_ready(const struct ublk_queue *ubq)
{
	return ubq->nr_io_ready == ubq->q_depth;
}

static inline bool ublk_dev_ready(const struct ublk_device *ub)
{
	return ub->nr_queue_ready == ub->dev_info.nr_hw_queues;
}

static inline void ublk_init_req_ref(const struct ublk_queue *ubq,
		struct ublk_io *io)
{
	if (ublk_need_req_ref(ubq))
		refcount_set(&io->ref, UBLK_REFCOUNT_INIT);
}

static inline bool ublk_get_req_ref(struct ublk_io *io)
{
	return refcount_inc_not_zero(&io->ref);
}

static inline bool ublk_sub_req_ref(struct ublk_io *io)
{
	unsigned sub_refs = UBLK_REFCOUNT_INIT - io->task_registered_buffers;

	io->task_registered_buffers = 0;
	return refcount_sub_and_test(sub_refs, &io->ref);
}

static inline unsigned int ublk_req_build_flags(struct request *req)
{
	unsigned flags = 0;

	if (req->cmd_flags & REQ_FAILFAST_DEV)
		flags |= UBLK_IO_F_FAILFAST_DEV;

	if (req->cmd_flags & REQ_FAILFAST_TRANSPORT)
		flags |= UBLK_IO_F_FAILFAST_TRANSPORT;

	if (req->cmd_flags & REQ_FAILFAST_DRIVER)
		flags |= UBLK_IO_F_FAILFAST_DRIVER;

	if (req->cmd_flags & REQ_META)
		flags |= UBLK_IO_F_META;

	if (req->cmd_flags & REQ_FUA)
		flags |= UBLK_IO_F_FUA;

	if (req->cmd_flags & REQ_NOUNMAP)
		flags |= UBLK_IO_F_NOUNMAP;

	if (req->cmd_flags & REQ_SWAP)
		flags |= UBLK_IO_F_SWAP;

	if (blk_integrity_rq(req))
		flags |= UBLK_IO_F_INTEGRITY;

	return flags;
}

static inline bool ublk_need_map_req(const struct request *req)
{
	return blk_rq_has_data(req) && req_op(req) == REQ_OP_WRITE;
}

static inline bool ublk_need_unmap_req(const struct request *req)
{
	return blk_rq_has_data(req) &&
	       (req_op(req) == REQ_OP_READ || req_op(req) == REQ_OP_DRV_IN);
}

static inline int __ublk_queue_cmd_buf_size(int depth)
{
	return round_up(depth * sizeof(struct ublksrv_io_desc), PAGE_SIZE);
}

static inline int ublk_queue_cmd_buf_size(struct ublk_device *ub)
{
	return __ublk_queue_cmd_buf_size(ub->dev_info.queue_depth);
}

static inline int ublk_max_cmd_buf_size(void)
{
	return __ublk_queue_cmd_buf_size(UBLK_MAX_QUEUE_DEPTH);
}

static inline unsigned ublk_pos_to_hwq(loff_t pos)
{
	return ((pos - UBLKSRV_IO_BUF_OFFSET) >> UBLK_QID_OFF) &
		UBLK_QID_BITS_MASK;
}

static inline unsigned ublk_pos_to_buf_off(loff_t pos)
{
	return (pos - UBLKSRV_IO_BUF_OFFSET) & UBLK_IO_BUF_BITS_MASK;
}

static inline unsigned ublk_pos_to_tag(loff_t pos)
{
	return ((pos - UBLKSRV_IO_BUF_OFFSET) >> UBLK_TAG_OFF) &
		UBLK_TAG_BITS_MASK;
}

/* Once we return, `io->req` can't be used any more */
static inline struct request *
ublk_fill_io_cmd(struct ublk_io *io, struct io_uring_cmd *cmd)
{
	struct request *req = io->req;

	io->cmd = cmd;
	io->flags |= UBLK_IO_FLAG_ACTIVE;
	/* now this cmd slot is owned by ublk driver */
	io->flags &= ~UBLK_IO_FLAG_OWNED_BY_SRV;

	return req;
}

static inline void ublk_clear_auto_buf_reg(struct ublk_io *io,
					   struct io_uring_cmd *cmd,
					   u16 *buf_idx)
{
	if (io->flags & UBLK_IO_FLAG_AUTO_BUF_REG) {
		io->flags &= ~UBLK_IO_FLAG_AUTO_BUF_REG;

		/*
		 * `UBLK_F_AUTO_BUF_REG` only works iff `UBLK_IO_FETCH_REQ`
		 * and `UBLK_IO_COMMIT_AND_FETCH_REQ` are issued from same
		 * `io_ring_ctx`.
		 *
		 * If this uring_cmd's io_ring_ctx isn't same with the
		 * one for registering the buffer, it is ublk server's
		 * responsibility for unregistering the buffer, otherwise
		 * this ublk request gets stuck.
		 */
		if (io->buf_ctx_handle == io_uring_cmd_ctx_handle(cmd))
			*buf_idx = io->buf.auto_reg.index;
	}
}

static inline int ublk_check_fetch_buf(const struct ublk_device *ub,
				       __u64 buf_addr)
{
	if (ublk_dev_need_map_io(ub)) {
		/*
		 * FETCH_RQ has to provide IO buffer if NEED GET
		 * DATA is not enabled
		 */
		if (!buf_addr && !ublk_dev_need_get_data(ub))
			return -EINVAL;
	} else if (buf_addr) {
		/* User copy requires addr to be unset */
		return -EINVAL;
	}
	return 0;
}

static inline bool ublk_need_complete_req(const struct ublk_device *ub,
					  struct ublk_io *io)
{
	if (ublk_dev_need_req_ref(ub))
		return ublk_sub_req_ref(io);
	return true;
}

enum auto_buf_reg_res {
	AUTO_BUF_REG_FAIL,
	AUTO_BUF_REG_FALLBACK,
	AUTO_BUF_REG_OK,
};

/* ublk_main.c functions used by batch.c */
int ublk_init_hctx(struct blk_mq_hw_ctx *hctx, void *driver_data,
		   unsigned int hctx_idx);
enum blk_eh_timer_return ublk_timeout(struct request *rq);
int ublk_ch_open(struct inode *inode, struct file *filp);
int ublk_ch_release(struct inode *inode, struct file *filp);
ssize_t ublk_ch_read_iter(struct kiocb *iocb, struct iov_iter *to);
ssize_t ublk_ch_write_iter(struct kiocb *iocb, struct iov_iter *from);
int ublk_ch_mmap(struct file *filp, struct vm_area_struct *vma);
bool ublk_start_io(const struct ublk_queue *ubq, struct request *req,
		   struct ublk_io *io);
enum auto_buf_reg_res
ublk_auto_buf_register(const struct ublk_queue *ubq, struct request *req,
		       struct ublk_io *io, struct io_uring_cmd *cmd,
		       unsigned int issue_flags);
void ublk_auto_buf_io_setup(const struct ublk_queue *ubq,
			    struct request *req, struct ublk_io *io,
			    struct io_uring_cmd *cmd,
			    enum auto_buf_reg_res res);
blk_status_t __ublk_queue_rq_common(struct ublk_queue *ubq,
				    struct request *rq, bool *should_queue);
blk_status_t ublk_prep_req(struct ublk_queue *ubq, struct request *rq,
			   bool check_cancel);
int __ublk_fetch(struct io_uring_cmd *cmd, struct ublk_device *ub,
		 struct ublk_io *io, u16 q_id);
void ublk_mark_io_ready(struct ublk_device *ub, u16 q_id,
			struct ublk_io *io);
void __ublk_complete_rq(struct request *req, struct ublk_io *io,
			bool need_map, struct io_comp_batch *iob);
void ublk_start_cancel(struct ublk_device *ub);
void __ublk_fail_req(struct ublk_device *ub, struct ublk_io *io,
		     struct request *req);
int ublk_register_io_buf(struct io_uring_cmd *cmd, struct ublk_device *ub,
			 u16 q_id, u16 tag, struct ublk_io *io,
			 unsigned int index, unsigned int issue_flags);
int ublk_unregister_io_buf(struct io_uring_cmd *cmd,
			   const struct ublk_device *ub,
			   unsigned int index, unsigned int issue_flags);

/* batch.c exports */
extern const struct blk_mq_ops ublk_batch_mq_ops;
extern const struct file_operations ublk_ch_batch_io_fops;
void ublk_abort_batch_queue(struct ublk_device *ub, struct ublk_queue *ubq);
void ublk_batch_cancel_queue(struct ublk_queue *ubq);

#endif
