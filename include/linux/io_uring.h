/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_H
#define _LINUX_IO_URING_H

#include <linux/sched.h>
#include <linux/xarray.h>
#include <linux/bvec.h>
#include <uapi/linux/io_uring.h>

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER	= 1,
	IO_URING_F_UNLOCKED		= 2,
	/* the request is executed from poll, it should not be freed */
	IO_URING_F_MULTISHOT		= 4,
	/* executed by io-wq */
	IO_URING_F_IOWQ			= 8,
	/* int's last bit, sign checks are usually faster than a bit test */
	IO_URING_F_NONBLOCK		= INT_MIN,

	/* ctx state flags, for URING_CMD */
	IO_URING_F_SQE128		= (1 << 8),
	IO_URING_F_CQE32		= (1 << 9),
	IO_URING_F_IOPOLL		= (1 << 10),

	/* for FUSED_CMD only */
	IO_URING_F_FUSED_WRITE		= (1 << 11), /* slave writes to buffer */
	IO_URING_F_FUSED_READ		= (1 << 12), /* slave reads from buffer */
	/* driver incapable of FUSED_CMD should fail cmd when seeing F_FUSED */
	IO_URING_F_FUSED		= IO_URING_F_FUSED_WRITE |
		IO_URING_F_FUSED_READ,
};

union io_uring_fused_cmd_data {
	/*
	 * In case of slave request IOSQE_CQE_SKIP_SUCCESS, return slave
	 * result via master command; otherwise we simply return success
	 * if buffer is provided, and slave request will return its result
	 * via its CQE
	 */
	s32 slave_res;

	/* fused cmd private, driver do not touch it */
	struct io_kiocb *__slave;
};

struct io_uring_cmd {
	struct file	*file;
	const void	*cmd;
	union {
		/* callback to defer completions to task context */
		void (*task_work_cb)(struct io_uring_cmd *cmd);
		/* used for polled completion */
		void *cookie;
	};
	u32		cmd_op;
	u32		flags;

	/* for fused command, the available pdu is a bit less */
	union {
		u8		pdu[32]; /* available inline for free use */
		struct {
			u8	pdu[24]; /* available inline for free use */
			union io_uring_fused_cmd_data data;
		} fused;
	};
};

/* The mapper buffer is supposed to be immutable */
struct io_mapped_buf {
	/*
	 * For kernel buffer without virtual address, buf is set as zero,
	 * which is just fine given both buf/buf_end are just for
	 * calculating iov iter offset/len and validating buffer.
	 *
	 * So slave OP has to fail request in case that the OP doesn't
	 * support iov iter.
	 */
	u64		buf;
	u64		buf_end;
	unsigned int	nr_bvecs;
	union {
		unsigned int	acct_pages;

		/*
		 * offset into the bvecs, use for external user; with
		 * 'offset', immutable bvecs can be provided for io_uring
		 */
		unsigned int	offset;
	};
	struct bio_vec	*bvec;
	struct bio_vec	__bvec[];
};

#if defined(CONFIG_IO_URING)
void io_fused_cmd_provide_kbuf(struct io_uring_cmd *ioucmd, bool locked,
		const struct io_mapped_buf *imu,
		void (*complete_tw_cb)(struct io_uring_cmd *));
int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd);
void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret, ssize_t res2);
void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *));
struct sock *io_uring_get_socket(struct file *file);
void __io_uring_cancel(bool cancel_all);
void __io_uring_free(struct task_struct *tsk);
void io_uring_unreg_ringfd(void);
const char *io_uring_get_opcode(u8 opcode);

static inline void io_uring_files_cancel(void)
{
	if (current->io_uring) {
		io_uring_unreg_ringfd();
		__io_uring_cancel(false);
	}
}
static inline void io_uring_task_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(true);
}
static inline void io_uring_free(struct task_struct *tsk)
{
	if (tsk->io_uring)
		__io_uring_free(tsk);
}
#else
static inline void io_fused_cmd_provide_kbuf(struct io_uring_cmd *ioucmd,
		bool locked, const struct io_mapped_buf *fused_cmd_kbuf,
		unsigned int len, void (*complete_tw_cb)(struct io_uring_cmd *))
{
}
static inline int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd)
{
	return -EOPNOTSUPP;
}
static inline void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret,
		ssize_t ret2)
{
}
static inline void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *))
{
}
static inline struct sock *io_uring_get_socket(struct file *file)
{
	return NULL;
}
static inline void io_uring_task_cancel(void)
{
}
static inline void io_uring_files_cancel(void)
{
}
static inline void io_uring_free(struct task_struct *tsk)
{
}
static inline const char *io_uring_get_opcode(u8 opcode)
{
	return "";
}
#endif

#endif
