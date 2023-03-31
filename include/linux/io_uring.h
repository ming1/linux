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
};

struct io_uring_cmd {
	struct file	*file;
	const void	*cmd;
	union {
		/* callback to defer completions to task context */
		void (*task_work_cb)(struct io_uring_cmd *cmd, unsigned);
		/* used for polled completion */
		void *cookie;
	};
	u32		cmd_op;
	u32		flags;

	union {
		union {
			u8		pdu[32]; /* available inline for free use */

			/* 24bytes pdu for IORING_URING_CMD_XPIPE */
			struct {
				u8  pad[32 - 8];
				u16 nr_consumer;
				u16 xpipe_id;
				u32 xbuf_key;
			};
		};
	};
};

struct io_uring_bvec_buf {
	unsigned long	len;
	unsigned int	nr_bvecs;

	/* offset in the 1st bvec */
	unsigned int		offset;
	const struct bio_vec	*bvec;

	struct bio_vec		__bvec[];
};

#define IO_URING_XBUF_ACTIVE	(1 << 0) /* active now */
#define IO_URING_XBUF_KILLED	(1 << 1) /* erased from xpipe */
#define IO_URING_XBUF_SOURCE	(1 << 2) /* can read from buf */
#define IO_URING_XBUF_DEST	(1 << 3) /* can write to buf */
#define IO_URING_XBUF_FREE_BVEC	(1 << 4) /* need free bvec, for producer */
#define IO_URING_XBUF_AUTO	(1 << 5) /* auto removed */
struct io_uring_xpipe_buf {
	/* SQE can only provide 48bit key via xpipe_id & xbuf_key */
	u32	xbuf_key;
	u16	xpipe_id;
	/* atuo-removed after consumed by @nr_consumer OPs */
	u16	nr_consumer;

	u32	flags;
	u16	submit_cnt, comp_cnt;

	atomic_t ref;

	/* private part of buffer data, read only for consumer code */
	struct io_uring_bvec_buf __buf;

	/*
	 * Not like splice/pipe, xpipe provides whole buffer level lifetime,
	 * the buffer won't be released until ->buf_release_fn() returns
	 * since it is added to xpipe.
	 *
	 * Any xpipe buf not consumed will be released when destroying xpipe
	 * in io_uring exit or removed explicitly by REMOVE_XPIPE_BUF OP
	 */
	void  (*buf_release_fn)(struct io_uring_xpipe_buf *buf);
};

#if defined(CONFIG_IO_URING)
int io_uring_produce_xbuf(struct io_uring_cmd *ioucmd,
		struct io_uring_xpipe_buf *xbuf, unsigned xbuf_flags,
		unsigned issue_flags, bool *was_present);
int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd);
void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret, ssize_t res2,
			unsigned issue_flags);
void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned));
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
static inline int io_uring_produce_xbuf(struct io_uring_cmd *ioucmd,
		struct io_uring_xpipe_buf *xbuf, unsigned xbuf_flags,
		unsigned issue_flags, bool was_present)
{
	return -EOPNOTSUPP;
}
static inline int io_uring_cmd_import_fixed(u64 ubuf, unsigned long len, int rw,
			      struct iov_iter *iter, void *ioucmd)
{
	return -EOPNOTSUPP;
}
static inline void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret,
		ssize_t ret2, unsigned issue_flags)
{
}
static inline void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*task_work_cb)(struct io_uring_cmd *, unsigned))
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
