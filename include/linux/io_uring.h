/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_IO_URING_H
#define _LINUX_IO_URING_H

#include <linux/sched.h>
#include <linux/xarray.h>

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER	= 1,
	IO_URING_F_UNLOCKED		= 2,
	/* int's last bit, sign checks are usually faster than a bit test */
	IO_URING_F_NONBLOCK		= INT_MIN,
};

struct io_uring_cmd {
	struct file     *file;
	void            *cmd;
	/* for irq-completion - if driver requires doing stuff in task-context*/
	void (*driver_cb)(struct io_uring_cmd *cmd);
	u32             flags;
	u32             cmd_op;
	u16		cmd_len;
	u16		unused;
	u8		pdu[28]; /* available inline for free use */
};

#if defined(CONFIG_IO_URING)
void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret);
void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*driver_cb)(struct io_uring_cmd *));
struct sock *io_uring_get_socket(struct file *file);
void __io_uring_cancel(bool cancel_all);
void __io_uring_free(struct task_struct *tsk);

static inline void io_uring_files_cancel(void)
{
	if (current->io_uring)
		__io_uring_cancel(false);
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
static inline void io_uring_cmd_done(struct io_uring_cmd *cmd, ssize_t ret)
{
}
static inline void io_uring_cmd_complete_in_task(struct io_uring_cmd *ioucmd,
			void (*driver_cb)(struct io_uring_cmd *))
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
#endif

#endif
