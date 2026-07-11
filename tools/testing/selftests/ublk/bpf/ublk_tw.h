/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between ublk_tw.bpf.c and kublk userspace: layout of the per-I/O
 * buffer pool the task-work program manages in its arena.
 */
#ifndef UBLK_TW_H
#define UBLK_TW_H

#define NR_BUFS		64	/* power of 2, >= test fio iodepth */
#define NR_TAGS		1024	/* >= UBLK_QUEUE_DEPTH */

/*
 * Data payload for the real I/O carried through the arena buffer. The device's
 * max single-I/O size is UBLK_IO_MAX_BYTES (1 MiB), which would make a
 * per-buffer arena pool huge; use a fixed 64 KiB cap instead (the test drives
 * bs=4k, well within this) and clamp the userspace copy to IO_BUF_SIZE so a
 * larger I/O can never overrun the arena buffer.
 */
#define IO_BUF_SIZE	(64 * 1024)

struct tw_buf {
	__u64 in_use;
	unsigned char data[IO_BUF_SIZE];
};

#endif
