/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Shared between ublk_arena.bpf.c and kublk userspace: layout of the
 * per-I/O records the BPF program stores in its arena.
 */
#ifndef UBLK_ARENA_H
#define UBLK_ARENA_H

struct io_rec {
	__u64 seq;
	__u32 op_flags;
	__u32 nr_sectors;
	__u64 start_sector;
};

#define NR_RECS		512	/* power of 2 */

#endif
