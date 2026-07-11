// SPDX-License-Identifier: GPL-2.0
/*
 * BPF arena target for ublk: exercises BPF arena memory as I/O metadata
 * buffer allocated and written from queue_rq (queue_io_cmd) context.
 *
 * Each I/O bump-allocates a record slot from an __arena ring, stores the
 * I/O descriptor there, and verifies the arena write by reading it back
 * before completing the request. Any arena inconsistency fails the I/O,
 * so plain fio on the device asserts arena correctness end-to-end.
 * Userspace can also read the same arena pages via the skeleton mmap.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_arena_common.h"
#include "ublk_arena.h"
#include "ublk_bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 16); /* pages */
} arena SEC(".maps");

/* arena globals: pages are reserved and populated by libbpf at load */
struct io_rec __arena_global recs[NR_RECS];
__u64 __arena_global nr_ios;

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_arena_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;
	struct io_rec __arena *r;
	__u64 seq;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	seq = __sync_fetch_and_add(&nr_ios, 1);
	r = &recs[seq & (NR_RECS - 1)];
	r->seq = seq;
	r->op_flags = iod->op_flags;
	r->nr_sectors = iod->nr_sectors;
	r->start_sector = iod->start_sector;

	/* verify the arena write is readable and consistent */
	if (r->seq != seq || r->nr_sectors != iod->nr_sectors)
		return -5; /* -EIO: arena readback mismatch */

	/* > 0: I/O completed with this many bytes, do NOT forward */
	return iod->nr_sectors << 9;
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(ublk_arena_commit_io_cmd, void *bctx, int ubq_id)
{
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(ublk_arena_complete_io_cmd, void *bctx,
	      struct request *req)
{
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_arena_bpf_ops = {
	.id = 2,
	.queue_io_cmd = (void *)ublk_arena_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_arena_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_arena_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
