// SPDX-License-Identifier: GPL-2.0
/*
 * BPF task-work target for ublk: exercises ->queue_io_cmd_tw().
 *
 * The arena target runs its submission callback from queue_rq (the
 * submitter's context). queue_io_cmd_tw instead runs from the ublk daemon
 * task context, which is where per-I/O buffer allocation belongs: pulling a
 * buffer from a shared pool in an arbitrary submitter context races, while
 * the daemon context is serialized per queue.
 *
 * Each I/O dynamically allocates a slot from a shared BPF-arena pool and
 * records the tag->slot mapping in a BPF HASH map; queue_io_cmd_tw returns
 * void, so the request is then forwarded to the ublk server for completion.
 * The paired ->complete_io_cmd() (which struct ublk_bpf_ops requires whenever
 * queue_io_cmd_tw is set) releases the slot and drops the map entry.
 *
 * The device runs UBLK_F_USER_COPY, and userspace routes the real I/O data
 * through the mmapped arena buffer for the tag (looked up in the same map), so
 * the buffer is not just accounted but actually carries I/O. Userspace reads
 * the counters back to assert alloc/free are balanced and the pool never
 * handed out an in-use slot.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_arena_common.h"
#include "ublk_tw.h"
#include "ublk_bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2048); /* pages: NR_BUFS * sizeof(tw_buf) ~= 4 MiB */
} arena SEC(".maps");

/* tag -> allocated buffer index in the arena pool */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NR_TAGS);
	__type(key, __u32);
	__type(value, __u32);
} tag2buf SEC(".maps");

/* pool of dynamically-allocated per-I/O buffers */
struct tw_buf __arena_global bufs[NR_BUFS];

__u64 __arena_global alloc_cursor;
__u64 __arena_global nr_alloc;
__u64 __arena_global nr_free;
__u64 __arena_global nr_busy;	/* pool exhausted: no free slot found */
__u64 __arena_global nr_badtag;

SEC("struct_ops/queue_io_cmd_tw")
void BPF_PROG(ublk_tw_queue_io_cmd_tw, void *bctx, struct request *req)
{
	const struct ublksrv_io_desc *iod;
	__u64 seq;
	__u32 tag, idx, i;

	/*
	 * Returns void: the request is always forwarded to the ublk server
	 * for completion. Any failure here is recorded in our own state (the
	 * counters below) rather than reported to the kernel.
	 */
	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return;

	tag = req->tag;
	if (tag >= NR_TAGS) {
		__sync_fetch_and_add(&nr_badtag, 1);
		return;
	}

	/*
	 * Dynamically allocate a free slot from the shared arena pool: scan
	 * from a rotating cursor and claim the first free slot with a CAS.
	 * The pool is larger than the queue's in-flight depth, so a free slot
	 * always exists and an in-use buffer is never handed out.
	 */
	seq = __sync_fetch_and_add(&alloc_cursor, 1);
	idx = NR_BUFS;
	for (i = 0; i < NR_BUFS; i++) {
		__u32 cand = (seq + i) & (NR_BUFS - 1);

		if (__sync_bool_compare_and_swap(&bufs[cand].in_use, 0, 1)) {
			idx = cand;
			break;
		}
	}
	if (idx >= NR_BUFS) {
		__sync_fetch_and_add(&nr_busy, 1);	/* pool exhausted */
		return;
	}

	/* remember the slot so complete_io_cmd (and userspace) can find it */
	bpf_map_update_elem(&tag2buf, &tag, &idx, BPF_ANY);
	__sync_fetch_and_add(&nr_alloc, 1);
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(ublk_tw_complete_io_cmd, void *bctx, struct request *req)
{
	struct tw_buf __arena *b;
	__u32 tag, idx, *pidx;

	tag = req->tag;
	if (tag >= NR_TAGS)
		return;

	pidx = bpf_map_lookup_elem(&tag2buf, &tag);
	if (!pidx)
		return;

	idx = *pidx;
	if (idx >= NR_BUFS)
		return;

	b = &bufs[idx];
	b->in_use = 0;			/* free the buffer */
	bpf_map_delete_elem(&tag2buf, &tag);
	__sync_fetch_and_add(&nr_free, 1);
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_tw_bpf_ops = {
	.id = 5,
	.queue_io_cmd_tw = (void *)ublk_tw_queue_io_cmd_tw,
	.complete_io_cmd = (void *)ublk_tw_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
