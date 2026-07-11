// SPDX-License-Identifier: GPL-2.0
/*
 * BPF null target for ublk: immediately completes all I/O with success.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ublk_bpf.h"

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_null_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	/* > 0: I/O completed with this many bytes, do NOT forward */
	return iod->nr_sectors << 9;
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(ublk_null_commit_io_cmd, void *bctx, int ubq_id)
{
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(ublk_null_complete_io_cmd, void *bctx,
	      struct request *req)
{
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_null_bpf_ops = {
	.id = 1,
	.queue_io_cmd = (void *)ublk_null_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_null_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_null_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
