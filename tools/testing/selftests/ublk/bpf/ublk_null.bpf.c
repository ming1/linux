// SPDX-License-Identifier: GPL-2.0
/*
 * BPF null target for ublk: immediately completes all I/O with success.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* kfunc declarations */
extern struct ublksrv_io_desc *ublk_bpf_get_iod(struct request *req) __ksym;
extern void ublk_bpf_complete_io(struct request *req, int res) __ksym;

SEC("struct_ops.s/init_queue")
int BPF_PROG(ublk_null_init_queue, void *bctx, int qid, int depth)
{
	return 0;
}

SEC("struct_ops/deinit_queue")
void BPF_PROG(ublk_null_deinit_queue, void *bctx, int qid)
{
}

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_null_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	ublk_bpf_complete_io(req, iod->nr_sectors << 9);
	return 0;
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
	.init_queue = (void *)ublk_null_init_queue,
	.deinit_queue = (void *)ublk_null_deinit_queue,
	.queue_io_cmd = (void *)ublk_null_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_null_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_null_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
