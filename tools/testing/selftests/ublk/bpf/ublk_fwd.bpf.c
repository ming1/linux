// SPDX-License-Identifier: GPL-2.0
/*
 * BPF forwarding target for ublk: exercises the queue_io_cmd == 0
 * return path, where the BPF program inspects the request but asks
 * the driver to forward it to the ublk server for completion.
 *
 * This is the contract an NVMe UBLK_F_SHMEM_ZC target relies on: the
 * BPF program reads the I/O descriptor -- including the shmem buffer
 * index + offset encoded in iod->addr when UBLK_IO_F_SHMEM_ZC is set,
 * which maps to a pre-mapped IOVA -- submits the command to hardware,
 * and returns 0 so the server can poll the CQ and complete the I/O.
 * Here no hardware is involved, so the program only records what it
 * saw and forwards everything.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ublk_bpf.h"

/* mirrors UBLK_IO_F_SHMEM_ZC in uapi ublk_cmd.h */
#define UBLK_IO_F_SHMEM_ZC	(1U << 19)

__u64 nr_ios;
__u64 nr_shmem_zc_ios;

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_fwd_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	__sync_fetch_and_add(&nr_ios, 1);

	/*
	 * For a shmem_zc request, iod->addr encodes buffer index +
	 * offset; a real target would turn that into a pre-mapped IOVA
	 * and queue the command to hardware here.
	 */
	if (iod->op_flags & UBLK_IO_F_SHMEM_ZC)
		__sync_fetch_and_add(&nr_shmem_zc_ios, 1);

	return 0; /* forward to userspace for completion */
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(ublk_fwd_commit_io_cmd, void *bctx, int ubq_id)
{
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(ublk_fwd_complete_io_cmd, void *bctx,
	      struct request *req)
{
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_fwd_bpf_ops = {
	.id = 3,
	.queue_io_cmd = (void *)ublk_fwd_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_fwd_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_fwd_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
