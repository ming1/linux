// SPDX-License-Identifier: GPL-2.0
/*
 * BPF null target for ublk: immediately completes all I/O with success.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * When building against vmlinux BTF (CONFIG_BLK_DEV_UBLK=y), these types
 * come from vmlinux.h. When building against module BTF
 * (/sys/kernel/btf/ublk_drv), they also come from vmlinux.h.
 *
 * For cross-compilation without module BTF, define them locally.
 * The ___local suffix avoids redefinition when types exist in vmlinux.h;
 * libbpf CO-RE matches by removing the ___local suffix at runtime.
 */
#ifndef bpf_ublk_has_vmlinux_types
struct ublk_bpf_ctx___local {
	void *ub;
	void *bar0;
	unsigned long bar0_size;
} __attribute__((preserve_access_index));

struct ublk_bpf_ops___local {
	int (*queue_io_cmd)(struct ublk_bpf_ctx___local *ctx,
			    struct request *req, bool last);
	void (*commit_io_cmd)(struct ublk_bpf_ctx___local *ctx, int ubq_id);
	void (*complete_io_cmd)(struct ublk_bpf_ctx___local *ctx,
				struct request *req);
};

struct ublksrv_io_desc___local {
	__u32 op_flags;
	union {
		__u32 nr_sectors;
		__u32 nr_zones;
	};
	__u64 start_sector;
	__u64 addr;
} __attribute__((preserve_access_index));

#define ublk_bpf_ctx ublk_bpf_ctx___local
#define ublk_bpf_ops ublk_bpf_ops___local
#define ublksrv_io_desc ublksrv_io_desc___local
#endif

/* kfunc declarations */
extern struct ublksrv_io_desc *ublk_bpf_get_iod(struct request *req) __ksym;
extern void ublk_bpf_complete_io(struct request *req, int res) __ksym;

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_null_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	ublk_bpf_complete_io(req, iod->nr_sectors << 9);
	return 1; /* I/O completed, do NOT forward to userspace */
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
	.queue_io_cmd = (void *)ublk_null_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_null_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_null_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
