// SPDX-License-Identifier: GPL-2.0
/*
 * BPF DMA zero-copy test target for ublk.
 *
 * Exercises the DMA map/unmap kfuncs: maps bio pages via IOMMU in
 * queue_io_cmd, then completes immediately (null-like). Unmaps in
 * complete_io_cmd. This tests the full DMA kfunc path without
 * needing actual NVMe command submission.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef bpf_ublk_has_vmlinux_types
struct ublk_bpf_ctx___local {
	void *ub;
	void *bar0;
	unsigned long bar0_size;
} __attribute__((preserve_access_index));

struct ublk_bpf_ops___local {
	int (*init_queue)(struct ublk_bpf_ctx___local *ctx, int qid, int depth);
	void (*deinit_queue)(struct ublk_bpf_ctx___local *ctx, int qid);
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
extern int ublk_bpf_map_dma(struct request *req) __ksym;
extern void ublk_bpf_unmap_dma(struct request *req) __ksym;

SEC("struct_ops.s/init_queue")
int BPF_PROG(dma_zc_init_queue, void *bctx, int qid, int depth)
{
	return 0;
}

SEC("struct_ops/deinit_queue")
void BPF_PROG(dma_zc_deinit_queue, void *bctx, int qid)
{
}

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(dma_zc_queue_io_cmd, void *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;
	int ret;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	/* Map bio pages via IOMMU — exercises ublk_bpf_map_dma kfunc */
	ret = ublk_bpf_map_dma(req);
	if (ret < 0)
		return ret;

	/*
	 * In a real target, we'd use iod->addr (the IOVA) to build an
	 * NVMe SQ entry. For testing, just complete immediately.
	 */
	ublk_bpf_complete_io(req, iod->nr_sectors << 9);
	return 0;
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(dma_zc_commit_io_cmd, void *bctx, int ubq_id)
{
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(dma_zc_complete_io_cmd, void *bctx,
	      struct request *req)
{
	/* Unmap DMA — exercises ublk_bpf_unmap_dma kfunc */
	ublk_bpf_unmap_dma(req);
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_dma_zc_bpf_ops = {
	.init_queue = (void *)dma_zc_init_queue,
	.deinit_queue = (void *)dma_zc_deinit_queue,
	.queue_io_cmd = (void *)dma_zc_queue_io_cmd,
	.commit_io_cmd = (void *)dma_zc_commit_io_cmd,
	.complete_io_cmd = (void *)dma_zc_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
