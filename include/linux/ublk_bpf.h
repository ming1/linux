/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UBLK_BPF_H
#define UBLK_BPF_H

#include <linux/blkdev.h>

/*
 * Opaque context passed to all BPF struct_ops callbacks and kfuncs.
 * Provides access to the ublk device's IOMMU domain, ioremapped BARs,
 * and queue state without exposing kernel internals to BPF.
 */
struct ublk_bpf_ctx {
	struct ublk_device *ub;
	void __iomem *bar0;
	unsigned long bar0_size;
};

/*
 * BPF struct_ops for ublk I/O command handling.
 *
 * When attached, these callbacks are invoked directly from blk-mq
 * dispatch paths, bypassing userspace notification for I/O handling.
 * init_queue/deinit_queue run in sleepable context during device setup.
 * queue_io_cmd/commit_io_cmd/complete_io_cmd run from blk-mq context.
 */
struct ublk_bpf_ops {
	/* Per-queue lifecycle (sleepable context) */
	int (*init_queue)(struct ublk_bpf_ctx *ctx, int qid, int depth);
	void (*deinit_queue)(struct ublk_bpf_ctx *ctx, int qid);

	/* I/O hot path (non-sleepable, called from queue_rq) */
	int (*queue_io_cmd)(struct ublk_bpf_ctx *ctx,
			    struct request *req, bool last);
	void (*commit_io_cmd)(struct ublk_bpf_ctx *ctx, int ubq_id);

	/* Completion (called when request finishes) */
	void (*complete_io_cmd)(struct ublk_bpf_ctx *ctx,
				struct request *req);
};

#endif /* UBLK_BPF_H */
