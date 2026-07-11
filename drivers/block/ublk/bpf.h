/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __UBLK_BPF_H
#define __UBLK_BPF_H

/*
 * Included at the end of ublk.h, so struct ublk_queue / ublk_device / request
 * are already defined here.
 *
 * BPF struct_ops dispatch helpers, no-op when UBLK_F_BPF is unset or no
 * bpf_ops is attached to this queue.
 */
static inline bool ublk_has_bpf_ops(const struct ublk_queue *ubq)
{
#ifdef CONFIG_BPF
	return (ubq->flags & UBLK_F_BPF) && ubq->bpf_ops;
#else
	return false;
#endif
}

#ifdef CONFIG_BPF
/*
 * These helpers dereference struct ublk_bpf_ops (ubq->bpf_ops), so they are
 * defined out of line in bpf.c. Keeping the type's only member accesses in a
 * single translation unit means the module BTF carries just one copy of
 * struct ublk_bpf_ops; a second copy (from a second TU) would fail the
 * struct_ops value-type check on CONFIG_BLK_DEV_UBLK=m.
 */
bool ublk_bpf_queue_io(struct ublk_queue *ubq, struct request *rq, bool last);
bool ublk_has_bpf_tw_ops(const struct ublk_queue *ubq);
void ublk_bpf_queue_io_tw(struct ublk_queue *ubq, struct request *rq);
void ublk_bpf_commit_io_cmds(struct ublk_queue *ubq);
void ublk_bpf_complete_io_cmd(struct ublk_queue *ubq, struct request *req);
int ublk_bpf_attach(struct ublk_device *ub);
#else
static inline bool ublk_bpf_queue_io(struct ublk_queue *ubq,
				     struct request *rq, bool last)
{
	return true;
}

static inline bool ublk_has_bpf_tw_ops(const struct ublk_queue *ubq)
{
	return false;
}

static inline void ublk_bpf_queue_io_tw(struct ublk_queue *ubq,
					struct request *rq)
{
}

static inline void ublk_bpf_commit_io_cmds(struct ublk_queue *ubq)
{
}

static inline void ublk_bpf_complete_io_cmd(struct ublk_queue *ubq,
					    struct request *req)
{
}

static inline int ublk_bpf_attach(struct ublk_device *ub)
{
	return 0;
}
#endif /* CONFIG_BPF */

/*
 * Full definitions of the BPF struct_ops types.
 *
 * Guarded so only bpf.c (which defines __UBLK_BPF_INTERNAL before including
 * ublk.h) sees them, i.e. struct ublk_bpf_ops is materialized in a single
 * translation unit. Every other TU sees just the forward declaration in
 * ublk.h that struct ublk_queue's bpf_ops pointer needs. A second,
 * structurally identical copy in another TU's DWARF would land in the module
 * BTF too and fail bpf_struct_ops_desc_init()'s value-type check ("second
 * member ... should be ublk_bpf_ops") when ublk_drv is a module.
 */
#ifdef __UBLK_BPF_INTERNAL
/*
 * Opaque context passed to all BPF struct_ops callbacks and kfuncs,
 * constructed on the stack at each callback invocation. @ub is the owning
 * ublk device.
 */
struct ublk_bpf_ctx {
	struct ublk_device *ub;
};

/*
 * BPF struct_ops for ublk I/O command handling.
 *
 * When attached, these callbacks are invoked directly from blk-mq
 * dispatch paths, bypassing userspace notification for I/O handling.
 * All callbacks run in non-sleepable blk-mq context. Per-queue
 * resources (e.g. submission buffers) are managed by the BPF program
 * itself via BPF arena, so no kernel-side queue lifecycle hooks are
 * needed.
 */
struct ublk_bpf_ops {
	/*
	 * User-chosen registration id, < UBLK_BPF_MAX_PROGS. Set by the
	 * BPF program in its struct_ops definition; a device selects the
	 * prog to attach by this id via UBLK_PARAM_TYPE_BPF (default 0).
	 */
	u32 id;

	/* I/O hot path (non-sleepable, called from queue_rq) */
	int (*queue_io_cmd)(struct ublk_bpf_ctx *ctx,
			    struct request *req, bool last);

	/*
	 * Task-work variant of queue_io_cmd, invoked from the ublk daemon
	 * task context (ublk_dispatch_req) rather than the submitter's
	 * queue_rq context. Use it when the program allocates per-I/O state
	 * (e.g. a BPF arena buffer) that would race if built from an
	 * arbitrary submitter context.
	 *
	 * Returns void: the request is always forwarded to the ublk server
	 * for completion afterwards. There is no success/failure return
	 * value, so the program is responsible for dealing with a potential
	 * failure through its own state, and must pair with complete_io_cmd
	 * to release the per-I/O state when the request finishes.
	 *
	 * Mutually exclusive with queue_io_cmd and commit_io_cmd, and
	 * requires complete_io_cmd; both enforced at reg time. Batch/kick
	 * ordering is the program's own responsibility, so no commit_io_cmd
	 * hook is offered here.
	 */
	void (*queue_io_cmd_tw)(struct ublk_bpf_ctx *ctx, struct request *req);

	void (*commit_io_cmd)(struct ublk_bpf_ctx *ctx, int ubq_id);

	/* Completion (called when request finishes) */
	void (*complete_io_cmd)(struct ublk_bpf_ctx *ctx,
				struct request *req);
};
#endif /* __UBLK_BPF_INTERNAL */

#endif /* __UBLK_BPF_H */
