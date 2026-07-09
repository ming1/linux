// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops support for ublk (UBLK_F_BPF)
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

/* expose the full struct ublk_bpf_ops / ublk_bpf_ctx definitions from bpf.h */
#define __UBLK_BPF_INTERNAL
#include "ublk.h"

/* CFI stubs for ublk_bpf_ops */
static int bpf_ublk_queue_io_cmd_stub(struct ublk_bpf_ctx *ctx,
				      struct request *req, bool last)
{
	return -EOPNOTSUPP;
}

static void bpf_ublk_commit_io_cmd_stub(struct ublk_bpf_ctx *ctx,
					int ubq_id)
{
}

static void bpf_ublk_complete_io_cmd_stub(struct ublk_bpf_ctx *ctx,
					  struct request *req)
{
}

static struct ublk_bpf_ops __bpf_ops_ublk_bpf_ops = {
	.queue_io_cmd = bpf_ublk_queue_io_cmd_stub,
	.commit_io_cmd = bpf_ublk_commit_io_cmd_stub,
	.complete_io_cmd = bpf_ublk_complete_io_cmd_stub,
};

struct ublk_bpf_ops *ublk_bpf_global_ops;

static int ublk_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct ublk_bpf_ops *ops = kdata;

	/* a prog that can never be asked to submit I/O is meaningless */
	if (!ops->queue_io_cmd)
		return -EINVAL;

	ublk_bpf_global_ops = kdata;
	return 0;
}

static void ublk_bpf_unreg(void *kdata, struct bpf_link *link)
{
	ublk_bpf_global_ops = NULL;
}

static int ublk_bpf_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	return 0;
}

/*
 * All callbacks run from non-sleepable blk-mq dispatch context, so refuse
 * to attach a sleepable program.
 */
static int ublk_bpf_check_member(const struct btf_type *t,
				 const struct btf_member *member,
				 const struct bpf_prog *prog)
{
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static bool ublk_bpf_is_valid_access(int off, int size,
				     enum bpf_access_type type,
				     const struct bpf_prog *prog,
				     struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops ublk_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = ublk_bpf_is_valid_access,
};

static int ublk_bpf_init(struct btf *btf)
{
	return 0;
}

static struct bpf_struct_ops bpf_ublk_bpf_ops = {
	.verifier_ops = &ublk_bpf_verifier_ops,
	.reg = ublk_bpf_reg,
	.unreg = ublk_bpf_unreg,
	.init_member = ublk_bpf_init_member,
	.check_member = ublk_bpf_check_member,
	.init = ublk_bpf_init,
	.name = "ublk_bpf_ops",
	.cfi_stubs = &__bpf_ops_ublk_bpf_ops,
	.owner = THIS_MODULE,
};

int ublk_bpf_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_ublk_bpf_ops, ublk_bpf_ops);
}

/*
 * struct_ops dispatch helpers.
 *
 * These are the only places that dereference struct ublk_bpf_ops. Keeping
 * them out of line here (rather than inline in ublk.h) confines the type's
 * member accesses to this single translation unit, so the module BTF holds
 * exactly one struct ublk_bpf_ops. A second, structurally identical copy
 * from another TU would fail bpf_struct_ops_desc_init()'s value-type check
 * ("second member ... should be ublk_bpf_ops") when ublk_drv is a module.
 */

/*
 * Call BPF queue_io_cmd and complete the request based on its return
 * value, applied here after the callback returns so the request stays
 * valid for the whole callback and cannot be completed twice:
 *
 *   ret > 0: BPF completed the I/O with @ret bytes transferred.
 *            Do NOT forward to userspace.
 *
 *   ret == 0: BPF processed the request (e.g. submitted it to
 *             hardware through a pre-mapped UBLK_F_SHMEM_ZC IOVA)
 *             but did not complete it. Forward to userspace for
 *             CQ polling + completion.
 *
 *   ret < 0: Error. The negative errno is the result; complete immediately.
 *
 * The program signals completion and reports the result purely through the
 * return value, so it never writes io state from this non-daemon, unlocked
 * context.
 *
 * Returns true if the caller should forward to userspace
 * (schedule task_work / batch dispatch for notification).
 */
bool ublk_bpf_queue_io(struct ublk_queue *ubq, struct request *rq, bool last)
{
	struct ublk_bpf_ops *ops = ubq->bpf_ops;
	struct ublk_bpf_ctx ctx = { .ub = ubq->dev };
	struct ublk_io *io = &ubq->ios[rq->tag];
	int ret;

	/*
	 * We can only handle I/O whose buffer is a registered UBLK_F_SHMEM_ZC
	 * buffer (index + offset encoded in iod->addr). Without
	 * UBLK_IO_F_SHMEM_ZC we don't know the request buffer, so leave the I/O
	 * to the ublk server by forwarding it to userspace.
	 */
	if (!ublk_iod_is_shmem_zc(ubq, rq->tag))
		return true;

	ret = ops->queue_io_cmd(&ctx, rq, last);
	if (ret == 0)
		return true;	/* forward to userspace for completion */

	/* ret > 0: completed with @ret bytes; ret < 0: error result */
	io->res = ret;
	__ublk_complete_rq(rq, io, false, NULL);
	return false;
}

void ublk_bpf_commit_io_cmds(struct ublk_queue *ubq)
{
	struct ublk_bpf_ops *ops = ubq->bpf_ops;
	struct ublk_bpf_ctx ctx = { .ub = ubq->dev };

	if (ops->commit_io_cmd)
		ops->commit_io_cmd(&ctx, ubq->q_id);
}

void ublk_bpf_complete_io_cmd(struct ublk_queue *ubq, struct request *req)
{
	if (ublk_has_bpf_ops(ubq)) {
		struct ublk_bpf_ops *ops = ubq->bpf_ops;
		struct ublk_bpf_ctx ctx = { .ub = ubq->dev };

		if (ops->complete_io_cmd)
			ops->complete_io_cmd(&ctx, req);
	}
}
