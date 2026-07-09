// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops support for ublk (UBLK_F_BPF)
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/io.h>
#include <linux/xarray.h>

/* expose the full struct ublk_bpf_ops / ublk_bpf_ctx definitions from bpf.h */
#define __UBLK_BPF_INTERNAL
#include "ublk.h"

/*
 * BPF kfuncs for ublk struct_ops programs.
 */
__bpf_kfunc_start_defs();

/*
 * Get the I/O descriptor for a request.
 * Contains operation type, sector offset, size, and the buffer address
 * (a UBLK_F_SHMEM_ZC buffer index + offset when UBLK_IO_F_SHMEM_ZC is set).
 */
__bpf_kfunc struct ublksrv_io_desc *ublk_bpf_get_iod(struct request *req)
{
	struct ublk_queue *ubq = req->mq_hctx->driver_data;

	return ublk_get_iod(ubq, req->tag);
}


/*
 * Write a value into a registered shared buffer.
 *
 * v1 supports MMIO register windows (UBLK_SHMEM_BUF_MMIO): @buf_id is the id
 * returned by UBLK_U_CMD_REG_BUF, @offset the byte offset within the window,
 * @len must be 4, and the low 32 bits of @val are written to the register.
 * The register mapping is looked up under RCU; a concurrent UBLK_CMD_UNREG_BUF
 * that already erased it makes this return -ENOENT rather than touch freed
 * iomem.
 *
 * writel() carries the wmb() an NVMe doorbell needs, so prior arena stores
 * (e.g. the SQ entry) are ordered before the doorbell write.
 */
__bpf_kfunc int ublk_write_shmem_mmio(struct ublk_bpf_ctx *ctx, u32 buf_id,
				      u64 offset, u64 val, u32 len)
{
	struct ublk_device *ub = ctx->ub;
	struct ublk_mmio_buf *buf;
	int ret = 0;

	rcu_read_lock();
	buf = xa_load(&ub->mmio_bufs, buf_id);
	if (!buf) {
		ret = -ENOENT;
		goto out;
	}
	/* v1: single 32-bit, naturally aligned, in bounds. */
	if (len != 4 || (offset & 0x3) ||
	    offset > buf->len || len > buf->len - offset) {
		ret = -EINVAL;
		goto out;
	}
	writel(lower_32_bits(val), buf->reg + offset);
out:
	rcu_read_unlock();
	return ret;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ublk_bpf_kfunc_ids)
BTF_ID_FLAGS(func, ublk_bpf_get_iod)
BTF_ID_FLAGS(func, ublk_write_shmem_mmio)
BTF_KFUNCS_END(ublk_bpf_kfunc_ids)

static const struct btf_kfunc_id_set ublk_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ublk_bpf_kfunc_ids,
};

/* CFI stubs for ublk_bpf_ops */
static int bpf_ublk_queue_io_cmd_stub(struct ublk_bpf_ctx *ctx,
				      struct request *req, bool last)
{
	return -EOPNOTSUPP;
}

static void bpf_ublk_queue_io_cmd_tw_stub(struct ublk_bpf_ctx *ctx,
					  struct request *req)
{
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
	.queue_io_cmd_tw = bpf_ublk_queue_io_cmd_tw_stub,
	.commit_io_cmd = bpf_ublk_commit_io_cmd_stub,
	.complete_io_cmd = bpf_ublk_complete_io_cmd_stub,
};

/*
 * Registered struct_ops progs, indexed by their user-chosen id. Multiple
 * progs can be registered concurrently; a device selects one by id via
 * UBLK_PARAM_TYPE_BPF at START_DEV.
 */
static struct ublk_bpf_ops *ublk_bpf_progs[UBLK_BPF_MAX_PROGS];
static DEFINE_MUTEX(ublk_bpf_prog_lock);

static int ublk_bpf_reg(void *kdata, struct bpf_link *link)
{
	struct ublk_bpf_ops *ops = kdata;
	int ret = 0;

	if (ops->id >= UBLK_BPF_MAX_PROGS)
		return -EINVAL;

	/* a prog that can never be asked to submit I/O is meaningless */
	if (!ops->queue_io_cmd && !ops->queue_io_cmd_tw)
		return -EINVAL;

	/*
	 * queue_io_cmd_tw runs the submission callback from ublk daemon
	 * task-work context instead of queue_rq, so it replaces queue_io_cmd
	 * and its commit_io_cmd batching, and needs complete_io_cmd to release
	 * whatever per-I/O state it allocated.
	 */
	if (ops->queue_io_cmd_tw) {
		if (ops->queue_io_cmd || ops->commit_io_cmd)
			return -EINVAL;
		if (!ops->complete_io_cmd)
			return -EINVAL;
	}

	mutex_lock(&ublk_bpf_prog_lock);
	if (ublk_bpf_progs[ops->id])
		ret = -EBUSY;
	else
		ublk_bpf_progs[ops->id] = ops;
	mutex_unlock(&ublk_bpf_prog_lock);
	return ret;
}

static void ublk_bpf_unreg(void *kdata, struct bpf_link *link)
{
	struct ublk_bpf_ops *ops = kdata;

	/*
	 * Only hide the prog from new attachments: devices already attached
	 * hold a bpf_struct_ops_get() reference, so the struct_ops map (and
	 * its progs) stay alive until the last device detaches.
	 */
	mutex_lock(&ublk_bpf_prog_lock);
	if (ublk_bpf_progs[ops->id] == ops)
		ublk_bpf_progs[ops->id] = NULL;
	mutex_unlock(&ublk_bpf_prog_lock);
}

static int ublk_bpf_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	const struct ublk_bpf_ops *uops = udata;
	struct ublk_bpf_ops *ops = kdata;
	u32 moff;

	moff = __btf_member_bit_offset(t, member) / 8;
	if (moff == offsetof(struct ublk_bpf_ops, id)) {
		if (uops->id >= UBLK_BPF_MAX_PROGS)
			return -EINVAL;
		ops->id = uops->id;
		return 1;
	}
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
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&ublk_bpf_kfunc_set);
	if (ret)
		return ret;

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

/* Does this queue's program dispatch submission from task-work context? */
bool ublk_has_bpf_tw_ops(const struct ublk_queue *ubq)
{
	struct ublk_bpf_ops *ops = ubq->bpf_ops;

	return (ubq->flags & UBLK_F_BPF) && ops && ops->queue_io_cmd_tw;
}

/*
 * Task-work counterpart of ublk_bpf_queue_io(): invoked from the ublk daemon
 * task context (ublk_dispatch_req). The callback returns void; the request is
 * always forwarded to the ublk server for completion afterwards, so the
 * program owns any success/failure bookkeeping through its own state and pairs
 * with complete_io_cmd to release the per-I/O state when the request finishes.
 */
void ublk_bpf_queue_io_tw(struct ublk_queue *ubq, struct request *rq)
{
	struct ublk_bpf_ops *ops = ubq->bpf_ops;
	struct ublk_bpf_ctx ctx = { .ub = ubq->dev };

	ops->queue_io_cmd_tw(&ctx, rq);
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

/*
 * Attach the registered BPF struct_ops selected by UBLK_PARAM_TYPE_BPF
 * (prog id 0 when the parameter is absent) to this device. Called from
 * START_DEV; a UBLK_F_BPF device cannot start without an attached
 * struct_ops. Pins the struct_ops map until ublk_bpf_detach().
 */
int ublk_bpf_attach(struct ublk_device *ub)
{
	struct ublk_bpf_ops *ops;
	u32 id = 0;
	int i;

	if (!(ub->dev_info.flags & UBLK_F_BPF))
		return 0;

	if (ub->params.types & UBLK_PARAM_TYPE_BPF)
		id = ub->params.bpf.prog_id;

	mutex_lock(&ublk_bpf_prog_lock);
	ops = id < UBLK_BPF_MAX_PROGS ? ublk_bpf_progs[id] : NULL;
	if (ops && !bpf_struct_ops_get(ops))
		ops = NULL;
	mutex_unlock(&ublk_bpf_prog_lock);

	if (!ops) {
		pr_err("ublk: no BPF struct_ops registered with id %u\n", id);
		return -EINVAL;
	}
	/* queue_io_cmd_tw is not wired into the UBLK_F_BATCH_IO daemon path yet */
	if (ops->queue_io_cmd_tw &&
	    (ub->dev_info.flags & UBLK_F_BATCH_IO)) {
		pr_err("ublk: queue_io_cmd_tw unsupported with UBLK_F_BATCH_IO\n");
		bpf_struct_ops_put(ops);
		return -EINVAL;
	}
	ub->bpf_ops = ops;
	for (i = 0; i < ub->dev_info.nr_hw_queues; i++)
		ublk_get_queue(ub, i)->bpf_ops = ops;
	return 0;
}

/*
 * Drop the device's struct_ops reference. Called once I/O can no longer
 * reach the queues (START_DEV failure, or after del_gendisk() in
 * STOP_DEV/device removal); safe to call when nothing is attached.
 */
void ublk_bpf_detach(struct ublk_device *ub)
{
	int i;

	if (!ub->bpf_ops)
		return;

	for (i = 0; i < ub->dev_info.nr_hw_queues; i++)
		ublk_get_queue(ub, i)->bpf_ops = NULL;
	bpf_struct_ops_put(ub->bpf_ops);
	ub->bpf_ops = NULL;
}
