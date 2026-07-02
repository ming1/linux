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
#include "bpf.h"

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
