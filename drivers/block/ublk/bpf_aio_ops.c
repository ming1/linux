// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Red Hat */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/xarray.h>

#include "bpf_aio.h"

static DEFINE_XARRAY(bpf_aio_all_ops);
static DEFINE_MUTEX(bpf_aio_ops_lock);

static bool bpf_aio_ops_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_aio_ops_btf_struct_access(struct bpf_verifier_log *log,
		const struct bpf_reg_state *reg,
		int off, int size)
{
	/* bpf_aio prog can change nothing */
	if (size > 0)
		return -EACCES;

	return NOT_INIT;
}

static const struct bpf_verifier_ops bpf_aio_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_aio_ops_is_valid_access,
	.btf_struct_access = bpf_aio_ops_btf_struct_access,
};

static int bpf_aio_ops_init(struct btf *btf)
{
	return 0;
}

static int bpf_aio_ops_check_member(const struct btf_type *t,
		const struct btf_member *member,
		const struct bpf_prog *prog)
{
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_aio_ops_init_member(const struct btf_type *t,
		const struct btf_member *member,
		void *kdata, const void *udata)
{
	const struct bpf_aio_complete_ops *uops;
	struct bpf_aio_complete_ops *kops;
	u32 moff;

	uops = (const struct bpf_aio_complete_ops *)udata;
	kops = (struct bpf_aio_complete_ops*)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_aio_complete_ops, id):
		/* For dev_id, this function has to copy it and return 1 to
		 * indicate that the data has been handled by the struct_ops
		 * type, or the verifier will reject the map if the value of
		 * those fields is not zero.
		 */
		kops->id = uops->id;
		return 1;
	}
	return 0;
}

static int bpf_aio_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_aio_complete_ops *ops = kdata;
	struct bpf_aio_complete_ops *curr;
	int ret = -EBUSY;

	mutex_lock(&bpf_aio_ops_lock);
	if (!xa_load(&bpf_aio_all_ops, ops->id)) {
		curr = kmalloc(sizeof(*curr), GFP_KERNEL);
		if (curr) {
			*curr = *ops;
			bpf_prog_provider_init(&curr->provider);
			ret = xa_err(xa_store(&bpf_aio_all_ops, ops->id,
						curr, GFP_KERNEL));
		} else {
			ret = -ENOMEM;
		}
	}
	mutex_unlock(&bpf_aio_ops_lock);

	return ret;
}

static void bpf_aio_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_aio_complete_ops *ops = kdata;
	struct bpf_prog_consumer *consumer, *tmp;
	struct bpf_aio_complete_ops *curr;
	LIST_HEAD(consumer_list);

	mutex_lock(&bpf_aio_ops_lock);
	curr = xa_erase(&bpf_aio_all_ops, ops->id);
	if (curr)
		list_splice_init(&curr->provider.list, &consumer_list);
	mutex_unlock(&bpf_aio_ops_lock);

	list_for_each_entry_safe(consumer, tmp, &consumer_list, node)
		bpf_prog_consumer_detach(consumer, true);
	kfree(curr);
}

int bpf_aio_prog_attach(struct bpf_prog_consumer *consumer)
{
	unsigned id = consumer->prog_id;
	struct bpf_aio_complete_ops *ops;
	int ret = -EINVAL;

	mutex_lock(&bpf_aio_ops_lock);
	ops = xa_load(&bpf_aio_all_ops, id);
	if (ops && ops->id == id)
		ret = bpf_prog_consumer_attach(consumer, &ops->provider);
	mutex_unlock(&bpf_aio_ops_lock);

	return ret;
}

void bpf_aio_prog_detach(struct bpf_prog_consumer *consumer)
{
	mutex_lock(&bpf_aio_ops_lock);
	bpf_prog_consumer_detach(consumer, false);
	mutex_unlock(&bpf_aio_ops_lock);
}

static void bpf_aio_cb(struct bpf_aio *io, long ret)
{
}

static struct bpf_aio_complete_ops __bpf_aio_ops = {
	.bpf_aio_complete_cb	=	bpf_aio_cb,
};

static struct bpf_struct_ops bpf_aio_ops = {
	.verifier_ops = &bpf_aio_verifier_ops,
	.init = bpf_aio_ops_init,
	.check_member = bpf_aio_ops_check_member,
	.init_member = bpf_aio_ops_init_member,
	.reg = bpf_aio_reg,
	.unreg = bpf_aio_unreg,
	.name = "bpf_aio_complete_ops",
	.cfi_stubs = &__bpf_aio_ops,
	.owner = THIS_MODULE,
};

int __init bpf_aio_struct_ops_init(void)
{
	int err;

	err = register_bpf_struct_ops(&bpf_aio_ops, bpf_aio_complete_ops);
	if (err)
		pr_warn("error while registering bpf aio struct ops: %d", err);

	return 0;
}
