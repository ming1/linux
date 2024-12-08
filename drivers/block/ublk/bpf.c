// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Red Hat */

#include "ublk.h"
#include "bpf.h"

static int ublk_set_bpf_ops(struct ublk_device *ub,
		struct ublk_bpf_ops *ops)
{
	int i;

	for (i = 0; i < ub->dev_info.nr_hw_queues; i++) {
		if (ops && ublk_get_queue(ub, i)->bpf_ops) {
			ublk_set_bpf_ops(ub, NULL);
			return -EBUSY;
		}
		ublk_get_queue(ub, i)->bpf_ops = ops;
	}
	return 0;
}

static int ublk_bpf_prog_attach_cb(struct bpf_prog_consumer *consumer,
				   struct bpf_prog_provider *provider)
{
	struct ublk_device *ub = container_of(consumer, struct ublk_device,
					      prog);
	struct ublk_bpf_ops *ops = container_of(provider,
			struct ublk_bpf_ops, provider);
	int ret;

	if (!ublk_get_device(ub))
		return -ENODEV;

	ret = ublk_set_bpf_ops(ub, ops);
	if (ret)
		goto fail_put_dev;

	if (ops->attach_dev) {
		ret = ops->attach_dev(ub->dev_info.dev_id);
		if (ret)
			goto fail_reset_ops;
	}
	return 0;

fail_reset_ops:
	ublk_set_bpf_ops(ub, NULL);
fail_put_dev:
	ublk_put_device(ub);
	return ret;
}

static void ublk_bpf_prog_detach_cb(struct bpf_prog_consumer *consumer,
				    bool unreg)
{
	struct ublk_device *ub = container_of(consumer, struct ublk_device,
					      prog);
	struct ublk_bpf_ops *ops = container_of(consumer->provider,
			struct ublk_bpf_ops, provider);

	if (unreg) {
		blk_mq_freeze_queue(ub->ub_disk->queue);
		ublk_set_bpf_ops(ub, NULL);
		blk_mq_unfreeze_queue(ub->ub_disk->queue);
	} else {
		ublk_set_bpf_ops(ub, NULL);
	}
	if (ops->detach_dev)
		ops->detach_dev(ub->dev_info.dev_id);
	ublk_put_device(ub);
}

static const struct bpf_prog_consumer_ops ublk_prog_consumer_ops = {
	.attach_fn	= ublk_bpf_prog_attach_cb,
	.detach_fn	= ublk_bpf_prog_detach_cb,
};

int ublk_bpf_attach(struct ublk_device *ub)
{
	if (!ublk_dev_support_bpf(ub))
		return 0;

	/* todo: ublk device need to provide struct_ops prog id */
	ub->prog.prog_id = 0;
	ub->prog.ops = &ublk_prog_consumer_ops;

	return ublk_bpf_prog_attach(&ub->prog);
}

void ublk_bpf_detach(struct ublk_device *ub)
{
	if (!ublk_dev_support_bpf(ub))
		return;
	ublk_bpf_prog_detach(&ub->prog);
}


__bpf_kfunc_start_defs();
__bpf_kfunc const struct ublksrv_io_desc *
ublk_bpf_get_iod(const struct ublk_bpf_io *io)
{
	if (io)
		return io->iod;
	return NULL;
}

__bpf_kfunc unsigned int
ublk_bpf_get_io_tag(const struct ublk_bpf_io *io)
{
	if (io) {
		const struct request *req = ublk_bpf_get_req(io);

		return req->tag;
	}
	return -1;
}

__bpf_kfunc unsigned int
ublk_bpf_get_queue_id(const struct ublk_bpf_io *io)
{
	if (io) {
		const struct request *req = ublk_bpf_get_req(io);

		if (req->mq_hctx) {
			const struct ublk_queue *ubq = req->mq_hctx->driver_data;

			return ubq->q_id;
		}
	}
	return -1;
}

__bpf_kfunc unsigned int
ublk_bpf_get_dev_id(const struct ublk_bpf_io *io)
{
	if (io) {
		const struct request *req = ublk_bpf_get_req(io);

		if (req->mq_hctx) {
			const struct ublk_queue *ubq = req->mq_hctx->driver_data;

			return ubq->dev->dev_info.dev_id;
		}
	}
	return -1;
}

__bpf_kfunc void
ublk_bpf_complete_io(struct ublk_bpf_io *io, int res)
{
	ublk_bpf_complete_io_cmd(io, res);
}

BTF_KFUNCS_START(ublk_bpf_kfunc_ids)
BTF_ID_FLAGS(func, ublk_bpf_complete_io, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, ublk_bpf_get_iod, KF_TRUSTED_ARGS | KF_RET_NULL)
BTF_ID_FLAGS(func, ublk_bpf_get_io_tag, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, ublk_bpf_get_queue_id, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, ublk_bpf_get_dev_id, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(ublk_bpf_kfunc_ids)

static const struct btf_kfunc_id_set ublk_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ublk_bpf_kfunc_ids,
};

int __init ublk_bpf_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&ublk_bpf_kfunc_set);
	if (err) {
		pr_warn("error while setting UBLK BPF tracing kfuncs: %d", err);
		return err;
	}
	return ublk_bpf_struct_ops_init();
}
