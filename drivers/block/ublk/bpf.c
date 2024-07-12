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

	ub->prog.prog_id = ub->params.bpf.ops_id;
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

/* bpf aio kfunc */
BTF_ID_FLAGS(func, bpf_aio_alloc, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_aio_alloc_sleepable, KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_aio_release)
BTF_ID_FLAGS(func, bpf_aio_submit)
BTF_KFUNCS_END(ublk_bpf_kfunc_ids)

__bpf_kfunc void bpf_aio_release_dtor(void *aio)
{
	bpf_aio_release(aio);
}
CFI_NOSEAL(bpf_aio_release_dtor);
BTF_ID_LIST(bpf_aio_dtor_ids)
BTF_ID(struct, bpf_aio)
BTF_ID(func, bpf_aio_release_dtor)

static const struct btf_kfunc_id_set ublk_bpf_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &ublk_bpf_kfunc_ids,
};

int __init ublk_bpf_init(void)
{
	const struct btf_id_dtor_kfunc aio_dtors[] = {
		{
			.btf_id	      = bpf_aio_dtor_ids[0],
			.kfunc_btf_id = bpf_aio_dtor_ids[1]
		},
	};
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&ublk_bpf_kfunc_set);
	if (err) {
		pr_warn("error while setting UBLK BPF tracing kfuncs: %d", err);
		return err;
	}

	err = ublk_bpf_struct_ops_init();
	if (err) {
		pr_warn("error while initializing ublk bpf struct_ops: %d", err);
		return err;
	}

	err = register_btf_id_dtor_kfuncs(aio_dtors, ARRAY_SIZE(aio_dtors),
			THIS_MODULE);
	if (err) {
		pr_warn("error while registering aio destructor: %d", err);
		return err;
	}

	err = bpf_aio_init();
	if (err)
		pr_warn("error while initializing bpf aio kfunc: %d", err);
	return err;
}
