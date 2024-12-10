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

static int ublk_set_bpf_aio_op(struct ublk_device *ub,
		struct bpf_aio_complete_ops *ops)
{
	int i;

	for (i = 0; i < ub->dev_info.nr_hw_queues; i++) {
		if (ops && ublk_get_queue(ub, i)->bpf_aio_ops) {
			ublk_set_bpf_aio_op(ub, NULL);
			return -EBUSY;
		}
		ublk_get_queue(ub, i)->bpf_aio_ops = ops;
	}
	return 0;
}

static int ublk_bpf_aio_prog_attach_cb(struct bpf_prog_consumer *consumer,
				       struct bpf_prog_provider *provider)
{
	struct ublk_device *ub = container_of(consumer, struct ublk_device,
					      aio_prog);
	struct bpf_aio_complete_ops *ops = container_of(provider,
			struct bpf_aio_complete_ops, provider);
	int ret = -ENODEV;

	if (ublk_get_device(ub)) {
		ret = ublk_set_bpf_aio_op(ub, ops);
		if (ret)
			ublk_put_device(ub);
	}

	return ret;
}

static void ublk_bpf_aio_prog_detach_cb(struct bpf_prog_consumer *consumer,
					bool unreg)
{
	struct ublk_device *ub = container_of(consumer, struct ublk_device,
					      aio_prog);

	if (unreg) {
		blk_mq_freeze_queue(ub->ub_disk->queue);
		ublk_set_bpf_aio_op(ub, NULL);
		blk_mq_unfreeze_queue(ub->ub_disk->queue);
	} else {
		ublk_set_bpf_aio_op(ub, NULL);
	}
	ublk_put_device(ub);
}

static const struct bpf_prog_consumer_ops ublk_aio_prog_consumer_ops = {
	.attach_fn	= ublk_bpf_aio_prog_attach_cb,
	.detach_fn	= ublk_bpf_aio_prog_detach_cb,
};

static int ublk_bpf_aio_attach(struct ublk_device *ub)
{
	if (!ublk_dev_support_bpf_aio(ub))
		return 0;

	ub->aio_prog.prog_id = ub->params.bpf.aio_ops_id;
	ub->aio_prog.ops = &ublk_aio_prog_consumer_ops;

	return bpf_aio_prog_attach(&ub->aio_prog);
}

static void ublk_bpf_aio_detach(struct ublk_device *ub)
{
	if (!ublk_dev_support_bpf_aio(ub))
		return;
	bpf_aio_prog_detach(&ub->aio_prog);
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
	int ret;

	if (!ublk_dev_support_bpf(ub))
		return 0;

	ub->prog.prog_id = ub->params.bpf.ops_id;
	ub->prog.ops = &ublk_prog_consumer_ops;

	ret = ublk_bpf_prog_attach(&ub->prog);
	if (ret)
		return ret;
	return ublk_bpf_aio_attach(ub);
}

void ublk_bpf_detach(struct ublk_device *ub)
{
	if (!ublk_dev_support_bpf(ub))
		return;
	ublk_bpf_aio_detach(ub);
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

/*
 * Called before submitting one bpf aio in prog, and this ublk IO's
 * reference is increased.
 *
 * Grab reference of `io` for this `aio`, and the reference will be dropped
 * by ublk_bpf_dettach_and_complete_aio()
 */
__bpf_kfunc int
ublk_bpf_attach_and_prep_aio(const struct ublk_bpf_io *_io, unsigned off,
		unsigned bytes, struct bpf_aio *aio)
{
	struct ublk_bpf_io *io = (struct ublk_bpf_io *)_io;
	const struct request *req;
	const struct ublk_rq_data *data;
	const struct ublk_bpf_io *bpf_io;

	if (!io || !aio)
		return -EINVAL;

	req = ublk_bpf_get_req(io);
	if (!req)
		return -EINVAL;

	if (off + bytes > blk_rq_bytes(req))
		return -EINVAL;

	if (req->mq_hctx) {
		const struct ublk_queue *ubq = req->mq_hctx->driver_data;

		bpf_aio_assign_cb(aio, ubq->bpf_aio_ops);
	}

	data = blk_mq_rq_to_pdu((struct request *)req);
	bpf_io = &data->bpf_data;
	bpf_aio_assign_buf(aio, &bpf_io->buf, off, bytes);

	refcount_inc(&io->ref);
	aio->private_data = (void *)io;

	return 0;
}

/*
 * Called after this attached aio is completed, and the associated ublk IO's
 * reference is decreased, and if the reference is dropped to zero, complete
 * this ublk IO.
 *
 * Return -EIOCBQUEUED if this `io` is being handled, and 0 is returned
 * if it can be completed now.
 */
__bpf_kfunc void
ublk_bpf_dettach_and_complete_aio(struct bpf_aio *aio)
{
	struct ublk_bpf_io *io = aio->private_data;

	if (io) {
		ublk_bpf_io_dec_ref(io);
		aio->private_data = NULL;
	}
}

__bpf_kfunc struct ublk_bpf_io *ublk_bpf_acquire_io_from_aio(struct bpf_aio *aio)
{
	return aio->private_data;
}

__bpf_kfunc void ublk_bpf_release_io_from_aio(struct ublk_bpf_io *io)
{
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

/* ublk bpf aio kfuncs */
BTF_ID_FLAGS(func, ublk_bpf_attach_and_prep_aio)
BTF_ID_FLAGS(func, ublk_bpf_dettach_and_complete_aio)
BTF_ID_FLAGS(func, ublk_bpf_acquire_io_from_aio, KF_ACQUIRE)
BTF_ID_FLAGS(func, ublk_bpf_release_io_from_aio, KF_RELEASE)
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
