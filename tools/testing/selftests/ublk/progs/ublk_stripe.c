// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <linux/const.h>
#include <linux/errno.h>
#include <linux/falloc.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//#define DEBUG
#include "ublk_bpf.h"

/* libbpf v1.4.5 is required for struct_ops to work */

struct ublk_stripe {
#define MAX_BACKFILES	4
	unsigned char chunk_shift;
	unsigned char nr_backfiles;
	int fds[MAX_BACKFILES];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, unsigned int);	/* dev id */
	__type(value, struct ublk_stripe);	/* stripe setting */
} stripe_map SEC(".maps");

/* todo: make it writable payload of ublk_bpf_io */
struct ublk_io_payload {
	unsigned int ref;
	int res;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, unsigned long long);	/* dev_id + q_id + tag */
	__type(value, struct ublk_io_payload);	/* io payload */
} io_map SEC(".maps");

static inline void dec_stripe_io_ref(const struct ublk_bpf_io *io, struct ublk_io_payload *pv, int ret)
{
	if (!pv)
		return;

	if (pv->res >= 0)
		pv->res = ret;

	if (!__sync_sub_and_fetch(&pv->ref, 1)) {
		unsigned rw = (io->iod->op_flags & 0xff);

		if (pv->res >= 0 && (rw <= 1))
			pv->res = io->iod->nr_sectors << 9;
		ublk_bpf_complete_io(io, pv->res);
	}
}

static inline void ublk_stripe_comp_and_release_aio(struct bpf_aio *aio, int ret)
{
	struct ublk_bpf_io *io = ublk_bpf_acquire_io_from_aio(aio);
	struct ublk_io_payload *pv = NULL;
	unsigned long long io_key = build_io_key(io);

	if (!io)
		return;

	io_key = build_io_key(io);
	pv = bpf_map_lookup_elem(&io_map, &io_key);

	/* drop reference for each underlying aio */
	dec_stripe_io_ref(io, pv, ret);
	ublk_bpf_release_io_from_aio(io);

	ublk_bpf_dettach_and_complete_aio(aio);
	bpf_aio_release(aio);
}

SEC("struct_ops/bpf_aio_complete_cb")
void BPF_PROG(ublk_stripe_comp_cb, struct bpf_aio *aio, long ret)
{
	BPF_DBG("aio result %d, back_file %s pos %llx", ret,
			aio->iocb.ki_filp->f_path.dentry->d_name.name,
			aio->iocb.ki_pos);
	ublk_stripe_comp_and_release_aio(aio, ret);
}

SEC(".struct_ops.link")
struct bpf_aio_complete_ops stripe_ublk_bpf_aio_ops = {
	.id = 32,
	.bpf_aio_complete_cb = (void *)ublk_stripe_comp_cb,
};

static inline int ublk_stripe_submit_backing_io(const struct ublk_bpf_io *io,
		int backfile_fd, unsigned long backfile_off,
		unsigned int backfile_bytes,
		unsigned int buf_off)
{
	const struct ublksrv_io_desc *iod = io->iod;
	unsigned int op_flags = 0;
	struct bpf_aio *aio;
	int res = -EINVAL;
	int op;

	/* translate ublk opcode into backing file's */
	switch (iod->op_flags & 0xff) {
	case 0 /*UBLK_IO_OP_READ*/:
		op = BPF_AIO_OP_FS_READ;
		break;
	case 1 /*UBLK_IO_OP_WRITE*/:
		op = BPF_AIO_OP_FS_WRITE;
		break;
	case 2 /*UBLK_IO_OP_FLUSH*/:
		op = BPF_AIO_OP_FS_FSYNC;
		break;
	case 3 /*UBLK_IO_OP_DISCARD*/:
		op = BPF_AIO_OP_FS_FALLOCATE;
		op_flags = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
		break;
	case 4 /*UBLK_IO_OP_WRITE_SAME*/:
		op = BPF_AIO_OP_FS_FALLOCATE;
		op_flags = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
		break;
	case 5 /*UBLK_IO_OP_WRITE_ZEROES*/:
		op = BPF_AIO_OP_FS_FALLOCATE;
		op_flags = FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE;
		break;
	default:
		return -EINVAL;
	}

	res = -ENOMEM;
	aio = bpf_aio_alloc(op, 0);
	if (!aio)
		goto fail;

	/* attach aio into the specified range of this io command */
	res = ublk_bpf_attach_and_prep_aio(io, buf_off, backfile_bytes, aio);
	if (res < 0) {
		bpf_printk("bpf aio attaching failed %d\n", res);
		goto fail;
	}

	/* submit this aio onto the backing file */
	res = bpf_aio_submit(aio, backfile_fd, backfile_off, backfile_bytes, op_flags);
	if (res < 0) {
		bpf_printk("aio submit failed %d\n", res);
		ublk_stripe_comp_and_release_aio(aio, res);
	}
	return 0;
fail:
	return res;
}

static int calculate_backfile_off_bytes(const struct ublk_stripe *stripe,
		unsigned long stripe_off, unsigned int stripe_bytes,
		unsigned long *backfile_off,
		unsigned int *backfile_bytes)
{
	unsigned long chunk_size = 1U << stripe->chunk_shift;
	unsigned int nr_bf = stripe->nr_backfiles;
	unsigned long unit_chunk_size = nr_bf << stripe->chunk_shift;
	unsigned long start_off = stripe_off & ~(chunk_size - 1);
	unsigned long unit_start_off = stripe_off & ~(unit_chunk_size - 1);
	unsigned int idx = (start_off - unit_start_off) >> stripe->chunk_shift;

	*backfile_bytes = stripe_bytes;
	*backfile_off = (unit_start_off / nr_bf)  + (idx << stripe->chunk_shift)  + (stripe_off - start_off);

	return stripe->fds[idx % MAX_BACKFILES];
}

static unsigned int calculate_stripe_off_bytes(const struct ublk_stripe *stripe,
		const struct ublksrv_io_desc *iod, unsigned int this_off,
		unsigned long *stripe_off)
{
	unsigned long off, next_off;
	unsigned int chunk_size = 1U << stripe->chunk_shift;
	unsigned int max_size = (iod->nr_sectors << 9) - this_off;

	off = (iod->start_sector << 9) + this_off;
	next_off = (off & ~(chunk_size  - 1)) + chunk_size;;

	*stripe_off = off;

	if (max_size < next_off - off)
		return max_size;
	return next_off - off;
}

static inline ublk_bpf_return_t __ublk_stripe_handle_io_cmd(const struct ublk_bpf_io *io, unsigned int off)
{
	ublk_bpf_return_t ret = ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
	unsigned long stripe_off, backfile_off;
	unsigned int stripe_bytes, backfile_bytes;
	int dev_id = ublk_bpf_get_dev_id(io);
	const struct ublksrv_io_desc *iod;
	const struct ublk_stripe *stripe;
	int res = -EINVAL;
	int backfile_fd;
	unsigned long long io_key = build_io_key(io);
	struct ublk_io_payload pl = {
		.ref = 2,
		.res = 0,
	};
	struct ublk_io_payload *pv = NULL;

	iod = ublk_bpf_get_iod(io);
	if (!iod) {
		ublk_bpf_complete_io(io, res);
		return ret;
	}

	BPF_DBG("ublk dev %u qid %u: handle io cmd tag %u op %u %lx-%d off %u",
			ublk_bpf_get_dev_id(io),
			ublk_bpf_get_queue_id(io),
			ublk_bpf_get_io_tag(io),
			iod->op_flags & 0xff,
			iod->start_sector << 9,
			iod->nr_sectors << 9, off);

	/* retrieve backing file descriptor */
	stripe = bpf_map_lookup_elem(&stripe_map, &dev_id);
	if (!stripe) {
		bpf_printk("can't get FD from %d\n", dev_id);
		return ret;
	}

	/* todo: build as big chunk as possible for each underlying files/disks */
	stripe_bytes = calculate_stripe_off_bytes(stripe, iod, off, &stripe_off);
	backfile_fd = calculate_backfile_off_bytes(stripe, stripe_off, stripe_bytes,
			&backfile_off, &backfile_bytes);
	BPF_DBG("\t <chunk_shift %u files %u> stripe(%lx %lu) backfile(%d %lx %lu)",
			stripe->chunk_shift, stripe->nr_backfiles,
			stripe_off, stripe_bytes,
			backfile_fd, backfile_off, backfile_bytes);

	if (!stripe_bytes) {
		bpf_printk("submit bpf aio failed %d\n", res);
		res = -EINVAL;
		goto exit;
	}

	/* grab one submission reference, and one extra for the whole batch */
	if (!off) {
		res = bpf_map_update_elem(&io_map, &io_key, &pl, BPF_ANY);
		if (res) {
			bpf_printk("update io map element failed %d key %llx\n", res, io_key);
			goto exit;
		}
	} else {
		pv = bpf_map_lookup_elem(&io_map, &io_key);
		if (pv)
			__sync_fetch_and_add(&pv->ref, 1);
	}

	/* handle this io command by submitting IOs on backing file */
	res = ublk_stripe_submit_backing_io(io, backfile_fd, backfile_off, backfile_bytes, off);

exit:
	/* io cmd can't be completes until this reference is dropped */
	if (res < 0) {
		bpf_printk("submit bpf aio failed %d\n", res);
		ublk_bpf_complete_io(io, res);
		return ret;
	}

	/* drop the extra reference for the whole batch */
	if (off + stripe_bytes == iod->nr_sectors << 9) {
		if (!pv)
			pv = bpf_map_lookup_elem(&io_map, &io_key);
		dec_stripe_io_ref(io, pv, pv ? pv->res : 0);
	}

	return ublk_bpf_return_val(UBLK_BPF_IO_CONTINUE, stripe_bytes);
}

SEC("struct_ops/ublk_bpf_release_io_cmd")
void BPF_PROG(ublk_stripe_release_io_cmd, struct ublk_bpf_io *io)
{
	BPF_DBG("%s: complete io command %d", __func__, io->res);
}

SEC("struct_ops.s/ublk_bpf_queue_io_cmd_daemon")
ublk_bpf_return_t BPF_PROG(ublk_stripe_handle_io_cmd, struct ublk_bpf_io *io, unsigned int off)
{
	return __ublk_stripe_handle_io_cmd(io, off);
}

SEC("struct_ops/ublk_bpf_attach_dev")
int BPF_PROG(ublk_stripe_attach_dev, int dev_id)
{
	const struct ublk_stripe *stripe;

	/* retrieve backing file descriptor */
	stripe = bpf_map_lookup_elem(&stripe_map, &dev_id);
	if (!stripe) {
		bpf_printk("can't get FD from %d\n", dev_id);
		return -EINVAL;
	}

	if (stripe->nr_backfiles >= MAX_BACKFILES)
		return -EINVAL;

	if (stripe->chunk_shift < 12)
		return -EINVAL;

	return 0;
}

SEC(".struct_ops.link")
struct ublk_bpf_ops stripe_ublk_bpf_ops = {
	.id = 32,
	.attach_dev = (void *)ublk_stripe_attach_dev,
	.queue_io_cmd_daemon = (void *)ublk_stripe_handle_io_cmd,
	.release_io_cmd = (void *)ublk_stripe_release_io_cmd,
};

char LICENSE[] SEC("license") = "GPL";
