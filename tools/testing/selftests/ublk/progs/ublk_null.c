// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <linux/const.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//#define DEBUG
#include "ublk_bpf.h"

/* todo: make it writable payload of ublk_bpf_io */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, unsigned long long);	/* dev_id + q_id + tag */
	__type(value, int);
} io_map SEC(".maps");

/* libbpf v1.4.5 is required for struct_ops to work */

static inline ublk_bpf_return_t __ublk_null_handle_io_split(const struct ublk_bpf_io *io, unsigned int _off)
{
	unsigned long off = -1, sects = -1;
	const struct ublksrv_io_desc *iod;
	int res;

	iod = ublk_bpf_get_iod(io);
	if (iod) {
		res = iod->nr_sectors << 9;
		off = iod->start_sector;
		sects = iod->nr_sectors;
	} else
		res = -EINVAL;

	BPF_DBG("ublk dev %u qid %u: handle io tag %u %lx-%d res %d",
			ublk_bpf_get_dev_id(io),
			ublk_bpf_get_queue_id(io),
			ublk_bpf_get_io_tag(io),
			off, sects, res);
	if (res < 0) {
		ublk_bpf_complete_io(io, res);
		return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
	}

	/* split this io to one 512bytes sub-io and the remainder */
	if (_off < 512 && res > 512)
		return ublk_bpf_return_val(UBLK_BPF_IO_CONTINUE, 512);

	/* complete the whole io command after the 2nd sub-io is queued */
	ublk_bpf_complete_io(io, res);
	return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
}

static inline ublk_bpf_return_t __ublk_null_handle_io_redirect(const struct ublk_bpf_io *io, unsigned int _off)
{
	unsigned int tag = ublk_bpf_get_io_tag(io);
	unsigned long off = -1, sects = -1;
	const struct ublksrv_io_desc *iod;
	int res;

	iod = ublk_bpf_get_iod(io);
	if (iod) {
		res = iod->nr_sectors << 9;
		off = iod->start_sector;
		sects = iod->nr_sectors;
	} else
		res = -EINVAL;

	BPF_DBG("ublk dev %u qid %u: handle io tag %u %lx-%d res %d",
			ublk_bpf_get_dev_id(io),
			ublk_bpf_get_queue_id(io),
			ublk_bpf_get_io_tag(io),
			off, sects, res);
	if (res < 0) {
		ublk_bpf_complete_io(io, res);
		return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
	}

	if (tag & 0x1) {
		/* complete the whole io command after the 2nd sub-io is queued */
		ublk_bpf_complete_io(io, res);
		return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
	} else {
		unsigned long long key = build_io_key(io);
		int *pv;

		/* stored value means if it is ready to complete IO */
		pv = bpf_map_lookup_elem(&io_map, &key);
		if (pv && *pv) {
			ublk_bpf_complete_io(io, res);
			return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
		} else {
			int v = 0;
			res = bpf_map_update_elem(&io_map, &key, &v, BPF_ANY);
			if (res)
				bpf_printk("update io map element failed %d key %llx\n", res, key);
			return ublk_bpf_return_val(UBLK_BPF_IO_REDIRECT, 0);
		}
	}
}


static inline ublk_bpf_return_t __ublk_null_handle_io(const struct ublk_bpf_io *io, unsigned int _off)
{
	unsigned long off = -1, sects = -1;
	const struct ublksrv_io_desc *iod;
	int res;

	iod = ublk_bpf_get_iod(io);
	if (iod) {
		res = iod->nr_sectors << 9;
		off = iod->start_sector;
		sects = iod->nr_sectors;
	} else
		res = -EINVAL;

	BPF_DBG("ublk dev %u qid %u: handle io tag %u %lx-%d res %d",
			ublk_bpf_get_dev_id(io),
			ublk_bpf_get_queue_id(io),
			ublk_bpf_get_io_tag(io),
			off, sects, res);
	ublk_bpf_complete_io(io, res);

	return ublk_bpf_return_val(UBLK_BPF_IO_QUEUED, 0);
}

SEC("struct_ops/ublk_bpf_queue_io_cmd")
ublk_bpf_return_t BPF_PROG(ublk_null_handle_io, struct ublk_bpf_io *io, unsigned int off)
{
	return __ublk_null_handle_io(io, off);
}

SEC("struct_ops/ublk_bpf_attach_dev")
int BPF_PROG(ublk_null_attach_dev, int dev_id)
{
	return 0;
}

SEC("struct_ops/ublk_bpf_detach_dev")
void BPF_PROG(ublk_null_detach_dev, int dev_id)
{
}

SEC(".struct_ops.link")
struct ublk_bpf_ops null_ublk_bpf_ops = {
	.id = 0,
	.queue_io_cmd = (void *)ublk_null_handle_io,
	.attach_dev = (void *)ublk_null_attach_dev,
	.detach_dev = (void *)ublk_null_detach_dev,
};

SEC("struct_ops/ublk_bpf_queue_io_cmd")
ublk_bpf_return_t BPF_PROG(ublk_null_handle_io_split, struct ublk_bpf_io *io, unsigned int off)
{
	return __ublk_null_handle_io_split(io, off);
}

SEC(".struct_ops.link")
struct ublk_bpf_ops null_ublk_bpf_ops_split = {
	.id = 1,
	.queue_io_cmd = (void *)ublk_null_handle_io_split,
};

SEC("struct_ops/ublk_bpf_queue_io_cmd")
ublk_bpf_return_t BPF_PROG(ublk_null_handle_io_redirect, struct ublk_bpf_io *io, unsigned int off)
{
	return __ublk_null_handle_io_redirect(io, off);
}

SEC(".struct_ops.link")
struct ublk_bpf_ops null_ublk_bpf_ops_redirect = {
	.id = 2,
	.queue_io_cmd = (void *)ublk_null_handle_io_redirect,
};

char LICENSE[] SEC("license") = "GPL";
