/* SPDX-License-Identifier: GPL-2.0 */
#ifndef SELFTESTS_UBLK_UBLK_BPF_H
#define SELFTESTS_UBLK_UBLK_BPF_H

/*
 * Shared declarations for the ublk BPF struct_ops selftest programs.
 * Include after vmlinux.h and bpf_helpers.h.
 *
 * With CONFIG_BLK_DEV_UBLK=m the ublk types live in the ublk_drv module
 * BTF, not in the vmlinux BTF that vmlinux.h is generated from. The
 * Makefile defines UBLK_DRV_MODULE in that case, so declare the types the
 * programs use here; preserve_access_index lets CO-RE relocate the field
 * offsets against the module BTF at load time. For a builtin (=y) ublk
 * the same types come from vmlinux.h and this block is skipped.
 */
#ifdef UBLK_DRV_MODULE
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct ublk_bpf_ctx {
	void *ub;
};

struct ublksrv_io_desc {
	__u32 op_flags;
	union {
		__u32 nr_sectors;
		__u32 nr_zones;
	};
	__u64 start_sector;
	__u64 addr;
};

#pragma clang attribute pop

struct ublk_bpf_ops {
	__u32 id;
	int (*queue_io_cmd)(struct ublk_bpf_ctx *ctx, struct request *req,
			    bool last);
	void (*queue_io_cmd_tw)(struct ublk_bpf_ctx *ctx, struct request *req);
	void (*commit_io_cmd)(struct ublk_bpf_ctx *ctx, int ubq_id);
	void (*complete_io_cmd)(struct ublk_bpf_ctx *ctx, struct request *req);
};
#endif /* UBLK_DRV_MODULE */

extern struct ublksrv_io_desc *ublk_bpf_get_iod(struct request *req) __ksym;

#endif /* SELFTESTS_UBLK_UBLK_BPF_H */
