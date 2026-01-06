/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 * Test for uring_bpf_memcpy() kfunc.
 *
 * This tests the uring_bpf_memcpy() kfunc with USER buffer type,
 * copying data between two userspace buffers.
 *
 * Buffer descriptors are passed via sqe->addr as an array of two
 * io_bpf_buf_desc structures:
 *   [0] = source buffer descriptor
 *   [1] = destination buffer descriptor
 * sqe->len contains the number of descriptors (2).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

char LICENSE[] SEC("license") = "GPL";

/* PDU layout for storing buffer descriptors between prep and issue */
struct memcpy_pdu {
	struct io_bpf_buf_desc descs[2];  /* [0]=src, [1]=dst */
};

/* kfunc declarations */
extern void uring_bpf_set_result(struct uring_bpf_data *data, int res) __ksym;
extern int uring_bpf_read_buf_descs(struct io_bpf_buf_desc *descs,
				    __u64 user_addr, int nr_descs) __ksym;
extern __s64 uring_bpf_memcpy(const struct uring_bpf_data *data,
			      struct io_bpf_buf_desc *dst,
			      struct io_bpf_buf_desc *src) __ksym;

SEC("struct_ops/memcpy_prep")
int BPF_PROG(memcpy_prep, struct uring_bpf_data *data,
	     const struct io_uring_sqe *sqe)
{
	struct memcpy_pdu *pdu = (struct memcpy_pdu *)data->pdu;
	struct io_bpf_buf_desc descs[2];
	int ret;

	/* Validate descriptor count */
	if (sqe->len != 2)
		return -EINVAL;

	ret = bpf_probe_read_user(descs, sizeof(descs), (void *)sqe->addr);
	if (ret) {
		bpf_printk("memcpy_prep: uring_bpf_read_buf_descs failed: %d", ret);
		return ret;
	}

	__builtin_memcpy(&pdu->descs, &descs, sizeof(descs));
	bpf_printk("memcpy_prep: src=0x%llx dst=0x%llx len=%u",
		   pdu->descs[0].addr, pdu->descs[1].addr, pdu->descs[0].len);
	return 0;
}

SEC("struct_ops/memcpy_issue")
int BPF_PROG(memcpy_issue, struct uring_bpf_data *data)
{
	struct memcpy_pdu *pdu = (struct memcpy_pdu *)data->pdu;
	struct io_bpf_buf_desc dst_desc, src_desc;
	__s64 ret;

	/* Copy descriptors to stack to satisfy verifier type checking */
	src_desc = pdu->descs[0];
	dst_desc = pdu->descs[1];

	/* Call uring_bpf_memcpy() kfunc using stack-based descriptors */
	ret = uring_bpf_memcpy(data, &dst_desc, &src_desc);

	bpf_printk("memcpy_issue: uring_bpf_memcpy returned %lld", ret);

	uring_bpf_set_result(data, (int)ret);
	return 0;
}

SEC("struct_ops/memcpy_fail")
void BPF_PROG(memcpy_fail, struct uring_bpf_data *data)
{
	bpf_printk("memcpy_fail: invoked");
}

SEC("struct_ops/memcpy_cleanup")
void BPF_PROG(memcpy_cleanup, struct uring_bpf_data *data)
{
	bpf_printk("memcpy_cleanup: invoked");
}

SEC(".struct_ops.link")
struct uring_bpf_ops bpf_memcpy_ops = {
	.prep_fn	= (void *)memcpy_prep,
	.issue_fn	= (void *)memcpy_issue,
	.fail_fn	= (void *)memcpy_fail,
	.cleanup_fn	= (void *)memcpy_cleanup,
};
