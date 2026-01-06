/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 * Basic io_uring BPF struct_ops test.
 *
 * This tests registering a minimal uring_bpf_ops struct_ops
 * with prep/issue/cleanup callbacks.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* Counters to verify callbacks are invoked */
int prep_count = 0;
int issue_count = 0;
int cleanup_count = 0;

/* Test result stored in pdu */
#define PDU_MAGIC 0xdeadbeef

SEC("struct_ops/basic_prep")
int BPF_PROG(basic_prep, struct uring_bpf_data *data,
	     const struct io_uring_sqe *sqe)
{
	__u32 *magic;

	prep_count++;

	/* Store magic value in pdu to verify data flow */
	magic = (__u32 *)data->pdu;
	*magic = PDU_MAGIC;

	bpf_printk("basic_prep: count=%d", prep_count);
	return 0;
}

extern void uring_bpf_set_result(struct uring_bpf_data *data, int res) __ksym;

SEC("struct_ops/basic_issue")
int BPF_PROG(basic_issue, struct uring_bpf_data *data)
{
	__u32 *magic;

	issue_count++;

	/* Verify pdu contains the magic value from prep */
	magic = (__u32 *)data->pdu;
	if (*magic != PDU_MAGIC) {
		bpf_printk("basic_issue: pdu magic mismatch!");
		uring_bpf_set_result(data, -22); /* -EINVAL */
		return 0;
	}

	bpf_printk("basic_issue: count=%d, pdu_magic=0x%x", issue_count, *magic);

	/* Set successful result */
	uring_bpf_set_result(data, 42);
	return 0;
}

SEC("struct_ops/basic_fail")
void BPF_PROG(basic_fail, struct uring_bpf_data *data)
{
	bpf_printk("basic_fail: invoked");
}

SEC("struct_ops/basic_cleanup")
void BPF_PROG(basic_cleanup, struct uring_bpf_data *data)
{
	cleanup_count++;
	bpf_printk("basic_cleanup: count=%d", cleanup_count);
}

SEC(".struct_ops.link")
struct uring_bpf_ops basic_bpf_ops = {
	.id		= 0,
	.prep_fn	= (void *)basic_prep,
	.issue_fn	= (void *)basic_issue,
	.fail_fn	= (void *)basic_fail,
	.cleanup_fn	= (void *)basic_cleanup,
};

/* Second struct_ops to verify multiple registrations work */
SEC(".struct_ops.link")
struct uring_bpf_ops basic_bpf_ops_2 = {
	.id		= 1,
	.prep_fn	= (void *)basic_prep,
	.issue_fn	= (void *)basic_issue,
	.fail_fn	= (void *)basic_fail,
	.cleanup_fn	= (void *)basic_cleanup,
};
