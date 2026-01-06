/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 * Basic io_uring BPF struct_ops test - userspace part.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <io_uring/mini_liburing.h>

#include "iou_test.h"
#include "basic_bpf_ops.bpf.skel.h"

struct test_ctx {
	struct basic_bpf_ops *skel;
	struct bpf_link *link;
	struct bpf_link *link_2;
	struct io_uring ring;
	int nr_ops;
};

static enum iou_test_status bpf_setup(struct test_ctx *ctx)
{
	int ret;

	/* Load BPF skeleton */
	ctx->skel = basic_bpf_ops__open();
	if (!ctx->skel) {
		IOU_ERR("Failed to open BPF skeleton");
		return IOU_TEST_FAIL;
	}

	/* Set ring_fd in struct_ops before loading (id is hardcoded in BPF) */
	ctx->skel->struct_ops.basic_bpf_ops->ring_fd = ctx->ring.ring_fd;
	ctx->skel->struct_ops.basic_bpf_ops_2->ring_fd = ctx->ring.ring_fd;

	ret = basic_bpf_ops__load(ctx->skel);
	if (ret) {
		IOU_ERR("Failed to load BPF skeleton: %d", ret);
		basic_bpf_ops__destroy(ctx->skel);
		ctx->skel = NULL;
		return IOU_TEST_FAIL;
	}

	/* Attach first struct_ops */
	ctx->link = bpf_map__attach_struct_ops(ctx->skel->maps.basic_bpf_ops);
	if (!ctx->link) {
		IOU_ERR("Failed to attach struct_ops");
		basic_bpf_ops__destroy(ctx->skel);
		ctx->skel = NULL;
		return IOU_TEST_FAIL;
	}
	ctx->nr_ops++;

	/* Attach second struct_ops */
	ctx->link_2 = bpf_map__attach_struct_ops(ctx->skel->maps.basic_bpf_ops_2);
	if (!ctx->link_2) {
		IOU_ERR("Failed to attach struct_ops_2");
		bpf_link__destroy(ctx->link);
		ctx->link = NULL;
		basic_bpf_ops__destroy(ctx->skel);
		ctx->skel = NULL;
		return IOU_TEST_FAIL;
	}
	ctx->nr_ops++;

	return IOU_TEST_PASS;
}

static enum iou_test_status setup(void **ctx_out)
{
	struct io_uring_params p;
	struct test_ctx *ctx;
	enum iou_test_status status;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		IOU_ERR("Failed to allocate context");
		return IOU_TEST_FAIL;
	}

	/* Setup io_uring ring with BPF_OP flag */
	memset(&p, 0, sizeof(p));
	p.flags = IORING_SETUP_BPF_OP | IORING_SETUP_NO_SQARRAY;

	ret = io_uring_queue_init_params(8, &ctx->ring, &p);
	if (ret < 0) {
		IOU_ERR("io_uring_queue_init_params failed: %s (flags=0x%x)",
			strerror(-ret), p.flags);
		free(ctx);
		return IOU_TEST_SKIP;
	}

	status = bpf_setup(ctx);
	if (status != IOU_TEST_PASS) {
		io_uring_queue_exit(&ctx->ring);
		free(ctx);
		return status;
	}

	*ctx_out = ctx;
	return IOU_TEST_PASS;
}

static enum iou_test_status test_bpf_op(struct test_ctx *ctx, int op_id)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	__u64 user_data = 0x12345678 + op_id;
	int ret;

	sqe = io_uring_get_sqe(&ctx->ring);
	if (!sqe) {
		IOU_ERR("Failed to get SQE for op %d", op_id);
		return IOU_TEST_FAIL;
	}

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_BPF;
	sqe->fd = -1;
	sqe->bpf_op_flags = (op_id << IORING_BPF_OP_SHIFT);
	sqe->user_data = user_data;

	ret = io_uring_submit(&ctx->ring);
	if (ret < 0) {
		IOU_ERR("io_uring_submit for op %d failed: %d", op_id, ret);
		return IOU_TEST_FAIL;
	}

	ret = io_uring_wait_cqe(&ctx->ring, &cqe);
	if (ret < 0) {
		IOU_ERR("io_uring_wait_cqe for op %d failed: %d", op_id, ret);
		return IOU_TEST_FAIL;
	}

	if (cqe->user_data != user_data) {
		IOU_ERR("CQE user_data mismatch for op %d: 0x%llx", op_id, cqe->user_data);
		return IOU_TEST_FAIL;
	}

	if (cqe->res != 42) {
		IOU_ERR("CQE result mismatch for op %d: %d (expected 42)", op_id, cqe->res);
		return IOU_TEST_FAIL;
	}

	io_uring_cqe_seen(&ctx->ring);
	return IOU_TEST_PASS;
}

static enum iou_test_status verify_counters(struct test_ctx *ctx, int expected)
{
	if (ctx->skel->bss->prep_count != expected) {
		IOU_ERR("prep_count mismatch: %d (expected %d)",
			ctx->skel->bss->prep_count, expected);
		return IOU_TEST_FAIL;
	}
	if (ctx->skel->bss->issue_count != expected) {
		IOU_ERR("issue_count mismatch: %d (expected %d)",
			ctx->skel->bss->issue_count, expected);
		return IOU_TEST_FAIL;
	}
	if (ctx->skel->bss->cleanup_count != expected) {
		IOU_ERR("cleanup_count mismatch: %d (expected %d)",
			ctx->skel->bss->cleanup_count, expected);
		return IOU_TEST_FAIL;
	}
	return IOU_TEST_PASS;
}

static enum iou_test_status run(void *ctx_ptr)
{
	struct test_ctx *ctx = ctx_ptr;
	enum iou_test_status status;
	int i;

	/* Test all registered struct_ops */
	for (i = 0; i < ctx->nr_ops; i++) {
		status = test_bpf_op(ctx, i);
		if (status != IOU_TEST_PASS)
			return status;

		/* Verify counters after each op */
		status = verify_counters(ctx, i + 1);
		if (status != IOU_TEST_PASS)
			return status;
	}

	IOU_INFO("IORING_OP_BPF multiple struct_ops test passed");
	return IOU_TEST_PASS;
}

static void cleanup(void *ctx_ptr)
{
	struct test_ctx *ctx = ctx_ptr;

	if (ctx->link_2)
		bpf_link__destroy(ctx->link_2);
	if (ctx->link)
		bpf_link__destroy(ctx->link);
	if (ctx->skel)
		basic_bpf_ops__destroy(ctx->skel);
	io_uring_queue_exit(&ctx->ring);
	free(ctx);
}

struct iou_test basic_bpf_ops_test = {
	.name = "basic_bpf_ops",
	.description = "Test IORING_OP_BPF struct_ops registration and execution",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_IOU_TEST(basic_bpf_ops_test)
