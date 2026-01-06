/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Red Hat, Inc.
 * Test for uring_bpf_memcpy() kfunc - userspace part.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/io_uring.h>
#include <sys/uio.h>
#include <io_uring/mini_liburing.h>

#include "iou_test.h"
#include "bpf_memcpy.bpf.skel.h"

#define TEST_BUF_SIZE		(4096 * 4 + 1024 + 511)
#define TEST_PATTERN		0xAB
#define MAX_VECS		32

struct test_ctx {
	struct bpf_memcpy *skel;
	struct bpf_link *link;
	struct io_uring ring;

	/* Buffer descriptors and buffers */
	struct io_bpf_buf_desc descs[2];
	char *src_buf;
	char *dst_buf;
	size_t src_buf_size;
	size_t dst_buf_size;
	__u8 src_type;
	__u8 dst_type;
	const char *desc;

	/* Vectored buffer support */
	struct iovec src_vec[MAX_VECS];
	struct iovec dst_vec[MAX_VECS];
	int src_nr_vec;
	int dst_nr_vec;

	/* Fixed buffer support */
	__u16 src_buf_index;
	__u16 dst_buf_index;
};

static enum iou_test_status bpf_setup(struct test_ctx *ctx)
{
	int ret;

	/* Load BPF skeleton */
	ctx->skel = bpf_memcpy__open();
	if (!ctx->skel) {
		IOU_ERR("Failed to open BPF skeleton");
		return IOU_TEST_FAIL;
	}

	/* Set ring_fd in struct_ops before loading */
	ctx->skel->struct_ops.bpf_memcpy_ops->ring_fd = ctx->ring.ring_fd;
	ctx->skel->struct_ops.bpf_memcpy_ops->id = 0;

	ret = bpf_memcpy__load(ctx->skel);
	if (ret) {
		IOU_ERR("Failed to load BPF skeleton: %d", ret);
		bpf_memcpy__destroy(ctx->skel);
		ctx->skel = NULL;
		return IOU_TEST_FAIL;
	}

	/* Attach struct_ops */
	ctx->link = bpf_map__attach_struct_ops(ctx->skel->maps.bpf_memcpy_ops);
	if (!ctx->link) {
		IOU_ERR("Failed to attach struct_ops");
		bpf_memcpy__destroy(ctx->skel);
		ctx->skel = NULL;
		return IOU_TEST_FAIL;
	}

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

static int allocate_buf(char **buf, size_t size, __u8 buf_type,
			struct iovec *vec, int nr_vec)
{
	char *p;
	size_t chunk_size;
	int i;

	switch (buf_type) {
	case IO_BPF_BUF_USER:
	case IO_BPF_BUF_FIXED:
		p = aligned_alloc(4096, size);
		if (!p)
			return -ENOMEM;
		*buf = p;
		return 0;
	case IO_BPF_BUF_VEC:
	case IO_BPF_BUF_REG_VEC:
		if (nr_vec <= 0 || nr_vec > MAX_VECS)
			return -EINVAL;
		p = aligned_alloc(4096, size);
		if (!p)
			return -ENOMEM;
		*buf = p;
		/* Split buffer into nr_vec pieces */
		chunk_size = size / nr_vec;
		for (i = 0; i < nr_vec; i++) {
			vec[i].iov_base = p + i * chunk_size;
			vec[i].iov_len = chunk_size;
		}
		/* Last chunk gets remainder */
		vec[nr_vec - 1].iov_len += size % nr_vec;
		return 0;
	default:
		return -EINVAL;
	}
}

static void free_buf(char *buf, __u8 buf_type)
{
	switch (buf_type) {
	case IO_BPF_BUF_USER:
	case IO_BPF_BUF_VEC:
	case IO_BPF_BUF_FIXED:
	case IO_BPF_BUF_REG_VEC:
		free(buf);
		break;
	default:
		break;
	}
}

static inline bool is_registered_buf(__u8 type)
{
	return type == IO_BPF_BUF_FIXED || type == IO_BPF_BUF_REG_VEC;
}

static enum iou_test_status register_fixed_bufs(struct test_ctx *ctx)
{
	struct iovec iovecs[2];
	int nr_iovecs = 0;
	int ret;

	if (is_registered_buf(ctx->src_type)) {
		ctx->src_buf_index = nr_iovecs;
		iovecs[nr_iovecs].iov_base = ctx->src_buf;
		iovecs[nr_iovecs].iov_len = ctx->src_buf_size;
		nr_iovecs++;
	}

	if (is_registered_buf(ctx->dst_type)) {
		ctx->dst_buf_index = nr_iovecs;
		iovecs[nr_iovecs].iov_base = ctx->dst_buf;
		iovecs[nr_iovecs].iov_len = ctx->dst_buf_size;
		nr_iovecs++;
	}

	if (nr_iovecs == 0)
		return IOU_TEST_PASS;

	ret = io_uring_register_buffers(&ctx->ring, iovecs, nr_iovecs);
	if (ret) {
		IOU_ERR("Failed to register buffers: %d", ret);
		return IOU_TEST_FAIL;
	}

	return IOU_TEST_PASS;
}

static void unregister_fixed_bufs(struct test_ctx *ctx)
{
	if (is_registered_buf(ctx->src_type) ||
	    is_registered_buf(ctx->dst_type))
		io_uring_unregister_buffers(&ctx->ring);
}

static enum iou_test_status allocate_bufs(struct test_ctx *ctx)
{
	enum iou_test_status status;
	int ret;

	ret = allocate_buf(&ctx->src_buf, ctx->src_buf_size, ctx->src_type,
			   ctx->src_vec, ctx->src_nr_vec);
	if (ret) {
		IOU_ERR("Failed to allocate source buffer: %d", ret);
		return IOU_TEST_FAIL;
	}

	ret = allocate_buf(&ctx->dst_buf, ctx->dst_buf_size, ctx->dst_type,
			   ctx->dst_vec, ctx->dst_nr_vec);
	if (ret) {
		IOU_ERR("Failed to allocate destination buffer: %d", ret);
		free_buf(ctx->src_buf, ctx->src_type);
		ctx->src_buf = NULL;
		return IOU_TEST_FAIL;
	}

	/* Initialize source buffer with pattern, destination with zeros */
	memset(ctx->src_buf, TEST_PATTERN, ctx->src_buf_size);
	memset(ctx->dst_buf, 0, ctx->dst_buf_size);

	/* Register fixed buffers if needed */
	status = register_fixed_bufs(ctx);
	if (status != IOU_TEST_PASS) {
		free_buf(ctx->dst_buf, ctx->dst_type);
		ctx->dst_buf = NULL;
		free_buf(ctx->src_buf, ctx->src_type);
		ctx->src_buf = NULL;
		return status;
	}

	/* Build buffer descriptors */
	memset(ctx->descs, 0, sizeof(ctx->descs));
	ctx->descs[0].type = ctx->src_type;
	ctx->descs[1].type = ctx->dst_type;

	if (ctx->src_type == IO_BPF_BUF_VEC) {
		ctx->descs[0].addr = (__u64)(uintptr_t)ctx->src_vec;
		ctx->descs[0].len = ctx->src_nr_vec;
	} else if (ctx->src_type == IO_BPF_BUF_FIXED) {
		ctx->descs[0].addr = (__u64)(uintptr_t)ctx->src_buf;
		ctx->descs[0].len = ctx->src_buf_size;
		ctx->descs[0].buf_index = ctx->src_buf_index;
	} else if (ctx->src_type == IO_BPF_BUF_REG_VEC) {
		ctx->descs[0].addr = (__u64)(uintptr_t)ctx->src_vec;
		ctx->descs[0].len = ctx->src_nr_vec;
		ctx->descs[0].buf_index = ctx->src_buf_index;
	} else {
		ctx->descs[0].addr = (__u64)(uintptr_t)ctx->src_buf;
		ctx->descs[0].len = ctx->src_buf_size;
	}

	if (ctx->dst_type == IO_BPF_BUF_VEC) {
		ctx->descs[1].addr = (__u64)(uintptr_t)ctx->dst_vec;
		ctx->descs[1].len = ctx->dst_nr_vec;
	} else if (ctx->dst_type == IO_BPF_BUF_FIXED) {
		ctx->descs[1].addr = (__u64)(uintptr_t)ctx->dst_buf;
		ctx->descs[1].len = ctx->dst_buf_size;
		ctx->descs[1].buf_index = ctx->dst_buf_index;
	} else if (ctx->dst_type == IO_BPF_BUF_REG_VEC) {
		ctx->descs[1].addr = (__u64)(uintptr_t)ctx->dst_vec;
		ctx->descs[1].len = ctx->dst_nr_vec;
		ctx->descs[1].buf_index = ctx->dst_buf_index;
	} else {
		ctx->descs[1].addr = (__u64)(uintptr_t)ctx->dst_buf;
		ctx->descs[1].len = ctx->dst_buf_size;
	}

	return IOU_TEST_PASS;
}

static void free_bufs(struct test_ctx *ctx)
{
	unregister_fixed_bufs(ctx);

	if (ctx->src_buf) {
		free_buf(ctx->src_buf, ctx->src_type);
		ctx->src_buf = NULL;
	}
	if (ctx->dst_buf) {
		free_buf(ctx->dst_buf, ctx->dst_type);
		ctx->dst_buf = NULL;
	}
}

static enum iou_test_status submit_and_wait(struct test_ctx *ctx)
{
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int ret;

	/* Get an SQE and prepare BPF op request */
	sqe = io_uring_get_sqe(&ctx->ring);
	if (!sqe) {
		IOU_ERR("Failed to get SQE");
		return IOU_TEST_FAIL;
	}

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_BPF;
	sqe->fd = -1;
	sqe->bpf_op_flags = (0 << IORING_BPF_OP_SHIFT); /* BPF op id = 0 */
	sqe->addr = (__u64)(uintptr_t)ctx->descs;
	sqe->len = 2;  /* number of descriptors */
	sqe->user_data = 0xCAFEBABE;

	/* Submit and wait for completion */
	ret = io_uring_submit(&ctx->ring);
	if (ret < 0) {
		IOU_ERR("io_uring_submit failed: %d", ret);
		return IOU_TEST_FAIL;
	}

	ret = io_uring_wait_cqe(&ctx->ring, &cqe);
	if (ret < 0) {
		IOU_ERR("io_uring_wait_cqe failed: %d", ret);
		return IOU_TEST_FAIL;
	}

	/* Verify CQE */
	if (cqe->user_data != 0xCAFEBABE) {
		IOU_ERR("CQE user_data mismatch: 0x%llx", cqe->user_data);
		return IOU_TEST_FAIL;
	}

	if (cqe->res != (int)ctx->src_buf_size) {
		IOU_ERR("CQE result mismatch: %d (expected %zu)",
			cqe->res, ctx->src_buf_size);
		if (cqe->res < 0)
			IOU_ERR("Error from uring_bpf_memcpy: %s", strerror(-cqe->res));
		return IOU_TEST_FAIL;
	}

	io_uring_cqe_seen(&ctx->ring);

	/* Verify destination buffer contains the pattern */
	for (size_t i = 0; i < ctx->dst_buf_size; i++) {
		if ((unsigned char)ctx->dst_buf[i] != TEST_PATTERN) {
			IOU_ERR("Data mismatch at offset %zu: 0x%02x (expected 0x%02x)",
				i, (unsigned char)ctx->dst_buf[i], TEST_PATTERN);
			return IOU_TEST_FAIL;
		}
	}

	return IOU_TEST_PASS;
}

static enum iou_test_status test_copy(struct test_ctx *ctx)
{
	enum iou_test_status status;

	status = allocate_bufs(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = submit_and_wait(ctx);
	free_bufs(ctx);

	if (status == IOU_TEST_PASS)
		IOU_INFO("%s: copied %zu bytes", ctx->desc, ctx->src_buf_size);

	return status;
}

static enum iou_test_status copy_user_to_user(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_USER;
	ctx->dst_type = IO_BPF_BUF_USER;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->desc = "USER -> USER";

	return test_copy(ctx);
}

static enum iou_test_status copy_vec_to_vec(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_VEC;
	ctx->dst_type = IO_BPF_BUF_VEC;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->src_nr_vec = 4;
	ctx->dst_nr_vec = 4;
	ctx->desc = "VEC -> VEC";

	return test_copy(ctx);
}

static enum iou_test_status copy_user_to_vec(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_USER;
	ctx->dst_type = IO_BPF_BUF_VEC;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->dst_nr_vec = 4;
	ctx->desc = "USER -> VEC";

	return test_copy(ctx);
}

static enum iou_test_status copy_user_to_fixed(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_USER;
	ctx->dst_type = IO_BPF_BUF_FIXED;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->desc = "USER -> FIXED";

	return test_copy(ctx);
}

static enum iou_test_status copy_fixed_to_user(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_FIXED;
	ctx->dst_type = IO_BPF_BUF_USER;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->desc = "FIXED -> USER";

	return test_copy(ctx);
}

static enum iou_test_status copy_user_to_reg_vec(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_USER;
	ctx->dst_type = IO_BPF_BUF_REG_VEC;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->dst_nr_vec = 4;
	ctx->desc = "USER -> REG_VEC";

	return test_copy(ctx);
}

static enum iou_test_status copy_reg_vec_to_user(struct test_ctx *ctx)
{
	ctx->src_type = IO_BPF_BUF_REG_VEC;
	ctx->dst_type = IO_BPF_BUF_USER;
	ctx->src_buf_size = TEST_BUF_SIZE;
	ctx->dst_buf_size = TEST_BUF_SIZE;
	ctx->src_nr_vec = 4;
	ctx->desc = "REG_VEC -> USER";

	return test_copy(ctx);
}

static enum iou_test_status run(void *ctx_ptr)
{
	struct test_ctx *ctx = ctx_ptr;
	enum iou_test_status status;

	status = copy_user_to_user(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_vec_to_vec(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_user_to_vec(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_user_to_fixed(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_fixed_to_user(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_user_to_reg_vec(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	status = copy_reg_vec_to_user(ctx);
	if (status != IOU_TEST_PASS)
		return status;

	return IOU_TEST_PASS;
}

static void cleanup(void *ctx_ptr)
{
	struct test_ctx *ctx = ctx_ptr;

	if (ctx->link)
		bpf_link__destroy(ctx->link);
	if (ctx->skel)
		bpf_memcpy__destroy(ctx->skel);
	io_uring_queue_exit(&ctx->ring);
	free(ctx);
}

struct iou_test bpf_memcpy_test = {
	.name = "bpf_memcpy",
	.description = "Test uring_bpf_memcpy() kfunc with USER, VEC, FIXED, REG_VEC buffer types",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_IOU_TEST(bpf_memcpy_test)
