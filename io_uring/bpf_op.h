// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_OP_H
#define IOU_BPF_OP_H

struct io_kiocb;
struct io_uring_sqe;
struct uring_bpf_ops;

/* Arbitrary limit, can be raised if need be */
#define IO_RING_MAX_BPF_OPS 16

struct uring_bpf_data {
	void				*req_data;  /* not for bpf prog */
	const struct uring_bpf_ops	*ops;
	u32				opf;

	/* writeable for bpf prog */
	u8              pdu[64 - sizeof(void *) -
		sizeof(struct uring_bpf_ops *) - sizeof(u32)];
};

typedef int (*uring_bpf_prep_t)(struct uring_bpf_data *data,
				const struct io_uring_sqe *sqe);
typedef int (*uring_bpf_issue_t)(struct uring_bpf_data *data);
typedef void (*uring_bpf_fail_t)(struct uring_bpf_data *data);
typedef void (*uring_bpf_cleanup_t)(struct uring_bpf_data *data);

struct uring_bpf_ops {
	unsigned short		id;
	int			ring_fd;
	uring_bpf_prep_t	prep_fn;
	uring_bpf_issue_t	issue_fn;
	uring_bpf_fail_t	fail_fn;
	uring_bpf_cleanup_t	cleanup_fn;
};

/* TODO: manage it via `io_rsrc_node` */
struct uring_bpf_ops_kern {
	const struct uring_bpf_ops *ops;
	int refcount;
};

#ifdef CONFIG_IO_URING_BPF_OP
int io_uring_bpf_issue(struct io_kiocb *req, unsigned int issue_flags);
int io_uring_bpf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
void io_uring_bpf_fail(struct io_kiocb *req);
void io_uring_bpf_cleanup(struct io_kiocb *req);
int io_bpf_alloc(struct io_ring_ctx *ctx);
void io_bpf_free(struct io_ring_ctx *ctx);
#else
static inline int io_bpf_alloc(struct io_ring_ctx *ctx)
{
	return 0;
}
static inline void io_bpf_free(struct io_ring_ctx *ctx)
{
}
#endif

#endif
