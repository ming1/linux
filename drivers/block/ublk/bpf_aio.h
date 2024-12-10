// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2024 Red Hat */
#ifndef UBLK_BPF_AIO_HEADER
#define UBLK_BPF_AIO_HEADER

#include "bpf_reg.h"

#define	BPF_AIO_OP_BITS		8
#define	BPF_AIO_OP_MASK		((1 << BPF_AIO_OP_BITS) - 1)

enum bpf_aio_op {
	BPF_AIO_OP_FS_READ	= 0,
	BPF_AIO_OP_FS_WRITE,
	BPF_AIO_OP_FS_FSYNC,
	BPF_AIO_OP_FS_FALLOCATE,
	BPF_AIO_OP_LAST,
};

enum bpf_aio_flag_bits {
	/* force to submit io from wq */
	__BPF_AIO_FORCE_WQ	= BPF_AIO_OP_BITS,
	__BPF_AIO_NR_BITS,	/* stops here */
};

enum bpf_aio_flag {
	BPF_AIO_FORCE_WQ	= (1 << __BPF_AIO_FORCE_WQ),
};

struct bpf_aio_work {
	struct bpf_aio		*aio;
	struct work_struct	work;
};

/* todo: support ubuf & iovec in future */
struct bpf_aio_buf {
	unsigned int		bvec_off;
	int			nr_bvec;
	const struct bio_vec	*bvec;
};

struct bpf_aio {
	unsigned int opf;
	union {
		unsigned int bytes;
		unsigned int buf_size;
	};
	struct bpf_aio_buf	buf;
	struct bpf_aio_work	*work;
	const struct bpf_aio_complete_ops *ops;
	struct kiocb iocb;
	void	*private_data;
};

typedef void (*bpf_aio_complete_t)(struct bpf_aio *io, long ret);

/**
 * struct bpf_aio_complete_ops - A BPF struct_ops of callbacks allowing to
 * 	complete `bpf_aio` submitted by `bpf_aio_submit()`
 * @id: id used by bpf aio consumer, defined by globally
 * @bpf_aio_complete_cb: callback for completing submitted `bpf_aio`
 * @provider: holding all consumers of this struct_ops prog, used by
 * 	kernel only
 */
struct bpf_aio_complete_ops {
	unsigned int		id;
	bpf_aio_complete_t	bpf_aio_complete_cb;
	struct bpf_prog_provider provider;
};

static inline unsigned int bpf_aio_get_op(const struct bpf_aio *aio)
{
	return aio->opf & BPF_AIO_OP_MASK;
}

/* Must be called from kfunc defined in consumer subsystem */
static inline void bpf_aio_assign_cb(struct bpf_aio *aio,
		const struct bpf_aio_complete_ops *ops)
{
	aio->ops = ops;
}

/*
 * Skip `skip` bytes and assign the advanced source buffer for `aio`, so
 * we can cover this part of source buffer by this `aio`
 */
static inline void bpf_aio_assign_buf(struct bpf_aio *aio,
		const struct bpf_aio_buf *src, unsigned skip,
		unsigned bytes)
{
	const struct bio_vec *bvec, *end;
	struct bpf_aio_buf *abuf = &aio->buf;

	skip += src->bvec_off;
	for (bvec = src->bvec, end = bvec + src->nr_bvec; bvec < end; bvec++) {
		if (likely(skip < bvec->bv_len))
			break;
		skip -= bvec->bv_len;
	}

	aio->buf_size = bytes;
	abuf->bvec_off = skip;
	abuf->nr_bvec = src->nr_bvec - (bvec - src->bvec);
	abuf->bvec = bvec;
}


int bpf_aio_init(void);
int bpf_aio_struct_ops_init(void);
struct bpf_aio *bpf_aio_alloc(unsigned int op, enum bpf_aio_flag aio_flags);
struct bpf_aio *bpf_aio_alloc_sleepable(unsigned int op, enum bpf_aio_flag aio_flags);
void bpf_aio_release(struct bpf_aio *aio);
int bpf_aio_submit(struct bpf_aio *aio, int fd, loff_t pos, unsigned bytes,
		unsigned io_flags);

int bpf_aio_prog_attach(struct bpf_prog_consumer *consumer);
void bpf_aio_prog_detach(struct bpf_prog_consumer *consumer);

#endif
