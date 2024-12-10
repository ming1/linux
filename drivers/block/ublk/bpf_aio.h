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
	unsigned int bytes;
	struct bpf_aio_buf	buf;
	struct bpf_aio_work	*work;
	const struct bpf_aio_complete_ops *ops;
	struct kiocb iocb;
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

int bpf_aio_init(void);
int bpf_aio_struct_ops_init(void);
struct bpf_aio *bpf_aio_alloc(unsigned int op, enum bpf_aio_flag aio_flags);
struct bpf_aio *bpf_aio_alloc_sleepable(unsigned int op, enum bpf_aio_flag aio_flags);
void bpf_aio_release(struct bpf_aio *aio);
int bpf_aio_submit(struct bpf_aio *aio, int fd, loff_t pos, unsigned bytes,
		unsigned io_flags);
#endif
