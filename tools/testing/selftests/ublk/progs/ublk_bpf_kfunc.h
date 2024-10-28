// SPDX-License-Identifier: GPL-2.0
#ifndef UBLK_BPF_INTERNAL_H
#define UBLK_BPF_INTERNAL_H

#ifndef BITS_PER_LONG
#define BITS_PER_LONG	(sizeof(unsigned long) * 8)
#endif

#define UBLK_BPF_DISPOSITION_BITS       (4)
#define UBLK_BPF_DISPOSITION_SHIFT      (BITS_PER_LONG - UBLK_BPF_DISPOSITION_BITS)

static inline ublk_bpf_return_t ublk_bpf_return_val(enum ublk_bpf_disposition rc,
                unsigned int bytes)
{
	return (ublk_bpf_return_t) ((unsigned long)rc << UBLK_BPF_DISPOSITION_SHIFT) | bytes;
}

extern const struct ublksrv_io_desc *ublk_bpf_get_iod(const struct ublk_bpf_io *io) __ksym;
extern void ublk_bpf_complete_io(const struct ublk_bpf_io *io, int res) __ksym;
extern int ublk_bpf_get_dev_id(const struct ublk_bpf_io *io) __ksym;
extern int ublk_bpf_get_queue_id(const struct ublk_bpf_io *io) __ksym;
extern int ublk_bpf_get_io_tag(const struct ublk_bpf_io *io) __ksym;

extern void ublk_bpf_dettach_and_complete_aio(struct bpf_aio *aio) __ksym;
extern int ublk_bpf_attach_and_prep_aio(const struct ublk_bpf_io *_io, unsigned off, unsigned bytes, struct bpf_aio *aio) __ksym;
extern struct ublk_bpf_io *ublk_bpf_acquire_io_from_aio(struct bpf_aio *aio) __ksym;
extern void ublk_bpf_release_io_from_aio(struct ublk_bpf_io *io) __ksym;

extern struct bpf_aio *bpf_aio_alloc(unsigned int op, enum bpf_aio_flag flags) __ksym;
extern struct bpf_aio *bpf_aio_alloc_sleepable(unsigned int op, enum bpf_aio_flag flags) __ksym;
extern void bpf_aio_release(struct bpf_aio *aio) __ksym;
extern int bpf_aio_submit(struct bpf_aio *aio, int fd, loff_t pos,
                unsigned bytes, unsigned io_flags) __ksym;

static inline unsigned long long build_io_key(const struct ublk_bpf_io *io)
{
	unsigned long long dev_id = (unsigned short)ublk_bpf_get_dev_id(io);
	unsigned long long q_id = (unsigned short)ublk_bpf_get_queue_id(io);
	unsigned long long tag = ublk_bpf_get_io_tag(io);

	return (dev_id << 32) | (q_id << 16) | tag;
}

#endif
