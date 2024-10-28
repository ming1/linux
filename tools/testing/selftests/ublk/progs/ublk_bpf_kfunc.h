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
#endif
