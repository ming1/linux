// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_OP_H
#define IOU_BPF_OP_H

struct io_kiocb;
struct io_uring_sqe;

#ifdef CONFIG_IO_URING_BPF_OP
int io_uring_bpf_issue(struct io_kiocb *req, unsigned int issue_flags);
int io_uring_bpf_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
void io_uring_bpf_fail(struct io_kiocb *req);
void io_uring_bpf_cleanup(struct io_kiocb *req);
#endif

#endif
