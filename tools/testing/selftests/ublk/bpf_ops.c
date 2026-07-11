// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops support for kublk selftest.
 *
 * Loads and attaches the ublk BPF struct_ops program selected with
 * --bpf_prog, and passes its registration id via UBLK_PARAM_TYPE_BPF.
 */
#include "kublk.h"

#ifdef HAVE_BPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static struct bpf_link *ops_link;

/* registration id of the loaded struct_ops prog, -1 when none */
static int ublk_bpf_ops_id = -1;

/* registration id of the loaded struct_ops prog, -1 when none is loaded */
int ublk_bpf_prog_id(void)
{
	return ublk_bpf_ops_id;
}

int ublk_bpf_dev_ready(const struct dev_ctx *ctx, struct ublk_dev *dev)
{
	return 0;
}

int ublk_bpf_load(const char *prog)
{

	ublk_err("BPF: unsupported prog '%s'\n", prog);
	return -EINVAL;
}

void ublk_bpf_unload(void)
{
	if (ops_link) {
		bpf_link__destroy(ops_link);
		ops_link = NULL;
	}
}

#else /* !HAVE_BPF */

int ublk_bpf_load(const char *prog)
{
	ublk_err("BPF support not compiled\n");
	return -ENOTSUP;
}

void ublk_bpf_unload(void)
{
}

int ublk_bpf_dev_ready(const struct dev_ctx *ctx, struct ublk_dev *dev)
{
	return 0;
}

void *ublk_bpf_tw_io_buf(unsigned short tag)
{
	return NULL;
}

int ublk_bpf_prog_id(void)
{
	return -1;
}

#endif /* HAVE_BPF */
