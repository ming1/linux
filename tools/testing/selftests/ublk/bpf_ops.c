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
#include "ublk_null.bpf.skel.h"

static struct ublk_null *null_skel;
static struct bpf_link *ops_link;

/* registration id of the loaded struct_ops prog, -1 when none */
static int ublk_bpf_ops_id = -1;

static int ublk_bpf_load_null(void)
{
	int err;

	null_skel = ublk_null__open();
	if (!null_skel) {
		ublk_err("BPF: failed to open null skeleton\n");
		return -ENOMEM;
	}

	err = ublk_null__load(null_skel);
	if (err) {
		ublk_err("BPF: failed to load null skeleton: %d\n", err);
		ublk_null__destroy(null_skel);
		null_skel = NULL;
		return err;
	}

	ops_link = bpf_map__attach_struct_ops(null_skel->maps.ublk_null_bpf_ops);
	if (!ops_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_null__destroy(null_skel);
		null_skel = NULL;
		return err;
	}

	ublk_bpf_ops_id = null_skel->struct_ops.ublk_null_bpf_ops->id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: null struct_ops attached\n");
	return 0;
}

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
	if (!strcmp(prog, "null"))
		return ublk_bpf_load_null();

	ublk_err("BPF: unsupported prog '%s'\n", prog);
	return -EINVAL;
}

void ublk_bpf_unload(void)
{
	if (ops_link) {
		bpf_link__destroy(ops_link);
		ops_link = NULL;
	}
	if (null_skel) {
		ublk_null__destroy(null_skel);
		null_skel = NULL;
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
