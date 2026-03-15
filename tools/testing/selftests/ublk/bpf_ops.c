// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops support for kublk selftest.
 *
 * Loads and attaches ublk BPF struct_ops programs.
 */
#include "kublk.h"

#ifdef HAVE_BPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ublk_null.bpf.skel.h"
#include "ublk_dma_zc.bpf.skel.h"

static struct ublk_null *null_skel;
static struct ublk_dma_zc *dma_zc_skel;
static struct bpf_link *bpf_link;

int ublk_bpf_load(const char *type)
{
	int err;

	if (!strcmp(type, "null")) {
		null_skel = ublk_null__open();
		if (!null_skel) {
			ublk_err("BPF: failed to open null skeleton\n");
			return -ENOMEM;
		}
		err = ublk_null__load(null_skel);
		if (err) {
			ublk_err("BPF: failed to load null: %d\n", err);
			ublk_null__destroy(null_skel);
			null_skel = NULL;
			return err;
		}
		bpf_link = bpf_map__attach_struct_ops(
				null_skel->maps.ublk_null_bpf_ops);
	} else if (!strcmp(type, "dma_zc")) {
		dma_zc_skel = ublk_dma_zc__open();
		if (!dma_zc_skel) {
			ublk_err("BPF: failed to open dma_zc skeleton\n");
			return -ENOMEM;
		}
		err = ublk_dma_zc__load(dma_zc_skel);
		if (err) {
			ublk_err("BPF: failed to load dma_zc: %d\n", err);
			ublk_dma_zc__destroy(dma_zc_skel);
			dma_zc_skel = NULL;
			return err;
		}
		bpf_link = bpf_map__attach_struct_ops(
				dma_zc_skel->maps.ublk_dma_zc_bpf_ops);
	} else {
		ublk_err("BPF: unsupported target type '%s'\n", type);
		return -EINVAL;
	}

	if (!bpf_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_bpf_unload();
		return err;
	}

	ublk_dbg(UBLK_DBG_DEV, "BPF: %s struct_ops attached\n", type);
	return 0;
}

void ublk_bpf_unload(void)
{
	if (bpf_link) {
		bpf_link__destroy(bpf_link);
		bpf_link = NULL;
	}
	if (null_skel) {
		ublk_null__destroy(null_skel);
		null_skel = NULL;
	}
	if (dma_zc_skel) {
		ublk_dma_zc__destroy(dma_zc_skel);
		dma_zc_skel = NULL;
	}
}

#else /* !HAVE_BPF */

int ublk_bpf_load(const char *type)
{
	ublk_err("BPF support not compiled\n");
	return -ENOTSUP;
}

void ublk_bpf_unload(void)
{
}

#endif /* HAVE_BPF */
