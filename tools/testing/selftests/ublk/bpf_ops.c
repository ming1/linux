// SPDX-License-Identifier: GPL-2.0
/*
 * BPF struct_ops support for kublk selftest.
 *
 * Loads and attaches ublk BPF struct_ops programs (e.g., null target).
 */
#include "kublk.h"

#ifdef HAVE_BPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ublk_null.bpf.skel.h"

static struct ublk_null *null_skel;
static struct bpf_link *null_link;

int ublk_bpf_load(const char *type)
{
	int err;

	if (strcmp(type, "null") != 0) {
		ublk_err("BPF: unsupported target type '%s'\n", type);
		return -EINVAL;
	}

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

	null_link = bpf_map__attach_struct_ops(null_skel->maps.ublk_null_bpf_ops);
	if (!null_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_null__destroy(null_skel);
		null_skel = NULL;
		return err;
	}

	ublk_dbg(UBLK_DBG_DEV, "BPF: null struct_ops attached\n");
	return 0;
}

void ublk_bpf_unload(void)
{
	if (null_link) {
		bpf_link__destroy(null_link);
		null_link = NULL;
	}
	if (null_skel) {
		ublk_null__destroy(null_skel);
		null_skel = NULL;
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
