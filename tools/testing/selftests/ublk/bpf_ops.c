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
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ublk_null.bpf.skel.h"
#include "bpf/ublk_arena.h"
#include "bpf/ublk_tw.h"
#include "ublk_arena.bpf.skel.h"
#include "ublk_fwd.bpf.skel.h"
#include "ublk_mmio.bpf.skel.h"
#include "ublk_tw.bpf.skel.h"

static struct ublk_null *null_skel;
static struct ublk_arena *arena_skel;
static struct ublk_fwd *fwd_skel;
static struct ublk_mmio *mmio_skel;
static struct ublk_tw *tw_skel;
static struct bpf_link *ops_link;

/* registration id of the loaded struct_ops prog, -1 when none */
static int ublk_bpf_ops_id = -1;

/* number of real I/O copies routed through a tw arena buffer */
static __u64 nr_arena_copies;

/* State for the MMIO-doorbell target (see ublk_mmio.bpf.c). */
static struct {
	void *bar_base;		/* mmap of the PCI BAR (resource0) */
	size_t bar_len;
	__u32 buf_id;		/* id returned by UBLK_U_CMD_REG_BUF, 0 = none */
	int dev_id;
	int unreg_after_ms;	/* >0: self-unregister mid-load (ENOENT test) */
	const char *stat_path;	/* where the monitor writes live counters */
	pthread_t monitor;
	int monitor_started;
	int stop;	/* re-read each loop across the usleep() call */
	int did_unreg;
} mmio;

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

static int ublk_bpf_load_arena(void)
{
	int err;

	arena_skel = ublk_arena__open();
	if (!arena_skel) {
		ublk_err("BPF: failed to open arena skeleton\n");
		return -ENOMEM;
	}

	err = ublk_arena__load(arena_skel);
	if (err) {
		ublk_err("BPF: failed to load arena skeleton: %d\n", err);
		ublk_arena__destroy(arena_skel);
		arena_skel = NULL;
		return err;
	}

	ops_link = bpf_map__attach_struct_ops(arena_skel->maps.ublk_arena_bpf_ops);
	if (!ops_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_arena__destroy(arena_skel);
		arena_skel = NULL;
		return err;
	}

	ublk_bpf_ops_id = arena_skel->struct_ops.ublk_arena_bpf_ops->id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: arena struct_ops attached\n");
	return 0;
}

static int ublk_bpf_load_fwd(void)
{
	int err;

	fwd_skel = ublk_fwd__open();
	if (!fwd_skel) {
		ublk_err("BPF: failed to open fwd skeleton\n");
		return -ENOMEM;
	}

	err = ublk_fwd__load(fwd_skel);
	if (err) {
		ublk_err("BPF: failed to load fwd skeleton: %d\n", err);
		ublk_fwd__destroy(fwd_skel);
		fwd_skel = NULL;
		return err;
	}

	ops_link = bpf_map__attach_struct_ops(fwd_skel->maps.ublk_fwd_bpf_ops);
	if (!ops_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_fwd__destroy(fwd_skel);
		fwd_skel = NULL;
		return err;
	}

	ublk_bpf_ops_id = fwd_skel->struct_ops.ublk_fwd_bpf_ops->id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: fwd struct_ops attached\n");
	return 0;
}

static int ublk_bpf_load_mmio(void)
{
	int err;

	mmio_skel = ublk_mmio__open();
	if (!mmio_skel) {
		ublk_err("BPF: failed to open mmio skeleton\n");
		return -ENOMEM;
	}

	err = ublk_mmio__load(mmio_skel);
	if (err) {
		ublk_err("BPF: failed to load mmio skeleton: %d\n", err);
		goto destroy;
	}

	/*
	 * Attach now; the datapath only rings once doorbell_buf_id is set
	 * (in ublk_bpf_dev_ready, before I/O starts), so early I/O is inert.
	 */
	ops_link = bpf_map__attach_struct_ops(mmio_skel->maps.ublk_mmio_bpf_ops);
	if (!ops_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		goto destroy;
	}

	ublk_bpf_ops_id = mmio_skel->struct_ops.ublk_mmio_bpf_ops->id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: mmio struct_ops attached\n");
	return 0;

destroy:
	ublk_mmio__destroy(mmio_skel);
	mmio_skel = NULL;
	return err;
}

/* Snapshot the datapath counters into the stat file for the test to read. */
static void ublk_mmio_write_stats(const char *phase)
{
	char buf[256];
	int fd, n;

	if (!mmio.stat_path)
		return;
	fd = open(mmio.stat_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;
	n = snprintf(buf, sizeof(buf),
		     "phase=%s calls=%llu rings=%llu enoent=%llu other=%llu\n",
		     phase,
		     (unsigned long long)mmio_skel->bss->nr_calls,
		     (unsigned long long)mmio_skel->bss->nr_rings,
		     (unsigned long long)mmio_skel->bss->nr_enoent,
		     (unsigned long long)mmio_skel->bss->nr_other_err);
	if (n > 0)
		(void)!write(fd, buf, n);
	close(fd);
}

/*
 * Monitor thread: publishes live datapath counters and, when configured,
 * unregisters the MMIO window mid-load so the test can observe post-unreg
 * rings returning -ENOENT (the RCU teardown fence) without a crash.
 */
static void *ublk_mmio_monitor(void *arg)
{
	int elapsed = 0;

	while (!mmio.stop) {
		const char *phase = mmio.did_unreg ? "post-unreg" : "armed";

		if (mmio.unreg_after_ms > 0 && !mmio.did_unreg &&
		    elapsed >= mmio.unreg_after_ms) {
			int ret = ublk_ctrl_unreg_buf_by_id(mmio.dev_id,
							    mmio.buf_id);
			ublk_dbg(UBLK_DBG_DEV,
				 "BPF: mmio self-unreg id %u ret %d\n",
				 mmio.buf_id, ret);
			mmio.did_unreg = 1;
			phase = "post-unreg";
		}

		ublk_mmio_write_stats(phase);
		usleep(100 * 1000);
		elapsed += 100;
	}
	ublk_mmio_write_stats(mmio.did_unreg ? "post-unreg" : "armed");
	return NULL;
}

/*
 * Register the MMIO doorbell window once the char device exists. The BAR
 * VA must live in this (daemon) process for the kernel to resolve its
 * VM_PFNMAP PTE, so the mmap and the UBLK_U_CMD_REG_BUF are both done here.
 *
 * Config comes from the environment so no new kublk option is needed:
 *   UBLK_MMIO_PCI       PCI address, e.g. 0000:00:0c.0 (required to arm)
 *   UBLK_MMIO_BAR_OFF   byte offset of the register in BAR0 (default 0x1000,
 *                       the NVMe SQ0 tail doorbell)
 *   UBLK_MMIO_UNREG_MS  ms after which to self-unregister (0 = never)
 *   UBLK_MMIO_STAT      path the monitor writes live counters to
 */
static int ublk_bpf_setup_mmio(struct ublk_dev *dev)
{
	const char *pci = getenv("UBLK_MMIO_PCI");
	const char *off_s = getenv("UBLK_MMIO_BAR_OFF");
	const char *ms_s = getenv("UBLK_MMIO_UNREG_MS");
	unsigned long bar_off = off_s ? strtoul(off_s, NULL, 0) : 0x1000;
	char path[256];
	struct stat st;
	void *base;
	int fd, id;

	mmio.buf_id = 0;
	mmio.stat_path = getenv("UBLK_MMIO_STAT");
	mmio.unreg_after_ms = ms_s ? atoi(ms_s) : 0;
	mmio.dev_id = dev->dev_info.dev_id;

	/* No device named: behave like the null target (leaves it disarmed). */
	if (!pci || !*pci) {
		ublk_dbg(UBLK_DBG_DEV, "BPF: mmio disarmed (no UBLK_MMIO_PCI)\n");
		return 0;
	}

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/resource0", pci);
	fd = open(path, O_RDWR | O_SYNC);
	if (fd < 0) {
		ublk_err("BPF: mmio open %s: %m\n", path);
		return -errno;
	}
	if (fstat(fd, &st) < 0 || st.st_size <= (off_t)bar_off) {
		ublk_err("BPF: mmio bad BAR size for %s\n", pci);
		close(fd);
		return -EINVAL;
	}
	base = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (base == MAP_FAILED) {
		ublk_err("BPF: mmio mmap %s: %m\n", path);
		return -errno;
	}
	mmio.bar_base = base;
	mmio.bar_len = st.st_size;

	id = ublk_ctrl_reg_buf(dev, (char *)base + bar_off, 4,
			       UBLK_SHMEM_BUF_MMIO);
	if (id < 0) {
		ublk_err("BPF: mmio REG_BUF failed: %d\n", id);
		munmap(base, st.st_size);
		mmio.bar_base = NULL;
		return id;
	}
	mmio.buf_id = id;
	mmio_skel->bss->doorbell_buf_id = id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: mmio armed id %d bar %s+0x%lx\n",
		 id, pci, bar_off);

	mmio.stop = 0;
	mmio.did_unreg = 0;
	if (pthread_create(&mmio.monitor, NULL, ublk_mmio_monitor, NULL) == 0)
		mmio.monitor_started = 1;
	else
		ublk_mmio_write_stats("armed");

	return 0;
}

static int ublk_bpf_load_tw(void)
{
	int err;

	tw_skel = ublk_tw__open();
	if (!tw_skel) {
		ublk_err("BPF: failed to open tw skeleton\n");
		return -ENOMEM;
	}

	err = ublk_tw__load(tw_skel);
	if (err) {
		ublk_err("BPF: failed to load tw skeleton: %d\n", err);
		ublk_tw__destroy(tw_skel);
		tw_skel = NULL;
		return err;
	}

	ops_link = bpf_map__attach_struct_ops(tw_skel->maps.ublk_tw_bpf_ops);
	if (!ops_link) {
		err = -errno;
		ublk_err("BPF: failed to attach struct_ops: %d\n", err);
		ublk_tw__destroy(tw_skel);
		tw_skel = NULL;
		return err;
	}

	ublk_bpf_ops_id = tw_skel->struct_ops.ublk_tw_bpf_ops->id;
	ublk_dbg(UBLK_DBG_DEV, "BPF: tw struct_ops attached\n");
	return 0;
}

/* registration id of the loaded struct_ops prog, -1 when none is loaded */
int ublk_bpf_prog_id(void)
{
	return ublk_bpf_ops_id;
}

/*
 * Return the mmapped arena buffer that the tw program allocated for @tag, or
 * NULL when this device is not the tw target (or no buffer is mapped for the
 * tag). Used by ublk_user_copy() to route the real I/O data through the arena
 * buffer, proving it carries I/O rather than just being accounted.
 *
 * The arena buffers are IO_BUF_SIZE; a request larger than that (blk-mq can
 * merge adjacent I/O far beyond the fio block size) must use the regular
 * per-tag buffer instead, so pass the request length in @len and both the
 * char-dev copy and the backing-file I/O consistently fall back.
 */
void *ublk_bpf_tw_io_buf(unsigned short tag, __u32 len)
{
	__u32 key = tag;
	__u32 idx;

	if (!tw_skel || len > IO_BUF_SIZE)
		return NULL;

	if (bpf_map__lookup_elem(tw_skel->maps.tag2buf, &key, sizeof(key),
				 &idx, sizeof(idx), 0))
		return NULL;
	if (idx >= NR_BUFS)
		return NULL;

	__sync_fetch_and_add(&nr_arena_copies, 1);
	return &tw_skel->arena->bufs[idx].data[0];
}

int ublk_bpf_dev_ready(const struct dev_ctx *ctx, struct ublk_dev *dev)
{
	if (mmio_skel)
		return ublk_bpf_setup_mmio(dev);
	return 0;
}

int ublk_bpf_load(const char *prog)
{
	if (!strcmp(prog, "null"))
		return ublk_bpf_load_null();
	if (!strcmp(prog, "arena"))
		return ublk_bpf_load_arena();
	if (!strcmp(prog, "fwd"))
		return ublk_bpf_load_fwd();
	if (!strcmp(prog, "mmio"))
		return ublk_bpf_load_mmio();
	if (!strcmp(prog, "tw"))
		return ublk_bpf_load_tw();

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
	if (fwd_skel) {
		ublk_dbg(UBLK_DBG_DEV, "BPF: fwd saw %llu ios (%llu shmem_zc)\n",
			 (unsigned long long)fwd_skel->bss->nr_ios,
			 (unsigned long long)fwd_skel->bss->nr_shmem_zc_ios);
		ublk_fwd__destroy(fwd_skel);
		fwd_skel = NULL;
	}
	if (arena_skel) {
		/*
		 * The arena pages are shared with the BPF program; report
		 * how many I/Os it recorded for debugging.
		 */
		ublk_dbg(UBLK_DBG_DEV, "BPF: arena recorded %llu ios\n",
			 (unsigned long long)arena_skel->arena->nr_ios);
		ublk_arena__destroy(arena_skel);
		arena_skel = NULL;
	}
	if (tw_skel) {
		/*
		 * struct_ops is detached above, so no more task-work callbacks
		 * run. Report the pool accounting for the test to assert on,
		 * both to stderr and (if configured) to UBLK_TW_STAT.
		 */
		const char *stat = getenv("UBLK_TW_STAT");
		char buf[160];
		int n;

		n = snprintf(buf, sizeof(buf),
			     "alloc=%llu free=%llu busy=%llu badtag=%llu arena_copies=%llu\n",
			     (unsigned long long)tw_skel->arena->nr_alloc,
			     (unsigned long long)tw_skel->arena->nr_free,
			     (unsigned long long)tw_skel->arena->nr_busy,
			     (unsigned long long)tw_skel->arena->nr_badtag,
			     (unsigned long long)nr_arena_copies);
		fprintf(stderr, "BPF: tw %s", buf);
		if (stat && n > 0) {
			int fd = open(stat, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (fd >= 0) {
				(void)!write(fd, buf, n);
				close(fd);
			}
		}
		ublk_tw__destroy(tw_skel);
		tw_skel = NULL;
	}
	if (mmio_skel) {
		/*
		 * struct_ops is already detached above, so the datapath can no
		 * longer ring. Stop the monitor, unregister the window if it is
		 * still live, and drop our BAR mapping.
		 */
		if (mmio.monitor_started) {
			mmio.stop = 1;
			pthread_join(mmio.monitor, NULL);
			mmio.monitor_started = 0;
		}
		if (mmio.buf_id && !mmio.did_unreg)
			ublk_ctrl_unreg_buf_by_id(mmio.dev_id, mmio.buf_id);
		if (mmio.bar_base) {
			munmap(mmio.bar_base, mmio.bar_len);
			mmio.bar_base = NULL;
		}
		fprintf(stderr,
			"BPF: mmio calls %llu rings %llu enoent %llu other %llu\n",
			(unsigned long long)mmio_skel->bss->nr_calls,
			(unsigned long long)mmio_skel->bss->nr_rings,
			(unsigned long long)mmio_skel->bss->nr_enoent,
			(unsigned long long)mmio_skel->bss->nr_other_err);
		ublk_mmio__destroy(mmio_skel);
		mmio_skel = NULL;
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

void *ublk_bpf_tw_io_buf(unsigned short tag, __u32 len)
{
	return NULL;
}

int ublk_bpf_prog_id(void)
{
	return -1;
}

#endif /* HAVE_BPF */
