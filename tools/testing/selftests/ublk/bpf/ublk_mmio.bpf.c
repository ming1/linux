// SPDX-License-Identifier: GPL-2.0
/*
 * BPF MMIO-doorbell target for ublk: like the null target, but each I/O
 * also rings a device MMIO register through the ublk_write_shmem_mmio()
 * kfunc before completing.
 *
 * Userspace mmaps a PCI device BAR (e.g. an NVMe controller's BAR0 via
 * /sys/bus/pci/.../resource0), registers a 4-byte register window with
 * UBLK_U_CMD_REG_BUF | UBLK_SHMEM_BUF_MMIO, and publishes the returned
 * buffer id into @doorbell_buf_id below. queue_io_cmd then rings that
 * register from the non-sleepable struct_ops hook.
 *
 * The register mapping and its lifetime live in the ublk driver, and the
 * datapath reaches it through a single kfunc that looks the window up
 * under RCU.
 *
 * Return values are tallied so the test can assert both the happy path
 * (ret == 0 while the window is registered) and the teardown fence (ret
 * == -ENOENT after a concurrent UBLK_U_CMD_UNREG_BUF), all without the
 * datapath ever touching freed iomem.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ublk_bpf.h"

extern int ublk_write_shmem_mmio(struct ublk_bpf_ctx *ctx, __u32 buf_id,
				 __u64 offset, __u64 val, __u32 len) __ksym;

/* Set by userspace after UBLK_U_CMD_REG_BUF; 0 means "not armed yet". */
__u32 doorbell_buf_id;

/* Datapath statistics, read by the loader. */
__u64 nr_calls;		/* queue_io_cmd invocations that attempted a ring */
__u64 nr_rings;		/* ublk_write_shmem_mmio() returned 0 */
__u64 nr_enoent;	/* returned -ENOENT (window unregistered) */
__u64 nr_other_err;	/* any other negative return */

SEC("struct_ops/queue_io_cmd")
int BPF_PROG(ublk_mmio_queue_io_cmd, struct ublk_bpf_ctx *bctx,
	     struct request *req, bool last)
{
	const struct ublksrv_io_desc *iod;

	iod = ublk_bpf_get_iod(req);
	if (!iod)
		return -22; /* -EINVAL */

	/*
	 * queue_io_cmd runs in a non-sleepable struct_ops hook, i.e. an
	 * implicit RCU read-side critical section. ublk_write_shmem_mmio()
	 * looks the window up under rcu_read_lock(), so a concurrent
	 * UBLK_U_CMD_UNREG_BUF that already erased it simply returns
	 * -ENOENT here rather than dereferencing freed iomem.
	 *
	 * Write 0 to the register: the window points at the NVMe SQ0 tail
	 * doorbell of an idle (driver-detached) controller, so the value is
	 * inert -- we are exercising the reg-buf + kfunc plumbing, not
	 * driving a live submission queue.
	 */
	if (doorbell_buf_id) {
		int ret = ublk_write_shmem_mmio(bctx, doorbell_buf_id, 0, 0, 4);

		__sync_fetch_and_add(&nr_calls, 1);
		if (ret == 0)
			__sync_fetch_and_add(&nr_rings, 1);
		else if (ret == -2)
			__sync_fetch_and_add(&nr_enoent, 1);
		else
			__sync_fetch_and_add(&nr_other_err, 1);
	}

	/* > 0: I/O completed with this many bytes, do NOT forward */
	return iod->nr_sectors << 9;
}

SEC("struct_ops/commit_io_cmd")
void BPF_PROG(ublk_mmio_commit_io_cmd, void *bctx, int ubq_id)
{
}

SEC("struct_ops/complete_io_cmd")
void BPF_PROG(ublk_mmio_complete_io_cmd, void *bctx, struct request *req)
{
}

SEC(".struct_ops.link")
struct ublk_bpf_ops ublk_mmio_bpf_ops = {
	.id = 4,
	.queue_io_cmd = (void *)ublk_mmio_queue_io_cmd,
	.commit_io_cmd = (void *)ublk_mmio_commit_io_cmd,
	.complete_io_cmd = (void *)ublk_mmio_complete_io_cmd,
};

char _license[] SEC("license") = "GPL";
