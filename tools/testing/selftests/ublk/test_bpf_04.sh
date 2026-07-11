#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test: ring an MMIO doorbell via ublk_write_shmem_mmio from queue_io_cmd
#
# The mmio BPF target completes I/O like the null target, but each request
# also rings a device MMIO register through the ublk_write_shmem_mmio()
# kfunc. Userspace mmaps an NVMe controller's BAR0 (via sysfs resource0),
# registers the 4-byte SQ0 tail doorbell as an MMIO window with
# UBLK_U_CMD_REG_BUF | UBLK_SHMEM_BUF_MMIO, and publishes the returned id
# to the BPF program.
#
# The daemon self-unregisters the window partway through the fio run
# (UBLK_MMIO_UNREG_MS), so the test also proves the RCU teardown fence:
# datapath rings after UNREG_BUF return -ENOENT instead of touching freed
# iomem, and dispatch keeps completing I/O without a crash.
#
# The NVMe driver is detached first so the SQ0 doorbell belongs to an idle
# (controller-disabled) device and the writes are inert -- this exercises
# the reg-buf + kfunc plumbing, not a live NVMe submission queue.

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

ERR_CODE=0

if ! _have_program fio; then
	exit "$UBLK_SKIP_CODE"
fi

if ! _have_feature "BPF"; then
	exit "$UBLK_SKIP_CODE"
fi

if ! grep -q hugetlbfs /proc/filesystems; then
	echo "SKIP: hugetlbfs not supported"
	exit "$UBLK_SKIP_CODE"
fi

# Find the first NVMe controller (PCI class 0x010802).
_find_nvme_pci() {
	local d cls
	for d in /sys/bus/pci/devices/*; do
		cls=$(cat "$d/class" 2>/dev/null)
		if [ "$cls" = "0x010802" ]; then
			basename "$d"
			return 0
		fi
	done
	return 1
}

PCI=$(_find_nvme_pci)
if [ -z "$PCI" ] || [ ! -e "/sys/bus/pci/devices/$PCI/resource0" ]; then
	echo "no NVMe PCI device with a mmappable BAR0; skipping"
	exit "$UBLK_SKIP_CODE"
fi

# A mounted namespace means this controller is in live use (e.g. backing
# the root fs). Unbinding it and ringing its doorbell would disturb real
# I/O, so skip rather than risk it.
_nvme_ns_mounted() {
	local ns dev
	for ns in /sys/bus/pci/devices/"$PCI"/nvme/nvme*/nvme*n*; do
		[ -e "$ns" ] || continue
		dev=$(basename "$ns")
		# skip hidden multipath path devices (nvmeXcYnZ)
		case "$dev" in *c*n*) continue ;; esac
		if grep -q "/dev/$dev" /proc/mounts; then
			return 0
		fi
	done
	return 1
}

if _nvme_ns_mounted; then
	echo "NVMe controller $PCI has a mounted namespace; skipping"
	exit "$UBLK_SKIP_CODE"
fi

# Detach the nvme driver so doorbell writes hit an idle controller.
NVME_DRV=""
UNBOUND=""
if [ -L "/sys/bus/pci/devices/$PCI/driver" ]; then
	NVME_DRV=$(basename "$(readlink "/sys/bus/pci/devices/$PCI/driver")")
	echo "$PCI" > "/sys/bus/pci/devices/$PCI/driver/unbind" 2>/dev/null || true
fi

_rebind_nvme() {
	[ -n "$UNBOUND" ] || return 0
	[ -e "/sys/bus/pci/devices/$PCI/driver" ] && return 0
	echo "$PCI" > "/sys/bus/pci/drivers/$NVME_DRV/bind" 2>/dev/null || true
}

# Confirm the driver really detached; otherwise we'd be writing a live
# controller's doorbell. Skip if it is still bound.
if [ -n "$NVME_DRV" ]; then
	cur=""
	if [ -L "/sys/bus/pci/devices/$PCI/driver" ]; then
		cur=$(basename "$(readlink "/sys/bus/pci/devices/$PCI/driver")")
	fi
	if [ "$cur" = "$NVME_DRV" ]; then
		echo "failed to unbind $NVME_DRV from $PCI; skipping"
		exit "$UBLK_SKIP_CODE"
	fi
	UNBOUND=1
fi

STAT=$(mktemp "${UBLK_TMP_DIR:-/tmp}"/ublk_mmio_stat_XXXXX 2>/dev/null || mktemp)

export UBLK_MMIO_PCI="$PCI"
export UBLK_MMIO_BAR_OFF=0x1000
export UBLK_MMIO_UNREG_MS=1500
export UBLK_MMIO_STAT="$STAT"

_prep_test "bpf" "ring an MMIO doorbell via ublk_write_shmem_mmio"

# queue_io_cmd (where the doorbell rings) only runs for UBLK_IO_F_SHMEM_ZC
# I/O, so back the device with a hugetlb shmem-zc buffer and drive fio from
# the same pages -- otherwise the requests never match and the prog is skipped.
OLD_NR_HP=$(cat /proc/sys/vm/nr_hugepages)
echo 10 > /proc/sys/vm/nr_hugepages
if [ "$(cat /proc/sys/vm/nr_hugepages)" -lt 2 ]; then
	echo "SKIP: cannot allocate hugepages"
	echo "$OLD_NR_HP" > /proc/sys/vm/nr_hugepages
	_rebind_nvme
	exit "$UBLK_SKIP_CODE"
fi
HTLB_MNT=$(mktemp -d "${UBLK_TEST_DIR}/htlb_mnt_XXXXXX")
if ! mount -t hugetlbfs none "$HTLB_MNT"; then
	echo "SKIP: cannot mount hugetlbfs"
	rmdir "$HTLB_MNT"
	echo "$OLD_NR_HP" > /proc/sys/vm/nr_hugepages
	_rebind_nvme
	exit "$UBLK_SKIP_CODE"
fi
HTLB_FILE="$HTLB_MNT/ublk_buf"
fallocate -l 4M "$HTLB_FILE"

dev_id=$(_add_ublk_dev -t null --shmem_zc --htlb "$HTLB_FILE" --bpf_prog mmio)
_check_add_dev "$TID" $?

fio --name=job1 --filename=/dev/ublkb"${dev_id}" --ioengine=io_uring \
	--rw=randrw --direct=1 --bs=4k --iodepth=32 --runtime=4 --time_based \
	--numjobs=1 --size=4M --mem=mmaphuge:"$HTLB_FILE" > /dev/null 2>&1
ERR_CODE=$?

# Let the monitor thread flush its final counters.
sleep 1
STAT_LINE=$(cat "$STAT" 2>/dev/null)
rings=$(printf '%s' "$STAT_LINE" | sed -n 's/.*rings=\([0-9]*\).*/\1/p')
enoent=$(printf '%s' "$STAT_LINE" | sed -n 's/.*enoent=\([0-9]*\).*/\1/p')
echo "mmio doorbell stats: [$STAT_LINE]"

# Happy path: rings landed while the window was registered.
if [ "${rings:-0}" -le 0 ]; then
	echo "FAIL: no successful ublk_write_shmem_mmio rings"
	ERR_CODE=255
fi
# Teardown fence: rings after the self-UNREG returned -ENOENT (no crash).
if [ "${enoent:-0}" -le 0 ]; then
	echo "FAIL: no -ENOENT rings observed after UNREG_BUF"
	ERR_CODE=255
fi

# Delete the device first so the daemon releases the htlb mmap, then tear the
# hugetlbfs mount down before _cleanup_test removes UBLK_TEST_DIR.
_ublk_del_dev "${dev_id}"
rm -f "$HTLB_FILE"
umount "$HTLB_MNT"
rmdir "$HTLB_MNT"
echo "$OLD_NR_HP" > /proc/sys/vm/nr_hugepages

_cleanup_test "bpf"
rm -f "$STAT"
_rebind_nvme

_show_result "$TID" "$ERR_CODE"
