#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test BPF DMA zero-copy: exercises ublk_bpf_map_dma/ublk_bpf_unmap_dma
# kfuncs with a real VFIO PCI device.
#
# Requires: IOMMU, NVMe PCI device, vfio-pci module

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

ERR_CODE=0

if ! _have_feature "BPF"; then
	exit "$UBLK_SKIP_CODE"
fi

if ! _have_feature "DMA_ZC"; then
	exit "$UBLK_SKIP_CODE"
fi

# Find NVMe PCI device
PCI=$(lspci | grep -i "Non-Volatile\|nvme" | head -1 | awk '{ print $1 }')
if [ -z "$PCI" ]; then
	exit "$UBLK_SKIP_CODE"
fi
PCI_ADDR="0000:${PCI}"

# Ensure vfio-pci is loaded
modprobe vfio_pci 2>/dev/null

# Unbind from nvme driver if needed
if [ -e "/sys/bus/pci/devices/${PCI_ADDR}/driver" ]; then
	driver=$(readlink "/sys/bus/pci/devices/${PCI_ADDR}/driver" | xargs basename)
	if [ "$driver" != "vfio-pci" ]; then
		echo "${PCI_ADDR}" > "/sys/bus/pci/devices/${PCI_ADDR}/driver/unbind" 2>/dev/null
		sleep 1
	fi
fi

_prep_test "bpf" "DMA zero-copy via BPF struct_ops (PCI ${PCI_ADDR})"

dev_id=$(_add_ublk_dev -t null --bpf=dma_zc --pci "${PCI_ADDR}" -d 32 -q 1)
_check_add_dev $TID $?

# Run I/O test
dd if=/dev/ublkb"${dev_id}" of=/dev/null bs=4k count=1000 2>/dev/null
ERR_CODE=$?

_cleanup_test "bpf"

_show_result $TID $ERR_CODE
