#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test nvme_user target: Verify ublk disk queue limits match NVMe disk

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

TID="nvme_user_01"
ERR_CODE=0

# Helper function to get NVMe block device from char device
_get_nvme_block_dev() {
	local ng_dev=$1
	local ng_name

	# Convert /dev/ng0n1 -> nvme0n1
	ng_name=$(basename "$ng_dev")
	if [[ ! "$ng_name" =~ ^ng[0-9]+n[0-9]+$ ]]; then
		echo "Invalid NVMe char device: $ng_dev" >&2
		return 1
	fi

	echo "nvme${ng_name#ng}"
}

# Helper function to compare queue limits
_compare_queue_limit() {
	local nvme_dev=$1
	local ublk_dev=$2
	local limit=$3
	local nvme_val
	local ublk_val

	nvme_val=$(cat "/sys/block/$nvme_dev/queue/$limit" 2>/dev/null)
	ublk_val=$(cat "/sys/block/$ublk_dev/queue/$limit" 2>/dev/null)

	if [ "$nvme_val" != "$ublk_val" ]; then
		echo "FAIL: $limit mismatch - nvme:$nvme_val ublk:$ublk_val" >&2
		return 1
	fi

	[ "$UBLK_TEST_QUIET" -eq 0 ] && echo "  $limit: $nvme_val (match)"
	return 0
}

# Use NVME_CHAR from environment or find first NVMe character device
if [ -n "$NVME_CHAR" ]; then
	NVME_CHAR_DEV="$NVME_CHAR"
else
	NVME_CHAR_DEV=$(ls /dev/ng* 2>/dev/null | head -1)
fi

if [ -z "$NVME_CHAR_DEV" ]; then
	echo "No NVMe character device found, skipping test" >&2
	exit "$UBLK_SKIP_CODE"
fi

if [ ! -c "$NVME_CHAR_DEV" ]; then
	echo "$NVME_CHAR_DEV is not a character device, skipping test" >&2
	exit "$UBLK_SKIP_CODE"
fi

# Get corresponding block device
NVME_BLOCK_DEV=$(_get_nvme_block_dev "$NVME_CHAR_DEV")
if [ -z "$NVME_BLOCK_DEV" ] || [ ! -b "/dev/$NVME_BLOCK_DEV" ]; then
	echo "Cannot find NVMe block device for $NVME_CHAR_DEV" >&2
	exit "$UBLK_SKIP_CODE"
fi

_prep_test "nvme_user" "queue limits alignment test ($NVME_CHAR_DEV -> $NVME_BLOCK_DEV)"

# Add ublk device with nvme_user target
dev_id=$(_add_ublk_dev -t nvme_user "$NVME_CHAR_DEV")
_check_add_dev "$TID" $?

UBLK_BLOCK_DEV="ublkb${dev_id}"

[ "$UBLK_TEST_QUIET" -eq 0 ] && echo "Comparing queue limits: $NVME_BLOCK_DEV vs $UBLK_BLOCK_DEV"

# Compare key queue limits
FAIL_COUNT=0

# max_sectors_kb - Maximum request size in KB
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "max_sectors_kb"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# max_segments - Maximum scatter-gather segments
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "max_segments"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# max_segment_size - Maximum size of a single segment
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "max_segment_size"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# virt_boundary_mask - Virtual boundary alignment mask
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "virt_boundary_mask"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# logical_block_size - Logical block size
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "logical_block_size"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# physical_block_size - Physical block size
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "physical_block_size"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# write_cache - Write cache support
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "write_cache"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# fua - Force Unit Access support
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "fua"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

# chunk_sectors - Optimal I/O boundary
if ! _compare_queue_limit "$NVME_BLOCK_DEV" "$UBLK_BLOCK_DEV" "chunk_sectors"; then
	FAIL_COUNT=$((FAIL_COUNT + 1))
fi

if [ "$FAIL_COUNT" -gt 0 ]; then
	ERR_CODE=1
	echo "$FAIL_COUNT queue limit(s) did not match" >&2
else
	[ "$UBLK_TEST_QUIET" -eq 0 ] && echo "All queue limits match successfully"
fi

_cleanup_test "nvme_user"

_show_result "$TID" "$ERR_CODE"
