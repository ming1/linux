#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

TID="nvme_user_02"
ERR_CODE=0

# Require NVME_CHAR from environment (no auto-detection to prevent data loss)
if [ -z "$NVME_CHAR" ]; then
	echo "NVME_CHAR not set. Please specify NVMe device (e.g., NVME_CHAR=/dev/ng0n1)" >&2
	exit "$UBLK_SKIP_CODE"
fi

NVME_CHAR_DEV="$NVME_CHAR"

if [ ! -c "$NVME_CHAR_DEV" ]; then
	echo "$NVME_CHAR_DEV is not a character device" >&2
	exit "$UBLK_SKIP_CODE"
fi

_prep_test "nvme_user" "mkfs & mount & umount ($NVME_CHAR_DEV)"

dev_id=$(_add_ublk_dev -t nvme_user "$NVME_CHAR_DEV")
_check_add_dev $TID $?

_mkfs_mount_test /dev/ublkb"${dev_id}"
ERR_CODE=$?

_cleanup_test "nvme_user"

_show_result $TID $ERR_CODE
