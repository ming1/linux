#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

ERR_CODE=0

if ! _have_program fio; then
	exit "$UBLK_SKIP_CODE"
fi

if ! _have_feature "BPF"; then
	exit "$UBLK_SKIP_CODE"
fi

_prep_test "bpf" "null target via BPF struct_ops"

dev_id=$(_add_ublk_dev -t null --bpf)
_check_add_dev $TID $?

fio --name=job1 --filename=/dev/ublkb"${dev_id}" --ioengine=libaio \
	--rw=readwrite --iodepth=32 --size=256M > /dev/null 2>&1
ERR_CODE=$?

_cleanup_test "bpf"

_show_result $TID $ERR_CODE
