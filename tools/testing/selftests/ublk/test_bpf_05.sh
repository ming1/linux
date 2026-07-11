#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# Test: dynamic per-I/O buffer allocation from a BPF arena in task-work context
#
# The tw target dispatches its submission callback (queue_io_cmd_tw) from the
# ublk daemon task context rather than the submitter's queue_rq context, and
# allocates a per-I/O buffer from a shared BPF-arena pool there, recording the
# tag->buffer mapping in a BPF map. The required complete_io_cmd releases the
# buffer and drops the map entry when the request finishes.
#
# It runs a loop (file-backed) target under UBLK_F_USER_COPY, and userspace
# routes the real I/O data through the arena buffer for the tag on both the
# char-dev copy and the backing-file I/O. fio then does a crc write+verify
# pass, so the arena buffer really carries -- and must correctly round-trip --
# the I/O data. The demo keys the map by request tag, so it runs a single
# queue (tags are only unique within one queue), and also checks the pool
# accounting is balanced: every allocation is freed and no slot is reused
# while still in use.

. "$(cd "$(dirname "$0")" && pwd)"/test_common.sh

ERR_CODE=0

if ! _have_program fio; then
	exit "$UBLK_SKIP_CODE"
fi

if ! _have_feature "BPF"; then
	exit "$UBLK_SKIP_CODE"
fi

STAT=$(mktemp "${UBLK_TMP_DIR:-/tmp}"/ublk_tw_stat_XXXXX 2>/dev/null || mktemp)
export UBLK_TW_STAT="$STAT"

_prep_test "bpf" "dynamic arena buffer alloc via queue_io_cmd_tw, loop verify"

_create_backfile 0 256M

dev_id=$(_add_ublk_dev -t loop -q 1 --bpf_prog tw "${UBLK_BACKFILES[0]}")
_check_add_dev "$TID" $?

# Write with a crc, read back and verify: the data must survive the round-trip
# fio <-> arena buffer <-> backing file, proving the arena buffer really
# carries correct I/O.
_run_fio_verify_io --filename=/dev/ublkb"${dev_id}" --size=256M
ERR_CODE=$?

_cleanup_test "bpf"

# The daemon writes final pool counters on teardown; give it a moment.
sleep 1
STAT_LINE=$(cat "$STAT" 2>/dev/null)
echo "tw pool stats: [$STAT_LINE]"
alloc=$(printf '%s' "$STAT_LINE" | sed -n 's/.*alloc=\([0-9]*\).*/\1/p')
free=$(printf '%s' "$STAT_LINE" | sed -n 's/.*free=\([0-9]*\).*/\1/p')
busy=$(printf '%s' "$STAT_LINE" | sed -n 's/.*busy=\([0-9]*\).*/\1/p')
badtag=$(printf '%s' "$STAT_LINE" | sed -n 's/.*badtag=\([0-9]*\).*/\1/p')
arena_copies=$(printf '%s' "$STAT_LINE" | sed -n 's/.*arena_copies=\([0-9]*\).*/\1/p')

# Allocations happened, and each was released from complete_io_cmd.
if [ "${alloc:-0}" -le 0 ]; then
	echo "FAIL: no task-work allocations recorded"
	ERR_CODE=255
fi
if [ "${alloc:-0}" -ne "${free:-0}" ]; then
	echo "FAIL: alloc ($alloc) != free ($free)"
	ERR_CODE=255
fi
# No slot was reused while in use, and no out-of-range tag was seen.
if [ "${busy:-1}" -ne 0 ] || [ "${badtag:-1}" -ne 0 ]; then
	echo "FAIL: pool anomaly (busy=$busy badtag=$badtag)"
	ERR_CODE=255
fi
# Real I/O data actually flowed through the arena buffers (UBLK_F_USER_COPY).
if [ "${arena_copies:-0}" -le 0 ]; then
	echo "FAIL: no I/O routed through arena buffer (arena_copies=$arena_copies)"
	ERR_CODE=255
fi

rm -f "$STAT"

_show_result "$TID" "$ERR_CODE"
