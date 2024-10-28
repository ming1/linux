#!/bin/bash

. test_common.sh

TID="null_02"
ERR_CODE=0

# prepare & register and pin bpf prog
_prep_bpf_test "null" ublk_null.bpf.o

# add two ublk null disks with the pinned bpf prog
_add_ublk_dev -t null -n 0 --bpf_prog 0 --quiet
_add_ublk_dev -t null -n 1 --bpf_prog 0 --quiet

# run fio over the two disks
fio --name=job1 --filename=/dev/ublkb0 --rw=readwrite --size=256M \
	--name=job2 --filename=/dev/ublkb1 --rw=readwrite --size=256M > /dev/null 2>&1
ERR_CODE=$?

# cleanup & unregister and unpin the bpf prog
_cleanup_bpf_test "null"

_show_result $TID $ERR_CODE
