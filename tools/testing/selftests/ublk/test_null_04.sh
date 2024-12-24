#!/bin/bash

. test_common.sh

TID="null_04"
ERR_CODE=0

# prepare and register & pin bpf prog
_prep_bpf_test "null" ublk_null.bpf.o

# add two ublk null disks with the pinned bpf prog
_add_ublk_dev -t null -n 0 --bpf_prog 2 --quiet

# run fio over the ublk disk
fio --name=job1 --filename=/dev/ublkb0 --ioengine=libaio --rw=readwrite --iodepth=32 --size=256M > /dev/null 2>&1
ERR_CODE=$?

# clean and unregister & unpin the bpf prog
_cleanup_bpf_test "null"

_show_result $TID $ERR_CODE
