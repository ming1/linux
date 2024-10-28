#!/bin/bash

. test_common.sh

TID="null_01"
ERR_CODE=0

_prep_test

# add single ublk null disk without bpf prog
_add_ublk_dev -t null -n 0 --quiet

# run fio over the two disks
fio --name=job1 --filename=/dev/ublkb0 --ioengine=libaio --rw=readwrite --iodepth=32 --size=256M > /dev/null 2>&1
ERR_CODE=$?

_cleanup_test

_show_result $TID $ERR_CODE
