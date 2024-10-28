#!/bin/bash

. test_common.sh

TID="loop_01"
ERR_CODE=0

# prepare & register and pin bpf prog
_prep_bpf_test "loop" ublk_loop.bpf.o

backfile_0=`_create_backfile 256M`

# add two ublk null disks with the pinned bpf prog
_add_ublk_dev -t loop -n 0 --bpf_prog 16 --bpf_aio_prog 16 --quiet $backfile_0

# run fio over the ublk disk
fio --name=write_and_verify \
    --filename=/dev/ublkb0 \
    --ioengine=libaio --iodepth=4 \
    --rw=write \
    --size=256M \
    --direct=1 \
    --verify=crc32c \
    --do_verify=1 \
    --bs=4k > /dev/null 2>&1
ERR_CODE=$?

# cleanup & unregister and unpin the bpf prog
_cleanup_bpf_test "loop"

_remove_backfile $backfile_0

_show_result $TID $ERR_CODE
