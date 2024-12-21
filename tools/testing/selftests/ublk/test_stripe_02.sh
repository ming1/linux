#!/bin/bash

. test_common.sh

TID="stripe_02"
ERR_CODE=0

# prepare & register and pin bpf prog
_prep_bpf_test "stripe" ublk_stripe.bpf.o

backfile_0=`_create_backfile 256M`
backfile_1=`_create_backfile 256M`

# add two ublk null disks with the pinned bpf prog
_add_ublk_dev -t stripe -n 0 --bpf_prog 32 --bpf_aio_prog 32 --quiet $backfile_0 $backfile_1

_mkfs_mount_test /dev/ublkb0
ERR_CODE=$?

# cleanup & unregister and unpin the bpf prog
_cleanup_bpf_test "stripe"

_remove_backfile $backfile_0
_remove_backfile $backfile_1

_show_result $TID $ERR_CODE
