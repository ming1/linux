#!/bin/bash

_check_root() {
	local ksft_skip=4

	if [ $UID != 0 ]; then
		echo please run this as root >&2
		exit $ksft_skip
	fi
}

_remove_ublk_devices() {
	${UBLK_PROG} del -a
}

_get_ublk_dev_state() {
	${UBLK_PROG} list -n "$1" | grep "state" | awk '{print $11}'
}

_get_ublk_daemon_pid() {
	${UBLK_PROG} list -n "$1" | grep "pid" | awk '{print $7}'
}

_prep_test() {
	_check_root
	export UBLK_PROG=$(pwd)/ublk_bpf
	_remove_ublk_devices
}

_prep_bpf_test() {
	_prep_test
	_reg_bpf_prog $@
}

_show_result()
{
	if [ $2 -ne 0 ]; then
		echo "$1 : [FAIL]"
	else
		echo "$1 : [PASS]"
	fi
}

_cleanup_test() {
	_remove_ublk_devices
}

_cleanup_bpf_test() {
	_cleanup_test
	_unreg_bpf_prog $@
}

_reg_bpf_prog() {
	${UBLK_PROG} reg -t $1 $2
	if [ $? -ne 0 ]; then
		echo "fail to register bpf prog $1 $2"
		exit -1
	fi
}

_unreg_bpf_prog() {
	${UBLK_PROG} unreg -t $1
}

_add_ublk_dev() {
	${UBLK_PROG} add $@
	if [ $? -ne 0 ]; then
		echo "fail to add ublk dev $@"
		exit -1
	fi
	udevadm settle
}
