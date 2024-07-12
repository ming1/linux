# SPDX-License-Identifier: GPL-2.0

# needed for trace events
ccflags-y			+= -I$(src)

ublk_drv-$(CONFIG_BLK_DEV_UBLK)	:= main.o
ifeq ($(CONFIG_UBLK_BPF), y)
ublk_drv-$(CONFIG_BLK_DEV_UBLK)	+= bpf_ops.o bpf.o bpf_aio.o
endif
obj-$(CONFIG_BLK_DEV_UBLK)	+= ublk_drv.o
