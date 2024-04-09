# SPDX-License-Identifier: GPL-2.0

# needed for trace events
ccflags-y			+= -I$(src)

ublk_drv-$(CONFIG_BLK_DEV_UBLK)	:= main.o
obj-$(CONFIG_BLK_DEV_UBLK)	+= ublk_drv.o
