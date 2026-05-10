# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_BLK_DEV_UBLK)	+= ublk_drv.o
ublk_drv-y			+= ublk_main.o batch.o
ublk_drv-$(CONFIG_BLK_DEV_ZONED) += zoned.o
