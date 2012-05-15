/****************************************************************************/

/*
 *	uclinux.c -- generic memory mapped MTD driver for uclinux
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 */

/****************************************************************************/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

/****************************************************************************/

extern char _ebss;

struct map_info uclinux_ram_map = {
	.name = "RAM",
	.phys = (unsigned long)&_ebss,
	.size = 0,
};

static struct mtd_info *uclinux_ram_mtdinfo;

/****************************************************************************/

static struct mtd_partition uclinux_romfs[] = {
	{ .name = "ROMfs" }
};

#define	NUM_PARTITIONS	ARRAY_SIZE(uclinux_romfs)

/****************************************************************************/

static int uclinux_point(struct mtd_info *mtd, loff_t from, size_t len,
	size_t *retlen, void **virt, resource_size_t *phys)
{
	struct map_info *map = mtd->priv;
	*virt = (void *)(unsigned long)map->virt + from;
	if (phys)
		*phys = map->phys + from;
	*retlen = len;
	return 0;
}

/****************************************************************************/

static int __init uclinux_mtd_init(void)
{
	struct mtd_info *mtd;
	struct map_info *mapp;

	mapp = &uclinux_ram_map;
	if (!mapp->size)
		mapp->size = PAGE_ALIGN(ntohl(*((unsigned long *)(mapp->phys + 8))));
	mapp->bankwidth = 4;

	printk(KERN_NOTICE "uclinux[mtd]: RAM probe address=0x%x size=0x%x\n",
	       (int)mapp->phys, (int)mapp->size);

	mapp->virt = (void __iomem *)(unsigned long)phys_to_virt(mapp->phys);

	if (mapp->virt == NULL) {
		printk(KERN_ERR "uclinux[mtd]: no virtual mapping?\n");
		return -EIO;
	}

	simple_map_init(mapp);

	mtd = do_map_probe("map_ram", mapp);
	if (!mtd) {
		printk(KERN_ERR "uclinux[mtd]: failed to find a mapping?\n");
		return -ENXIO;
	}

	mtd->owner = THIS_MODULE;
	mtd->_point = uclinux_point;
	mtd->priv = mapp;

	uclinux_ram_mtdinfo = mtd;
	mtd_device_register(mtd, uclinux_romfs, NUM_PARTITIONS);

	return 0;
}

/****************************************************************************/

static void __exit uclinux_mtd_cleanup(void)
{
	mtd_device_unregister(uclinux_ram_mtdinfo);
	map_destroy(uclinux_ram_mtdinfo);
}

/****************************************************************************/

module_init(uclinux_mtd_init);
module_exit(uclinux_mtd_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Ungerer <gerg@snapgear.com>");
MODULE_DESCRIPTION("Generic RAM based MTD for uClinux");

/****************************************************************************/
