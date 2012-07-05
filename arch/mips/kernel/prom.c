/*
 * MIPS support for CONFIG_OF device tree support
 *
 * Copyright (C) 2010 Cisco Systems Inc. <dediao@cisco.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bootmem.h>
#include <linux/initrd.h>
#include <linux/debugfs.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>

#include <asm/page.h>
#include <asm/prom.h>

int __init early_init_dt_scan_memory_arch(unsigned long node,
					  const char *uname, int depth,
					  void *data)
{
	return early_init_dt_scan_memory(node, uname, depth, data);
}

void __init early_init_dt_add_memory_arch(u64 base, u64 size)
{
	return add_memory_region(base, size, BOOT_MEM_RAM);
}

int __init reserve_mem_mach(unsigned long addr, unsigned long size)
{
	return reserve_bootmem(addr, size, BOOTMEM_DEFAULT);
}

void __init free_mem_mach(unsigned long addr, unsigned long size)
{
	return free_bootmem(addr, size);
}

void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	return __alloc_bootmem(size, align, __pa(MAX_DMA_ADDRESS));
}

#ifdef CONFIG_BLK_DEV_INITRD
void __init early_init_dt_setup_initrd_arch(unsigned long start,
					    unsigned long end)
{
	initrd_start = (unsigned long)__va(start);
	initrd_end = (unsigned long)__va(end);
	initrd_below_start_ok = 1;
}
#endif

void __init __dt_setup_arch(struct boot_param_header *bph)
{
	if (be32_to_cpu(bph->magic) != OF_DT_HEADER) {
		pr_err("DTB has bad magic, ignoring builtin OF DTB\n");

		return;
	}

	initial_boot_params = bph;

	early_init_devtree(initial_boot_params);
}
