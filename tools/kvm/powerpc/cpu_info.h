/*
 * PPC CPU identification
 *
 * Copyright 2012 Matt Evans <matt@ozlabs.org>, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 */

#ifndef CPU_INFO_H
#define CPU_INFO_H

#include <linux/types.h>
#include <linux/kernel.h>

struct cpu_info {
	const char	*name;
	u32 		*page_sizes_prop;
	u32		page_sizes_prop_len;
	u32 		*segment_sizes_prop;
	u32		segment_sizes_prop_len;
	u32		slb_size;
	u32		tb_freq;
	u32		d_bsize;
	u32		i_bsize;
	u32		flags;
};

struct pvr_info {
	u32		pvr_mask;
	u32		pvr;
	struct cpu_info *cpu_info;
};

/* Misc capabilities/CPU properties */
#define CPUINFO_FLAG_DFP	0x00000001
#define CPUINFO_FLAG_VMX	0x00000002
#define CPUINFO_FLAG_VSX	0x00000004

struct cpu_info *find_cpu_info(u32 pvr);

#endif
