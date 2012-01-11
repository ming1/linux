/*
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 *
 * Copyright (C) 2010 John Crispin <blogic@openwrt.org>
 */

#include <linux/export.h>
#include <linux/clk.h>
#include <asm/bootinfo.h>
#include <asm/time.h>

#include <lantiq.h>

#include "prom.h"
#include "clk.h"

/* access to the ebu needs to be locked between different drivers */
DEFINE_SPINLOCK(ebu_lock);
EXPORT_SYMBOL_GPL(ebu_lock);

static struct ltq_soc_info soc_info;

unsigned int ltq_get_cpu_ver(void)
{
	return soc_info.rev;
}
EXPORT_SYMBOL(ltq_get_cpu_ver);

unsigned int ltq_get_soc_type(void)
{
	return soc_info.type;
}
EXPORT_SYMBOL(ltq_get_soc_type);

const char *get_system_type(void)
{
	return soc_info.sys_type;
}

void prom_free_prom_memory(void)
{
}

static void __init prom_init_cmdline(void)
{
	int argc = fw_arg0;
	char **argv = (char **) KSEG1ADDR(fw_arg1);
	int i;

	arcs_cmdline[0] = '\0';

	for (i = 0; i < argc; i++) {
		char *p = (char *) KSEG1ADDR(argv[i]);

		if (CPHYSADDR(p) && *p) {
			strlcat(arcs_cmdline, p, sizeof(arcs_cmdline));
			strlcat(arcs_cmdline, " ", sizeof(arcs_cmdline));
		}
	}
}

void __iomem *ltq_remap_resource(struct resource *res)
{
	__iomem void *ret = NULL;
	struct resource *lookup = lookup_resource(&iomem_resource, res->start);

	if (lookup && strcmp(lookup->name, res->name)) {
		pr_err("conflicting memory range %s\n", res->name);
		return NULL;
	}
	if (!lookup) {
		if (insert_resource(&iomem_resource, res) < 0) {
			pr_err("Failed to insert %s memory\n", res->name);
			return NULL;
		}
	}
	if (request_mem_region(res->start,
			resource_size(res), res->name) < 0) {
		pr_err("Failed to request %s memory\n", res->name);
		goto err_res;
	}

	ret = ioremap_nocache(res->start, resource_size(res));
	if (!ret)
		goto err_mem;

	pr_debug("remap: 0x%08X-0x%08X : \"%s\"\n",
		res->start, res->end, res->name);
	return ret;

err_mem:
	panic("Failed to remap %s memory", res->name);
	release_mem_region(res->start, resource_size(res));

err_res:
	release_resource(res);
	return NULL;
}
EXPORT_SYMBOL(ltq_remap_resource);

void __init prom_init(void)
{
	ltq_soc_detect(&soc_info);
	clk_init();
	snprintf(soc_info.sys_type, LTQ_SYS_TYPE_LEN - 1, "%s rev %s",
		soc_info.name, soc_info.rev_type);
	soc_info.sys_type[LTQ_SYS_TYPE_LEN - 1] = '\0';
	pr_info("SoC: %s\n", soc_info.sys_type);
	prom_init_cmdline();
}
