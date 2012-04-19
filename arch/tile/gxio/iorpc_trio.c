/*
 * Copyright 2011 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

/* This file is machine-generated; DO NOT EDIT! */
#include "gxio/iorpc_trio.h"

typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_asids_param_t;

int gxio_trio_alloc_asids(gxio_trio_context_t * context, unsigned int count,
			  unsigned int first, unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_asids_param_t temp;
	alloc_asids_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_TRIO_OP_ALLOC_ASIDS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_alloc_asids);


typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_memory_maps_param_t;

int gxio_trio_alloc_memory_maps(gxio_trio_context_t * context,
				unsigned int count, unsigned int first,
				unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_memory_maps_param_t temp;
	alloc_memory_maps_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_TRIO_OP_ALLOC_MEMORY_MAPS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_alloc_memory_maps);


typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_pio_regions_param_t;

int gxio_trio_alloc_pio_regions(gxio_trio_context_t * context,
				unsigned int count, unsigned int first,
				unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_pio_regions_param_t temp;
	alloc_pio_regions_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_TRIO_OP_ALLOC_PIO_REGIONS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_alloc_pio_regions);

typedef struct {
	unsigned int pio_region;
	unsigned int mac;
	uint32_t bus_address_hi;
	unsigned int flags;
} init_pio_region_aux_param_t;

int gxio_trio_init_pio_region_aux(gxio_trio_context_t * context,
				  unsigned int pio_region, unsigned int mac,
				  uint32_t bus_address_hi, unsigned int flags)
{
	uint64_t __offset;
	int __result;
	init_pio_region_aux_param_t temp;
	init_pio_region_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->pio_region = pio_region;
	params->mac = mac;
	params->bus_address_hi = bus_address_hi;
	params->flags = flags;

	__offset = GXIO_TRIO_OP_INIT_PIO_REGION_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_init_pio_region_aux);


typedef struct {
	unsigned int map;
	unsigned long va;
	uint64_t size;
	unsigned int asid;
	unsigned int mac;
	uint64_t bus_address;
	unsigned int node;
	unsigned int order_mode;
} init_memory_map_mmu_aux_param_t;

int gxio_trio_init_memory_map_mmu_aux(gxio_trio_context_t * context,
				      unsigned int map, unsigned long va,
				      uint64_t size, unsigned int asid,
				      unsigned int mac, uint64_t bus_address,
				      unsigned int node,
				      unsigned int order_mode)
{
	uint64_t __offset;
	int __result;
	init_memory_map_mmu_aux_param_t temp;
	init_memory_map_mmu_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->map = map;
	params->va = va;
	params->size = size;
	params->asid = asid;
	params->mac = mac;
	params->bus_address = bus_address;
	params->node = node;
	params->order_mode = order_mode;

	__offset = GXIO_TRIO_OP_INIT_MEMORY_MAP_MMU_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_init_memory_map_mmu_aux);


typedef struct {
	iorpc_interrupt_t interrupt;
	unsigned int mac;
	unsigned int intx;
} config_legacy_intr_param_t;

int gxio_trio_config_legacy_intr(gxio_trio_context_t * context, int inter_x,
				 int inter_y, int inter_ipi, int inter_event,
				 unsigned int mac, unsigned int intx)
{
	uint64_t __offset;
	int __result;
	config_legacy_intr_param_t temp;
	config_legacy_intr_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->interrupt.kernel.x = inter_x;
	params->interrupt.kernel.y = inter_y;
	params->interrupt.kernel.ipi = inter_ipi;
	params->interrupt.kernel.event = inter_event;
	params->mac = mac;
	params->intx = intx;

	__offset = GXIO_TRIO_OP_CONFIG_LEGACY_INTR;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_config_legacy_intr);

typedef struct {
	iorpc_interrupt_t interrupt;
	unsigned int mac;
	unsigned int mem_map;
	uint64_t mem_map_base;
	uint64_t mem_map_limit;
	unsigned int asid;
} config_msi_intr_param_t;

int gxio_trio_config_msi_intr(gxio_trio_context_t * context, int inter_x,
			      int inter_y, int inter_ipi, int inter_event,
			      unsigned int mac, unsigned int mem_map,
			      uint64_t mem_map_base, uint64_t mem_map_limit,
			      unsigned int asid)
{
	uint64_t __offset;
	int __result;
	config_msi_intr_param_t temp;
	config_msi_intr_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->interrupt.kernel.x = inter_x;
	params->interrupt.kernel.y = inter_y;
	params->interrupt.kernel.ipi = inter_ipi;
	params->interrupt.kernel.event = inter_event;
	params->mac = mac;
	params->mem_map = mem_map;
	params->mem_map_base = mem_map_base;
	params->mem_map_limit = mem_map_limit;
	params->asid = asid;

	__offset = GXIO_TRIO_OP_CONFIG_MSI_INTR;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_config_msi_intr);


typedef struct {
	uint16_t mps;
	uint16_t mrs;
	unsigned int mac;
} set_mps_mrs_param_t;

int gxio_trio_set_mps_mrs(gxio_trio_context_t * context, uint16_t mps,
			  uint16_t mrs, unsigned int mac)
{
	uint64_t __offset;
	int __result;
	set_mps_mrs_param_t temp;
	set_mps_mrs_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->mps = mps;
	params->mrs = mrs;
	params->mac = mac;

	__offset = GXIO_TRIO_OP_SET_MPS_MRS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_set_mps_mrs);

typedef struct {
	unsigned int mac;
} force_link_up_param_t;

int gxio_trio_force_link_up(gxio_trio_context_t * context, unsigned int mac)
{
	uint64_t __offset;
	int __result;
	force_link_up_param_t temp;
	force_link_up_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->mac = mac;

	__offset = GXIO_TRIO_OP_FORCE_LINK_UP;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_force_link_up);

typedef struct {
	HV_PTE base;
} get_mmio_base_param_t;

int gxio_trio_get_mmio_base(gxio_trio_context_t * context, HV_PTE *base)
{
	uint64_t __offset;
	int __result;
	get_mmio_base_param_t temp;
	get_mmio_base_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__offset = GXIO_TRIO_OP_GET_MMIO_BASE;
	__result =
	    hv_dev_pread(context->fd, 0, (HV_VirtAddr) params, __size,
			 __offset);
	*base = params->base;

	return __result;
}

EXPORT_SYMBOL(gxio_trio_get_mmio_base);

typedef struct {
	unsigned long offset;
	unsigned long size;
} check_mmio_offset_param_t;

int gxio_trio_check_mmio_offset(gxio_trio_context_t * context,
				unsigned long offset, unsigned long size)
{
	uint64_t __offset;
	int __result;
	check_mmio_offset_param_t temp;
	check_mmio_offset_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->offset = offset;
	params->size = size;

	__offset = GXIO_TRIO_OP_CHECK_MMIO_OFFSET;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_trio_check_mmio_offset);
