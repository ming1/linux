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
#include "gxio/iorpc_mpipe_info.h"


typedef struct {
	_gxio_mpipe_link_name_t name;
	_gxio_mpipe_link_mac_t mac;
} enumerate_aux_param_t;

int gxio_mpipe_info_enumerate_aux(gxio_mpipe_info_context_t * context,
				  unsigned int idx,
				  _gxio_mpipe_link_name_t * name,
				  _gxio_mpipe_link_mac_t * mac)
{
	uint64_t __offset;
	int __result;
	enumerate_aux_param_t temp;
	enumerate_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__offset = (((uint64_t) idx << 32) | GXIO_MPIPE_INFO_OP_ENUMERATE_AUX);
	__result =
	    hv_dev_pread(context->fd, 0, (HV_VirtAddr) params, __size,
			 __offset);
	*name = params->name;
	*mac = params->mac;

	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_info_enumerate_aux);

typedef struct {
	HV_PTE base;
} get_mmio_base_param_t;

int gxio_mpipe_info_get_mmio_base(gxio_mpipe_info_context_t * context,
				  HV_PTE *base)
{
	uint64_t __offset;
	int __result;
	get_mmio_base_param_t temp;
	get_mmio_base_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__offset = GXIO_MPIPE_INFO_OP_GET_MMIO_BASE;
	__result =
	    hv_dev_pread(context->fd, 0, (HV_VirtAddr) params, __size,
			 __offset);
	*base = params->base;

	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_info_get_mmio_base);

typedef struct {
	unsigned long offset;
	unsigned long size;
} check_mmio_offset_param_t;

int gxio_mpipe_info_check_mmio_offset(gxio_mpipe_info_context_t * context,
				      unsigned long offset, unsigned long size)
{
	uint64_t __offset;
	int __result;
	check_mmio_offset_param_t temp;
	check_mmio_offset_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->offset = offset;
	params->size = size;

	__offset = GXIO_MPIPE_INFO_OP_CHECK_MMIO_OFFSET;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_info_check_mmio_offset);
