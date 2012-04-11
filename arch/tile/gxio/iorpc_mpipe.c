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
#include "gxio/iorpc_mpipe.h"

typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_buffer_stacks_param_t;

int gxio_mpipe_alloc_buffer_stacks(gxio_mpipe_context_t * context,
				   unsigned int count, unsigned int first,
				   unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_buffer_stacks_param_t temp;
	alloc_buffer_stacks_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_ALLOC_BUFFER_STACKS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_alloc_buffer_stacks);

typedef struct {
	iorpc_mem_buffer_t buffer;
	unsigned int stack;
	unsigned int buffer_size_enum;
} init_buffer_stack_aux_param_t;

int gxio_mpipe_init_buffer_stack_aux(gxio_mpipe_context_t * context,
				     void *mem_va, size_t mem_size,
				     unsigned int mem_flags, unsigned int stack,
				     unsigned int buffer_size_enum)
{
	uint64_t __offset;
	int __result;
	unsigned long long __cpa;
	pte_t __pte;
	init_buffer_stack_aux_param_t temp;
	init_buffer_stack_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__result = va_to_cpa_and_pte(mem_va, &__cpa, &__pte);
	if (__result != 0)
		return __result;
	params->buffer.kernel.cpa = __cpa;
	params->buffer.kernel.size = mem_size;
	params->buffer.kernel.pte = __pte;
	params->buffer.kernel.flags = mem_flags;
	params->stack = stack;
	params->buffer_size_enum = buffer_size_enum;

	__offset = GXIO_MPIPE_OP_INIT_BUFFER_STACK_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_init_buffer_stack_aux);


typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_notif_rings_param_t;

int gxio_mpipe_alloc_notif_rings(gxio_mpipe_context_t * context,
				 unsigned int count, unsigned int first,
				 unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_notif_rings_param_t temp;
	alloc_notif_rings_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_ALLOC_NOTIF_RINGS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_alloc_notif_rings);

typedef struct {
	iorpc_mem_buffer_t buffer;
	unsigned int ring;
} init_notif_ring_aux_param_t;

int gxio_mpipe_init_notif_ring_aux(gxio_mpipe_context_t * context, void *mem_va,
				   size_t mem_size, unsigned int mem_flags,
				   unsigned int ring)
{
	uint64_t __offset;
	int __result;
	unsigned long long __cpa;
	pte_t __pte;
	init_notif_ring_aux_param_t temp;
	init_notif_ring_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__result = va_to_cpa_and_pte(mem_va, &__cpa, &__pte);
	if (__result != 0)
		return __result;
	params->buffer.kernel.cpa = __cpa;
	params->buffer.kernel.size = mem_size;
	params->buffer.kernel.pte = __pte;
	params->buffer.kernel.flags = mem_flags;
	params->ring = ring;

	__offset = GXIO_MPIPE_OP_INIT_NOTIF_RING_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_init_notif_ring_aux);

typedef struct {
	iorpc_interrupt_t interrupt;
	unsigned int ring;
} request_notif_ring_interrupt_param_t;

int gxio_mpipe_request_notif_ring_interrupt(gxio_mpipe_context_t * context,
					    int inter_x, int inter_y,
					    int inter_ipi, int inter_event,
					    unsigned int ring)
{
	uint64_t __offset;
	int __result;
	request_notif_ring_interrupt_param_t temp;
	request_notif_ring_interrupt_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->interrupt.kernel.x = inter_x;
	params->interrupt.kernel.y = inter_y;
	params->interrupt.kernel.ipi = inter_ipi;
	params->interrupt.kernel.event = inter_event;
	params->ring = ring;

	__offset = GXIO_MPIPE_OP_REQUEST_NOTIF_RING_INTERRUPT;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_request_notif_ring_interrupt);

typedef struct {
	unsigned int ring;
} enable_notif_ring_interrupt_param_t;

int gxio_mpipe_enable_notif_ring_interrupt(gxio_mpipe_context_t * context,
					   unsigned int ring)
{
	uint64_t __offset;
	int __result;
	enable_notif_ring_interrupt_param_t temp;
	enable_notif_ring_interrupt_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->ring = ring;

	__offset = GXIO_MPIPE_OP_ENABLE_NOTIF_RING_INTERRUPT;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_enable_notif_ring_interrupt);

typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_notif_groups_param_t;

int gxio_mpipe_alloc_notif_groups(gxio_mpipe_context_t * context,
				  unsigned int count, unsigned int first,
				  unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_notif_groups_param_t temp;
	alloc_notif_groups_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_ALLOC_NOTIF_GROUPS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_alloc_notif_groups);

typedef struct {
	unsigned int group;
	gxio_mpipe_notif_group_bits_t bits;
} init_notif_group_param_t;

int gxio_mpipe_init_notif_group(gxio_mpipe_context_t * context,
				unsigned int group,
				gxio_mpipe_notif_group_bits_t bits)
{
	uint64_t __offset;
	int __result;
	init_notif_group_param_t temp;
	init_notif_group_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->group = group;
	params->bits = bits;

	__offset = GXIO_MPIPE_OP_INIT_NOTIF_GROUP;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_init_notif_group);

typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_buckets_param_t;

int gxio_mpipe_alloc_buckets(gxio_mpipe_context_t * context, unsigned int count,
			     unsigned int first, unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_buckets_param_t temp;
	alloc_buckets_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_ALLOC_BUCKETS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_alloc_buckets);

typedef struct {
	unsigned int bucket;
	MPIPE_LBL_INIT_DAT_BSTS_TBL_t bucket_info;
} init_bucket_param_t;

int gxio_mpipe_init_bucket(gxio_mpipe_context_t * context, unsigned int bucket,
			   MPIPE_LBL_INIT_DAT_BSTS_TBL_t bucket_info)
{
	uint64_t __offset;
	int __result;
	init_bucket_param_t temp;
	init_bucket_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->bucket = bucket;
	params->bucket_info = bucket_info;

	__offset = GXIO_MPIPE_OP_INIT_BUCKET;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_init_bucket);

typedef struct {
	unsigned int count;
	unsigned int first;
	unsigned int flags;
} alloc_edma_rings_param_t;

int gxio_mpipe_alloc_edma_rings(gxio_mpipe_context_t * context,
				unsigned int count, unsigned int first,
				unsigned int flags)
{
	uint64_t __offset;
	int __result;
	alloc_edma_rings_param_t temp;
	alloc_edma_rings_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->count = count;
	params->first = first;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_ALLOC_EDMA_RINGS;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_alloc_edma_rings);

typedef struct {
	iorpc_mem_buffer_t buffer;
	unsigned int ring;
	unsigned int channel;
} init_edma_ring_aux_param_t;

int gxio_mpipe_init_edma_ring_aux(gxio_mpipe_context_t * context, void *mem_va,
				  size_t mem_size, unsigned int mem_flags,
				  unsigned int ring, unsigned int channel)
{
	uint64_t __offset;
	int __result;
	unsigned long long __cpa;
	pte_t __pte;
	init_edma_ring_aux_param_t temp;
	init_edma_ring_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__result = va_to_cpa_and_pte(mem_va, &__cpa, &__pte);
	if (__result != 0)
		return __result;
	params->buffer.kernel.cpa = __cpa;
	params->buffer.kernel.size = mem_size;
	params->buffer.kernel.pte = __pte;
	params->buffer.kernel.flags = mem_flags;
	params->ring = ring;
	params->channel = channel;

	__offset = GXIO_MPIPE_OP_INIT_EDMA_RING_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_init_edma_ring_aux);


int gxio_mpipe_commit_rules(gxio_mpipe_context_t * context, const void *blob,
			    size_t blob_size)
{
	uint64_t __offset;
	int __result;
	size_t __size = blob_size;
	const void *params = blob;

	__offset = GXIO_MPIPE_OP_COMMIT_RULES;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_commit_rules);

typedef struct {
	unsigned int iotlb;
	HV_PTE pte;
	unsigned int flags;
} register_client_memory_param_t;

int gxio_mpipe_register_client_memory(gxio_mpipe_context_t * context,
				      unsigned int iotlb, HV_PTE pte,
				      unsigned int flags)
{
	uint64_t __offset;
	int __result;
	register_client_memory_param_t temp;
	register_client_memory_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->iotlb = iotlb;
	params->pte = pte;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_REGISTER_CLIENT_MEMORY;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_register_client_memory);

typedef struct {
	_gxio_mpipe_link_name_t name;
	unsigned int flags;
} link_open_aux_param_t;

int gxio_mpipe_link_open_aux(gxio_mpipe_context_t * context,
			     _gxio_mpipe_link_name_t name, unsigned int flags)
{
	uint64_t __offset;
	int __result;
	link_open_aux_param_t temp;
	link_open_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->name = name;
	params->flags = flags;

	__offset = GXIO_MPIPE_OP_LINK_OPEN_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_link_open_aux);

typedef struct {
	int mac;
} link_close_aux_param_t;

int gxio_mpipe_link_close_aux(gxio_mpipe_context_t * context, int mac)
{
	uint64_t __offset;
	int __result;
	link_close_aux_param_t temp;
	link_close_aux_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->mac = mac;

	__offset = GXIO_MPIPE_OP_LINK_CLOSE_AUX;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_link_close_aux);


typedef struct {
	iorpc_pollfd_t pollfd;
} arm_pollfd_param_t;

int gxio_mpipe_arm_pollfd(gxio_mpipe_context_t * context, int pollfd_cookie)
{
	uint64_t __offset;
	int __result;
	arm_pollfd_param_t temp;
	arm_pollfd_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->pollfd.kernel.cookie = pollfd_cookie;

	__offset = GXIO_MPIPE_OP_ARM_POLLFD;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_arm_pollfd);

typedef struct {
	iorpc_pollfd_t pollfd;
} close_pollfd_param_t;

int gxio_mpipe_close_pollfd(gxio_mpipe_context_t * context, int pollfd_cookie)
{
	uint64_t __offset;
	int __result;
	close_pollfd_param_t temp;
	close_pollfd_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->pollfd.kernel.cookie = pollfd_cookie;

	__offset = GXIO_MPIPE_OP_CLOSE_POLLFD;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_close_pollfd);

typedef struct {
	HV_PTE base;
} get_mmio_base_param_t;

int gxio_mpipe_get_mmio_base(gxio_mpipe_context_t * context, HV_PTE *base)
{
	uint64_t __offset;
	int __result;
	get_mmio_base_param_t temp;
	get_mmio_base_param_t *params = &temp;
	size_t __size = sizeof(*params);

	__offset = GXIO_MPIPE_OP_GET_MMIO_BASE;
	__result =
	    hv_dev_pread(context->fd, 0, (HV_VirtAddr) params, __size,
			 __offset);
	*base = params->base;

	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_get_mmio_base);

typedef struct {
	unsigned long offset;
	unsigned long size;
} check_mmio_offset_param_t;

int gxio_mpipe_check_mmio_offset(gxio_mpipe_context_t * context,
				 unsigned long offset, unsigned long size)
{
	uint64_t __offset;
	int __result;
	check_mmio_offset_param_t temp;
	check_mmio_offset_param_t *params = &temp;
	size_t __size = sizeof(*params);

	params->offset = offset;
	params->size = size;

	__offset = GXIO_MPIPE_OP_CHECK_MMIO_OFFSET;
	__result =
	    hv_dev_pwrite(context->fd, 0, (HV_VirtAddr) params, __size,
			  __offset);
	return __result;
}

EXPORT_SYMBOL(gxio_mpipe_check_mmio_offset);
