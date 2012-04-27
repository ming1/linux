/*
 * Copyright 2012 Tilera Corporation. All Rights Reserved.
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

#ifndef _GXIO_DMA_QUEUE_H_
#define _GXIO_DMA_QUEUE_H_

/*
 * DMA queue management APIs shared between TRIO and mPIPE.
 */

#include "common.h"

/* State object that tracks a DMA queue's head and tail indices, as
    well as the number of commands posted and completed.  The
    structure is accessed via a thread-safe, lock-free algorithm. */
typedef struct {
  /* Address of a MPIPE_EDMA_POST_REGION_VAL_t,
      TRIO_PUSH_DMA_REGION_VAL_t, or TRIO_PULL_DMA_REGION_VAL_t
      register.  These register have identical encodings and provide
      information about how many commands have been processed. */
	void *post_region_addr;

  /* A lazily-updated count of how many commands the hardware has
      completed. */
	uint64_t hw_complete_count __attribute__ ((aligned(64)));

  /* High 32 bits are a count of available egress command credits,
      low 32 bits are the next command index. */
	int64_t credits_and_next_index;
} __gxio_dma_queue_t;

/* Initialize a dma queue. */
void __gxio_dma_queue_init(__gxio_dma_queue_t *dma_queue,
			   void *post_region_addr, unsigned int num_entries);

/* Try to reserve credits, potentially blocking. */
int64_t __gxio_dma_queue_reserve_aux(__gxio_dma_queue_t *dma_queue,
				     unsigned int num, int wait);

/* Wait for credits to become available. */
int64_t __gxio_dma_queue_wait_for_credits(__gxio_dma_queue_t *dma_queue,
					  int64_t modifier);

/* Check whether a particular slot has completed. */
int __gxio_dma_queue_is_complete(__gxio_dma_queue_t *dma_queue, int64_t slot,
				 int update);

#endif /* !_GXIO_DMA_QUEUE_H_ */
