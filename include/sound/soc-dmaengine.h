/*
 * Generic ASoC DMA engine backend
 *
 * Copyright (C) 2012 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef _LINUX_SND_SOC_DMAENGINE_H
#define _LINUX_SND_SOC_DMAENGINE_H

#include <linux/dmaengine.h>

struct soc_dma_config {
	dma_filter_fn filter;
	void *data;

	dma_addr_t reg;
	enum dma_slave_buswidth width;
	u32 maxburst;
	size_t align;
	size_t fifo_size;
};

#endif
