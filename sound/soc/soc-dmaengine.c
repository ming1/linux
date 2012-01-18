/*
 * Generic ASoC DMA engine backend
 *
 * Copyright (C) 2012 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * We expect the DMA engine to give accurate residue information,
 * returning the number of bytes left to complete to the requested
 * cookie.  We also expect the DMA engine to be able to resume
 * submitted descriptors after a suspend/resume cycle.
 */
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <sound/core.h>
#include <sound/soc-dmaengine.h>
#include <sound/soc.h>
#include <sound/pcm_params.h>

#define BUFFER_SIZE_MAX		65536
#define PERIOD_SIZE_MIN		32
#define PERIOD_SIZE_MAX		16384
#define PERIODS_MIN		2
#define PERIODS_MAX		256

struct buf_info {
	struct scatterlist sg;
	dma_cookie_t cookie;
};

struct soc_dma_chan {
	const struct soc_dma_config *conf;
	spinlock_t lock;
	struct dma_chan *chan;
	struct dma_slave_config cfg;
	enum dma_transfer_direction dir;
	unsigned nr_periods;
	unsigned sg_index;
	unsigned stopped;
	struct buf_info buf[PERIODS_MAX];
};

struct soc_dma_info {
	struct soc_dma_chan *chan[2];
};

static const struct snd_pcm_hardware soc_dmaengine_hardware = {
	.info			= SNDRV_PCM_INFO_MMAP |
				  SNDRV_PCM_INFO_MMAP_VALID |
				  SNDRV_PCM_INFO_INTERLEAVED |
				  SNDRV_PCM_INFO_PAUSE |
				  SNDRV_PCM_INFO_RESUME,
	.period_bytes_min	= PERIOD_SIZE_MIN,
	.period_bytes_max	= PERIOD_SIZE_MAX,
	.periods_min		= PERIODS_MIN,
	.periods_max		= PERIODS_MAX,
	.buffer_bytes_max	= BUFFER_SIZE_MAX,
};

static int soc_dmaengine_submit(struct snd_pcm_substream *substream,
	struct soc_dma_chan *dma);

static void soc_dmaengine_callback(void *data)
{
	struct snd_pcm_substream *substream = data;
	struct soc_dma_chan *dma = substream->runtime->private_data;
	int ret;

	snd_pcm_period_elapsed(substream);

	if (!dma->stopped) {
		spin_lock(&dma->lock);
		ret = soc_dmaengine_submit(substream, dma);
		spin_unlock(&dma->lock);

		if (ret == 0)
			dma_async_issue_pending(dma->chan);
		else
			pr_err("%s: failed to submit next DMA buffer\n", __func__);
	}
}

static int soc_dmaengine_submit(struct snd_pcm_substream *substream,
	struct soc_dma_chan *dma)
{
	struct dma_async_tx_descriptor *tx;
	struct dma_chan *ch = dma->chan;
	struct buf_info *buf;
	unsigned sg_index;

	sg_index = dma->sg_index;

	buf = &dma->buf[sg_index];

	tx = ch->device->device_prep_slave_sg(ch, &buf->sg, 1,
		dma->dir, DMA_PREP_INTERRUPT | DMA_CTRL_ACK);
	if (tx) {
		tx->callback = soc_dmaengine_callback;
		tx->callback_param = substream;

		buf->cookie = dmaengine_submit(tx);

		sg_index++;
		if (sg_index >= dma->nr_periods)
			sg_index = 0;
		dma->sg_index = sg_index;
	}

	return tx ? 0 : -ENOMEM;
}

static int soc_dmaengine_start(struct snd_pcm_substream *substream)
{
	struct soc_dma_chan *dma = substream->runtime->private_data;
	unsigned long flags;
	unsigned i;
	int ret = 0;

	spin_lock_irqsave(&dma->lock, flags);
	for (i = 0; i < dma->nr_periods; i++) {
		ret = soc_dmaengine_submit(substream, dma);
		if (ret)
			break;
	}
	spin_unlock_irqrestore(&dma->lock, flags);
	if (ret == 0) {
		dma->stopped = 0;
		dma_async_issue_pending(dma->chan);
	} else {
		dma->stopped = 1;
		dmaengine_terminate_all(dma->chan);
	}

	return ret;
}

static int soc_dmaengine_stop(struct snd_pcm_substream *substream)
{
	struct soc_dma_chan *dma = substream->runtime->private_data;

	dma->stopped = 1;
	dmaengine_terminate_all(dma->chan);

	return 0;
}

static int soc_dmaengine_open(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct soc_dma_info *info = snd_soc_platform_get_drvdata(rtd->platform);
	struct soc_dma_chan *dma;
	int ret = 0;

	dma = info->chan[substream->stream];
	if (!dma)
		return -EINVAL;

	runtime->hw = soc_dmaengine_hardware;
	runtime->hw.fifo_size = dma->conf->fifo_size;

	if (dma->conf->align) {
		/*
		 * FIXME: Ideally, there should be some way to query
		 * this from the DMA engine itself.
		 *
		 * It would also be helpful to know the maximum size
		 * a scatterlist entry can be to set the period size.
		 */
		ret = snd_pcm_hw_constraint_step(runtime, 0,
			SNDRV_PCM_HW_PARAM_PERIOD_BYTES, dma->conf->align);
		if (ret)
			goto err;

		ret = snd_pcm_hw_constraint_step(runtime, 0,
			SNDRV_PCM_HW_PARAM_BUFFER_BYTES, dma->conf->align);
		if (ret)
			goto err;
	}

	runtime->private_data = dma;

 err:
	return ret;
}

static int soc_dmaengine_close(struct snd_pcm_substream *substream)
{
	return 0;
}

static int soc_dmaengine_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params)
{
	int ret = snd_pcm_lib_malloc_pages(substream,
			params_buffer_bytes(params));

	return ret < 0 ? ret : 0;
}

static int soc_dmaengine_prepare(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct soc_dma_chan *dma = runtime->private_data;
	size_t buf_size = snd_pcm_lib_buffer_bytes(substream);
	size_t period = snd_pcm_lib_period_bytes(substream);
	dma_addr_t addr = runtime->dma_addr;
	unsigned i;

	/* Create an array of sg entries, one for each period */
	for (i = 0; i < PERIODS_MAX && buf_size; i++) {
		BUG_ON(buf_size < period);

		sg_dma_address(&dma->buf[i].sg) = addr;
		sg_dma_len(&dma->buf[i].sg) = period;

		addr += period;
		buf_size -= period;
	}

	if (buf_size) {
		pr_err("DMA buffer size not a multiple of the period size: residue=%zu\n", buf_size);
		return -EINVAL;
	}

	dma->nr_periods = i;
	dma->sg_index = 0;

	return 0;
}

static int soc_dmaengine_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct soc_dma_chan *dma = runtime->private_data;
	int ret;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		ret = soc_dmaengine_start(substream);
		break;

	case SNDRV_PCM_TRIGGER_STOP:
		ret = soc_dmaengine_stop(substream);
		break;

	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		ret = dmaengine_pause(dma->chan);
		break;

	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		ret = dmaengine_resume(dma->chan);
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static snd_pcm_uframes_t soc_dmaengine_pointer(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct soc_dma_chan *dma = runtime->private_data;
	struct dma_chan *ch = dma->chan;
	struct dma_tx_state state;
	enum dma_status status;
	unsigned index, last, bytes = 0, pos;
	size_t period = snd_pcm_lib_period_bytes(substream);
	unsigned long flags;
	dma_cookie_t cookie;

	/*
	 * Get the next-to-be-submitted index, and the last submitted
	 * cookie value.  We use this to obtain the DMA engine state.
	 */
	spin_lock_irqsave(&dma->lock, flags);
	index = dma->sg_index;
	last = (index == 0 ? dma->nr_periods : index) - 1;
	cookie = dma->buf[last].cookie;
	spin_unlock_irqrestore(&dma->lock, flags);

	/* The end of the current DMA buffer */
	pos = index * period;

	status = ch->device->device_tx_status(ch, cookie, &state);

	/* The last submitted cookie should not have completed. */
	if (status == DMA_IN_PROGRESS) {
		if (state.residue) {
			/*
			 * Good, the DMA engine provides us with the
			 * number of bytes to be transferred until the
			 * requested cookie.  Use this to calculate
			 * where the DMA engine is in the buffer.
			 */
			int off = pos - state.residue;
			if (off < 0)
				off += period * dma->nr_periods;
			bytes = off;
		} else {
			/*
			 * The DMA engine does not provide us with
			 * this information, so we have to work out
			 * which cookie is complete.
			 */
			unsigned i;

			for (i = 0; i < dma->nr_periods; i++) {
				status = dma_async_is_complete(
						dma->buf[i].cookie,
						state.last, state.used);
			}
		}
	}

	pr_debug("%s: index %u last %u residue %04x pos %04x bytes %04x\n",
		__func__, index, last, state.residue, pos, bytes);

	return bytes_to_frames(runtime, bytes);
}

static int soc_dmaengine_mmap(struct snd_pcm_substream *substream,
	struct vm_area_struct *vma)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct snd_dma_buffer *buf = runtime->dma_buffer_p;

	return dma_mmap_writecombine(buf->dev.dev, vma,
		runtime->dma_area, runtime->dma_addr, runtime->dma_bytes);
}

static struct snd_pcm_ops soc_dmaengine_ops = {
	.open = soc_dmaengine_open,
	.close = soc_dmaengine_close,
	.ioctl = snd_pcm_lib_ioctl,
	.hw_params = soc_dmaengine_hw_params,
	.hw_free = snd_pcm_lib_free_pages,
	.prepare = soc_dmaengine_prepare,
	.trigger = soc_dmaengine_trigger,
	.pointer = soc_dmaengine_pointer,
	.mmap = soc_dmaengine_mmap,
};

static struct soc_dma_chan *soc_dmaengine_alloc(void)
{
	struct soc_dma_chan *dma = kzalloc(sizeof(*dma), GFP_KERNEL);
	unsigned i;

	if (dma) {
		spin_lock_init(&dma->lock);
		for (i = 0; i < PERIODS_MAX; i++)
			sg_init_table(&dma->buf[i].sg, 1);
	}
	return dma;
}

static int soc_dmaengine_request(struct soc_dma_chan *dma,
	struct soc_dma_config *cfg, unsigned stream)
{
	dma_cap_mask_t m;
	int ret;

	dma_cap_zero(m);
	dma_cap_set(DMA_SLAVE, m);
	dma->conf = cfg;
	dma->chan = dma_request_channel(m, cfg->filter, cfg->data);
	if (!dma->chan) {
		ret = -ENXIO;
		goto err_dma_req;
	}

	if (stream == SNDRV_PCM_STREAM_PLAYBACK) {
		dma->dir = DMA_MEM_TO_DEV;
		dma->cfg.direction = DMA_MEM_TO_DEV;
		dma->cfg.dst_addr = cfg->reg;
		dma->cfg.dst_addr_width = cfg->width;
		dma->cfg.dst_maxburst = cfg->maxburst;
	} else {
		dma->dir = DMA_DEV_TO_MEM;
		dma->cfg.direction = DMA_DEV_TO_MEM;
		dma->cfg.src_addr = cfg->reg;
		dma->cfg.src_addr_width = cfg->width;
		dma->cfg.src_maxburst = cfg->maxburst;
	}

	ret = dmaengine_slave_config(dma->chan, &dma->cfg);
	if (ret)
		goto err_dma_cfg;

	return 0;

 err_dma_cfg:
	dma_release_channel(dma->chan);
	dma->chan = NULL;
 err_dma_req:
	return ret;
}

static void soc_dmaengine_release(struct soc_dma_chan *dma)
{
	if (dma && dma->chan)
		dma_release_channel(dma->chan);
	kfree(dma);
}

static int soc_dmaengine_preallocate_buffer(struct snd_pcm *pcm,
	unsigned stream, struct soc_dma_chan *dma)
{
	struct snd_pcm_substream *substream = pcm->streams[stream].substream;
	int ret = 0;

	if (substream) {
		struct snd_dma_buffer *buf = &substream->dma_buffer;

		buf->dev.type = SNDRV_DMA_TYPE_DEV;
		buf->dev.dev = dma->chan->device->dev;
		buf->private_data = NULL;
		buf->area = dma_alloc_writecombine(buf->dev.dev,
				BUFFER_SIZE_MAX, &buf->addr, GFP_KERNEL);
		if (!buf->area)
			return -ENOMEM;

		buf->bytes = BUFFER_SIZE_MAX;
	}
	return ret;
}

static int soc_dmaengine_pcm_new(struct snd_soc_pcm_runtime *rtd)
{
	struct snd_pcm *pcm = rtd->pcm;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct soc_dma_info *info;
	unsigned stream;
	int ret = 0;

	if (!cpu_dai)
		return -EINVAL;

	if (!cpu_dai->playback_dma_data &&
	    !cpu_dai->capture_dma_data) {
		pr_err("soc_dmaengine: %s has no cpu_dai DMA data - incorrect probe ordering?\n",
			rtd->card->name);
		return -EINVAL;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	for (stream = 0; stream < ARRAY_SIZE(pcm->streams); stream++) {
		struct soc_dma_config *cfg = NULL;
		struct soc_dma_chan *dma;

		if (stream == SNDRV_PCM_STREAM_PLAYBACK)
			cfg = cpu_dai->playback_dma_data;
		else if (stream == SNDRV_PCM_STREAM_CAPTURE)
			cfg = cpu_dai->capture_dma_data;

		if (!cfg)
			continue;

		info->chan[stream] = dma = soc_dmaengine_alloc();
		if (!dma) {
			ret = -ENOMEM;
			break;
		}

		ret = soc_dmaengine_request(dma, cfg, stream);
		if (ret)
			return ret;

		ret = soc_dmaengine_preallocate_buffer(pcm, stream, dma);
		if (ret)
			break;
	}

	if (ret) {
		for (stream = 0; stream < ARRAY_SIZE(info->chan); stream++)
			soc_dmaengine_release(info->chan[stream]);
		kfree(info);
	} else {
		snd_soc_platform_set_drvdata(rtd->platform, info);
	}

	return ret;
}

/*
 * Use write-combining memory here: the standard ALSA
 * snd_free_dev_pages() doesn't support this.
 */
static void soc_dmaengine_pcm_free(struct snd_pcm *pcm)
{
	unsigned stream;

	for (stream = 0; stream < ARRAY_SIZE(pcm->streams); stream++) {
		struct snd_pcm_substream *substream = pcm->streams[stream].substream;
		struct snd_dma_buffer *buf;

		if (!substream)
			continue;
		buf = &substream->dma_buffer;
		if (!buf->area)
			continue;

		if (buf->dev.type == SNDRV_DMA_TYPE_DEV)
			dma_free_writecombine(buf->dev.dev, buf->bytes,
					      buf->area, buf->addr);
		else
			snd_dma_free_pages(buf);
		buf->area = NULL;
	}
}

/*
 * This is annoying - we can't have symetry with .pcm_new because .pcm_free
 * is called after the runtime information has been removed.  It would be
 * better if we could find somewhere else to store our soc_dma_info pointer.
 */
static int soc_dmaengine_plat_remove(struct snd_soc_platform *platform)
{
	struct soc_dma_info *info = snd_soc_platform_get_drvdata(platform);
	unsigned stream;

	for (stream = 0; stream < ARRAY_SIZE(info->chan); stream++)
		soc_dmaengine_release(info->chan[stream]);
	kfree(info);

	return 0;
}

static struct snd_soc_platform_driver soc_dmaengine_platform = {
	.remove = soc_dmaengine_plat_remove,
	.pcm_new = soc_dmaengine_pcm_new,
	.pcm_free = soc_dmaengine_pcm_free,
	.ops = &soc_dmaengine_ops,
	/* Wait until the cpu_dai has been probed */
	.probe_order = SND_SOC_COMP_ORDER_LATE,
};

static int __devinit soc_dmaengine_probe(struct platform_device *pdev)
{
	return snd_soc_register_platform(&pdev->dev, &soc_dmaengine_platform);
}

static int __devexit soc_dmaengine_remove(struct platform_device *pdev)
{
	snd_soc_unregister_platform(&pdev->dev);
	return 0;
}

static struct platform_driver soc_dmaengine_driver = {
	.driver = {
		.name = "soc-dmaengine",
		.owner = THIS_MODULE,
	},
	.probe = soc_dmaengine_probe,
	.remove = soc_dmaengine_remove,
};

module_platform_driver(soc_dmaengine_driver);

MODULE_AUTHOR("Russell King");
MODULE_DESCRIPTION("ALSA SoC DMA engine driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:soc-dmaengine");
