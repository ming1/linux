/*
 * ASoC SA11x0 SSP DAI driver
 *
 * Copyright (C) 2012 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The SA11x0 SSP interface gives us four signals: TXD, RXD, SFRM and SCLK,
 * and SFRM pulses for each and every word transmitted.  These signals can
 * be routed to GPIO10(TXD), GPIO11(RXD), GPIO12(SCLK), and GPIO13(SFRM)
 * when the PPAR_SPR bit it set, along with the appropriate GAFR and GPDR
 * configuration.  If PPAR_SPR is clear, the SSP shares the same pins with
 * the MCP.
 */
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/sa11x0-dma.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc-dmaengine.h>
#include <sound/soc.h>

#include "sa11x0-ssp.h"

#define SA11X0_SSP_CHANNELS_MIN	1
#define SA11X0_SSP_CHANNELS_MAX	8

/*
 * This isn't really up to us - it depends how the board implements the
 * clocking, whether the board uses the on-board clock source, or whether
 * the SSP is clocked via GPIO19.
 */
#define SA11X0_SSP_RATES \
	(SNDRV_PCM_RATE_8000_48000 | SNDRV_PCM_RATE_CONTINUOUS)
#define SA11X0_SSP_FORMATS \
	(SNDRV_PCM_FORMAT_S8		| SNDRV_PCM_FORMAT_U8		| \
	 SNDRV_PCM_FORMAT_S16_LE	| SNDRV_PCM_FORMAT_U16_LE)

#define SSCR0		0x60
#define SSCR0_DSS	(15 << 0)	/* s */
#define SSCR0_FRF_MOT	(0 << 4)
#define SSCR0_FRF_TI	(1 << 4)
#define SSCR0_FRF_NAT	(2 << 4)
#define SSCR0_SSE	(1 << 7)	/* s */
#define SSCR0_SCR	(0xff << 8)	/* s */
#define SSCR1		0x64
#define SSCR1_RIE	(1 << 0)
#define SSCR1_TIE	(1 << 1)
#define SSCR1_LBM	(1 << 2)
#define SSCR1_SPO	(1 << 3)
#define SSCR1_SP	(1 << 4)
#define SSCR1_ECS	(1 << 5)	/* s */
#define SSDR		0x6c
#define SSSR		0x74

struct ssp_priv {
	struct resource *res;
	void __iomem *base;
	u32 cr0;
	u32 cr1;
};

static struct soc_dma_config sa11x0_tx_cfg = {
	.filter = sa11x0_dma_filter_fn,
	.data = "Ser4SSPTr",
	.reg = 0x80070000 + SSDR,
	.width = DMA_SLAVE_BUSWIDTH_2_BYTES,
	.maxburst = 4,
	.align = 32,
	.fifo_size = 2 * 8,
};

static struct soc_dma_config sa11x0_rx_cfg = {
	.filter = sa11x0_dma_filter_fn,
	.data = "Ser4SSPRc",
	.reg = 0x80070000 + SSDR,
	.width = DMA_SLAVE_BUSWIDTH_2_BYTES,
	.maxburst = 4,
	.align = 32,
	.fifo_size = 2 * 12,
};

static int sa11x0_ssp_startup(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	if (!dai->active) {
		struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

		writel_relaxed(ssp->cr0, ssp->base + SSCR0);
		writel_relaxed(ssp->cr1, ssp->base + SSCR1);
		ssp->cr0 |= SSCR0_SSE;
		writel_relaxed(ssp->cr0, ssp->base + SSCR0);
	}

	return 0;
}

static void sa11x0_ssp_shutdown(struct snd_pcm_substream *substream,
	struct snd_soc_dai *dai)
{
	if (!dai->active) {
		struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

		ssp->cr0 &= ~SSCR0_SSE;
		writel_relaxed(ssp->cr0, ssp->base + SSCR0);
	}
}

static int sa11x0_ssp_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params, struct snd_soc_dai *dai)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);
	snd_pcm_format_t fmt = params_format(params);
	int width = snd_pcm_format_width(fmt);
	u32 cr0;

	if (width < 0)
		return width;
	if (width < 4 || width > 16)
		return -EINVAL;

	/* Set the bit-width for the format */
	cr0 = (ssp->cr0 & ~SSCR0_DSS) | (width - 1);
	if (cr0 != ssp->cr0) {
		ssp->cr0 = cr0;
		writel_relaxed(cr0, ssp->base + SSCR0);
	}

	return 0;
}

static int sa11x0_ssp_set_sysclk(struct snd_soc_dai *dai, int clk_id,
	unsigned int freq, int dir)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

	switch (clk_id) {
	case SA11X0_SSP_CLK_INT:
		ssp->cr1 &= ~SSCR1_ECS;
		break;

	case SA11X0_SSP_CLK_EXT:
		ssp->cr1 |= SSCR1_ECS;
		break;

	default:
		return -EINVAL;
	}
	writel_relaxed(ssp->cr1, ssp->base + SSCR1);

	return 0;
}

static int sa11x0_ssp_set_clkdiv(struct snd_soc_dai *dai, int div_id, int div)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);
	u32 cr0;

	if (div_id != SA11X0_SSP_DIV_SCR)
		return -EINVAL;

	cr0 = (ssp->cr0 & ~SSCR0_SCR) | ((div - 2) / 2) << 8;
	if (cr0 != ssp->cr0) {
		ssp->cr0 = cr0;
		writel_relaxed(cr0, ssp->base + SSCR0);
	}

	return 0;
}

static int sa11x0_ssp_set_fmt(struct snd_soc_dai *dai, unsigned int fmt)
{
	/* We generate the clock and frm signals */
	if ((fmt & SND_SOC_DAIFMT_MASTER_MASK) != SND_SOC_DAIFMT_CBS_CFS)
		return -EINVAL;

	return 0;
}

static struct snd_soc_dai_ops sa11x0_ssp_ops = {
	.startup = sa11x0_ssp_startup,
	.shutdown = sa11x0_ssp_shutdown,
	.hw_params = sa11x0_ssp_hw_params,
	.set_sysclk = sa11x0_ssp_set_sysclk,
	.set_clkdiv = sa11x0_ssp_set_clkdiv,
	.set_fmt = sa11x0_ssp_set_fmt,
};

static int sa11x0_ssp_probe(struct snd_soc_dai *dai)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

	/* Default to TI mode and a bit-width of 16 */
	ssp->cr0 = SSCR0_FRF_TI | 15;

	/*
	 * Set the DMA data now - it's needed for the dmaengine backend to
	 * obtain its DMA channel, in turn its struct device, and therefore
	 * a struct device to allocate DMA memory against.
	 */
	dai->playback_dma_data = &sa11x0_tx_cfg;
	dai->capture_dma_data = &sa11x0_rx_cfg;

	return 0;
}

static int sa11x0_ssp_remove(struct snd_soc_dai *dai)
{
	return 0;
}

#ifdef CONFIG_PM
static int sa11x0_ssp_suspend(struct snd_soc_dai *dai)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

	writel_relaxed(ssp->cr0 & ~SSCR0_SSE, ssp->base + SSCR0);

	return 0;
}

static int sa11x0_ssp_resume(struct snd_soc_dai *dai)
{
	struct ssp_priv *ssp = snd_soc_dai_get_drvdata(dai);

	writel_relaxed(ssp->cr0 & ~SSCR0_SSE, ssp->base + SSCR0);
	writel_relaxed(ssp->cr1, ssp->base + SSCR1);
	if (ssp->cr0 & SSCR0_SSE)
		writel_relaxed(ssp->cr0, ssp->base + SSCR0);

	return 0;
}
#else
#define sa11x0_ssp_suspend NULL
#define sa11x0_ssp_resume NULL
#endif

static struct snd_soc_dai_driver sa11x0_ssp_driver = {
	.probe = sa11x0_ssp_probe,
	.remove = sa11x0_ssp_remove,
	.suspend = sa11x0_ssp_suspend,
	.resume = sa11x0_ssp_resume,
	.ops = &sa11x0_ssp_ops,
	.capture = {
		.channels_min = SA11X0_SSP_CHANNELS_MIN,
		.channels_max = SA11X0_SSP_CHANNELS_MAX,
		.rates = SA11X0_SSP_RATES,
		.formats = SA11X0_SSP_FORMATS,
	},
	.playback = {
		.channels_min = SA11X0_SSP_CHANNELS_MIN,
		.channels_max = SA11X0_SSP_CHANNELS_MAX,
		.rates = SA11X0_SSP_RATES,
		.formats = SA11X0_SSP_FORMATS,
	},
	.symmetric_rates = 1,
};

static int __devinit sa11x0_ssp_plat_probe(struct platform_device *pdev)
{
	struct ssp_priv *ssp;
	struct resource *res;
	int ret;

	ssp = kzalloc(sizeof(*ssp), GFP_KERNEL);
	if (!ssp) {
		ret = -ENOMEM;
		goto err;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		ret = -EINVAL;
		goto err;
	}

	if (!request_mem_region(res->start, resource_size(res),
				dev_name(&pdev->dev))) {
		ret = -EBUSY;
		goto err;
	}

	ssp->res = res;
	ssp->base = ioremap(res->start, resource_size(res));
	if (!ssp->base) {
		ret = -ENOMEM;
		goto err;
	}

	writel_relaxed(ssp->cr0, ssp->base + SSCR0);
	writel_relaxed(ssp->cr1, ssp->base + SSCR1);

	platform_set_drvdata(pdev, ssp);
	ret = snd_soc_register_dai(&pdev->dev, &sa11x0_ssp_driver);
	if (ret)
		goto err;

	return 0;

 err:
	platform_set_drvdata(pdev, NULL);
	if (ssp && ssp->base)
		iounmap(ssp->base);
	if (ssp && ssp->res)
		release_mem_region(ssp->res->start, resource_size(ssp->res));
	kfree(ssp);
	return ret;
}

static int __devexit sa11x0_ssp_plat_remove(struct platform_device *pdev)
{
	struct ssp_priv *ssp = platform_get_drvdata(pdev);

	snd_soc_unregister_dai(&pdev->dev);

	platform_set_drvdata(pdev, NULL);
	iounmap(ssp->base);
	release_mem_region(ssp->res->start, resource_size(ssp->res));
	kfree(ssp);

	return 0;
}

static struct platform_driver sa11x0_ssp_plat_driver = {
	.driver = {
		.name = "sa11x0-ssp",
		.owner = THIS_MODULE,
	},
	.probe = sa11x0_ssp_plat_probe,
	.remove = __devexit_p(sa11x0_ssp_plat_remove),
};
module_platform_driver(sa11x0_ssp_plat_driver);

MODULE_AUTHOR("Russell King <linux@arm.linux.org.uk>");
MODULE_DESCRIPTION("SA11x0 SSP/PCM SoC Interface");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:sa11x0-ssp");
