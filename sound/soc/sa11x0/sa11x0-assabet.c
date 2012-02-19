/*
 * SA11x0 Assabet ASoC driver
 *
 * Copyright (C) 2012 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The Assabet board uses an unused SDRAM clock output as the source
 * clock for the UDA1341 audio subsystem.  This clock is supplied to
 * via a CPLD divider to the SA11x0 GPIO19 (alternately the SSP block
 * external clock input) and to the UDA1341 as the bit clock.
 *
 * As the SSPs TXD,RXD,SFRM,SCLK outputs are not directly compatible
 * with the UDA1341 input, the CPLD implements logic to provide the
 * WS (LRCK) signal to the UDA1341, and buffer the RXD and clock signals.
 *
 * The UDA1341 is powered by the AUDIO3P3V supply, which can be turned
 * off.  This tristates the CPLD outputs, preventing power draining
 * into the UDA1341.  However, revision 4 Assabets do not tristate the
 * WS signal, and so need to be worked-around to place this at logic 0.
 *
 * A side effect of using the SDRAM clock is that this scales with the
 * core CPU frequency.  Hence, the available sample rate depends on the
 * CPU clock rate.  At present, we have no logic here to restrict the
 * requested sample rate; the UDA1341 driver will just fail the preparation.
 * We rely on userspace (at present) to ask for the correct sample rate.
 */
#include <linux/cpufreq.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/module.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/soc.h>
#include <sound/uda134x.h>

#include <mach/assabet.h>
#include "sa11x0-ssp.h"

#define GPIO_TXD	10
#define GPIO_RXD	11
#define GPIO_SCLK	12
#define GPIO_SFRM	13
#define GPIO_L3_DAT	15
#define GPIO_L3_MODE	17
#define GPIO_L3_SCK	18
#define GPIO_CLK	19

/*
 * The UDA1341 wants a WS (or LRCK), and the Assabet derives this from
 * the SFRM pulses from the SSP.  Unfortunately, some Assabets have a bug
 * in the hardware where the WS output from the CPLD remains high even
 * after the codec is powered down, causing power to drain through the
 * CPLD to the UDA1341.
 *
 * Although the Assabet provides a reset signal to initialize WS to a
 * known state, this presents two problems: (a) this forces the WS output
 * high, (b) this signal also resets the UCB1300 device.
 */
static void assabet_asoc_uda1341_power(int on)
{
	static bool state;

	if (state == !!on)
		return;
	state = !!on;

	if (on) {
		/*
		 * Enable the power for the UDA1341 before fixing WS.
		 * Also assert the mute signal.
		 */
		ASSABET_BCR_set(ASSABET_BCR_AUDIO_ON | ASSABET_BCR_QMUTE);

		/*
		 * Toggle SFRM with the codec reset signal held active.
		 * This will set LRCK high, which results in the left
		 * sample being transmitted first.
		 */
		gpio_set_value(GPIO_SFRM, 1);
		gpio_set_value(GPIO_SFRM, 0);

		/*
		 * If the reset was being held, release it now.  This
		 * ensures that the above SFRM fiddling has no effect
		 * should the reset be raised elsewhere.
		 */
		ASSABET_BCR_set(ASSABET_BCR_CODEC_RST);
	} else {
		/*
		 * The SSP will have transmitted a whole number of 32-bit
		 * words, so we know that LRCK will be left high at this
		 * point.  Toggle SFRM once to kick the LRCK low before
		 * powering down the codec.
		 */
		gpio_set_value(GPIO_SFRM, 1);
		gpio_set_value(GPIO_SFRM, 0);

		/* Finally, disable the audio power */
		ASSABET_BCR_clear(ASSABET_BCR_AUDIO_ON);

		/* And lower the QMUTE signal to stop power draining */
		ASSABET_BCR_clear(ASSABET_BCR_QMUTE);
	}
}

static void assabet_asoc_init_clk(void)
{
	u32 mdrefr, mdrefr_old;

	/*
	 * The assabet board uses the SDRAM clock as the source clock for
	 * audio. This is supplied to the SA11x0 from the CPLD on pin 19.
	 * At 206MHz we need to run the audio clock (SDRAM bank 2) at half
	 * speed.  This clock will scale with core frequency so the audio
	 * sample rate will also scale. The CPLD on Assabet will need to
	 * be programmed to match the core frequency.
	 */
	mdrefr_old = MDREFR;
	mdrefr = mdrefr_old & ~(MDREFR_EAPD | MDREFR_KAPD);
	mdrefr = mdrefr | MDREFR_K2DB2 | MDREFR_K2RUN;
	if (mdrefr != mdrefr_old) {
		MDREFR = mdrefr;
		(void) MDREFR;
	}
}

/*
 * We really ought to only do this when the device is in use, but finding
 * that out from a snd_soc_card is no trivial matter.  The way ASoC is
 * structured, a 'card' can encompass multiple audio subsystems...  It
 * would be nice if ASoC had suspend/resume callbacks in snd_soc_ops, then
 * we'd know.
 */
static int assabet_asoc_resume_pre(struct snd_soc_card *card)
{
	unsigned long flags;

	local_irq_save(flags);
	assabet_asoc_init_clk();
	local_irq_restore(flags);

	return 0;
}

static int assabet_asoc_startup(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;

	if (!cpu_dai->active) {
		unsigned long flags;

		/*
		 * Hand the SFRM signal over to the SSP block as it is
		 * now enabled.  This keeps SFRM low until the interface
		 * starts outputting data.
		 */
		local_irq_save(flags);
		GAFR |= GPIO_SSP_SFRM;

		assabet_asoc_init_clk();
		local_irq_restore(flags);
	}

	/* Enable the audio power amp */
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		ASSABET_BCR_clear(ASSABET_BCR_QMUTE | ASSABET_BCR_SPK_OFF);

	return 0;
}

static void assabet_asoc_shutdown(struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;

	/* Disable the audio power amp */
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		ASSABET_BCR_set(ASSABET_BCR_QMUTE | ASSABET_BCR_SPK_OFF);

	if (!cpu_dai->active) {
		unsigned long flags;

		/*
		 * Take the SFRM pin away from the SSP block before it
		 * shuts down.  We must do this to keep SFRM low.
		 */
		local_irq_save(flags);
		GAFR &= ~GPIO_SSP_SFRM;
		local_irq_restore(flags);
	}
}

static int assabet_asoc_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	unsigned rate = params_rate(params);
	unsigned clk_ref, sysclk, sclk;
	int ret, div;

	clk_ref = cpufreq_get(0) * 1000;

	/*
	 * sysclk is the codecs sysclk signal.  sclk is supplied to the
	 * SA1110 GPIO19 to drive the SSP at sysclk/4 by the CPLD.
	 */
	sysclk = clk_ref / 18;
	sclk = sysclk / 4;

	if (rate > sysclk * 4 / (256 * 7)) {
		/* fs256 */
		div = 2;
	} else {
		/* fs512 */
		div = 4;
	}

	ret = snd_soc_dai_set_sysclk(codec_dai, 0, sysclk, SND_SOC_CLOCK_IN);
	if (ret < 0)
		return ret;

	ret = snd_soc_dai_set_sysclk(cpu_dai, SA11X0_SSP_CLK_EXT, sclk,
		SND_SOC_CLOCK_IN);
	if (ret < 0)
		return ret;

	ret = snd_soc_dai_set_clkdiv(cpu_dai, SA11X0_SSP_DIV_SCR, div);
	if (ret < 0)
		return ret;

	return 0;
}

static struct snd_soc_ops assabet_asoc_ops = {
	.startup = assabet_asoc_startup,
	.shutdown = assabet_asoc_shutdown,
	.hw_params = assabet_asoc_hw_params,
};

static struct snd_soc_dai_link assabet_asoc_dai = {
	.name = "Assabet",
	.stream_name = "Assabet",
	.codec_name = "uda134x-codec",
	.platform_name = "soc-dmaengine",
	.cpu_dai_name = "sa11x0-ssp",
	.codec_dai_name = "uda134x-hifi",
	.ops = &assabet_asoc_ops,
	.dai_fmt = SND_SOC_DAIFMT_RIGHT_J | SND_SOC_DAIFMT_NB_NF |
		   SND_SOC_DAIFMT_CBS_CFS,
};

static struct snd_soc_card snd_soc_assabet = {
	.name = "Assabet",
	.resume_pre = assabet_asoc_resume_pre,
	.dai_link = &assabet_asoc_dai,
	.num_links = 1,
};

/*
 * This is not-quite-right stuff: we have to _hope_ by a miracle that
 * we don't stamp on the toes of I2C, which shares these pins.
 */
static void assabet_setdat(int v)
{
	gpio_set_value(GPIO_L3_DAT, !!v);
}

static void assabet_setclk(int v)
{
	gpio_set_value(GPIO_L3_SCK, !!v);
}

static void assabet_setmode(int v)
{
	gpio_set_value(GPIO_L3_MODE, !!v);
}

static struct uda134x_platform_data uda1341_data = {
	.l3 = {
		.setdat = assabet_setdat,
		.setclk = assabet_setclk,
		.setmode = assabet_setmode,
		.data_hold = 1,
		.data_setup = 1,
		.clock_high = 1,
		.mode_hold = 1,
		.mode = 1,
		.mode_setup = 1,
	},
	.model = UDA134X_UDA1341,
	.power = assabet_asoc_uda1341_power,
};

static struct gpio ssp_gpio[] = {
	{
		.gpio = GPIO_TXD,
		.flags = GPIOF_OUT_INIT_LOW,
		.label = "ssp_txd",
	}, {
		.gpio = GPIO_RXD,
		.flags = GPIOF_IN,
		.label = "ssp_rxd",
	}, {
		.gpio = GPIO_SCLK,
		.flags = GPIOF_OUT_INIT_LOW,
		.label = "ssp_sclk",
	}, {
		.gpio = GPIO_SFRM,
		.flags = GPIOF_OUT_INIT_LOW,
		.label = "ssp_sfrm",
	}, {
		.gpio = GPIO_CLK,
		.flags = GPIOF_IN,
		.label = "ssp_clk",
	}, {
		.gpio = GPIO_L3_MODE,
		.flags = GPIOF_OUT_INIT_LOW,
		.label = "l3_mode",
	},
};

static struct platform_device *soc, *uda, *dma;

static int assabet_init(void)
{
	unsigned long flags;
	int ret;

	ret = gpio_request_array(ssp_gpio, ARRAY_SIZE(ssp_gpio));
	if (ret)
		return ret;

	/*
	 * Request these irrespective of whether they succeed.  Wish we
	 * could have our shared I2C/L3 driver from v2.4 kernels, but
	 * alas this would require a buggeration of the ASoC code.
	 * Not only this, but we have no way to do any kind of locking
	 * between the UDA134x L3 driver and I2C.
	 */
	gpio_request_one(GPIO_L3_DAT, GPIOF_OUT_INIT_LOW, "l3_dat");
	gpio_request_one(GPIO_L3_SCK, GPIOF_OUT_INIT_LOW, "l3_sck");

	/*
	 * Put the LRCK signal into a known good state: early Assabets
	 * do not mask the LRCK signal when the codec is powered down,
	 * and it defaults to logic 1.  So, first release the reset,
	 * and then toggle the SFRM signal to set LRCK to zero.
	 */
	ASSABET_BCR_set(ASSABET_BCR_CODEC_RST | ASSABET_BCR_SPK_OFF);
	ASSABET_BCR_clear(ASSABET_BCR_STEREO_LB);

	gpio_set_value(GPIO_SFRM, 1);
	gpio_set_value(GPIO_SFRM, 0);

	local_irq_save(flags);
	/*
	 * Ensure SSP pin reassignment is enabled, so that the SSP appears
	 * on the GPIO pins rather than the deddicated UART4 pins.
	 */
	PPAR |= PPAR_SPR;

	/* Configure the SSP input clock, and most SSP output signals */
	GAFR |= GPIO_SSP_TXD | GPIO_SSP_RXD | GPIO_SSP_SCLK | GPIO_SSP_CLK;

	local_irq_restore(flags);

	/*
	 * This is horrible, vile, disgusting abuse of the driver model
	 * just for the hell of it.  ASoC abuses the driver model elsewhere
	 * by kfreeing kobjects too!  As long as it does this kind of vile
	 * abuse, it is a total disaster waiting to happen, and should
	 * never have been merged into the kernel in the first place.
	 *   --rmk
	 */
	uda = platform_device_alloc(assabet_asoc_dai.codec_name, -1);
	soc = platform_device_alloc("soc-audio", -1);
	dma = platform_device_alloc("soc-dmaengine", -1);
	if (!soc || !uda || !dma) {
		ret = -ENOMEM;
		goto err_dev_alloc;
	}
	/* Ah, a void pointer, what can we stuff in here to pass around... */
	platform_set_drvdata(soc, &snd_soc_assabet);
	/* Oh look mummy, another void pointer, what can we stuff in here? */
	platform_device_add_data(soc, &uda1341_data, sizeof(uda1341_data));

	/* Let's at least give soc-audio a decent parent */
	soc->dev.parent = &uda->dev;

	ret = platform_device_add(uda);
	if (ret)
		goto err_dev_alloc;
	ret = platform_device_add(dma);
	if (ret)
		goto err_dev_add_dma;
	ret = platform_device_add(soc);
	if (ret == 0)
		return 0;

	platform_device_del(dma);
 err_dev_add_dma:
	platform_device_del(uda);
 err_dev_alloc:
	if (soc)
		platform_device_put(soc);
	if (uda)
		platform_device_put(uda);

	gpio_free_array(ssp_gpio, ARRAY_SIZE(ssp_gpio));

	return ret;
}
module_init(assabet_init);

static void assabet_exit(void)
{
	platform_device_unregister(soc);
	platform_device_unregister(dma);
	platform_device_unregister(uda);

	gpio_free_array(ssp_gpio, ARRAY_SIZE(ssp_gpio));
}
module_exit(assabet_exit);

MODULE_LICENSE("GPL");
