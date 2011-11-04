/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2007 Aurelien Jarno <aurelien@aurel32.net>
 */

#ifndef __BCM47XX_GPIO_H
#define __BCM47XX_GPIO_H

#include <linux/ssb/ssb_embedded.h>
#include <asm/mach-bcm47xx/bcm47xx.h>

#define BCM47XX_EXTIF_GPIO_LINES	5
#define BCM47XX_CHIPCO_GPIO_LINES	16

extern int gpio_request(unsigned gpio, const char *label);
extern void gpio_free(unsigned gpio);
extern int gpio_to_irq(unsigned gpio);

static inline int gpio_get_value(unsigned gpio)
{
	return ssb_gpio_in(&ssb_bcm47xx, 1 << gpio);
}

#define gpio_get_value_cansleep	gpio_get_value

static inline void gpio_set_value(unsigned gpio, int value)
{
	ssb_gpio_out(&ssb_bcm47xx, 1 << gpio, value ? 1 << gpio : 0);
}

#define gpio_set_value_cansleep gpio_set_value

static inline int gpio_cansleep(unsigned gpio)
{
	return 0;
}

static inline int gpio_is_valid(unsigned gpio)
{
	return gpio < (BCM47XX_EXTIF_GPIO_LINES + BCM47XX_CHIPCO_GPIO_LINES);
}


static inline int gpio_direction_input(unsigned gpio)
{
	ssb_gpio_outen(&ssb_bcm47xx, 1 << gpio, 0);
	return 0;
}

static inline int gpio_direction_output(unsigned gpio, int value)
{
	/* first set the gpio out value */
	ssb_gpio_out(&ssb_bcm47xx, 1 << gpio, value ? 1 << gpio : 0);
	/* then set the gpio mode */
	ssb_gpio_outen(&ssb_bcm47xx, 1 << gpio, 1 << gpio);
	return 0;
}

static inline int gpio_intmask(unsigned gpio, int value)
{
	ssb_gpio_intmask(&ssb_bcm47xx, 1 << gpio,
			 value ? 1 << gpio : 0);
	return 0;
}

static inline int gpio_polarity(unsigned gpio, int value)
{
	ssb_gpio_polarity(&ssb_bcm47xx, 1 << gpio,
			  value ? 1 << gpio : 0);
	return 0;
}


#endif /* __BCM47XX_GPIO_H */
