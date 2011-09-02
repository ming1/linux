#ifndef _TS5500_ADC_H
#define _TS5500_ADC_H

#define TS5500_ADC_CTRL_REG		0x195	/* Conversion state register */
#define TS5500_ADC_INIT_LSB_REG		0x196	/* Init conv. / LSB register */
#define TS5500_ADC_MSB_REG		0x197	/* MSB register */
/*
 * Control bits of A/D command
 * bits 0-2:	selected channel (0 - 7)
 * bits 3:	uni/bipolar (0 = unipolar (ie 0 to +5V))
 *			    (1 = bipolar (ie -5 to +5V))
 * bit 4:	selected range (0 = 5v range, 1 = 10V range)
 * bit 5-7:	padded zero (unused)
 */

#define TS5500_ADC_CHANNELS_MAX		8	/* 0 to 7 channels on device */

#define TS5500_ADC_BIPOLAR		0x08
#define TS5500_ADC_UNIPOLAR		0x00
#define TS5500_ADC_RANGE_5V		0x00	/* 0 to 5V range */
#define TS5500_ADC_RANGE_10V		0x10	/* 0 to 10V range */

#define TS5500_ADC_READ_DELAY		15	/* usec */
#define TS5500_ADC_READ_BUSY_MASK	0x01
#define TS5500_ADC_NAME			"MAX197 (8 channels)"

/**
 * struct ts5500_adc_platform_data
 * @name:	Name of the device.
 * @ioaddr:	I/O address containing:
 *		.data:		Data register for conversion reading.
 *		.ctrl:		A/D Control Register (bit 0 = 0 when
 *				conversion completed).
 * @read:	Information about conversion reading, with:
 *		.delay:		Delay before next conversion.
 *		.busy_mask:	Control register bit 0 equals 1 means
 *				conversion is not completed yet.
 * @ctrl:	Data tables addressable by [polarity][range].
 * @ranges:	Ranges.
 *		.min:		Min value.
 *		.max:		Max value.
 * @scale:	Polarity/Range coefficients to scale raw conversion reading.
 */
struct ts5500_adc_platform_data {
	const char *name;
	struct {
		int data;
		int ctrl;
	} ioaddr;
	struct {
		u8 delay;
		u8 busy_mask;
	} read;
	u8 ctrl[2][2];
	struct {
		int min[2][2];
		int max[2][2];
	} ranges;
	int scale[2][2];
};

#endif
