/*
 * GPIO (DIO) driver for Technologic Systems TS-5500
 *
 * Copyright (c) 2010 Savoir-faire Linux Inc.
 *	Jerome Oufella <jerome.oufella@savoirfairelinux.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _TS5500_GPIO_H
#define _TS5500_GPIO_H

#define TS5500_DIO1_0		0
#define TS5500_DIO1_1		1
#define TS5500_DIO1_2		2
#define TS5500_DIO1_3		3
#define TS5500_DIO1_4		4
#define TS5500_DIO1_5		5
#define TS5500_DIO1_6		6
#define TS5500_DIO1_7		7
#define TS5500_DIO1_8		8
#define TS5500_DIO1_9		9
#define TS5500_DIO1_10		10
#define TS5500_DIO1_11		11
#define TS5500_DIO1_12		12
#define TS5500_DIO1_13		13
#define TS5500_DIO2_0		14
#define TS5500_DIO2_1		15
#define TS5500_DIO2_2		16
#define TS5500_DIO2_3		17
#define TS5500_DIO2_4		18
#define TS5500_DIO2_5		19
#define TS5500_DIO2_6		20
#define TS5500_DIO2_7		21
#define TS5500_DIO2_8		22
#define TS5500_DIO2_9		23
#define TS5500_DIO2_10		24
#define TS5500_DIO2_11		25
/* #define TS5500_DIO2_12 - Keep commented out as it simply doesn't exist. */
#define TS5500_DIO2_13		26
#define TS5500_LCD_0		27
#define TS5500_LCD_1		28
#define TS5500_LCD_2		29
#define TS5500_LCD_3		30
#define TS5500_LCD_4		31
#define TS5500_LCD_5		32
#define TS5500_LCD_6		33
#define TS5500_LCD_7		34
#define TS5500_LCD_EN		35
#define TS5500_LCD_RS		36
#define TS5500_LCD_WR		37

/* Lines that can trigger IRQs */
#define TS5500_DIO1_13_IRQ	7
#define TS5500_DIO2_13_IRQ	6
#define TS5500_LCD_RS_IRQ	1

#endif /* _TS5500_GPIO_H */
