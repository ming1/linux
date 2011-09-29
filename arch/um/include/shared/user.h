/* 
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#ifndef __USER_H__
#define __USER_H__

#include "kern_constants.h"

/*
 * The usual definition - copied here because the kernel provides its own,
 * fancier, type-safe, definition.  Using that one would require
 * copying too much infrastructure for my taste, so userspace files
 * get less checking than kernel files.
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* This is to get size_t */
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

extern __printf(1, 2) void panic(const char *fmt, ...);

#ifdef UML_CONFIG_PRINTK
extern __printf(1, 2) int printk(const char *fmt, ...);
#else
static inline __printf(1, 2) int printk(const char *fmt, ...)
{
	return 0;
}
#endif

extern void schedule(void);
extern int in_aton(char *str);
extern int open_gdb_chan(void);
extern size_t strlcpy(char *, const char *, size_t);
extern size_t strlcat(char *, const char *, size_t);

#endif
