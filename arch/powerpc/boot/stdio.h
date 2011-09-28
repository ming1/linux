#ifndef _PPC_BOOT_STDIO_H_
#define _PPC_BOOT_STDIO_H_

#include <stdarg.h>

#define	ENOMEM		12	/* Out of Memory */
#define	EINVAL		22	/* Invalid argument */
#define ENOSPC		28	/* No space left on device */

extern __printf(1, 2) int printf(const char *fmt, ...);

#define fprintf(fmt, args...)	printf(args)

extern __printf(2, 3) int sprintf(char *buf, const char *fmt, ...);

extern int vsprintf(char *buf, const char *fmt, va_list args);

#endif				/* _PPC_BOOT_STDIO_H_ */
