/*
 * S390 kdump implementation
 *
 * Copyright IBM Corp. 2011
 * Author(s): Michael Holzheu <holzheu@linux.vnet.ibm.com>
 */

#include <linux/crash_dump.h>
#include <asm/lowcore.h>

/*
 * Copy one page from "oldmem"
 *
 * For the kdump reserved memory this functions performs a swap operation:
 *  - [OLDMEM_BASE - OLDMEM_BASE + OLDMEM_SIZE] is mapped to [0 - OLDMEM_SIZE].
 *  - [0 - OLDMEM_SIZE] is mapped to [OLDMEM_BASE - OLDMEM_BASE + OLDMEM_SIZE]
 */
ssize_t copy_oldmem_page(unsigned long pfn, char *buf,
			 size_t csize, unsigned long offset, int userbuf)
{
	unsigned long src;
	int rc;

	if (!csize)
		return 0;

	src = (pfn << PAGE_SHIFT) + offset;
	if (src < OLDMEM_SIZE)
		src += OLDMEM_BASE;
	else if (src > OLDMEM_BASE &&
		 src < OLDMEM_BASE + OLDMEM_SIZE)
		src -= OLDMEM_BASE;
	if (userbuf)
		rc = copy_to_user_real((void __user *) buf, (void *) src,
				       csize);
	else
		rc = memcpy_real(buf, (void *) src, csize);
	return rc < 0 ? rc : csize;
}
