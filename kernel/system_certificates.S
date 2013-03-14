#include <linux/export.h>

#define GLOBAL(name)	\
	.globl VMLINUX_SYMBOL(name);	\
	VMLINUX_SYMBOL(name):

	.section ".init.data","aw"

GLOBAL(system_certificate_list)
	.incbin "kernel/x509_certificate_list"
GLOBAL(system_certificate_list_end)
