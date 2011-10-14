/*
 * arch/s390/kernel/machine_kexec.c
 *
 * Copyright IBM Corp. 2005,2011
 *
 * Author(s): Rolf Adelsberger,
 *	      Heiko Carstens <heiko.carstens@de.ibm.com>
 *	      Michael Holzheu <holzheu@linux.vnet.ibm.com>
 */

#include <linux/device.h>
#include <linux/mm.h>
#include <linux/kexec.h>
#include <linux/delay.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <asm/cio.h>
#include <asm/setup.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/system.h>
#include <asm/smp.h>
#include <asm/reset.h>
#include <asm/ipl.h>
#include <asm/diag.h>
#include <asm/asm-offsets.h>

typedef void (*relocate_kernel_t)(kimage_entry_t *, unsigned long);

extern const unsigned char relocate_kernel[];
extern const unsigned long long relocate_kernel_len;

#ifdef CONFIG_CRASH_DUMP

#define ROUNDUP(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define PTR_ADD(x, y) (((char *) (x)) + ((unsigned long) (y)))

#ifndef NT_FPREGSET
#define NT_FPREGSET 2
#endif

/*
 * fpregset ELF Note
 */
struct nt_fpregset_64 {
	u32	fpc;
	u32	pad;
	u64	fprs[16];
} __packed;

/*
 * Initialize ELF note
 */
static void *nt_init(void *buf, Elf64_Word type, void *desc, int d_len,
		     const char *name)
{
	Elf64_Nhdr *note;
	u64 len;

	note = (Elf64_Nhdr *)buf;
	note->n_namesz = strlen(name) + 1;
	note->n_descsz = d_len;
	note->n_type = type;
	len = sizeof(Elf64_Nhdr);

	memcpy(buf + len, name, note->n_namesz);
	len = ROUNDUP(len + note->n_namesz, 4);

	memcpy(buf + len, desc, note->n_descsz);
	len = ROUNDUP(len + note->n_descsz, 4);

	return PTR_ADD(buf, len);
}

/*
 * Initialize prstatus note
 */
static void *nt_prstatus(void *ptr, struct save_area *sa)
{
	struct elf_prstatus nt_prstatus;
	static int cpu_nr = 1;

	memset(&nt_prstatus, 0, sizeof(nt_prstatus));
	memcpy(&nt_prstatus.pr_reg.gprs, sa->gp_regs, sizeof(sa->gp_regs));
	memcpy(&nt_prstatus.pr_reg.psw, sa->psw, sizeof(sa->psw));
	memcpy(&nt_prstatus.pr_reg.acrs, sa->acc_regs, sizeof(sa->acc_regs));
	nt_prstatus.pr_pid = cpu_nr;
	cpu_nr++;

	return nt_init(ptr, NT_PRSTATUS, &nt_prstatus, sizeof(nt_prstatus),
			 "CORE");
}

/*
 * Initialize fpregset (floating point) note
 */
static void *nt_fpregset(void *ptr, struct save_area *sa)
{
	struct nt_fpregset_64 nt_fpregset;

	memset(&nt_fpregset, 0, sizeof(nt_fpregset));
	memcpy(&nt_fpregset.fpc, &sa->fp_ctrl_reg, sizeof(sa->fp_ctrl_reg));
	memcpy(&nt_fpregset.fprs, &sa->fp_regs, sizeof(sa->fp_regs));

	return nt_init(ptr, NT_FPREGSET, &nt_fpregset, sizeof(nt_fpregset),
			 "CORE");
}

/*
 * Initialize timer note
 */
static void *nt_s390_timer(void *ptr, struct save_area *sa)
{
	return nt_init(ptr, NT_S390_TIMER, &sa->timer, sizeof(sa->timer),
			 KEXEC_CORE_NOTE_NAME);
}

/*
 * Initialize TOD clock comparator note
 */
static void *nt_s390_tod_cmp(void *ptr, struct save_area *sa)
{
	return nt_init(ptr, NT_S390_TODCMP, &sa->clk_cmp,
		       sizeof(sa->clk_cmp), KEXEC_CORE_NOTE_NAME);
}

/*
 * Initialize TOD programmable register note
 */
static void *nt_s390_tod_preg(void *ptr, struct save_area *sa)
{
	return nt_init(ptr, NT_S390_TODPREG, &sa->tod_reg,
		       sizeof(sa->tod_reg), KEXEC_CORE_NOTE_NAME);
}

/*
 * Initialize control register note
 */
static void *nt_s390_ctrs(void *ptr, struct save_area *sa)
{
	return nt_init(ptr, NT_S390_CTRS, &sa->ctrl_regs,
		       sizeof(sa->ctrl_regs), KEXEC_CORE_NOTE_NAME);
}

/*
 * Initialize prefix register note
 */
static void *nt_s390_prefix(void *ptr, struct save_area *sa)
{
	return nt_init(ptr, NT_S390_PREFIX, &sa->pref_reg,
			 sizeof(sa->pref_reg), KEXEC_CORE_NOTE_NAME);
}

/*
 * Final empty node
 */
static void nt_final(void *ptr)
{
	memset(ptr, 0, sizeof(struct elf_note));
}

/*
 * Add create ELF notes for CPU
 */
static void add_elf_notes(int cpu)
{
	struct save_area *sa = (void *) 4608 + store_prefix();
	void *ptr;

	memcpy((void *) (4608UL + sa->pref_reg), sa, sizeof(*sa));
	ptr = (u64 *) per_cpu_ptr(crash_notes, cpu);
	ptr = nt_prstatus(ptr, sa);
	ptr = nt_fpregset(ptr, sa);
	ptr = nt_s390_timer(ptr, sa);
	ptr = nt_s390_tod_cmp(ptr, sa);
	ptr = nt_s390_tod_preg(ptr, sa);
	ptr = nt_s390_ctrs(ptr, sa);
	ptr = nt_s390_prefix(ptr, sa);
	nt_final(ptr);
}

/*
 * Store status of next available physical CPU
 */
static int store_status_next(int start_cpu, int this_cpu)
{
	struct save_area *sa = (void *) 4608 + store_prefix();
	int cpu, rc;

	for (cpu = start_cpu; cpu < 65536; cpu++) {
		if (cpu == this_cpu)
			continue;
		do {
			rc = raw_sigp(cpu, sigp_stop_and_store_status);
		} while (rc == sigp_busy);
		if (rc != sigp_order_code_accepted)
			continue;
		if (sa->pref_reg)
			return cpu;
	}
	return -1;
}

/*
 * Initialize CPU ELF notes
 */
void setup_regs(void)
{
	unsigned long sa = S390_lowcore.prefixreg_save_area + SAVE_AREA_BASE;
	int cpu, this_cpu, phys_cpu = 0, first = 1;

	this_cpu = stap();

	if (!S390_lowcore.prefixreg_save_area)
		first = 0;
	for_each_online_cpu(cpu) {
		if (first) {
			add_elf_notes(cpu);
			first = 0;
			continue;
		}
		phys_cpu = store_status_next(phys_cpu, this_cpu);
		if (phys_cpu == -1)
			break;
		add_elf_notes(cpu);
		phys_cpu++;
	}
	/* Copy dump CPU store status info to absolute zero */
	memcpy((void *) SAVE_AREA_BASE, (void *) sa, sizeof(struct save_area));
}

#endif

/*
 * Start kdump: We expect here that a store status has been done on our CPU
 */
static void __do_machine_kdump(void *image)
{
#ifdef CONFIG_CRASH_DUMP
	int (*start_kdump)(int) = (void *)((struct kimage *) image)->start;

	__load_psw_mask(PSW_MASK_BASE | PSW_DEFAULT_KEY | PSW_MASK_EA | PSW_MASK_BA);
	setup_regs();
	start_kdump(1);
#endif
}

/*
 * Check if kdump checksums are valid: We call purgatory with parameter "0"
 */
static int kdump_csum_valid(struct kimage *image)
{
#ifdef CONFIG_CRASH_DUMP
	int (*start_kdump)(int) = (void *)image->start;
	int rc;

	__arch_local_irq_stnsm(0xfb); /* disable DAT */
	rc = start_kdump(0);
	__arch_local_irq_stosm(0x04); /* enable DAT */
	return rc ? 0 : -EINVAL;
#else
	return -EINVAL;
#endif
}

/*
 * Map or unmap crashkernel memory
 */
static void crash_map_pages(int enable)
{
	unsigned long size = resource_size(&crashk_res);

	BUG_ON(crashk_res.start % KEXEC_CRASH_MEM_ALIGN ||
	       size % KEXEC_CRASH_MEM_ALIGN);
	if (enable)
		vmem_add_mapping(crashk_res.start, size);
	else
		vmem_remove_mapping(crashk_res.start, size);
}

/*
 * Map crashkernel memory
 */
void crash_map_reserved_pages(void)
{
	crash_map_pages(1);
}

/*
 * Unmap crashkernel memory
 */
void crash_unmap_reserved_pages(void)
{
	crash_map_pages(0);
}

/*
 * Give back memory to hypervisor before new kdump is loaded
 */
static int machine_kexec_prepare_kdump(void)
{
#ifdef CONFIG_CRASH_DUMP
	if (MACHINE_IS_VM)
		diag10_range(PFN_DOWN(crashk_res.start),
			     PFN_DOWN(crashk_res.end - crashk_res.start + 1));
	return 0;
#else
	return -EINVAL;
#endif
}

int machine_kexec_prepare(struct kimage *image)
{
	void *reboot_code_buffer;

	/* Can't replace kernel image since it is read-only. */
	if (ipl_flags & IPL_NSS_VALID)
		return -ENOSYS;

	if (image->type == KEXEC_TYPE_CRASH)
		return machine_kexec_prepare_kdump();

	/* We don't support anything but the default image type for now. */
	if (image->type != KEXEC_TYPE_DEFAULT)
		return -EINVAL;

	/* Get the destination where the assembler code should be copied to.*/
	reboot_code_buffer = (void *) page_to_phys(image->control_code_page);

	/* Then copy it */
	memcpy(reboot_code_buffer, relocate_kernel, relocate_kernel_len);
	return 0;
}

void machine_kexec_cleanup(struct kimage *image)
{
}

void arch_crash_save_vmcoreinfo(void)
{
	VMCOREINFO_SYMBOL(lowcore_ptr);
	VMCOREINFO_LENGTH(lowcore_ptr, NR_CPUS);
}

void machine_shutdown(void)
{
}

/*
 * Do normal kexec
 */
static void __do_machine_kexec(void *data)
{
	relocate_kernel_t data_mover;
	struct kimage *image = data;

	data_mover = (relocate_kernel_t) page_to_phys(image->control_code_page);

	/* Call the moving routine */
	(*data_mover)(&image->head, image->start);
}

/*
 * Reset system and call either kdump or normal kexec
 */
static void __machine_kexec(void *data)
{
	struct kimage *image = data;

	pfault_fini();
	if (image->type == KEXEC_TYPE_CRASH)
		s390_reset_system(__do_machine_kdump, data);
	else
		s390_reset_system(__do_machine_kexec, data);
	disabled_wait((unsigned long) __builtin_return_address(0));
}

/*
 * Do either kdump or normal kexec. In case of kdump we first ask
 * purgatory, if kdump checksums are valid.
 */
void machine_kexec(struct kimage *image)
{
	if (image->type == KEXEC_TYPE_CRASH && !kdump_csum_valid(image))
		return;
	tracer_disable();
	smp_send_stop();
	smp_switch_to_ipl_cpu(__machine_kexec, image);
}
