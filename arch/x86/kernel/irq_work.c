/*
 * x86 specific code for irq_work
 *
 * Copyright (C) 2010 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 */

#include <linux/kernel.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <asm/apic.h>
#include <trace/events/irq_vectors.h>

void smp_irq_work_interrupt(struct pt_regs *regs)
{
	irq_enter();
	ack_APIC_irq();
	trace_irq_vector_entry(IRQ_WORK_VECTOR);
	inc_irq_stat(apic_irq_work_irqs);
	irq_work_run();
	trace_irq_vector_exit(IRQ_WORK_VECTOR);
	irq_exit();
}

void arch_irq_work_raise(void)
{
#ifdef CONFIG_X86_LOCAL_APIC
	if (!cpu_has_apic)
		return;

	apic->send_IPI_self(IRQ_WORK_VECTOR);
	apic_wait_icr_idle();
#endif
}
