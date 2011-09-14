/*
 * Interrupt support for Hexagon
 *
 * Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <linux/init.h>
#include <linux/delay.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <linux/version.h>

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *)v, cpu;
	struct irqaction *action;
	unsigned long flags;

	if (i == 0) {
		seq_puts(p, "           ");
		for_each_online_cpu(cpu)
			seq_printf(p, "CPU%d       ", cpu);
		seq_putc(p, '\n');
	}

	if (i < NR_IRQS) {
		struct irq_desc *desc = irq_to_desc(i);

		raw_spin_lock_irqsave(&desc->lock, flags);

		action = irq_desc[i].action;
		if (action) {
			seq_printf(p, "%3d: ", i);
			for_each_online_cpu(cpu) {
				seq_printf(p, "%10u ", kstat_irqs_cpu(i, cpu));
			}
			seq_printf(p, " %8s",
				   irq_desc_get_chip(&irq_desc[i])->name ?
				   : "-");
			seq_printf(p, "  %s", action->name);
			for (action = action->next; action;
			     action = action->next) {
				seq_printf(p, ", %s", action->name);
			}

			seq_putc(p, '\n');
		}
		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}

	return 0;
}
