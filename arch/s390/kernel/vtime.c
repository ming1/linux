/*
 *  arch/s390/kernel/vtime.c
 *    Virtual cpu timer based timer functions.
 *
 *  S390 version
 *    Copyright (C) 2004 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Jan Glauber <jan.glauber@de.ibm.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/timex.h>
#include <linux/notifier.h>
#include <linux/kernel_stat.h>
#include <linux/rcupdate.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#include <linux/kprobes.h>

#include <asm/timer.h>
#include <asm/irq_regs.h>
#include <asm/cputime.h>
#include <asm/irq.h>
#include "entry.h"

static void virt_timer_forward(u64 elapsed);

DEFINE_PER_CPU(struct s390_idle_data, s390_idle);

static LIST_HEAD(virt_timer_list);
static DEFINE_SPINLOCK(virt_timer_lock);
static atomic64_t virt_timer_current;
static atomic64_t virt_timer_elapsed;

static inline u64 get_vtimer(void)
{
	u64 timer;

	asm volatile("STPT %0" : "=m" (timer));
	return timer;
}

static inline void set_vtimer(u64 expires)
{
	u64 timer;

	asm volatile ("  STPT %0\n"  /* Store current cpu timer value */
		      "  SPT %1"     /* Set new value immediately afterwards */
		      : "=m" (timer) : "m" (expires) );
	S390_lowcore.system_timer += S390_lowcore.last_update_timer - timer;
	S390_lowcore.last_update_timer = expires;
}

/*
 * Update process times based on virtual cpu times stored by entry.S
 * to the lowcore fields user_timer, system_timer & steal_clock.
 */
static void do_account_vtime(struct task_struct *tsk, int hardirq_offset)
{
	struct thread_info *ti = task_thread_info(tsk);
	u64 timer, clock, user, system, steal;

	timer = S390_lowcore.last_update_timer;
	clock = S390_lowcore.last_update_clock;
	asm volatile ("  STPT %0\n"    /* Store current cpu timer value */
		      "  STCK %1"      /* Store current tod clock value */
		      : "=m" (S390_lowcore.last_update_timer),
		        "=m" (S390_lowcore.last_update_clock) );
	S390_lowcore.system_timer += timer - S390_lowcore.last_update_timer;
	S390_lowcore.steal_timer += S390_lowcore.last_update_clock - clock;

	user = S390_lowcore.user_timer - ti->user_timer;
	S390_lowcore.steal_timer -= user;
	ti->user_timer = S390_lowcore.user_timer;
	account_user_time(tsk, user, user);

	system = S390_lowcore.system_timer - ti->system_timer;
	S390_lowcore.steal_timer -= system;
	ti->system_timer = S390_lowcore.system_timer;
	account_system_time(tsk, hardirq_offset, system, system);

	steal = S390_lowcore.steal_timer;
	if ((s64) steal > 0) {
		S390_lowcore.steal_timer = 0;
		account_steal_time(steal);
	}

	virt_timer_forward(user + system);
}

void account_vtime(struct task_struct *prev, struct task_struct *next)
{
	struct thread_info *ti;

	do_account_vtime(prev, 0);
	ti = task_thread_info(prev);
	ti->user_timer = S390_lowcore.user_timer;
	ti->system_timer = S390_lowcore.system_timer;
	ti = task_thread_info(next);
	S390_lowcore.user_timer = ti->user_timer;
	S390_lowcore.system_timer = ti->system_timer;
}

void account_process_tick(struct task_struct *tsk, int user_tick)
{
	do_account_vtime(tsk, HARDIRQ_OFFSET);
}

/*
 * Update process times based on virtual cpu times stored by entry.S
 * to the lowcore fields user_timer, system_timer & steal_clock.
 */
void account_system_vtime(struct task_struct *tsk)
{
	struct thread_info *ti = task_thread_info(tsk);
	u64 timer, system;

	timer = S390_lowcore.last_update_timer;
	S390_lowcore.last_update_timer = get_vtimer();
	S390_lowcore.system_timer += timer - S390_lowcore.last_update_timer;

	system = S390_lowcore.system_timer - ti->system_timer;
	S390_lowcore.steal_timer -= system;
	ti->system_timer = S390_lowcore.system_timer;
	account_system_time(tsk, 0, system, system);

	virt_timer_forward(system);
}
EXPORT_SYMBOL_GPL(account_system_vtime);

void __kprobes vtime_stop_cpu(void)
{
	struct s390_idle_data *idle = &__get_cpu_var(s390_idle);
	unsigned long long idle_time;
	unsigned long psw_mask;

	trace_hardirqs_on();
	/* Don't trace preempt off for idle. */
	stop_critical_timings();

	/* Wait for external, I/O or machine check interrupt. */
	psw_mask = psw_kernel_bits | PSW_MASK_WAIT | PSW_MASK_DAT |
		PSW_MASK_IO | PSW_MASK_EXT | PSW_MASK_MCHECK;
	idle->nohz_delay = 0;

	/* Call the assembler magic in entry.S */
	psw_idle(idle, psw_mask);

	/* Reenable preemption tracer. */
	start_critical_timings();

	/* Account time spent with enabled wait psw loaded as idle time. */
	idle->sequence++;
	smp_wmb();
	idle_time = idle->clock_idle_exit - idle->clock_idle_enter;
	idle->clock_idle_enter = idle->clock_idle_exit = 0ULL;
	idle->idle_time += idle_time;
	idle->idle_count++;
	account_idle_time(idle_time);
	smp_wmb();
	idle->sequence++;
}

cputime64_t s390_get_idle_time(int cpu)
{
	struct s390_idle_data *idle = &per_cpu(s390_idle, cpu);
	unsigned long long now, idle_enter, idle_exit;
	unsigned int sequence;

	do {
		now = get_clock();
		sequence = ACCESS_ONCE(idle->sequence);
		idle_enter = ACCESS_ONCE(idle->clock_idle_enter);
		idle_exit = ACCESS_ONCE(idle->clock_idle_exit);
	} while ((sequence & 1) || (idle->sequence != sequence));
	return idle_enter ? ((idle_exit ? : now) - idle_enter) : 0;
}

/*
 * Sorted add to a list. List is linear searched until first bigger
 * element is found.
 */
static void list_add_sorted(struct vtimer_list *timer, struct list_head *head)
{
	struct vtimer_list *event;

	list_for_each_entry(event, head, entry) {
		if (event->expires > timer->expires) {
			list_add_tail(&timer->entry, &event->entry);
			return;
		}
	}
	list_add_tail(&timer->entry, head);
}

/*
 * Handler for the virtual CPU timer.
 */
static void virt_timer_forward(u64 elapsed)
{
	struct vtimer_list *event, *tmp;
	struct list_head cb_list;	/* the callback queue */

	BUG_ON(!irqs_disabled());

	if (list_empty(&virt_timer_list))
		return;

	elapsed = atomic64_add_return(elapsed, &virt_timer_elapsed);
	if (elapsed < atomic64_read(&virt_timer_current))
		return;

	INIT_LIST_HEAD(&cb_list);

	/* walk timer list, fire all expired events */
	spin_lock(&virt_timer_lock);
	list_for_each_entry_safe(event, tmp, &virt_timer_list, entry) {
		if (event->expires < elapsed)
			/* move expired timer to the callback queue */
			list_move_tail(&event->entry, &cb_list);
		else
			event->expires -= elapsed;
	}
	if (!list_empty(&virt_timer_list)) {
		event = list_first_entry(&virt_timer_list,
					 struct vtimer_list, entry);
		atomic64_set(&virt_timer_current, event->expires);
	}
	atomic64_sub(elapsed, &virt_timer_elapsed);
	spin_unlock(&virt_timer_lock);

	if (list_empty(&cb_list))
		return;

	/* Do callbacks and recharge periodic timer */
	list_for_each_entry_safe(event, tmp, &cb_list, entry) {
		list_del_init(&event->entry);
		(event->function)(event->data);
		if (event->interval) {
			/* Recharge interval timer */
			event->expires = event->interval +
				atomic64_read(&virt_timer_elapsed);
			spin_lock(&virt_timer_lock);
			list_add_sorted(event, &virt_timer_list);
			spin_unlock(&virt_timer_lock);
		}
	}
}

void init_virt_timer(struct vtimer_list *timer)
{
	timer->function = NULL;
	INIT_LIST_HEAD(&timer->entry);
}
EXPORT_SYMBOL(init_virt_timer);

static inline int vtimer_pending(struct vtimer_list *timer)
{
	return (!list_empty(&timer->entry));
}

static void internal_add_vtimer(struct vtimer_list *timer)
{
	if (list_empty(&virt_timer_list)) {
		/* First timer, just program it. */
		atomic64_set(&virt_timer_current, timer->expires);
		atomic64_set(&virt_timer_elapsed, 0);
		list_add(&timer->entry, &virt_timer_list);
	} else {
		/* Update timer against current base. */
		timer->expires += atomic64_read(&virt_timer_elapsed);
		if (likely((s64) timer->expires <
			   (s64) atomic64_read(&virt_timer_current)))
			/* The new timer expires before the current timer. */
			atomic64_set(&virt_timer_current, timer->expires);
		/* Insert new timer into the list. */
		list_add_sorted(timer, &virt_timer_list);
	}
}

/*
 * add_virt_timer - add an oneshot virtual CPU timer
 */
void add_virt_timer(struct vtimer_list *timer)
{
	unsigned long flags;

	timer->interval = 0;
	spin_lock_irqsave(&virt_timer_lock, flags);
	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
}
EXPORT_SYMBOL(add_virt_timer);

/*
 * add_virt_timer_int - add an interval virtual CPU timer
 */
void add_virt_timer_periodic(struct vtimer_list *timer)
{
	unsigned long flags;

	timer->interval = timer->expires;
	spin_lock_irqsave(&virt_timer_lock, flags);
	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
}
EXPORT_SYMBOL(add_virt_timer_periodic);

static int __mod_vtimer(struct vtimer_list *timer, u64 expires, int periodic)
{
	unsigned long flags;
	int rc;

	BUG_ON(!timer->function);
	BUG_ON(!expires || expires > VTIMER_MAX_SLICE);

	if (timer->expires == expires && vtimer_pending(timer))
		return 1;

	/* Disable interrupts before test if timer is pending. */
	spin_lock_irqsave(&virt_timer_lock, flags);

	/* Remove timer from the list if it is pending. */
	rc = vtimer_pending(timer);
	if (rc)
		list_del_init(&timer->entry);
	/* Initialize timer. */
	timer->interval = periodic ? expires : 0;
	timer->expires = expires;

	/* Add the timer again. */
	internal_add_vtimer(timer);

	spin_unlock_irqrestore(&virt_timer_lock, flags);
	return rc;
}

/*
 * If we change a pending timer the function must be called on the CPU
 * where the timer is running on.
 *
 * returns whether it has modified a pending timer (1) or not (0)
 */
int mod_virt_timer(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 0);
}
EXPORT_SYMBOL(mod_virt_timer);

/*
 * If we change a pending timer the function must be called on the CPU
 * where the timer is running on.
 *
 * returns whether it has modified a pending timer (1) or not (0)
 */
int mod_virt_timer_periodic(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 1);
}
EXPORT_SYMBOL(mod_virt_timer_periodic);

/*
 * delete a virtual timer
 *
 * returns whether the deleted timer was pending (1) or not (0)
 */
int del_virt_timer(struct vtimer_list *timer)
{
	unsigned long flags;

	/* check if timer is pending */
	if (!vtimer_pending(timer))
		return 0;

	spin_lock_irqsave(&virt_timer_lock, flags);

	/* we don't interrupt a running timer, just let it expire! */
	list_del_init(&timer->entry);

	spin_unlock_irqrestore(&virt_timer_lock, flags);
	return 1;
}
EXPORT_SYMBOL(del_virt_timer);

/*
 * Start the virtual CPU timer on the current CPU.
 */
void init_cpu_vtimer(void)
{
	/* set initial cpu timer */
	set_vtimer(0x7fffffffffffffffULL);
}

static int __cpuinit s390_nohz_notify(struct notifier_block *self,
				      unsigned long action, void *hcpu)
{
	struct s390_idle_data *idle;
	long cpu = (long) hcpu;

	idle = &per_cpu(s390_idle, cpu);
	switch (action) {
	case CPU_DYING:
	case CPU_DYING_FROZEN:
		idle->nohz_delay = 0;
	default:
		break;
	}
	return NOTIFY_OK;
}

void __init vtime_init(void)
{
	/* Enable cpu timer interrupts on the boot cpu. */
	init_cpu_vtimer();
	cpu_notifier(s390_nohz_notify, 0);
}

