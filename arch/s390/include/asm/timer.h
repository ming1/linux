/*
 *  include/asm-s390/timer.h
 *
 *  (C) Copyright IBM Corp. 2003,2006
 *  Virtual CPU timer
 *
 *  Author: Jan Glauber (jang@de.ibm.com)
 */

#ifndef _ASM_S390_TIMER_H
#define _ASM_S390_TIMER_H

#include <linux/timer.h>

#define VTIMER_MAX_SLICE (0x7ffffffffffff000LL)

struct vtimer_list {
	struct list_head entry;

	u64 expires;
	u64 interval;

	void (*function)(unsigned long);
	unsigned long data;
};

extern void init_virt_timer(struct vtimer_list *timer);
extern void add_virt_timer(struct vtimer_list *timer);
extern void add_virt_timer_periodic(struct vtimer_list *timer);
extern int mod_virt_timer(struct vtimer_list *timer, u64 expires);
extern int mod_virt_timer_periodic(struct vtimer_list *timer, u64 expires);
extern int del_virt_timer(struct vtimer_list *timer);

extern void init_cpu_vtimer(void);
extern void vtime_init(void);

extern void vtime_stop_cpu(void);
extern void vtime_start_leave(void);

#endif /* _ASM_S390_TIMER_H */
