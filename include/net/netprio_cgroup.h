/*
 * netprio_cgroup.h			Control Group Priority set
 *
 *
 * Authors:	Neil Horman <nhorman@tuxdriver.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#ifndef _NETPRIO_CGROUP_H
#define _NETPRIO_CGROUP_H
#include <linux/module.h>
#include <linux/cgroup.h>
#include <linux/hardirq.h>
#include <linux/rcupdate.h>

#if IS_ENABLED(CONFIG_NETPRIO_CGROUP)

struct cgroup_netprio_state {
	struct cgroup_subsys_state css;
	u32 prioidx;
};

struct netprio_map {
	struct rcu_head rcu;
	u32 priomap_len;
	u32 priomap[];
};

extern int net_prio_subsys_id;

extern void sock_update_netprioidx(struct sock *sk);

static inline struct cgroup_netprio_state *
task_netprio_state(struct task_struct *p)
{
	return container_of(task_subsys_state(p, net_prio_subsys_id),
			    struct cgroup_netprio_state, css);
}

#else	/* CONFIG_NETPRIO_CGROUP */

static inline void sock_update_netprioidx(struct sock *sk)
{
}

static inline struct cgroup_netprio_state *
task_netprio_state(struct task_struct *p)
{
	return NULL;
}

#endif	/* CONFIG_NETPRIO_CGROUP */

#endif  /* _NET_CLS_CGROUP_H */
