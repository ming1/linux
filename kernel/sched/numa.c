/*
 * NUMA scheduler
 *
 *  Copyright (C) 2011-2012 Red Hat, Inc., Peter Zijlstra <pzijlstr@redhat.com>
 *
 * With input and fixes from:
 *
 *  Ingo Molnar <mingo@elte.hu>
 *  Bharata B Rao <bharata@linux.vnet.ibm.com>
 *  Dan Smith <danms@us.ibm.com>
 *
 * For licensing details see kernel-base/COPYING
 */

#include <linux/mempolicy.h>
#include <linux/kthread.h>
#include <linux/compat.h>

#include "sched.h"

struct static_key sched_numa_disabled = STATIC_KEY_INIT_FALSE;
static DEFINE_MUTEX(sched_numa_mutex);
int sysctl_sched_numa = IS_ENABLED(CONFIG_SCHED_NUMA_DEFAULT);

static const int numa_balance_interval = 2 * HZ; /* 2 seconds */

struct numa_ops {
	unsigned long	(*mem_load)(struct numa_entity *ne);
	unsigned long	(*cpu_load)(struct numa_entity *ne);

	void		(*mem_migrate)(struct numa_entity *ne, int node);
	void		(*cpu_migrate)(struct numa_entity *ne, int node);

	bool		(*can_migrate)(struct numa_entity *ne, int node);

	bool		(*tryget)(struct numa_entity *ne);
	void		(*put)(struct numa_entity *ne);
};

struct numa_cpu_load {
	unsigned long	remote; /* load of tasks running away from their home node */
	unsigned long	all;	/* load of tasks that should be running on this node */
};

static struct numa_cpu_load **numa_load_array;

static struct {
	spinlock_t		lock;
	unsigned long		load;
} max_mem_load = {
	.lock = __SPIN_LOCK_UNLOCKED(max_mem_load.lock),
	.load = 0,
};

/*
 * Assumes symmetric NUMA -- that is, each node is of equal size.
 */
static void set_max_mem_load(unsigned long load)
{
	unsigned long old_load;

	spin_lock(&max_mem_load.lock);
	old_load = max_mem_load.load;
	if (!old_load)
		old_load = load;
	max_mem_load.load = (old_load + load) >> 1;
	spin_unlock(&max_mem_load.lock);
}

static unsigned long get_max_mem_load(void)
{
	return max_mem_load.load;
}

struct node_queue {
	struct task_struct	*numad;

	unsigned long		remote_cpu_load;
	unsigned long		cpu_load;

	unsigned long		prev_numa_foreign;
	unsigned long		remote_mem_load;

	spinlock_t		lock;
	struct list_head	entity_list;
	int			nr_processes;

	unsigned long		next_schedule;
	int			node;
};

static struct node_queue **nqs;

static inline struct node_queue *nq_of(int node)
{
	return nqs[node];
}

static inline struct node_queue *this_nq(void)
{
	return nq_of(numa_node_id());
}

bool account_numa_enqueue(struct task_struct *p)
{
	int home_node = tsk_home_node(p);
	int cpu = task_cpu(p);
	int node = cpu_to_node(cpu);
	struct rq *rq = cpu_rq(cpu);
	struct numa_cpu_load *nl;
	unsigned long load;

	/*
	 * not actually an auto-numa task, ignore
	 */
	if (home_node == -1)
		return false;

	load = task_h_load(p);
	nl = this_cpu_ptr(numa_load_array[home_node]);
	p->numa_remote = (node != home_node);
	p->numa_contrib = load;
	nl->all += load;
	if (p->numa_remote)
		nl->remote += load;

	/*
	 * the task is on its home-node, we're done, the rest is offnode
	 * accounting.
	 */
	if (!p->numa_remote)
		return false;

	list_add_tail(&p->se.group_node, &rq->offnode_tasks);
	rq->offnode_running++;
	rq->offnode_weight += load;

	return true;
}

void account_numa_dequeue(struct task_struct *p)
{
	int home_node = p->node; /* ignore sched_numa_disabled */
	struct numa_cpu_load *nl;
	struct rq *rq;

	/*
	 * not actually an auto-numa task, ignore
	 */
	if (home_node == -1)
		return;

	nl = this_cpu_ptr(numa_load_array[home_node]);
	nl->all -= p->numa_contrib;
	if (p->numa_remote)
		nl->remote -= p->numa_contrib;

	/*
	 * the task is on its home-node, we're done, the rest is offnode
	 * accounting.
	 */
	if (!p->numa_remote)
		return;

	rq = task_rq(p);
	rq->offnode_running--;
	rq->offnode_weight -= p->numa_contrib;
}

static inline struct mm_struct *ne_mm(struct numa_entity *ne)
{
	return container_of(ne, struct mm_struct, numa);
}

static inline struct task_struct *ne_owner(struct numa_entity *ne)
{
	return rcu_dereference(ne_mm(ne)->owner);
}

static unsigned long process_cpu_load(struct numa_entity *ne)
{
	unsigned long load = 0;
	struct task_struct *t, *p;

	rcu_read_lock();
	t = p = ne_owner(ne);
	if (p) do {
		load += t->numa_contrib;
	} while ((t = next_thread(t)) != p);
	rcu_read_unlock();

	return load;
}

static unsigned long process_mem_load(struct numa_entity *ne)
{
	return get_mm_counter(ne_mm(ne), MM_ANONPAGES);
}

static void process_cpu_migrate(struct numa_entity *ne, int node)
{
	struct task_struct *p, *t;

	rcu_read_lock();
	t = p = ne_owner(ne);
	if (p) do {
		sched_setnode(t, node);
	} while ((t = next_thread(t)) != p);
	rcu_read_unlock();
}

static void process_mem_migrate(struct numa_entity *ne, int node)
{
	lazy_migrate_process(ne_mm(ne), node);
}

static bool __task_can_migrate(struct task_struct *t, u64 *runtime, int node)
{
#ifdef CONFIG_CPUSETS
	if (!node_isset(node, t->mems_allowed))
		return false;
#endif

	if (!cpumask_intersects(cpumask_of_node(node), tsk_cpus_allowed(t)))
		return false;

	*runtime += t->se.sum_exec_runtime; // @#$#@ 32bit

	return true;
}

static bool process_can_migrate(struct numa_entity *ne, int node)
{
	struct task_struct *p, *t;
	bool allowed = false;
	u64 runtime = 0;

	rcu_read_lock();
	t = p = ne_owner(ne);
	if (p) do {
		allowed = __task_can_migrate(t, &runtime, node);
		if (!allowed)
			break;
	} while ((t = next_thread(t)) != p);
	rcu_read_unlock();

	/*
	 * Don't bother migrating memory if there's less than 1 second
	 * of runtime on the tasks.
	 */
	return allowed && runtime > NSEC_PER_SEC;
}

static bool process_tryget(struct numa_entity *ne)
{
	/*
	 * This is possible when we hold &nq_of(ne->node)->lock since then
	 * numa_exit() will block on that lock, we can't however write an
	 * assertion to check this, since if we don't hold the lock that
	 * expression isn't safe to evaluate.
	 */
	return atomic_inc_not_zero(&ne_mm(ne)->mm_users);
}

static void process_put(struct numa_entity *ne)
{
	mmput(ne_mm(ne));
}

static const struct numa_ops process_numa_ops = {
	.mem_load	= process_mem_load,
	.cpu_load	= process_cpu_load,

	.mem_migrate	= process_mem_migrate,
	.cpu_migrate	= process_cpu_migrate,

	.can_migrate	= process_can_migrate,

	.tryget		= process_tryget,
	.put		= process_put,
};

static struct node_queue *lock_ne_nq(struct numa_entity *ne)
{
	struct node_queue *nq;
	int node;

	for (;;) {
		node = ACCESS_ONCE(ne->node);
		/*
		 * Make sure any dequeue is properly done before
		 * we can observe node == -1, see dequeue_ne().
		 */
		smp_rmb();
		if (node == -1)
			return NULL;

		nq = nq_of(node);
		spin_lock(&nq->lock);
		if (likely(ne->node == node))
			break;
		spin_unlock(&nq->lock);
	}

	return nq;
}

static void double_lock_nq(struct node_queue *nq1, struct node_queue *nq2)
{
	if (nq1 > nq2)
		swap(nq1, nq2);

	spin_lock(&nq1->lock);
	if (nq2 != nq1)
		spin_lock_nested(&nq2->lock, SINGLE_DEPTH_NESTING);
}

static void double_unlock_nq(struct node_queue *nq1, struct node_queue *nq2)
{
	if (nq1 > nq2)
		swap(nq1, nq2);

	if (nq2 != nq1)
		spin_unlock(&nq2->lock);
	spin_unlock(&nq1->lock);
}

static void __enqueue_ne(struct node_queue *nq, struct numa_entity *ne)
{
	ne->node = nq->node;
	list_add_tail(&ne->numa_entry, &nq->entity_list);
	nq->nr_processes++;
}

static void __dequeue_ne(struct node_queue *nq, struct numa_entity *ne)
{
	list_del(&ne->numa_entry);
	nq->nr_processes--;
	BUG_ON(nq->nr_processes < 0);
}

static void enqueue_ne(struct numa_entity *ne, int node)
{
	struct node_queue *nq = nq_of(node);

	BUG_ON(ne->node != -1);

	ne->nops->cpu_migrate(ne, node);
	ne->nops->mem_migrate(ne, node);

	spin_lock(&nq->lock);
	__enqueue_ne(nq, ne);
	spin_unlock(&nq->lock);
}

static void dequeue_ne(struct numa_entity *ne)
{
	struct node_queue *nq;

	nq = lock_ne_nq(ne);
	if (nq) {
		__dequeue_ne(nq, ne);
		/*
		 * ensure the dequeue is complete before lock_ne_nq()
		 * can observe the ne->node == -1.
		 */
		smp_wmb();
		ne->node = -1;
		spin_unlock(&nq->lock);
	}
}

static void init_ne(struct numa_entity *ne, const struct numa_ops *nops)
{
	ne->node = -1;
	ne->nops = nops;
}

void mm_init_numa(struct mm_struct *mm)
{
	init_ne(&mm->numa, &process_numa_ops);
}

void exit_numa(struct mm_struct *mm)
{
	dequeue_ne(&mm->numa);
}

static inline unsigned long node_pages_load(int node)
{
	unsigned long pages = 0;

	pages += node_page_state(node, NR_ANON_PAGES);
	pages += node_page_state(node, NR_ACTIVE_FILE);

	return pages;
}

static int find_idlest_node(int this_node)
{
	unsigned long mem_load, cpu_load;
	unsigned long min_cpu_load;
	unsigned long this_cpu_load;
	int min_node;
	int node, cpu;

	min_node = -1;
	this_cpu_load = min_cpu_load = ULONG_MAX;

	// XXX should be sched_domain aware
	for_each_online_node(node) {
		struct node_queue *nq = nq_of(node);
		/*
		 * Pick the node that has least cpu load provided there's no
		 * foreign memory load.
		 *
		 * XXX if all nodes were to have foreign allocations we'd OOM,
		 *     however check the low-pass filter in update_node_load().
		 */
		mem_load = nq->remote_mem_load;
		if (mem_load)
			continue;

		cpu_load = 0;
		for_each_cpu_mask(cpu, *cpumask_of_node(node))
			cpu_load += cpu_rq(cpu)->load.weight;
		cpu_load += nq->remote_cpu_load;

		if (this_node == node)
			this_cpu_load = cpu_load;

		if (cpu_load < min_cpu_load) {
			min_cpu_load = cpu_load;
			min_node = node;
		}
	}

	/*
	 * If there's no choice, stick to where we are.
	 */
	if (min_node == -1)
		return this_node;

	/*
	 * Add a little hysteresis so we don't hard-interleave over nodes
	 * scattering workloads.
	 */
	if (this_cpu_load != ULONG_MAX && this_node != min_node) {
		if (this_cpu_load * 100 < min_cpu_load * 110)
			return this_node;
	}

	return min_node;
}

void select_task_node(struct task_struct *p, struct mm_struct *mm, int sd_flags)
{
	int node;

	if (!sched_feat(NUMA_SELECT) || !sysctl_sched_numa) {
		p->node = -1;
		return;
	}

	if (!mm)
		return;

	/*
	 * If there's an explicit task policy set, bail.
	 */
	if (p->flags & PF_MEMPOLICY) {
		p->node = -1;
		return;
	}

	if (sd_flags & SD_BALANCE_FORK) {
		/* For new threads, set the home-node. */
		if (mm == current->mm) {
			p->node = mm->numa.node;
			return;
		}
	}

	node = find_idlest_node(p->node);
	if (node == -1)
		node = numa_node_id();
	enqueue_ne(&mm->numa, node);
}

__init void init_sched_numa(void)
{
	int node;

	numa_load_array = kzalloc(sizeof(struct numa_cpu_load *) * nr_node_ids, GFP_KERNEL);
	BUG_ON(!numa_load_array);

	for_each_node(node) {
		numa_load_array[node] = alloc_percpu(struct numa_cpu_load);
		BUG_ON(!numa_load_array[node]);
	}
}

static void add_load(unsigned long *load, unsigned long new_load)
{
	if (sched_feat(NUMA_SLOW)) {
		*load = (*load + new_load) >> 1;
		return;
	}

	*load = new_load;
}

/*
 * Called every @numa_balance_interval to update current node state.
 */
static void update_node_load(struct node_queue *nq)
{
	unsigned long pages, delta;
	struct numa_cpu_load l;
	int cpu;

	memset(&l, 0, sizeof(l));

	/*
	 * Aggregate per-cpu cpu-load values for this node as per
	 * account_numa_{en,de}queue().
	 *
	 * XXX limit to max balance sched_domain
	 */
	for_each_online_cpu(cpu) {
		struct numa_cpu_load *nl = per_cpu_ptr(numa_load_array[nq->node], cpu);

		l.remote += nl->remote;
		l.all += nl->all;
	}

	add_load(&nq->remote_cpu_load, l.remote);
	add_load(&nq->cpu_load, l.all);

	/*
	 * Fold regular samples of NUMA_FOREIGN into a memory load measure.
	 */
	pages = node_page_state(nq->node, NUMA_FOREIGN);
	delta = pages - nq->prev_numa_foreign;
	nq->prev_numa_foreign = pages;
	add_load(&nq->remote_mem_load, delta);

	/*
	 * If there was NUMA_FOREIGN load, that means this node was at its
	 * maximum memory capacity, record that.
	 */
	set_max_mem_load(node_pages_load(nq->node));
}

enum numa_balance_type {
	NUMA_BALANCE_NONE = 0,
	NUMA_BALANCE_CPU  = 1,
	NUMA_BALANCE_MEM  = 2,
	NUMA_BALANCE_ALL  = 3,
};

struct numa_imbalance {
	long cpu, mem;
	long mem_load;
	enum numa_balance_type type;
};

static int find_busiest_node(int this_node, struct numa_imbalance *imb)
{
	unsigned long cpu_load, mem_load;
	unsigned long max_cpu_load, max_mem_load;
	unsigned long sum_cpu_load, sum_mem_load;
	unsigned long mem_cpu_load, cpu_mem_load;
	int cpu_node, mem_node;
	struct node_queue *nq;
	int node;

	sum_cpu_load = sum_mem_load = 0;
	max_cpu_load = max_mem_load = 0;
	mem_cpu_load = cpu_mem_load = 0;
	cpu_node = mem_node = -1;

	/* XXX scalability -- sched_domain */
	for_each_online_node(node) {
		nq = nq_of(node);

		cpu_load = nq->remote_cpu_load;
		mem_load = nq->remote_mem_load;

		/*
		 * If this node is overloaded on memory, we don't want more
		 * tasks, bail!
		 */
		if (node == this_node) {
			if (mem_load)
				return -1;
		}

		sum_cpu_load += cpu_load;
		if (cpu_load > max_cpu_load) {
			max_cpu_load = cpu_load;
			cpu_mem_load = mem_load;
			cpu_node = node;
		}

		sum_mem_load += mem_load;
		if (mem_load > max_mem_load) {
			max_mem_load = mem_load;
			mem_cpu_load = cpu_load;
			mem_node = node;
		}
	}

	/*
	 * Nobody had overload of any kind, cool we're done!
	 */
	if (cpu_node == -1 && mem_node == -1)
		return -1;

	if (mem_node == -1) {
set_cpu_node:
		node = cpu_node;
		cpu_load = max_cpu_load;
		mem_load = cpu_mem_load;
		goto calc_imb;
	}

	if (cpu_node == -1) {
set_mem_node:
		node = mem_node;
		cpu_load = mem_cpu_load;
		mem_load = max_mem_load;
		goto calc_imb;
	}

	/*
	 * We have both cpu and mem overload, oh my! pick whichever is most
	 * overloaded wrt the average.
	 */
	if ((u64)max_mem_load * sum_cpu_load > (u64)max_cpu_load * sum_mem_load)
		goto set_mem_node;

	goto set_cpu_node;

calc_imb:
	memset(imb, 0, sizeof(*imb));

	if (cpu_node != -1) {
		imb->type |= NUMA_BALANCE_CPU;
		imb->cpu = (long)(nq_of(node)->cpu_load -
				  nq_of(this_node)->cpu_load) / 2;
	}

	if (mem_node != -1) {
		imb->type |= NUMA_BALANCE_MEM;
		imb->mem_load = node_pages_load(this_node);
		imb->mem = (long)(node_pages_load(node) - imb->mem_load) / 2;
	}

	return node;
}

static void move_processes(struct node_queue *busiest_nq,
			   struct node_queue *this_nq,
			   struct numa_imbalance *imb)
{
	unsigned long max_mem_load = get_max_mem_load();
	long cpu_moved = 0, mem_moved = 0;
	struct numa_entity *ne;
	long ne_mem, ne_cpu;
	int loops;

	double_lock_nq(this_nq, busiest_nq);
	loops = busiest_nq->nr_processes;
	while (!list_empty(&busiest_nq->entity_list) && loops--) {
		ne = list_first_entry(&busiest_nq->entity_list,
				     struct numa_entity,
				     numa_entry);

		ne_cpu = ne->nops->cpu_load(ne);
		ne_mem = ne->nops->mem_load(ne);

		if (sched_feat(NUMA_BALANCE_FILTER)) {
			/*
			 * Avoid moving ne's when we create a larger imbalance
			 * on the other end.
			 */
			if ((imb->type & NUMA_BALANCE_CPU) &&
			    imb->cpu - cpu_moved < ne_cpu / 2)
				goto next;

			/*
			 * Avoid migrating ne's when we'll know we'll push our
			 * node over the memory limit.
			 */
			if (max_mem_load &&
			    imb->mem_load + mem_moved + ne_mem > max_mem_load)
				goto next;
		}

		if (!ne->nops->can_migrate(ne, this_nq->node))
			goto next;

		__dequeue_ne(busiest_nq, ne);
		__enqueue_ne(this_nq, ne);
		if (ne->nops->tryget(ne)) {
			double_unlock_nq(this_nq, busiest_nq);

			ne->nops->cpu_migrate(ne, this_nq->node);
			ne->nops->mem_migrate(ne, this_nq->node);
			ne->nops->put(ne);

			double_lock_nq(this_nq, busiest_nq);
		}

		cpu_moved += ne_cpu;
		mem_moved += ne_mem;

		if (imb->cpu - cpu_moved <= 0 &&
		    imb->mem - mem_moved <= 0)
			break;

		continue;

next:
		list_move_tail(&ne->numa_entry, &busiest_nq->entity_list);
	}
	double_unlock_nq(this_nq, busiest_nq);
}

static void numa_balance(struct node_queue *this_nq)
{
	struct numa_imbalance imb;
	int busiest;

	busiest = find_busiest_node(this_nq->node, &imb);
	if (busiest == -1)
		return;

	if (imb.cpu <= 0 && imb.mem <= 0)
		return;

	move_processes(nq_of(busiest), this_nq, &imb);
}

static int wait_for_next_balance(struct node_queue *nq)
{
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		long timeout = nq->next_schedule - jiffies;
		if (timeout <= 0) {
			__set_current_state(TASK_RUNNING);
			return 1;
		}
		schedule_timeout(timeout);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static int numad_thread(void *data)
{
	struct node_queue *nq = data;
	struct task_struct *p = nq->numad;

	set_cpus_allowed_ptr(p, cpumask_of_node(nq->node));

	while (wait_for_next_balance(nq)) {

		get_online_cpus();
		update_node_load(nq);
		if (sched_feat(NUMA_BALANCE))
			numa_balance(nq);
		put_online_cpus();

		nq->next_schedule += numa_balance_interval;
	}

	return 0;
}

static int numad_create(struct node_queue *nq)
{
	struct task_struct *numad;

	if (!sysctl_sched_numa)
		return 0;

	numad = kthread_create_on_node(numad_thread,
			nq, nq->node, "numad/%d", nq->node);
	if (IS_ERR(numad))
		return PTR_ERR(numad);

	nq->numad = numad;
	nq->next_schedule = jiffies + HZ;

	return 0;
}

static void numad_destroy(struct node_queue *nq)
{
	kthread_stop(nq->numad);
	nq->numad = NULL;
}

int sched_numa_handler(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int old, new, ret, node;

	mutex_lock(&sched_numa_mutex);
	get_online_cpus();

	old = sysctl_sched_numa;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	new = sysctl_sched_numa;

	if (old == new)
		goto unlock;

	if (new)
		static_key_slow_dec(&sched_numa_disabled);
	else
		static_key_slow_inc(&sched_numa_disabled);

	for_each_online_node(node) {
		struct node_queue *nq = nq_of(node);

		if (new && !nq->numad) {
			if (!numad_create(nq))
				wake_up_process(nq->numad);
		} else if (!new && nq->numad)
			numad_destroy(nq);
	}

unlock:
	put_online_cpus();
	mutex_unlock(&sched_numa_mutex);

	return ret;
}

static int __cpuinit
numa_hotplug(struct notifier_block *nb, unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	int node = cpu_to_node(cpu);
	struct node_queue *nq = nq_of(node);
	int err = 0;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		if (nq->numad)
			break;

		err = numad_create(nq);
		break;

	case CPU_ONLINE:
		if (nq->numad)
			wake_up_process(nq->numad);
		break;

	case CPU_DEAD:
	case CPU_UP_CANCELED:
		if (!nq->numad)
			break;

		if (cpumask_any_and(cpu_online_mask,
				    cpumask_of_node(node)) >= nr_cpu_ids)
			numad_destroy(nq);
		break;
	}

	return notifier_from_errno(err);
}

static __init int numa_init(void)
{
	int node, cpu, err;

	nqs = kzalloc(sizeof(struct node_queue*) * nr_node_ids, GFP_KERNEL);
	BUG_ON(!nqs);

	for_each_node(node) {
		struct node_queue *nq = kmalloc_node(sizeof(*nq),
				GFP_KERNEL | __GFP_ZERO,
				node_online(node) ? node : NUMA_NO_NODE);
		BUG_ON(!nq);

		spin_lock_init(&nq->lock);
		INIT_LIST_HEAD(&nq->entity_list);

		nq->next_schedule = jiffies + HZ;
		nq->node = node;
		nqs[node] = nq;
	}

	get_online_cpus();
	cpu_notifier(numa_hotplug, 0);
	for_each_online_cpu(cpu) {
		err = numa_hotplug(NULL, CPU_UP_PREPARE, (void *)(long)cpu);
		BUG_ON(notifier_to_errno(err));
		numa_hotplug(NULL, CPU_ONLINE, (void *)(long)cpu);
	}
	put_online_cpus();

	return 0;
}
early_initcall(numa_init);


/*
 *  numa_group bits
 */

#include <linux/idr.h>
#include <linux/srcu.h>
#include <linux/syscalls.h>

static struct srcu_struct ng_srcu;

static DEFINE_MUTEX(numa_group_idr_lock);
static DEFINE_IDR(numa_group_idr);

static inline struct numa_group *ne_ng(struct numa_entity *ne)
{
	return container_of(ne, struct numa_group, numa_entity);
}

static inline bool ng_tryget(struct numa_group *ng)
{
	return atomic_inc_not_zero(&ng->ref);
}

static inline void ng_get(struct numa_group *ng)
{
	atomic_inc(&ng->ref);
}

static void __ng_put_rcu(struct rcu_head *rcu)
{
	struct numa_group *ng = container_of(rcu, struct numa_group, rcu);

	put_cred(ng->cred);
	kfree(ng);
}

struct static_key sched_numa_groups = STATIC_KEY_INIT_FALSE;

static void __ng_put(struct numa_group *ng)
{
	mutex_lock(&numa_group_idr_lock);
	idr_remove(&numa_group_idr, ng->id);
	mutex_unlock(&numa_group_idr_lock);

	WARN_ON(!list_empty(&ng->tasks));
	WARN_ON(!list_empty(&ng->vmas));

	dequeue_ne(&ng->numa_entity);

	static_key_slow_dec(&sched_numa_groups);

	call_rcu(&ng->rcu, __ng_put_rcu);
}

static inline void ng_put(struct numa_group *ng)
{
	if (atomic_dec_and_test(&ng->ref))
		__ng_put(ng);
}

/*
 * numa_ops
 */

static unsigned long numa_group_mem_load(struct numa_entity *ne)
{
	struct numa_group *ng = ne_ng(ne);

	return atomic_long_read(&ng->rss.count[MM_ANONPAGES]);
}

static unsigned long numa_group_cpu_load(struct numa_entity *ne)
{
	struct numa_group *ng = ne_ng(ne);
	unsigned long load = 0;
	struct task_struct *p;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &ng->tasks, ng_entry)
		load += p->numa_contrib;
	rcu_read_unlock();

	return load;
}

static void numa_group_mem_migrate(struct numa_entity *ne, int node)
{
	struct numa_group *ng = ne_ng(ne);
	struct vm_area_struct *vma;
	struct mempolicy *mpol;
	struct mm_struct *mm;
	int idx;

	/*
	 * Horrid code this..
	 *
	 * The main problem is that ng->lock nests inside mmap_sem [
	 * numa_vma_{,un}link() gets called under mmap_sem ]. But here we need
	 * to iterate that list and acquire mmap_sem for each entry.
	 *
	 * We start here with no locks held. numa_vma_unlink() is used to add
	 * an SRCU delayed reference count to the mpols. This allows us to do
	 * lockless iteration of the list.
	 *
	 * Once we have an mpol we need to acquire mmap_sem, this too isn't
	 * straight fwd, take ng->lock to pin mpol->vma due to its
	 * serialization against numa_vma_unlink(). While that vma pointer is
	 * stable the vma->vm_mm pointer must be good too, so acquire an extra
	 * reference to the mm.
	 *
	 * This reference keeps mm stable so we can drop ng->lock and acquire
	 * mmap_sem. After which mpol->vma is stable again since the memory map
	 * is stable. So verify ->vma is still good (numa_vma_unlink clears it)
	 * and the mm is still the same (paranoia, can't see how that could
	 * happen).
	 */

	idx = srcu_read_lock(&ng_srcu);
	list_for_each_entry_rcu(mpol, &ng->vmas, ng_entry) {
		nodemask_t mask = nodemask_of_node(node);

		spin_lock(&ng->lock); /* pin mpol->vma */
		vma = mpol->vma;
		if (!vma) {
			spin_unlock(&ng->lock);
			continue;
		}
		mm = vma->vm_mm;
		atomic_inc(&mm->mm_users); /* pin mm */
		spin_unlock(&ng->lock);

		down_read(&mm->mmap_sem);
		vma = mpol->vma;
		if (!vma)
			goto unlock_next;

		mpol_rebind_policy(mpol, &mask, MPOL_REBIND_ONCE);
		lazy_migrate_vma(vma, node);
unlock_next:
		up_read(&mm->mmap_sem);
		mmput(mm);
	}
	srcu_read_unlock(&ng_srcu, idx);
}

static void numa_group_cpu_migrate(struct numa_entity *ne, int node)
{
	struct numa_group *ng = ne_ng(ne);
	struct task_struct *p;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &ng->tasks, ng_entry)
		sched_setnode(p, node);
	rcu_read_unlock();
}

static bool numa_group_can_migrate(struct numa_entity *ne, int node)
{
	struct numa_group *ng = ne_ng(ne);
	struct task_struct *t;
	bool allowed = false;
	u64 runtime = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(t, &ng->tasks, ng_entry) {
		allowed = __task_can_migrate(t, &runtime, node);
		if (!allowed)
			break;
	}
	rcu_read_unlock();

	/*
	 * Don't bother migrating memory if there's less than 1 second
	 * of runtime on the tasks.
	 */
	return allowed && runtime > NSEC_PER_SEC;
}

static bool numa_group_tryget(struct numa_entity *ne)
{
	/*
	 * See process_tryget(), similar but against ng_put().
	 */
	return ng_tryget(ne_ng(ne));
}

static void numa_group_put(struct numa_entity *ne)
{
	ng_put(ne_ng(ne));
}

static const struct numa_ops numa_group_ops = {
	.mem_load	= numa_group_mem_load,
	.cpu_load	= numa_group_cpu_load,

	.mem_migrate	= numa_group_mem_migrate,
	.cpu_migrate	= numa_group_cpu_migrate,

	.can_migrate	= numa_group_can_migrate,

	.tryget		= numa_group_tryget,
	.put		= numa_group_put,
};

static struct numa_group *lock_p_ng(struct task_struct *p)
{
	struct numa_group *ng;

	for (;;) {
		ng = ACCESS_ONCE(p->numa_group);
		if (!ng)
			return NULL;

		spin_lock(&ng->lock);
		if (p->numa_group == ng)
			break;
		spin_unlock(&ng->lock);
	}

	return ng;
}

void __numa_task_exit(struct task_struct *p)
{
	struct numa_group *ng;

	ng = lock_p_ng(p);
	if (ng) {
		list_del_rcu(&p->ng_entry);
		p->numa_group = NULL;
		spin_unlock(&ng->lock);

		ng_put(ng);
	}
}

/*
 * memory (vma) accounting/tracking
 *
 * We assume a 1:1 relation between vmas and mpols and keep a list of mpols in
 * the numa_group, and a vma backlink in the mpol.
 */

void numa_vma_link(struct vm_area_struct *new, struct vm_area_struct *old)
{
	struct numa_group *ng = NULL;

	if (old && old->vm_policy)
		ng = old->vm_policy->numa_group;

	if (!ng && new->vm_policy)
		ng = new->vm_policy->numa_group;

	if (!ng)
		return;

	ng_get(ng);
	new->vm_policy->numa_group = ng;
	new->vm_policy->vma = new;

	spin_lock(&ng->lock);
	list_add_rcu(&new->vm_policy->ng_entry, &ng->vmas);
	spin_unlock(&ng->lock);
}

static void __mpol_put_rcu(struct rcu_head *rcu)
{
	struct mempolicy *mpol = container_of(rcu, struct mempolicy, rcu);
	mpol_put(mpol);
}

void numa_vma_unlink(struct vm_area_struct *vma)
{
	struct mempolicy *mpol;
	struct numa_group *ng;

	if (!vma)
		return;

	mpol = vma->vm_policy;
	if (!mpol)
		return;

	ng = mpol->numa_group;
	if (!ng)
		return;

	spin_lock(&ng->lock);
	list_del_rcu(&mpol->ng_entry);
	/*
	 * Rediculous, see numa_group_mem_migrate.
	 */
	mpol->vma = NULL;
	mpol_get(mpol);
	call_srcu(&ng_srcu, &mpol->rcu, __mpol_put_rcu);
	spin_unlock(&ng->lock);

	ng_put(ng);
}

/*
 * syscall bits
 */

#define MS_ID_GET	-2
#define MS_ID_NEW	-1

static struct numa_group *ng_create(struct task_struct *p)
{
	struct numa_group *ng;
	int node, err;

	ng = kzalloc(sizeof(*ng), GFP_KERNEL);
	if (!ng)
		goto fail;

	err = idr_pre_get(&numa_group_idr, GFP_KERNEL);
	if (!err)
		goto fail_alloc;

	mutex_lock(&numa_group_idr_lock);
	err = idr_get_new(&numa_group_idr, ng, &ng->id);
	mutex_unlock(&numa_group_idr_lock);

	if (err)
		goto fail_alloc;

	static_key_slow_inc(&sched_numa_groups);

	spin_lock_init(&ng->lock);
	atomic_set(&ng->ref, 1);
	ng->cred = get_task_cred(p);
	INIT_LIST_HEAD(&ng->tasks);
	INIT_LIST_HEAD(&ng->vmas);
	init_ne(&ng->numa_entity, &numa_group_ops);

	dequeue_ne(&p->mm->numa);
	node = find_idlest_node(tsk_home_node(p));
	enqueue_ne(&ng->numa_entity, node);

	return ng;

fail_alloc:
	kfree(ng);
fail:
	return ERR_PTR(-ENOMEM);
}

/*
 * More or less equal to ptrace_may_access(); XXX
 */
static int ng_allowed(struct numa_group *ng, struct task_struct *p)
{
	const struct cred *cred = ng->cred, *tcred;

	rcu_read_lock();
	tcred = __task_cred(p);
	if (cred->user_ns == tcred->user_ns &&
	    (cred->uid == tcred->euid &&
	     cred->uid == tcred->suid &&
	     cred->uid == tcred->uid  &&
	     cred->gid == tcred->egid &&
	     cred->gid == tcred->sgid &&
	     cred->gid == tcred->gid))
		goto ok;
	if (ns_capable(tcred->user_ns, CAP_SYS_PTRACE))
		goto ok;
	rcu_read_unlock();
	return -EPERM;

ok:
	rcu_read_unlock();
	return 0;
}

static struct numa_group *ng_lookup(int ng_id, struct task_struct *p)
{
	struct numa_group *ng;

	rcu_read_lock();
again:
	ng = idr_find(&numa_group_idr, ng_id);
	if (!ng) {
		rcu_read_unlock();
		return ERR_PTR(-EINVAL);
	}
	if (ng_allowed(ng, p)) {
		rcu_read_unlock();
		return ERR_PTR(-EPERM);
	}
	if (!ng_tryget(ng))
		goto again;
	rcu_read_unlock();

	return ng;
}

static int ng_task_assign(struct task_struct *p, int ng_id)
{
	struct numa_group *old_ng, *ng;

	ng = ng_lookup(ng_id, p);
	if (IS_ERR(ng))
		return PTR_ERR(ng);

	old_ng = lock_p_ng(p);
	if (old_ng) {
		/*
		 * Special numa_group that assists in serializing the
		 * p->numa_group hand-over. Assume concurrent ng_task_assign()
		 * invocation, only one can remove the old_ng, but both need
		 * to serialize against RCU.
		 *
		 * Therefore we cannot clear p->numa_group, this would lead to
		 * the second not observing old_ng and thus missing the RCU
		 * sync.
		 *
		 * We also cannot set p->numa_group to ng, since then we'd
		 * try to remove ourselves from a list we're not on yet --
		 * double list_del_rcu() invocation.
		 *
		 * Solve this by using this special intermediate numa_group,
		 * we set p->numa_group to this object so that the second
		 * observes a !NULL numa_group, however we skip the
		 * list_del_rcu() when we find this special group avoiding the
		 * double delete.
		 */
		static struct numa_group __ponies = {
			.lock = __SPIN_LOCK_UNLOCKED(__ponies.lock),
		};

		if (likely(old_ng != &__ponies)) {
			list_del_rcu(&p->ng_entry);
			p->numa_group = &__ponies;
		}
		spin_unlock(&old_ng->lock);

		if (unlikely(old_ng == &__ponies))
			old_ng = NULL; /* avoid ng_put() */

		/*
		 * We have to wait for the old ng_entry users to go away before
		 * we can re-use the link entry for the new list.
		 */
		synchronize_rcu();
	}

	spin_lock(&ng->lock);
	p->numa_group = ng;
	list_add_rcu(&p->ng_entry, &ng->tasks);
	spin_unlock(&ng->lock);

	sched_setnode(p, ng->numa_entity.node);

	if (old_ng)
		ng_put(old_ng);

	return ng_id;
}

static struct task_struct *find_get_task(pid_t tid)
{
	struct task_struct *p;

	rcu_read_lock();
	if (!tid)
		p = current;
	else
		p = find_task_by_vpid(tid);

	if (p->flags & PF_EXITING)
		p = NULL;

	if (p)
		get_task_struct(p);
	rcu_read_unlock();

	if (!p)
		return ERR_PTR(-ESRCH);

	return p;
}

/*
 * Bind a thread to a numa group or query its binding or create a new group.
 *
 * sys_numa_tbind(tid, -1, 0);	  // create new group, return new ng_id
 * sys_numa_tbind(tid, -2, 0);	  // returns existing ng_id
 * sys_numa_tbind(tid, ng_id, 0); // set ng_id
 *
 * Returns:
 *  -ESRCH	tid->task resolution failed
 *  -EINVAL	task didn't have a ng_id, flags was wrong
 *  -EPERM	we don't have privileges over tid
 *
 */
SYSCALL_DEFINE3(numa_tbind, int, tid, int, ng_id, unsigned long, flags)
{
	struct task_struct *p = find_get_task(tid);
	struct numa_group *ng = NULL;
	int orig_ng_id = ng_id;

	if (IS_ERR(p))
		return PTR_ERR(p);

	if (flags) {
		ng_id = -EINVAL;
		goto out;
	}

	switch (ng_id) {
	case MS_ID_GET:
		ng_id = -EINVAL;
		rcu_read_lock();
		ng = rcu_dereference(p->numa_group);
		if (ng)
			ng_id = ng->id;
		rcu_read_unlock();
		break;

	case MS_ID_NEW:
		ng = ng_create(p);
		if (IS_ERR(ng)) {
			ng_id = PTR_ERR(ng);
			break;
		}
		ng_id = ng->id;
		/* fall through */

	default:
		ng_id = ng_task_assign(p, ng_id);
		if (ng && orig_ng_id < 0)
			ng_put(ng);
		break;
	}

out:
	put_task_struct(p);
	return ng_id;
}

/*
 * Bind a memory region to a numa group.
 *
 * sys_numa_mbind(addr, len, ng_id, 0);
 *
 * create a non-mergable vma over [addr,addr+len) and assign a mpol binding it
 * to the numa group identified by ng_id.
 *
 */
SYSCALL_DEFINE4(numa_mbind, unsigned long, addr, unsigned long, len,
			    int, ng_id, unsigned long, flags)
{
	struct mm_struct *mm = current->mm;
	struct mempolicy *mpol;
	struct numa_group *ng;
	nodemask_t mask;
	int err = 0;

	if (flags)
		return -EINVAL;

	if (addr & ~PAGE_MASK)
		return -EINVAL;

	ng = ng_lookup(ng_id, current);
	if (IS_ERR(ng))
		return PTR_ERR(ng);

	mask = nodemask_of_node(ng->numa_entity.node);
	mpol = mpol_new(MPOL_BIND, 0, &mask);
	if (IS_ERR(mpol)) {
		ng_put(ng);
		return PTR_ERR(mpol);
	}
	mpol->flags |= MPOL_MF_LAZY;
	mpol->numa_group = ng;

	down_write(&mm->mmap_sem);
	err = mpol_do_mbind(addr, len, mpol, MPOL_BIND,
			&mask, MPOL_MF_MOVE|MPOL_MF_LAZY);
	up_write(&mm->mmap_sem);
	mpol_put(mpol);
	ng_put(ng);

	if (!err) {
		/*
		 * There's a small overlap between ng and mm here, we only
		 * remove the mm after we associate the VMAs with the ng. Since
		 * lazy_migrate_vma() checks the mempolicy hierarchy this works
		 * out fine.
		 */
		dequeue_ne(&mm->numa);
	}

	return err;
}

#ifdef CONFIG_COMPAT

asmlinkage long compat_sys_numa_mbind(compat_ulong_t addr, compat_ulong_t len,
				      compat_int_t ng_id, compat_ulong_t flags)
{
	return sys_numa_mbind(addr, len, ng_id, flags);
}

asmlinkage long compat_sys_numa_tbind(compat_int_t tid, compat_int_t ng_id,
				      compat_ulong_t flags)
{
	return sys_numa_tbind(tid, ng_id, flags);
}

#endif /* CONFIG_COMPAT */

static __init int numa_group_init(void)
{
	init_srcu_struct(&ng_srcu);
	return 0;
}
early_initcall(numa_group_init);
