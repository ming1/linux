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

#include "sched.h"


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
	int home_node = tsk_home_node(p);
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

	if (!sched_feat(NUMA_SELECT)) {
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

static int __cpuinit
numa_hotplug(struct notifier_block *nb, unsigned long action, void *hcpu)
{
	int cpu = (long)hcpu;
	int node = cpu_to_node(cpu);
	struct node_queue *nq = nq_of(node);
	struct task_struct *numad;
	int err = 0;

	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_UP_PREPARE:
		if (nq->numad)
			break;

		numad = kthread_create_on_node(numad_thread,
				nq, node, "numad/%d", node);
		if (IS_ERR(numad)) {
			err = PTR_ERR(numad);
			break;
		}

		nq->numad = numad;
		nq->next_schedule = jiffies + HZ; // XXX sync-up?
		break;

	case CPU_ONLINE:
		wake_up_process(nq->numad);
		break;

	case CPU_DEAD:
	case CPU_UP_CANCELED:
		if (!nq->numad)
			break;

		if (cpumask_any_and(cpu_online_mask,
				    cpumask_of_node(node)) >= nr_cpu_ids) {
			kthread_stop(nq->numad);
			nq->numad = NULL;
		}
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
