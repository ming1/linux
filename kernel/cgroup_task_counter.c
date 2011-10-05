/*
 * Limits on number of tasks subsystem for cgroups
 *
 * Copyright (C) 2011 Red Hat, Inc., Frederic Weisbecker <fweisbec@redhat.com>
 *
 * Thanks to Andrew Morton, Johannes Weiner, Li Zefan, Oleg Nesterov and
 * Paul Menage for their suggestions.
 *
 */

#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/res_counter.h>


struct task_counter {
	struct res_counter		res;
	struct cgroup_subsys_state	css;
};

/*
 * The root task counter doesn't exist because it's not part of the
 * whole task counting. We want to optimize the trivial case of only
 * one root cgroup living.
 */
static struct cgroup_subsys_state root_css;


static inline struct task_counter *cgroup_task_counter(struct cgroup *cgrp)
{
	if (!cgrp->parent)
		return NULL;

	return container_of(cgroup_subsys_state(cgrp, tasks_subsys_id),
			    struct task_counter, css);
}

static inline struct res_counter *cgroup_task_res_counter(struct cgroup *cgrp)
{
	struct task_counter *cnt;

	cnt = cgroup_task_counter(cgrp);
	if (!cnt)
		return NULL;

	return &cnt->res;
}

static struct cgroup_subsys_state *
task_counter_create(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	struct task_counter *cnt;
	struct res_counter *parent_res;

	if (!cgrp->parent)
		return &root_css;

	cnt = kzalloc(sizeof(*cnt), GFP_KERNEL);
	if (!cnt)
		return ERR_PTR(-ENOMEM);

	parent_res = cgroup_task_res_counter(cgrp->parent);

	res_counter_init(&cnt->res, parent_res);

	return &cnt->css;
}

/*
 * Inherit the limit value of the parent. This is not really to enforce
 * a limit below or equal to the one of the parent which can be changed
 * concurrently anyway. This is just to honour the clone flag.
 */
static void task_counter_post_clone(struct cgroup_subsys *ss,
				    struct cgroup *cgrp)
{
	/* cgrp can't be root, so cgroup_task_res_counter() can't return NULL */
	res_counter_inherit(cgroup_task_res_counter(cgrp), RES_LIMIT);
}

static void task_counter_destroy(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	struct task_counter *cnt = cgroup_task_counter(cgrp);

	kfree(cnt);
}

/* Uncharge the cgroup the task was attached to */
static void task_counter_exit(struct cgroup_subsys *ss, struct cgroup *cgrp,
			      struct cgroup *old_cgrp, struct task_struct *task)
{
	/* Optimize for the root cgroup case */
	if (old_cgrp->parent)
		res_counter_uncharge(cgroup_task_res_counter(old_cgrp), 1);
}

/*
 * Protected amongst can_attach_task/attach_task/cancel_attach_task by
 * cgroup mutex
 */
static struct res_counter *common_ancestor;

/*
 * This does more than just probing the ability to attach to the dest cgroup.
 * We can not just _check_ if we can attach to the destination and do the real
 * attachment later in task_counter_attach_task() because a task in the dest
 * cgroup can fork before and steal the last remaining count.
 * Thus we need to charge the dest cgroup right now.
 */
static int task_counter_can_attach_task(struct cgroup *cgrp,
					struct cgroup *old_cgrp,
					struct task_struct *tsk)
{
	struct res_counter *res = cgroup_task_res_counter(cgrp);
	struct res_counter *old_res = cgroup_task_res_counter(old_cgrp);
	int err;

	/*
	 * When moving a task from a cgroup to another, we don't want
	 * to charge the common ancestors, even though they will be
	 * uncharged later from attach_task(), because during that
	 * short window between charge and uncharge, a task could fork
	 * in the ancestor and spuriously fail due to the temporary
	 * charge.
	 */
	common_ancestor = res_counter_common_ancestor(res, old_res);

	/*
	 * If cgrp is the root then res is NULL, however in this case
	 * the common ancestor is NULL as well, making the below a NOP.
	 */
	err = res_counter_charge_until(res, common_ancestor, 1, NULL);
	if (err)
		return -EINVAL;

	return 0;
}

/* Uncharge the dest cgroup that we charged in task_counter_can_attach_task() */
static void task_counter_cancel_attach_task(struct cgroup *cgrp,
					    struct task_struct *tsk)
{
	res_counter_uncharge_until(cgroup_task_res_counter(cgrp),
				   common_ancestor, 1);
}

/*
 * This uncharge the old cgroup. We can do that now that we are sure the
 * attachment can't cancelled anymore, because this uncharge operation
 * couldn't be reverted later: a task in the old cgroup could fork after
 * we uncharge and reach the task counter limit, making our return there
 * not possible.
 */
static void task_counter_attach_task(struct cgroup *cgrp,
				     struct cgroup *old_cgrp,
				     struct task_struct *tsk)
{
	res_counter_uncharge_until(cgroup_task_res_counter(old_cgrp),
				   common_ancestor, 1);
}

static u64 task_counter_read_u64(struct cgroup *cgrp, struct cftype *cft)
{
	int type = cft->private;

	return res_counter_read_u64(cgroup_task_res_counter(cgrp), type);
}

static int task_counter_write_u64(struct cgroup *cgrp, struct cftype *cft,
				  u64 val)
{
	int type = cft->private;

	res_counter_write_u64(cgroup_task_res_counter(cgrp), type, val);

	return 0;
}

static struct cftype files[] = {
	{
		.name		= "limit",
		.read_u64	= task_counter_read_u64,
		.write_u64	= task_counter_write_u64,
		.private	= RES_LIMIT,
	},

	{
		.name		= "usage",
		.read_u64	= task_counter_read_u64,
		.private	= RES_USAGE,
	},
};

static int task_counter_populate(struct cgroup_subsys *ss, struct cgroup *cgrp)
{
	if (!cgrp->parent)
		return 0;

	return cgroup_add_files(cgrp, ss, files, ARRAY_SIZE(files));
}

/*
 * Charge the task counter with the new child coming, or reject it if we
 * reached the limit.
 */
static int task_counter_fork(struct cgroup_subsys *ss,
			     struct task_struct *child)
{
	struct cgroup_subsys_state *css;
	struct cgroup *cgrp;
	int err;

	css = child->cgroups->subsys[tasks_subsys_id];
	cgrp = css->cgroup;

	/* Optimize for the root cgroup case, which doesn't have a limit */
	if (!cgrp->parent)
		return 0;

	err = res_counter_charge(cgroup_task_res_counter(cgrp), 1, NULL);
	if (err)
		return -EAGAIN;

	return 0;
}

struct cgroup_subsys tasks_subsys = {
	.name			= "tasks",
	.subsys_id		= tasks_subsys_id,
	.create			= task_counter_create,
	.post_clone		= task_counter_post_clone,
	.destroy		= task_counter_destroy,
	.exit			= task_counter_exit,
	.can_attach_task	= task_counter_can_attach_task,
	.cancel_attach_task	= task_counter_cancel_attach_task,
	.attach_task		= task_counter_attach_task,
	.fork			= task_counter_fork,
	.populate		= task_counter_populate,
};
