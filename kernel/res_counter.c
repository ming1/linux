/*
 * resource cgroups
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 *
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 */

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/fs.h>
#include <linux/res_counter.h>
#include <linux/uaccess.h>
#include <linux/mm.h>

void res_counter_init(struct res_counter *counter, struct res_counter *parent)
{
	spin_lock_init(&counter->lock);
	counter->limit = RESOURCE_MAX;
	counter->soft_limit = RESOURCE_MAX;
	counter->parent = parent;
}

int res_counter_charge_locked(struct res_counter *counter, unsigned long val)
{
	if (counter->usage + val > counter->limit) {
		counter->failcnt++;
		return -ENOMEM;
	}

	counter->usage += val;
	if (counter->usage > counter->max_usage)
		counter->max_usage = counter->usage;
	return 0;
}

int res_counter_charge_until(struct res_counter *counter,
			     struct res_counter *limit, unsigned long val,
			     struct res_counter **limit_fail_at)
{
	int ret;
	unsigned long flags;
	struct res_counter *c, *u;

	*limit_fail_at = NULL;
	local_irq_save(flags);
	for (c = counter; c != limit; c = c->parent) {
		spin_lock(&c->lock);
		ret = res_counter_charge_locked(c, val);
		spin_unlock(&c->lock);
		if (ret < 0) {
			*limit_fail_at = c;
			goto undo;
		}
	}
	ret = 0;
	goto done;
undo:
	for (u = counter; u != c; u = u->parent) {
		spin_lock(&u->lock);
		res_counter_uncharge_locked(u, val);
		spin_unlock(&u->lock);
	}
done:
	local_irq_restore(flags);
	return ret;
}

void res_counter_uncharge_locked(struct res_counter *counter, unsigned long val)
{
	if (WARN_ON(counter->usage < val))
		val = counter->usage;

	counter->usage -= val;
}

void res_counter_uncharge_until(struct res_counter *counter,
				struct res_counter *limit,
				unsigned long val)
{
	unsigned long flags;
	struct res_counter *c;

	local_irq_save(flags);
	for (c = counter; c != limit; c = c->parent) {
		spin_lock(&c->lock);
		res_counter_uncharge_locked(c, val);
		spin_unlock(&c->lock);
	}
	local_irq_restore(flags);
}

/*
 * Walk through r1 and r2 parents and try to find the closest common one
 * between both. If none is found, it returns NULL.
 */
struct res_counter *
res_counter_common_ancestor(struct res_counter *r1, struct res_counter *r2)
{
	struct res_counter *iter;
	int r1_depth = 0, r2_depth = 0;

	for (iter = r1; iter; iter = iter->parent)
		r1_depth++;

	for (iter = r2; iter; iter = iter->parent)
		r2_depth++;

	while (r1_depth > r2_depth) {
		r1 = r1->parent;
		r1_depth--;
	}

	while (r2_depth > r1_depth) {
		r2 = r2->parent;
		r2_depth--;
	}

	while (r1 != r2) {
		r1 = r1->parent;
		r2 = r2->parent;
	}

	return r1;
}

static inline unsigned long long *
res_counter_member(struct res_counter *counter, int member)
{
	switch (member) {
	case RES_USAGE:
		return &counter->usage;
	case RES_MAX_USAGE:
		return &counter->max_usage;
	case RES_LIMIT:
		return &counter->limit;
	case RES_FAILCNT:
		return &counter->failcnt;
	case RES_SOFT_LIMIT:
		return &counter->soft_limit;
	};

	BUG();
	return NULL;
}

ssize_t res_counter_read(struct res_counter *counter, int member,
		const char __user *userbuf, size_t nbytes, loff_t *pos,
		int (*read_strategy)(unsigned long long val, char *st_buf))
{
	unsigned long long *val;
	char buf[64], *s;

	s = buf;
	val = res_counter_member(counter, member);
	if (read_strategy)
		s += read_strategy(*val, s);
	else
		s += sprintf(s, "%llu\n", *val);
	return simple_read_from_buffer((void __user *)userbuf, nbytes,
			pos, buf, s - buf);
}

#if BITS_PER_LONG == 32
u64 res_counter_read_u64(struct res_counter *counter, int member)
{
	unsigned long flags;
	u64 ret;

	spin_lock_irqsave(&counter->lock, flags);
	ret = *res_counter_member(counter, member);
	spin_unlock_irqrestore(&counter->lock, flags);

	return ret;
}
#else
u64 res_counter_read_u64(struct res_counter *counter, int member)
{
	return *res_counter_member(counter, member);
}
#endif

int res_counter_memparse_write_strategy(const char *buf,
					unsigned long long *res)
{
	char *end;

	/* return RESOURCE_MAX(unlimited) if "-1" is specified */
	if (*buf == '-') {
		*res = simple_strtoull(buf + 1, &end, 10);
		if (*res != 1 || *end != '\0')
			return -EINVAL;
		*res = RESOURCE_MAX;
		return 0;
	}

	/* FIXME - make memparse() take const char* args */
	*res = memparse((char *)buf, &end);
	if (*end != '\0')
		return -EINVAL;

	*res = PAGE_ALIGN(*res);
	return 0;
}

void res_counter_write_u64(struct res_counter *counter, int member, u64 val)
{
	unsigned long long *target;
	unsigned long flags;

	/*
	 * We need the lock to protect against concurrent add/dec on 32 bits.
	 * No need to ifdef it's seldom used.
	 */
	spin_lock_irqsave(&counter->lock, flags);
	target = res_counter_member(counter, member);
	*target = val;
	spin_unlock_irqrestore(&counter->lock, flags);
}

int res_counter_write(struct res_counter *counter, int member,
		      const char *buf, write_strategy_fn write_strategy)
{
	char *end;
	unsigned long long tmp;

	if (write_strategy) {
		if (write_strategy(buf, &tmp))
			return -EINVAL;
	} else {
		tmp = simple_strtoull(buf, &end, 10);
		if (*end != '\0')
			return -EINVAL;
	}

	res_counter_write_u64(counter, member, tmp);

	return 0;
}

/*
 * Simple inheritance implementation to get the same value
 * than a parent. However this doesn't enforce the child value
 * to be always below the one of the parent. But the child is
 * subject to its parent limitation anyway.
 */
void res_counter_inherit(struct res_counter *counter, int member)
{
	struct res_counter *parent;
	unsigned long long val;

	parent = counter->parent;
	if (parent) {
		val = res_counter_read_u64(parent, member);
		res_counter_write_u64(counter, member, val);
	}
}
