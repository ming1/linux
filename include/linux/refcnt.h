/*
 * Use these types iff
 * a) object is created with refcount 1, and
 * b) every GET does +1, and
 * c) every PUT does -1, and
 * d) once refcount reaches 0, object is destroyed.
 *
 * Do not use otherwise.
 *
 * Use underscored version if refcount manipulations are already under
 * some sort of locking making additional atomicity unnecessary.
 */
#ifndef _LINUX_REFCNT_H
#define _LINUX_REFCNT_H
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/types.h>

typedef struct {
	int n;
} _refcnt_t;
#define _REFCNT_INIT	((_refcnt_t){ .n = 1 })

static inline void _refcnt_init(_refcnt_t *refcnt)
{
	refcnt->n = 1;
}

static inline void _refcnt_get(_refcnt_t *refcnt)
{
	if (IS_ENABLED(CONFIG_DEBUG_REFCNT))
		BUG_ON(refcnt->n < 1);
	refcnt->n++;
}

/*
 * Return 1 if PUT turned out to be last PUT, return 0 otherwise.
 *
 *	if (_refcnt_put(&obj->refcnt)) {
 *		[destroy object]
 *	}
 */
static inline int _refcnt_put(_refcnt_t *refcnt)
{
	if (IS_ENABLED(CONFIG_DEBUG_REFCNT))
		BUG_ON(refcnt->n < 1);
	refcnt->n--;
	return refcnt->n == 0;
}

typedef struct {
	atomic_t n;
} refcnt_t;
#define REFCNT_INIT	((refcnt_t){ .n = ATOMIC_INIT(1) })

static inline void refcnt_init(refcnt_t *refcnt)
{
	atomic_set(&refcnt->n, 1);
}

static inline void refcnt_get(refcnt_t *refcnt)
{
	if (IS_ENABLED(CONFIG_DEBUG_REFCNT)) {
		int rv;

		rv = atomic_inc_return(&refcnt->n);
		BUG_ON(rv < 2);
	} else
		atomic_inc(&refcnt->n);
}

/*
 * Return 1 if PUT turned out to be last PUT, return 0 otherwise.
 *
 *	if (refcnt_put(&obj->refcnt)) {
 *		[destroy object]
 *	}
 */
static inline int refcnt_put(refcnt_t *refcnt)
{
	if (IS_ENABLED(CONFIG_DEBUG_REFCNT)) {
		int rv;

		rv = atomic_dec_return(&refcnt->n);
		BUG_ON(rv < 0);
		return rv == 0;
	} else
		return atomic_dec_and_test(&refcnt->n);
}
#endif
