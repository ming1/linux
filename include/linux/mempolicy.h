#ifndef _LINUX_MEMPOLICY_H
#define _LINUX_MEMPOLICY_H 1

#include <linux/errno.h>

/*
 * NUMA memory policies for Linux.
 * Copyright 2003,2004 Andi Kleen SuSE Labs
 */

/*
 * Both the MPOL_* mempolicy mode and the MPOL_F_* optional mode flags are
 * passed by the user to either set_mempolicy() or mbind() in an 'int' actual.
 * The MPOL_MODE_FLAGS macro determines the legal set of optional mode flags.
 */

/* Policies */
enum {
	MPOL_DEFAULT,
	MPOL_PREFERRED,
	MPOL_BIND,
	MPOL_INTERLEAVE,
	MPOL_LOCAL,
	MPOL_NOOP,		/* retain existing policy for range */
	MPOL_MAX,	/* always last member of enum */
};

enum mpol_rebind_step {
	MPOL_REBIND_ONCE,	/* do rebind work at once(not by two step) */
	MPOL_REBIND_STEP1,	/* first step(set all the newly nodes) */
	MPOL_REBIND_STEP2,	/* second step(clean all the disallowed nodes)*/
	MPOL_REBIND_NSTEP,
};

/* Flags for set_mempolicy */
#define MPOL_F_STATIC_NODES	(1 << 15)
#define MPOL_F_RELATIVE_NODES	(1 << 14)

/*
 * MPOL_MODE_FLAGS is the union of all possible optional mode flags passed to
 * either set_mempolicy() or mbind().
 */
#define MPOL_MODE_FLAGS	(MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES)

/* Flags for get_mempolicy */
#define MPOL_F_NODE	(1<<0)	/* return next IL mode instead of node mask */
#define MPOL_F_ADDR	(1<<1)	/* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

/* Flags for mbind */
#define MPOL_MF_STRICT	(1<<0)	/* Verify existing pages in the mapping */
#define MPOL_MF_MOVE	 (1<<1)	/* Move pages owned by this process to conform
				   to policy */
#define MPOL_MF_MOVE_ALL (1<<2)	/* Move every page to conform to policy */
#define MPOL_MF_LAZY	 (1<<3)	/* Modifies '_MOVE:  lazy migrate on fault */
#define MPOL_MF_INTERNAL (1<<4)	/* Internal flags start here */

#define MPOL_MF_VALID	(MPOL_MF_STRICT   | 	\
			 MPOL_MF_MOVE     | 	\
			 MPOL_MF_MOVE_ALL |	\
			 MPOL_MF_LAZY)

/*
 * Internal flags that share the struct mempolicy flags word with
 * "mode flags".  These flags are allocated from bit 0 up, as they
 * are never OR'ed into the mode in mempolicy API arguments.
 */
#define MPOL_F_SHARED  (1 << 0)	/* identify shared policies */
#define MPOL_F_LOCAL   (1 << 1)	/* preferred local allocation */
#define MPOL_F_REBINDING (1 << 2)	/* identify policies in rebinding */
#define MPOL_F_MOF	(1 << 3) /* this policy wants migrate on fault */

#ifdef __KERNEL__

#include <linux/mmzone.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/nodemask.h>
#include <linux/pagemap.h>
#include <linux/migrate.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/mm_types.h>

#ifdef CONFIG_NUMA
/*
 * Support for managing mempolicy data objects (clone, copy, destroy)
 * The default fast path of a NULL MPOL_DEFAULT policy is always inlined.
 */

extern void __mpol_put(struct mempolicy *pol);
static inline void mpol_put(struct mempolicy *pol)
{
	if (pol)
		__mpol_put(pol);
}

/*
 * Does mempolicy pol need explicit unref after use?
 * Currently only needed for shared policies.
 */
static inline int mpol_needs_cond_ref(struct mempolicy *pol)
{
	return (pol && (pol->flags & MPOL_F_SHARED));
}

static inline void mpol_cond_put(struct mempolicy *pol)
{
	if (mpol_needs_cond_ref(pol))
		__mpol_put(pol);
}

extern struct mempolicy *__mpol_cond_copy(struct mempolicy *tompol,
					  struct mempolicy *frompol);
static inline struct mempolicy *mpol_cond_copy(struct mempolicy *tompol,
						struct mempolicy *frompol)
{
	if (!frompol)
		return frompol;
	return __mpol_cond_copy(tompol, frompol);
}

extern struct mempolicy *__mpol_dup(struct mempolicy *pol);
static inline struct mempolicy *mpol_dup(struct mempolicy *pol)
{
	if (pol)
		pol = __mpol_dup(pol);
	return pol;
}

#define vma_policy(vma) ((vma)->vm_policy)
#define vma_set_policy(vma, pol) ((vma)->vm_policy = (pol))

extern int vma_dup_policy(struct vm_area_struct *new, struct vm_area_struct *old);
extern void vma_put_policy(struct vm_area_struct *vma);

static inline void mpol_get(struct mempolicy *pol)
{
	if (pol)
		atomic_inc(&pol->refcnt);
}

extern bool __mpol_equal(struct mempolicy *a, struct mempolicy *b);
static inline bool mpol_equal(struct mempolicy *a, struct mempolicy *b)
{
	if (a == b)
		return true;
	return __mpol_equal(a, b);
}

/*
 * Tree of shared policies for a shared memory region.
 * Maintain the policies in a pseudo mm that contains vmas. The vmas
 * carry the policy. As a special twist the pseudo mm is indexed in pages, not
 * bytes, so that we can work with shared memory segments bigger than
 * unsigned long.
 */

struct sp_node {
	struct rb_node nd;
	unsigned long start, end;
	struct mempolicy *policy;
};

struct shared_policy {
	struct rb_root root;
	spinlock_t lock;
};

extern struct mempolicy *mpol_new(unsigned short mode, unsigned short flags,
				  nodemask_t *nodes);
extern long mpol_do_mbind(unsigned long start, unsigned long len,
				struct mempolicy *policy, unsigned long mode,
				nodemask_t *nmask, unsigned long flags);

void mpol_shared_policy_init(struct shared_policy *sp, struct mempolicy *mpol);
int mpol_set_shared_policy(struct shared_policy *info,
				struct vm_area_struct *vma,
				struct mempolicy *new);
void mpol_free_shared_policy(struct shared_policy *p);
struct mempolicy *mpol_shared_policy_lookup(struct shared_policy *sp,
					    unsigned long idx);

struct mempolicy *get_vma_policy(struct task_struct *tsk,
		struct vm_area_struct *vma, unsigned long addr);

extern void numa_default_policy(void);
extern void numa_policy_init(void);
extern void mpol_rebind_policy(struct mempolicy *pol, const nodemask_t *new,
				enum mpol_rebind_step step);
extern void mpol_rebind_task(struct task_struct *tsk, const nodemask_t *new,
				enum mpol_rebind_step step);
extern void mpol_rebind_mm(struct mm_struct *mm, nodemask_t *new);
extern void mpol_fix_fork_child_flag(struct task_struct *p);

extern struct zonelist *huge_zonelist(struct vm_area_struct *vma,
				unsigned long addr, gfp_t gfp_flags,
				struct mempolicy **mpol, nodemask_t **nodemask);
extern bool init_nodemask_of_mempolicy(nodemask_t *mask);
extern bool mempolicy_nodemask_intersects(struct task_struct *tsk,
				const nodemask_t *mask);
extern unsigned slab_node(struct mempolicy *policy);

extern enum zone_type policy_zone;

static inline void check_highest_zone(enum zone_type k)
{
	if (k > policy_zone && k != ZONE_MOVABLE)
		policy_zone = k;
}

int do_migrate_pages(struct mm_struct *mm,
	const nodemask_t *from_nodes, const nodemask_t *to_nodes, int flags);


#ifdef CONFIG_TMPFS
extern int mpol_parse_str(char *str, struct mempolicy **mpol, int no_context);
#endif

extern int mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol,
			int no_context);

extern int vma_migratable(struct vm_area_struct *);

extern int mpol_misplaced(struct page *, struct vm_area_struct *, unsigned long);

extern void lazy_migrate_vma(struct vm_area_struct *vma, int node);
extern void lazy_migrate_process(struct mm_struct *mm, int node);

#else

struct mempolicy {};

static inline bool mpol_equal(struct mempolicy *a, struct mempolicy *b)
{
	return true;
}

static inline void mpol_put(struct mempolicy *p)
{
}

static inline void mpol_cond_put(struct mempolicy *pol)
{
}

static inline struct mempolicy *mpol_cond_copy(struct mempolicy *to,
						struct mempolicy *from)
{
	return from;
}

static inline void mpol_get(struct mempolicy *pol)
{
}

static inline struct mempolicy *mpol_dup(struct mempolicy *old)
{
	return NULL;
}

struct shared_policy {};

static inline int mpol_set_shared_policy(struct shared_policy *info,
					struct vm_area_struct *vma,
					struct mempolicy *new)
{
	return -EINVAL;
}

static inline void mpol_shared_policy_init(struct shared_policy *sp,
						struct mempolicy *mpol)
{
}

static inline void mpol_free_shared_policy(struct shared_policy *p)
{
}

static inline struct mempolicy *
mpol_shared_policy_lookup(struct shared_policy *sp, unsigned long idx)
{
	return NULL;
}

#define vma_policy(vma) NULL
#define vma_set_policy(vma, pol) do {} while(0)
#define vma_dup_policy(new, old) (0)

static inline void vma_put_policy(struct vm_area_struct *vma)
{
}

static inline void numa_policy_init(void)
{
}

static inline void numa_default_policy(void)
{
}

static inline void mpol_rebind_task(struct task_struct *tsk,
				const nodemask_t *new,
				enum mpol_rebind_step step)
{
}

static inline void mpol_rebind_mm(struct mm_struct *mm, nodemask_t *new)
{
}

static inline void mpol_fix_fork_child_flag(struct task_struct *p)
{
}

static inline struct zonelist *huge_zonelist(struct vm_area_struct *vma,
				unsigned long addr, gfp_t gfp_flags,
				struct mempolicy **mpol, nodemask_t **nodemask)
{
	*mpol = NULL;
	*nodemask = NULL;
	return node_zonelist(0, gfp_flags);
}

static inline bool init_nodemask_of_mempolicy(nodemask_t *m)
{
	return false;
}

static inline bool mempolicy_nodemask_intersects(struct task_struct *tsk,
			const nodemask_t *mask)
{
	return false;
}

static inline int do_migrate_pages(struct mm_struct *mm,
			const nodemask_t *from_nodes,
			const nodemask_t *to_nodes, int flags)
{
	return 0;
}

static inline void check_highest_zone(int k)
{
}

#ifdef CONFIG_TMPFS
static inline int mpol_parse_str(char *str, struct mempolicy **mpol,
				int no_context)
{
	return 1;	/* error */
}
#endif

static inline int mpol_to_str(char *buffer, int maxlen, struct mempolicy *pol,
				int no_context)
{
	return 0;
}

#endif /* CONFIG_NUMA */

#ifdef CONFIG_NUMA

extern void __numa_task_exit(struct task_struct *);
extern void numa_vma_link(struct vm_area_struct *, struct vm_area_struct *);
extern void numa_vma_unlink(struct vm_area_struct *);

static inline void numa_task_exit(struct task_struct *p)
{
	if (p->numa_group)
		__numa_task_exit(p);
}

#else /* CONFIG_NUMA */

static inline void numa_task_exit(struct task_struct *p) { }
static inline void numa_vma_link(struct vm_area_struct *new, struct vm_area_struct *old) { }
static inline void numa_vma_unlink(struct vm_area_struct *vma) { }

#endif /* CONFIG_NUMA */

#endif /* __KERNEL__ */

#endif
