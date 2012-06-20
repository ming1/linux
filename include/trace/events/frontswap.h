#undef TRACE_SYSTEM
#define TRACE_SYSTEM frontswap

#if !defined(_TRACE_FRONTSWAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FRONTSWAP_H

#include <linux/tracepoint.h>

struct frontswap_ops;

TRACE_EVENT(frontswap_init,
	TP_PROTO(unsigned int type, void *sis, void *frontswap_map),
	TP_ARGS(type, sis, frontswap_map),

	TP_STRUCT__entry(
		__field(	unsigned int,	type		)
		__field(	void *,		sis		)
		__field(	void *,		frontswap_map	)
	),

	TP_fast_assign(
		__entry->type		= type;
		__entry->sis		= sis;
		__entry->frontswap_map	= frontswap_map;
	),

	TP_printk("type: %u sis: %p frontswap_map: %p",
		  __entry->type, __entry->sis, __entry->frontswap_map)
);

TRACE_EVENT(frontswap_register_ops,
	TP_PROTO(struct frontswap_ops *old, struct frontswap_ops *new),
	TP_ARGS(old, new),

	TP_STRUCT__entry(
		__field(struct frontswap_ops *,		old		)
		__field(struct frontswap_ops *,		new		)
	),

	TP_fast_assign(
		__entry->old		= old;
		__entry->new		= new;
	),

	TP_printk("old: {init=%p store=%p load=%p invalidate_page=%p invalidate_area=%p}"
		" new: {init=%p store=%p load=%p invalidate_page=%p invalidate_area=%p}",
		__entry->old->init,__entry->old->store,__entry->old->load,
		__entry->old->invalidate_page,__entry->old->invalidate_area,__entry->new->init,
		__entry->new->store,__entry->new->load,__entry->new->invalidate_page,
		__entry->new->invalidate_area)
);

TRACE_EVENT(frontswap_store,
	TP_PROTO(void *page, int dup, int ret),
	TP_ARGS(page, dup, ret),

	TP_STRUCT__entry(
		__field(	int,		dup		)
		__field(	int,		ret		)
		__field(	void *,		page		)
	),

	TP_fast_assign(
		__entry->dup		= dup;
		__entry->ret		= ret;
		__entry->page		= page;
	),

	TP_printk("page: %p dup: %d ret: %d",
		  __entry->page, __entry->dup, __entry->ret)
);

TRACE_EVENT(frontswap_load,
	TP_PROTO(void *page, int ret),
	TP_ARGS(page, ret),

	TP_STRUCT__entry(
		__field(	int,		ret		)
		__field(	void *,		page		)
	),

	TP_fast_assign(
		__entry->ret		= ret;
		__entry->page		= page;
	),

	TP_printk("page: %p ret: %d",
		  __entry->page, __entry->ret)
);

TRACE_EVENT(frontswap_invalidate_page,
	TP_PROTO(int type, unsigned long offset, void *sis, int test),
	TP_ARGS(type, offset, sis, test),

	TP_STRUCT__entry(
		__field(	int,		type		)
		__field(	unsigned long,	offset		)
		__field(	void *,		sis		)
		__field(	int,		test		)
	),

	TP_fast_assign(
		__entry->type		= type;
		__entry->offset		= offset;
		__entry->sis		= sis;
		__entry->test		= test;
	),

	TP_printk("type: %d offset: %lu sys: %p frontswap_test: %d",
		  __entry->type, __entry->offset, __entry->sis, __entry->test)
);

TRACE_EVENT(frontswap_invalidate_area,
	TP_PROTO(int type, void *sis, void *map),
	TP_ARGS(type, sis, map),

	TP_STRUCT__entry(
		__field(	int,		type		)
		__field(	void *,		map		)
		__field(	void *,		sis		)
	),

	TP_fast_assign(
		__entry->type		= type;
		__entry->sis		= sis;
		__entry->map		= map;
	),

	TP_printk("type: %d sys: %p map: %p",
		  __entry->type, __entry->sis, __entry->map)
);

TRACE_EVENT(frontswap_curr_pages,
	TP_PROTO(unsigned long totalpages),
	TP_ARGS(totalpages),

	TP_STRUCT__entry(
		__field(unsigned long,		totalpages	)
	),

	TP_fast_assign(
		__entry->totalpages	= totalpages;
	),

	TP_printk("total pages: %lu",
		  __entry->totalpages)
);

TRACE_EVENT(frontswap_shrink,
	TP_PROTO(unsigned long target_pages),
	TP_ARGS(target_pages),

	TP_STRUCT__entry(
		__field(unsigned long,		target_pages	)
	),

	TP_fast_assign(
		__entry->target_pages	= target_pages;
	),

	TP_printk("target pages: %lu",
		  __entry->target_pages)
);

#endif /* _TRACE_FRONTSWAP_H */

#include <trace/define_trace.h>
