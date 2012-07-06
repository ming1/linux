#undef TRACE_SYSTEM
#define TRACE_SYSTEM random

#if !defined(_TRACE_RANDOM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RANDOM_H

#include <linux/writeback.h>
#include <linux/tracepoint.h>

TRACE_EVENT(mix_pool_bytes,
	TP_PROTO(const char *pool_name, int bytes, unsigned long IP),

	TP_ARGS(pool_name, bytes, IP),

	TP_STRUCT__entry(
		__field( const char *,	pool_name		)
		__field(	  int,	bytes			)
		__field(unsigned long,	IP			)
	),

	TP_fast_assign(
		__entry->pool_name	= pool_name;
		__entry->bytes		= bytes;
		__entry->IP		= IP;
	),

	TP_printk("pool %s bytes %d caller %pF",
		  __entry->pool_name, __entry->bytes, (void *)__entry->IP)
);

TRACE_EVENT(credit_entropy_bits,
	TP_PROTO(const char *pool_name, int bits, int entropy_count,
		 int entropy_total, unsigned long IP),

	TP_ARGS(pool_name, bits, entropy_count, entropy_total, IP),

	TP_STRUCT__entry(
		__field( const char *,	pool_name		)
		__field(	  int,	bits			)
		__field(	  int,	entropy_count		)
		__field(	  int,	entropy_total		)
		__field(unsigned long,	IP			)
	),

	TP_fast_assign(
		__entry->pool_name	= pool_name;
		__entry->bits		= bits;
		__entry->entropy_count	= entropy_count;
		__entry->entropy_total	= entropy_total;
		__entry->IP		= IP;
	),

	TP_printk("pool %s bits %d entropy_count %d entropy_total %d "
		  "caller %pF", __entry->pool_name, __entry->bits,
		  __entry->entropy_count, __entry->entropy_total,
		  (void *)__entry->IP)
);

TRACE_EVENT(get_random_bytes,
	TP_PROTO(int nbytes, unsigned long IP),

	TP_ARGS(nbytes, IP),

	TP_STRUCT__entry(
		__field(	  int,	nbytes			)
		__field(unsigned long,	IP			)
	),

	TP_fast_assign(
		__entry->nbytes		= nbytes;
		__entry->IP		= IP;
	),

	TP_printk("nbytes %d caller %pF", __entry->nbytes, (void *)__entry->IP)
);

TRACE_EVENT(extract_entropy,
	TP_PROTO(const char *pool_name, int nbytes, int entropy_count,
		 unsigned long IP),

	TP_ARGS(pool_name, nbytes, entropy_count, IP),

	TP_STRUCT__entry(
		__field( const char *,	pool_name		)
		__field(	  int,	nbytes			)
		__field(	  int,	entropy_count		)
		__field(unsigned long,	IP			)
	),

	TP_fast_assign(
		__entry->pool_name	= pool_name;
		__entry->nbytes		= nbytes;
		__entry->entropy_count	= entropy_count;
		__entry->IP		= IP;
	),

	TP_printk("pool %s nbytes %d entropy_count %d caller %pF",
		  __entry->pool_name, __entry->nbytes, __entry->entropy_count,
		  (void *)__entry->IP)
);

TRACE_EVENT(extract_entropy_user,
	TP_PROTO(const char *pool_name, int nbytes, int entropy_count,
		 unsigned long IP),

	TP_ARGS(pool_name, nbytes, entropy_count, IP),

	TP_STRUCT__entry(
		__field( const char *,	pool_name		)
		__field(	  int,	nbytes			)
		__field(	  int,	entropy_count		)
		__field(unsigned long,	IP			)
	),

	TP_fast_assign(
		__entry->pool_name	= pool_name;
		__entry->nbytes		= nbytes;
		__entry->entropy_count	= entropy_count;
		__entry->IP		= IP;
	),

	TP_printk("pool %s nbytes %d entropy_count %d caller %pF",
		  __entry->pool_name, __entry->nbytes, __entry->entropy_count,
		  (void *)__entry->IP)
);



#endif /* _TRACE_RANDOM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
