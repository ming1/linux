#undef TRACE_SYSTEM
#define TRACE_SYSTEM irq_vectors

#if !defined(_TRACE_IRQ_VECTORS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IRQ_VECTORS_H

#include <linux/tracepoint.h>
#include <asm/irq.h>

#ifndef irq_vector_name_table
#define irq_vector_name_table { -1, NULL }
#endif

DECLARE_EVENT_CLASS(irq_vector,

	TP_PROTO(int irq),

	TP_ARGS(irq),

	TP_STRUCT__entry(
		__field(	int,	irq	)
	),

	TP_fast_assign(
		__entry->irq = irq;
	),

	TP_printk("irq=%d name=%s", __entry->irq,
		__print_symbolic(__entry->irq, irq_vector_name_table))
);

/*
 * irq_vector_entry - called before enterring a interrupt vector handler
 */
DEFINE_EVENT(irq_vector, irq_vector_entry,

	TP_PROTO(int irq),

	TP_ARGS(irq)
);

/*
 * irq_vector_exit - called immediately after the interrupt vector
 * handler returns
 */
DEFINE_EVENT(irq_vector, irq_vector_exit,

	TP_PROTO(int irq),

	TP_ARGS(irq)
);

#endif /*  _TRACE_IRQ_VECTORS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
