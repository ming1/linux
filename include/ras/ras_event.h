#undef TRACE_SYSTEM
#define TRACE_SYSTEM ras
#define TRACE_INCLUDE_FILE ras_event

#if !defined(_TRACE_HW_EVENT_MC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HW_EVENT_MC_H

#include <linux/tracepoint.h>
#include <linux/edac.h>
#include <linux/ktime.h>

/*
 * Hardware Events Report
 *
 * Those events are generated when hardware detected a corrected or
 * uncorrected event, and are meant to replace the current API to report
 * errors defined on both EDAC and MCE subsystems.
 *
 * FIXME: Add events for handling memory errors originated from the
 *        MCE subsystem.
 */

/*
 * Hardware-independent Memory Controller specific events
 */

/*
 * Default error mechanisms for Memory Controller errors (CE and UE)
 */
TRACE_EVENT(mc_event,

	TP_PROTO(const unsigned int err_type,
		 const unsigned int mc_index,
		 const char *error_msg,
		 const char *label,
		 int layer0,
		 int layer1,
		 int layer2,
		 unsigned long address,
		 unsigned long grain,
		 unsigned long syndrome,
		 const char *driver_detail),

	TP_ARGS(err_type, mc_index, error_msg, label, layer0, layer1, layer2,
		address, grain, syndrome, driver_detail),

	TP_STRUCT__entry(
		__field(	unsigned int,	err_type		)
		__field(	unsigned int,	mc_index		)
		__string(	msg,		error_msg		)
		__string(	label,		label			)
		__field(	int,		layer0			)
		__field(	int,		layer1			)
		__field(	int,		layer2			)
		__field(	int,		address			)
		__field(	int,		grain			)
		__field(	int,		syndrome		)
		__string(	driver_detail,	driver_detail		)
	),

	TP_fast_assign(
		__entry->err_type		= err_type;
		__entry->mc_index		= mc_index;
		__assign_str(msg, error_msg);
		__assign_str(label, label);
		__entry->layer0			= layer0;
		__entry->layer1			= layer1;
		__entry->layer2			= layer2;
		__entry->address		= address;
		__entry->grain			= grain;
		__entry->syndrome		= syndrome;
		__assign_str(driver_detail, driver_detail);
	),

	TP_printk("%s error:%s%s on memory stick \"%s\" (mc:%d location:%d:%d:%d address:0x%08x grain:%d syndrome:0x%08x%s%s)",
		  (__entry->err_type == HW_EVENT_ERR_CORRECTED) ? "Corrected" :
			((__entry->err_type == HW_EVENT_ERR_FATAL) ?
			"Fatal" : "Uncorrected"),
		  ((char *)__get_str(msg))[0] ? " " : "",
		  __get_str(msg),
		  __get_str(label),
		  __entry->mc_index,
		  __entry->layer0,
		  __entry->layer1,
		  __entry->layer2,
		  __entry->address,
		  __entry->grain,
		  __entry->syndrome,
		  ((char *)__get_str(driver_detail))[0] ? " " : "",
		  __get_str(driver_detail))
);

#endif /* _TRACE_HW_EVENT_MC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
