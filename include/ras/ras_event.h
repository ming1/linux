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
		 const char *location,
		 const char *core_detail,
		 const char *driver_detail),

	TP_ARGS(err_type, mc_index, error_msg, label, location,
		core_detail, driver_detail),

	TP_STRUCT__entry(
		__field(	unsigned int,	err_type		)
		__field(	unsigned int,	mc_index		)
		__string(	msg,		error_msg		)
		__string(	label,		label			)
		__string(	detail,		core_detail		)
		__string(	location,	location		)
		__string(	driver_detail,	driver_detail		)
	),

	TP_fast_assign(
		__entry->err_type		= err_type;
		__entry->mc_index		= mc_index;
		__assign_str(msg, error_msg);
		__assign_str(label, label);
		__assign_str(location, location);
		__assign_str(detail, core_detail);
		__assign_str(driver_detail, driver_detail);
	),

	TP_printk("%s error:%s%s on memory stick \"%s\" (mc:%d %s %s%s%s)",
		  (__entry->err_type == HW_EVENT_ERR_CORRECTED) ? "Corrected" :
			((__entry->err_type == HW_EVENT_ERR_FATAL) ?
			"Fatal" : "Uncorrected"),
		  ((char *)__get_str(msg))[0] ? " " : "",
		  __get_str(msg),
		  __get_str(label),
		  __entry->mc_index,
		  __get_str(location),
		  __get_str(detail),
		  ((char *)__get_str(driver_detail))[0] ? " " : "",
		  __get_str(driver_detail))
);

#endif /* _TRACE_HW_EVENT_MC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
