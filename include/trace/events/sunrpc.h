#undef TRACE_SYSTEM
#define TRACE_SYSTEM sunrpc

#if !defined(_TRACE_SUNRPC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUNRPC_H

#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/clnt.h>
#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(rpc_task_running,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const void *action),

	TP_ARGS(clnt, task, action),

	TP_STRUCT__entry(
		__field(const struct rpc_clnt *, clnt)
		__field(const struct rpc_task *, task)
		__field(const void *, action)
		__field(unsigned long, runstate)
		__field(int, status)
		__field(unsigned short, flags)
		),

	TP_fast_assign(
		__entry->clnt = clnt;
		__entry->task = task;
		__entry->action = action;
		__entry->runstate = task->tk_runstate;
		__entry->status = task->tk_status;
		__entry->flags = task->tk_flags;
		),

	TP_printk("task:%p@%p flags=%4.4x state=%4.4lx status=%d action=%pf",
		__entry->task,
		__entry->clnt,
		__entry->flags,
		__entry->runstate,
		__entry->status,
		__entry->action
		)
);

DEFINE_EVENT(rpc_task_running, rpc_task_begin,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const void *action),

	TP_ARGS(clnt, task, action)

);

DEFINE_EVENT(rpc_task_running, rpc_task_run_action,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const void *action),

	TP_ARGS(clnt, task, action)

);

DEFINE_EVENT(rpc_task_running, rpc_task_complete,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const void *action),

	TP_ARGS(clnt, task, action)

);

DECLARE_EVENT_CLASS(rpc_task_queued,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const struct rpc_wait_queue *q),

	TP_ARGS(clnt, task, q),

	TP_STRUCT__entry(
		__field(const struct rpc_clnt *, clnt)
		__field(const struct rpc_task *, task)
		__field(const struct rpc_wait_queue *, queue)
		__field(unsigned long, timeout)
		__field(unsigned long, runstate)
		__field(int, status)
		__field(unsigned short, flags)
		),

	TP_fast_assign(
		__entry->clnt = clnt;
		__entry->task = task;
		__entry->queue = q;
		__entry->timeout = task->tk_timeout;
		__entry->runstate = task->tk_runstate;
		__entry->status = task->tk_status;
		__entry->flags = task->tk_flags;
		),

	TP_printk("task:%p@%p flags=%4.4x state=%4.4lx status=%d timeout=%lu queue=%s",
		__entry->task,
		__entry->clnt,
		__entry->flags,
		__entry->runstate,
		__entry->status,
		__entry->timeout,
		rpc_qname(__entry->queue)
		)
);

DEFINE_EVENT(rpc_task_queued, rpc_task_sleep,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const struct rpc_wait_queue *q),

	TP_ARGS(clnt, task, q)

);

DEFINE_EVENT(rpc_task_queued, rpc_task_wakeup,

	TP_PROTO(const struct rpc_clnt *clnt, const struct rpc_task *task, const struct rpc_wait_queue *q),

	TP_ARGS(clnt, task, q)

);

#endif /* _TRACE_SUNRPC_H */

#include <trace/define_trace.h>
