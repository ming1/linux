/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_ublk - A sched_ext scheduler optimized for ublk I/O workloads.
 *
 * This scheduler reduces context switch overhead for cooperative task pairs
 * such as fio <-> kublk (ublk userspace daemon). When two tasks ping-pong
 * I/O on the same CPU, CFS treats them as independent competing tasks. This
 * scheduler encodes the cooperative relationship directly:
 *
 * 1. Direct handoff: When a paired task stops running, its partner is
 *    dispatched immediately via a per-CPU partner DSQ, bypassing the global
 *    scheduling decision entirely.
 *
 * 2. CPU affinity: Paired tasks are kept on the same CPU to avoid cross-CPU
 *    migration overhead and ensure handoffs stay local.
 *
 * 3. Extended timeslice: Paired tasks get a larger timeslice to reduce
 *    mid-batch preemption.
 *
 * 4. Fairness: Every SHARED_DSQ_INTERVAL partner dispatches, non-paired
 *    tasks get a chance to run, preventing starvation of kworkers and
 *    other CPU-pinned tasks.
 *
 * For all non-paired tasks, the scheduler falls back to simple global FIFO
 * scheduling (same as scx_simple with FIFO mode).
 *
 * Usage:
 *   scx_ublk -p <fio_pid>:<kublk_pid> [-p <pid1>:<pid2>] [-s slice_us]
 *
 * Copyright (c) 2024 Ming Lei
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/*
 * User-configurable parameters.
 */
const volatile u64 pair_slice_ns = 20 * 1000 * 1000;	/* 20ms for paired tasks */
const volatile u32 shared_dsq_interval = 32;		/* serve SHARED_DSQ every N dispatches */

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ	0
#define MAX_CPUS	1024
#define MAX_PAIRS	64

/*
 * Per-CPU DSQ IDs for partner handoff. DSQ ID = cpu + 1 (to avoid
 * collision with SHARED_DSQ at ID 0).
 */
#define PARTNER_DSQ_BASE	1

/*
 * Partner map: pid -> partner_pid.
 * Populated from userspace. Bidirectional — both sides of the pair
 * have entries.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_PAIRS * 2);
	__type(key, u32);	/* pid */
	__type(value, u32);	/* partner pid */
} partner_map SEC(".maps");

/*
 * Per-CPU dispatch counter — used to periodically yield to SHARED_DSQ
 * so non-paired tasks don't starve.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} dispatch_cnt SEC(".maps");

/*
 * Statistics.
 */
enum ublk_stat_idx {
	UBLK_STAT_LOCAL,	/* dispatched to local DSQ (idle CPU fast path) */
	UBLK_STAT_GLOBAL,	/* dispatched to shared global DSQ */
	UBLK_STAT_PARTNER,	/* dispatched via partner handoff */
	UBLK_STAT_SHARED_YIELD,	/* SHARED_DSQ served to prevent starvation */
	UBLK_STAT_CTX_SWITCH,	/* total context switches */
	UBLK_NR_STATS,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, UBLK_NR_STATS);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

/*
 * Look up the partner pid for a given task.
 * Returns 0 if the task has no partner.
 */
static u32 get_partner_pid(const struct task_struct *p)
{
	u32 pid = p->pid;
	u32 *partner;

	partner = bpf_map_lookup_elem(&partner_map, &pid);
	return partner ? *partner : 0;
}

/*
 * Compute the partner DSQ ID for a given CPU.
 */
static u64 partner_dsq_id(s32 cpu)
{
	return (u64)cpu + PARTNER_DSQ_BASE;
}

/*
 * select_cpu - Pick a CPU for a waking task.
 *
 * For paired tasks, we always return prev_cpu to keep both sides of the
 * pair on the same CPU. This maximizes cache reuse and ensures the partner
 * DSQ handoff works (which is per-CPU).
 *
 * For non-paired tasks, use the default CPU selection.
 */
s32 BPF_STRUCT_OPS(ublk_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	if (get_partner_pid(p)) {
		/*
		 * Paired task: stay on prev_cpu. If the CPU is idle,
		 * dispatch directly to its local DSQ for immediate
		 * execution (no scheduling delay).
		 */
		is_idle = scx_bpf_test_and_clear_cpu_idle(prev_cpu);
		if (is_idle) {
			stat_inc(UBLK_STAT_LOCAL);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, pair_slice_ns, 0);
		}
		return prev_cpu;
	}

	/* Non-paired task: default selection */
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(UBLK_STAT_LOCAL);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

/*
 * enqueue - Called when select_cpu() didn't immediately dispatch.
 *
 * For paired tasks, enqueue into the partner's per-CPU DSQ so that when
 * the partner stops running, dispatch() finds us immediately.
 *
 * For non-paired tasks, enqueue into the shared global DSQ.
 */
void BPF_STRUCT_OPS(ublk_enqueue, struct task_struct *p, u64 enq_flags)
{
	u32 partner_pid = get_partner_pid(p);
	s32 cpu;

	if (partner_pid) {
		/*
		 * Enqueue to the per-CPU partner DSQ on prev_cpu.
		 * When the partner finishes on this CPU, dispatch()
		 * will pull from this DSQ first.
		 */
		cpu = scx_bpf_task_cpu(p);
		scx_bpf_dsq_insert(p, partner_dsq_id(cpu), pair_slice_ns,
				    enq_flags);
		stat_inc(UBLK_STAT_PARTNER);
		return;
	}

	/* Non-paired: global FIFO */
	stat_inc(UBLK_STAT_GLOBAL);
	scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

/*
 * dispatch - Called when the CPU needs a new task to run.
 *
 * We check the per-CPU partner DSQ first for direct handoff. But to
 * prevent starvation of non-paired tasks (kworkers, io_uring workers,
 * etc.), we periodically serve SHARED_DSQ first.
 *
 * Without this fairness mechanism, a tight fio<->kublk ping-pong loop
 * would monopolize the CPU — there's always a partner task waiting,
 * so SHARED_DSQ never gets checked.
 */
void BPF_STRUCT_OPS(ublk_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 dsq_id = partner_dsq_id(cpu);
	u32 key = 0;
	u64 *cnt;

	cnt = bpf_map_lookup_elem(&dispatch_cnt, &key);
	if (cnt) {
		*cnt += 1;

		/*
		 * Every shared_dsq_interval dispatches, serve SHARED_DSQ
		 * first to prevent starvation. This guarantees non-paired
		 * tasks get at least 1/N of the CPU time.
		 */
		if (*cnt % shared_dsq_interval == 0) {
			if (scx_bpf_dsq_move_to_local(SHARED_DSQ)) {
				stat_inc(UBLK_STAT_SHARED_YIELD);
				return;
			}
		}
	}

	/*
	 * Try partner DSQ. If the previous task was one half of a
	 * cooperative pair, its partner should be waiting here.
	 */
	if (scx_bpf_dsq_move_to_local(dsq_id)) {
		stat_inc(UBLK_STAT_PARTNER);
		return;
	}

	/* Fallback to global DSQ */
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

/*
 * running - Called when a task starts executing on a CPU.
 */
void BPF_STRUCT_OPS(ublk_running, struct task_struct *p)
{
	stat_inc(UBLK_STAT_CTX_SWITCH);

	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

/*
 * stopping - Called when a task stops executing.
 *
 * Charge vtime for non-paired tasks. Paired tasks get special treatment:
 * we don't penalize them for using their full (extended) timeslice since
 * that's by design.
 */
void BPF_STRUCT_OPS(ublk_stopping, struct task_struct *p, bool runnable)
{
	if (get_partner_pid(p))
		return;

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(ublk_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ublk_init)
{
	s32 cpu;
	int ret;

	/* Create the shared global DSQ */
	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret) {
		scx_bpf_error("failed to create shared DSQ (%d)", ret);
		return ret;
	}

	/* Create per-CPU partner DSQs */
	bpf_for(cpu, 0, MAX_CPUS) {
		if (cpu >= scx_bpf_nr_cpu_ids())
			break;
		ret = scx_bpf_create_dsq(partner_dsq_id(cpu), -1);
		if (ret) {
			scx_bpf_error("failed to create partner DSQ for CPU %d (%d)",
				       cpu, ret);
			return ret;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(ublk_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(ublk_ops,
	       .select_cpu		= (void *)ublk_select_cpu,
	       .enqueue			= (void *)ublk_enqueue,
	       .dispatch		= (void *)ublk_dispatch,
	       .running			= (void *)ublk_running,
	       .stopping		= (void *)ublk_stopping,
	       .enable			= (void *)ublk_enable,
	       .init			= (void *)ublk_init,
	       .exit			= (void *)ublk_exit,
	       .name			= "ublk");
