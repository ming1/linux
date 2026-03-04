scx_ublk: A sched_ext Scheduler for ublk I/O Workloads
=======================================================

# Overview

scx_ublk is a sched_ext BPF scheduler that optimizes context switch behavior
for ublk (userspace block device) I/O workloads. It targets the cooperative
ping-pong pattern between an I/O submitter (e.g. fio) and a ublk userspace
daemon (e.g. kublk), where two tasks repeatedly alternate execution on the
same CPU.

CFS treats these two tasks as independent competing entities, routing each
wakeup through rbtree insertion, vruntime comparison, and load balancing
checks. scx_ublk encodes the cooperative relationship directly, enabling
O(1) direct handoff between partner tasks.


# The Problem

In the ublk I/O path, every block I/O follows this pattern:

```
fio                              kublk (ublk daemon)
 |                                |
 +-- submit I/O to /dev/ublkb0    |
 |   [block, wait for completion] |
 |           context switch ----->|
 |                                +-- io_uring CQE: got I/O request
 |                                +-- handle I/O (e.g. null, loop)
 |                                +-- commit result via io_uring
 |                                |   [block, wait for next I/O]
 |           context switch <-----|
 +-- I/O complete                 |
 +-- submit next I/O              |
 |   ...                          |
```

Each I/O round-trip requires at minimum 2 context switches. With CFS, each
switch involves:

1. Enqueue the waking task into the CFS rbtree (O(log n))
2. Dequeue the next task from the rbtree
3. Check load balancing, CPU migration, vruntime fairness
4. Perform the actual register save/restore and TLB handling

Steps 1-3 are pure scheduling overhead that adds no value for this
cooperative workload, because we always know who should run next: the
partner task.


# Design

## Core Concept: Per-CPU Partner DSQ

sched_ext allows creating custom Dispatch Queues (DSQs). scx_ublk creates
one partner DSQ per CPU, dedicated to partner task handoff:

```
                    CPU N
    +---------------------------------------+
    |                                       |
    |  +---------------+  <- checked first  |
    |  | partner_dsq   |  (paired tasks)    |
    |  +---------------+                    |
    |                                       |
    |  +---------------+  <- checked every  |
    |  | SHARED_DSQ    |    Nth dispatch     |
    |  +---------------+  (everything else) |
    |                                       |
    |  +---------------+  <- idle CPU fast   |
    |  | LOCAL_DSQ     |    path only        |
    |  +---------------+                    |
    +---------------------------------------+
```

When a paired task blocks, dispatch() finds its partner waiting in the
per-CPU partner DSQ and runs it immediately -- a single FIFO dequeue
instead of CFS's rbtree walk.

## Data Structures

```
partner_map (BPF_MAP_TYPE_HASH):
    Maps pid -> partner_pid, populated bidirectionally from userspace.
    Example: { fio_pid: kublk_pid, kublk_pid: fio_pid }

partner_dsq[cpu] (user-created DSQ, ID = cpu + 1):
    Per-CPU FIFO queue for partner task handoff.
    DSQ IDs start at 1 to avoid collision with SHARED_DSQ (ID 0).

SHARED_DSQ (user-created DSQ, ID = 0):
    Global FIFO queue for all non-paired tasks.

dispatch_cnt (BPF_MAP_TYPE_PERCPU_ARRAY):
    Per-CPU counter to implement fairness interleaving.
```

## Scheduling Path

The scheduler implements three key sched_ext callbacks:

### select_cpu() -- Choose which CPU to run on

```
task wakes up
    |
    +-- is paired?
    |       |
    |      yes --> return prev_cpu (stay on same CPU as partner)
    |       |       |
    |       |       +-- CPU idle? --> insert LOCAL_DSQ (immediate run)
    |       |       +-- CPU busy? --> fall through to enqueue()
    |       |
    |      no  --> scx_bpf_select_cpu_dfl() (standard CFS-like selection)
    |               |
    |               +-- found idle CPU? --> insert LOCAL_DSQ
    |               +-- no idle CPU?    --> fall through to enqueue()
```

The critical design choice: paired tasks always return prev_cpu. This pins
both halves of the pair to the same CPU, which is necessary because the
partner DSQ handoff is per-CPU. If fio migrates to CPU 2 but kublk enqueues
to partner_dsq[1], the handoff breaks.

### enqueue() -- Place task in a DSQ

```
task not dispatched in select_cpu
    |
    +-- is paired?
    |       |
    |      yes --> insert into partner_dsq[task's CPU]
    |              (partner will find it in dispatch)
    |       |
    |      no  --> insert into SHARED_DSQ
```

Paired tasks go into the per-CPU partner DSQ, not the global queue. This
is the rendezvous point for the handoff.

### dispatch() -- Pick the next task to run

```
CPU needs next task
    |
    +-- increment dispatch_cnt[cpu]
    |
    +-- every Nth dispatch? --> try SHARED_DSQ first (fairness)
    |
    +-- try partner_dsq[cpu]
    |       |
    |       +-- found task? --> run it (direct handoff, O(1))
    |       +-- empty?      --> continue
    |
    +-- try SHARED_DSQ (fallback for non-paired tasks)
```

## Fairness: Preventing Starvation

Without the periodic SHARED_DSQ check, the partner DSQ creates a starvation
problem. The paired tasks ping-pong continuously -- there is always a
partner task waiting in partner_dsq when dispatch() runs. Non-paired tasks
(kworkers, io_uring helpers, etc.) pinned to the same CPU would never get
scheduled, eventually triggering the sched_ext watchdog.

The fix: every `shared_dsq_interval` dispatches (default: 32), SHARED_DSQ
gets priority over the partner DSQ. This guarantees non-paired tasks get at
least 1/N of the CPU time, which is sufficient to keep system tasks alive.

## Steady State Behavior

In steady state, the pair alternates like this:

```
Time ---------------------------------------------------------------->

CPU 1:  [fio]--block--[kublk]--block--[fio]--block--[kublk]--...
               ^              ^             ^
               |              |             |
          dispatch():    dispatch():   dispatch():
          partner_dsq    partner_dsq   partner_dsq
          has kublk      has fio       has kublk
```

Each transition:
1. Running task blocks (voluntary context switch)
2. dispatch() called
3. scx_bpf_dsq_move_to_local(partner_dsq) -- one FIFO dequeue
4. Partner runs immediately

Compare with CFS for the same transition:
1. Running task blocks
2. pick_next_task_fair() called
3. Walk rb-tree, compare vruntimes, check load balancing, update stats
4. Task runs

## Additional Callbacks

- running(): Counts context switches and advances global vtime
- stopping(): Charges vtime for non-paired tasks; paired tasks are exempt
  since they use extended timeslices by design
- enable(): Initializes a task's vtime when it enters the scheduler


# Usage

## Building

```bash
cd tools/sched_ext
make scx_ublk
```

The binary is placed in `build/bin/scx_ublk`.

## Running

```bash
# Register a cooperative pair (fio pid 1234, kublk pid 5678)
./build/bin/scx_ublk -p 1234:5678

# Using pidof for convenience
./build/bin/scx_ublk -p $(pidof fio):$(pidof kublk)

# Multiple pairs (e.g. multi-queue ublk device)
./build/bin/scx_ublk -p 1234:5678 -p 2345:6789

# Custom timeslice for paired tasks (default: 20ms)
./build/bin/scx_ublk -p 1234:5678 -s 50000
```

## Command-Line Options

```
-p pid1:pid2    Register a cooperative task pair (repeatable, max 64)
-s slice_us     Timeslice for paired tasks in microseconds (default: 20000)
-v              Print libbpf debug messages
-h              Display help
```

## Statistics Output

The scheduler prints cumulative statistics every second:

```
local=1787 global=747 partner=2678967 shared_yield=549 ctx_switch=2681050
```

- local:        Tasks dispatched via idle CPU fast path in select_cpu()
- global:       Non-paired tasks enqueued to SHARED_DSQ
- partner:      Partner DSQ handoff dispatches (the fast path)
- shared_yield: Times SHARED_DSQ was served to prevent starvation
- ctx_switch:   Total context switches across all CPUs

Per-second partner rate approximates the I/O rate (one partner dispatch
per I/O completion). The ctx_switch rate shows total scheduling activity.


# Performance Characteristics

The scheduler improves ublk I/O performance by eliminating scheduling
overhead per context switch, not by reducing the number of switches.
Each I/O still requires 2 context switches, but each switch avoids
the CFS rbtree walk and associated bookkeeping.

For further I/O performance improvement, combine scx_ublk with:

- UBLK_F_BATCH_IO: Reduces switch count by handling multiple I/Os per
  wakeup cycle. Complementary to scx_ublk -- fewer switches AND faster
  switches.
- Separate CPUs: Pin fio and kublk to different CPUs to eliminate context
  switches entirely (kublk is already running when the I/O arrives).


# Limitations

- Static pairing: Pairs are set at startup via pids. Restarting fio or
  kublk requires restarting the scheduler.
- Single pair per CPU: Multiple pairs sharing a CPU use the same
  partner_dsq and interleave. Functional but not optimal.
- System-wide scheduler: scx_ublk replaces the scheduler for ALL tasks,
  not just the paired ones. Non-paired tasks fall back to global FIFO
  scheduling.


# Files

```
tools/sched_ext/scx_ublk.bpf.c    BPF scheduler program
tools/sched_ext/scx_ublk.c         Userspace loader
tools/sched_ext/Makefile            Build system (scx_ublk added to targets)
```
