/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_ublk - Userspace loader for the ublk-optimized sched_ext scheduler.
 *
 * Populates the partner_map with task pairs and loads/attaches the BPF
 * scheduler program. Reports handoff statistics every second.
 *
 * Usage:
 *   scx_ublk -p <pid1>:<pid2> [-p <pid3>:<pid4>] [-s slice_us] [-d] [-v]
 *
 * Example:
 *   # Pin fio (pid 1234) and kublk (pid 5678) as a cooperative pair
 *   scx_ublk -p 1234:5678 -s 20000
 *
 * Copyright (c) 2024 Ming Lei
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_ublk.bpf.skel.h"

#define MAX_PAIRS 64

const char help_fmt[] =
"A sched_ext scheduler optimized for ublk cooperative I/O task pairs.\n"
"\n"
"Reduces context switch overhead by implementing direct partner handoff:\n"
"when one task in a pair blocks, its partner is dispatched immediately\n"
"without going through the full scheduler decision path.\n"
"\n"
"Usage: %s [-p pid1:pid2] [-s slice_us] [-d] [-v]\n"
"\n"
"  -p pid1:pid2  Register a cooperative task pair (can be repeated, max %d)\n"
"  -s slice_us   Timeslice for paired tasks in microseconds (default: 20000)\n"
"  -d            Enable debug output in BPF\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n"
"\n"
"Example:\n"
"  # Find fio and kublk pids, then run:\n"
"  scx_ublk -p $(pidof fio):$(pidof kublk) -s 20000\n";

struct pair {
	__u32 pid_a;
	__u32 pid_b;
};

static struct pair pairs[MAX_PAIRS];
static int nr_pairs;
static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level,
			    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static int parse_pair(const char *arg, struct pair *p)
{
	if (sscanf(arg, "%u:%u", &p->pid_a, &p->pid_b) != 2)
		return -1;
	if (p->pid_a == 0 || p->pid_b == 0)
		return -1;
	if (p->pid_a == p->pid_b)
		return -1;
	return 0;
}

static int populate_partner_map(struct scx_ublk *skel)
{
	int fd = bpf_map__fd(skel->maps.partner_map);
	int i, ret;

	for (i = 0; i < nr_pairs; i++) {
		/* Bidirectional: A->B and B->A */
		ret = bpf_map_update_elem(fd, &pairs[i].pid_a,
					  &pairs[i].pid_b, BPF_ANY);
		if (ret) {
			fprintf(stderr, "Failed to add pair %u->%u: %s\n",
				pairs[i].pid_a, pairs[i].pid_b,
				strerror(-ret));
			return ret;
		}

		ret = bpf_map_update_elem(fd, &pairs[i].pid_b,
					  &pairs[i].pid_a, BPF_ANY);
		if (ret) {
			fprintf(stderr, "Failed to add pair %u->%u: %s\n",
				pairs[i].pid_b, pairs[i].pid_a,
				strerror(-ret));
			return ret;
		}

		printf("Registered pair: %u <-> %u\n",
		       pairs[i].pid_a, pairs[i].pid_b);
	}

	return 0;
}

static void read_stats(struct scx_ublk *skel, __u64 *out)
{
	int nr_cpus = libbpf_num_possible_cpus();
	assert(nr_cpus > 0);
	__u64 cnts[5][nr_cpus]; /* UBLK_NR_STATS = 5 */
	__u32 idx;

	memset(out, 0, sizeof(out[0]) * 5);

	for (idx = 0; idx < 5; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			out[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_ublk *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;
	__u64 slice_us = 0;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	optind = 1;
	skel = SCX_OPS_OPEN(ublk_ops, scx_ublk);

	while ((opt = getopt(argc, argv, "p:s:vh")) != -1) {
		switch (opt) {
		case 'p':
			if (nr_pairs >= MAX_PAIRS) {
				fprintf(stderr, "Too many pairs (max %d)\n",
					MAX_PAIRS);
				return 1;
			}
			if (parse_pair(optarg, &pairs[nr_pairs])) {
				fprintf(stderr,
					"Invalid pair format '%s', expected pid1:pid2\n",
					optarg);
				return 1;
			}
			nr_pairs++;
			break;
		case 's':
			slice_us = strtoull(optarg, NULL, 0);
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]), MAX_PAIRS);
			return opt != 'h';
		}
	}

	if (slice_us)
		skel->rodata->pair_slice_ns = slice_us * 1000;

	SCX_OPS_LOAD(skel, ublk_ops, scx_ublk, uei);

	/* Populate partner map after load but before attach */
	if (populate_partner_map(skel))
		return 1;

	link = SCX_OPS_ATTACH(skel, ublk_ops, scx_ublk);

	if (nr_pairs == 0) {
		printf("Warning: no task pairs registered. "
		       "Running as a simple FIFO scheduler.\n"
		       "Use -p pid1:pid2 to register cooperative pairs.\n");
	}

	printf("scx_ublk scheduler active (slice=%lluus, %d pairs)\n",
	       (unsigned long long)(slice_us ? slice_us : 20000), nr_pairs);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[5];

		read_stats(skel, stats);
		printf("local=%llu global=%llu partner=%llu shared_yield=%llu ctx_switch=%llu\n",
		       stats[0], stats[1], stats[2], stats[3], stats[4]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_ublk__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
