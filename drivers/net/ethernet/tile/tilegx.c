/*
 * Copyright 2011 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kernel.h>      /* printk() */
#include <linux/slab.h>        /* kmalloc() */
#include <linux/errno.h>       /* error codes */
#include <linux/types.h>       /* size_t */
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/irq.h>
#include <linux/netdevice.h>   /* struct device, and other headers */
#include <linux/etherdevice.h> /* eth_type_trans */
#include <linux/skbuff.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>
#include <linux/hugetlb.h>
#include <linux/in6.h>
#include <linux/timer.h>
#include <linux/io.h>
#include <linux/ctype.h>
#include <asm/checksum.h>
#include <asm/homecache.h>

#include <gxio/mpipe.h>

/* For TSO */
#include <linux/ip.h>
#include <linux/tcp.h>


#include <arch/sim.h>


/* #define USE_SIM_PRINTF */

#ifdef USE_SIM_PRINTF

static __attribute__((unused, format (printf, 1, 2))) void
sim_printf(const char *format, ...)
{
	char *str;
	char buf[1024];

	va_list args;
	va_start(args, format);
	(void)vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	/* NOTE: Copied from "sim_print()". */
	for (str = buf; *str != '\0'; str++) {
		__insn_mtspr(SPR_SIM_CONTROL, SIM_CONTROL_PUTC |
			     (*str << _SIM_CONTROL_OPERATOR_BITS));
	}
	__insn_mtspr(SPR_SIM_CONTROL, SIM_CONTROL_PUTC |
		     (SIM_PUTC_FLUSH_BINARY << _SIM_CONTROL_OPERATOR_BITS));
}


/* HACK: Allow use of "sim_printf()" instead of "printk()". */
#define printk sim_printf

#endif


/* First, "tile_net_init_module()" initializes each network cpu to
 * handle incoming packets, and initializes all the network devices.
 *
 * Then, "ifconfig DEVICE up" calls "tile_net_open()", which will
 * turn on packet processing, if needed.
 *
 * If "ifconfig DEVICE down" is called, it uses "tile_net_stop()" to
 * stop egress, and possibly turn off packet processing.
 *
 * We start out with the ingress IRQ enabled on each CPU.  When it
 * fires, it is automatically disabled, and we call "napi_schedule()".
 * This will cause "tile_net_poll()" to be called, which will pull
 * packets from the netio queue, filtering them out, or passing them
 * to "netif_receive_skb()".  If our budget is exhausted, we will
 * return, knowing we will be called again later.  Otherwise, we
 * reenable the ingress IRQ, and call "napi_complete()".
 *
 *
 * NOTE: Failing to free completions for an arbitrarily long time
 * (which is defined to be illegal) does in fact cause bizarre problems.
 *
 * NOTE: The egress code can be interrupted by the interrupt handler.
 */


/* HACK: Define to support GSO.
 * ISSUE: This may actually hurt performance of the TCP blaster.
 */
#undef TILE_NET_GSO

/* HACK: Define to support TSO. */
#define TILE_NET_TSO

/* Use 3000 to enable the Linux Traffic Control (QoS) layer, else 0. */
#define TILE_NET_TX_QUEUE_LEN 0

/* Define to dump packets (prints out the whole packet on tx and rx). */
#undef TILE_NET_DUMP_PACKETS

/* Define to use "round robin" distribution. */
#undef TILE_NET_ROUND_ROBIN

/* Default transmit lockup timeout period, in jiffies. */
#define TILE_NET_TIMEOUT (5 * HZ)

/* The number of distinct channels. */
#define TILE_NET_CHANNELS (MPIPE_NUM_SGMII_MACS + MPIPE_NUM_LOOPBACK_CHANNELS)

/* The max number of distinct devices ("xgbe" shares the "gbe" channels). */
#define TILE_NET_DEVS (TILE_NET_CHANNELS + MPIPE_NUM_XAUI_MACS)

/* Maximum number of idescs to handle per "poll". */
#define TILE_NET_BATCH 128

/* Maximum number of packets to handle per "poll". */
#define TILE_NET_WEIGHT 64

/* Number of entries in each iqueue. */
#define IQUEUE_ENTRIES 512

/* Number of entries in each equeue. */
#define EQUEUE_ENTRIES 2048

/* Total header bytes per equeue slot.  Must be big enough for 2 bytes
 * of NET_IP_ALIGN alignment, plus 14 bytes (?) of L2 header, plus up to
 * 60 bytes of actual TCP header.  We round up to align to cache lines.
 */
#define HEADER_BYTES 128

/* Maximum completions per cpu per device (must be a power of two).
 * ISSUE: What is the right number here?
 */
#define TILE_NET_MAX_COMPS 64


#define ROUND_UP(n, align) (((n) + (align) - 1) & -(align))


#define MAX_FRAGS (65536 / PAGE_SIZE + 2 + 1)


MODULE_AUTHOR("Tilera");
MODULE_LICENSE("GPL");



/* A "packet fragment" (a chunk of memory). */
struct frag {
	void *buf;
	size_t length;
};


/* Statistics counters for a specific cpu and device. */
struct tile_net_stats_t {
	u32 rx_packets;
	u32 rx_bytes;
	u32 tx_packets;
	u32 tx_bytes;
};


/* A single completion. */
struct tile_net_comp {
	/* The "complete_count" when the completion will be complete. */
	s64 when;
	/* The buffer to be freed when the completion is complete. */
	struct sk_buff *skb;
};


/* The completions for a given cpu and device. */
struct tile_net_comps {
	/* The completions. */
	struct tile_net_comp comp_queue[TILE_NET_MAX_COMPS];
	/* The number of completions used. */
	unsigned long comp_next;
	/* The number of completions freed. */
	unsigned long comp_last;
};


/* Info for a specific cpu.
 *
 * ISSUE: Should "comps" be per channel instead of per dev?
 */
struct tile_net_info_t {
	/* The NAPI struct. */
	struct napi_struct napi;
	/* Packet queue. */
	gxio_mpipe_iqueue_t iqueue;
	/* Our cpu. */
	int my_cpu;
	/* True if iqueue is valid. */
	bool has_iqueue;
	/* NAPI flags. */
	bool napi_added;
	bool napi_enabled;
	/* Number of small sk_buffs which must still be provided. */
	unsigned int num_needed_small_buffers;
	/* Number of large sk_buffs which must still be provided. */
	unsigned int num_needed_large_buffers;
	/* A timer for handling egress completions. */
	struct timer_list egress_timer;
	/* True if "egress_timer" is scheduled. */
	bool egress_timer_scheduled;
	/* Comps for each device. */
	struct tile_net_comps *comps_for_dev[TILE_NET_DEVS];
	/* Stats for each device. */
	struct tile_net_stats_t stats_for_dev[TILE_NET_DEVS];
};


/* Info for a specific device. */
struct tile_net_priv {
	/* Our network device. */
	struct net_device *dev;
	/* Our "devno". */
	int devno;
	/* The primary link. */
	gxio_mpipe_link_t link;
	/* The primary channel, if open, else -1. */
	int channel;
	/* The "loopify" egress link, if needed. */
	gxio_mpipe_link_t loopify_link;
	/* The "loopify" egress channel, if open, else -1. */
	int loopify_channel;
	/* Total stats. */
	struct net_device_stats stats;
	/* The (lazy) "equeue". */
	gxio_mpipe_equeue_t *equeue;
	/* The (lazy) headers for TSO. */
	unsigned char *headers;
};


/* The actual devices. */
static struct net_device *tile_net_devs[TILE_NET_DEVS];

/* The device for a given channel.  HACK: We use "32", not
 * TILE_NET_CHANNELS, because it is fairly subtle that the 5 bit
 * "idesc.channel" field never exceeds TILE_NET_CHANNELS.
 */
static struct net_device *tile_net_devs_for_channel[32];

/* A mutex for "tile_net_devs_for_channel". */
static struct mutex tile_net_devs_mutex;

/* The per-cpu info. */
static DEFINE_PER_CPU(struct tile_net_info_t, per_cpu_info);

/* Access to "per_cpu_info". */
static struct tile_net_info_t *infos[NR_CPUS];

/* The "context" for all devices. */
static gxio_mpipe_context_t context;

/* The small/large "buffer stacks". */
static int small_buffer_stack = -1;
static int large_buffer_stack = -1;

/* The buckets. */
static int first_bucket = -1;
static int num_buckets = 1;

/* The ingress irq. */
static int ingress_irq = -1;


/* True if "network_cpus" was specified. */
static bool network_cpus_used;

/* The actual cpus in "network_cpus". */
static struct cpumask network_cpus_map;


/* If "loopify=LINK" was specified, this is "LINK". */
static char loopify_link_name[16];



#ifdef TILE_NET_DUMP_PACKETS
/* Dump a packet. */
static void dump_packet(unsigned char *data, unsigned long length, char *s)
{
	unsigned long i;
	static unsigned int count;
	char buf[128];

	pr_info("Dumping %s packet of 0x%lx bytes at %p [%d]\n",
	       s, length, data, count++);

	pr_info("\n");

	for (i = 0; i < length; i++) {
		if ((i & 0xf) == 0)
			sprintf(buf, "%8.8lx:", i);
		sprintf(buf + strlen(buf), " %02x", data[i]);
		if ((i & 0xf) == 0xf || i == length - 1)
			pr_info("%s\n", buf);
	}

	pr_info("\n");
}
#endif


/* Convert a "buffer ptr" into a "buffer cpa". */
static inline void *buf_to_cpa(void *buf)
{
	return (void *)__pa(buf);
}


/* Convert a "buffer cpa" into a "buffer ptr". */
static inline void *cpa_to_buf(void *cpa)
{
	return (void *)__va(cpa);
}



/* Allocate and push a buffer. */
static bool tile_net_provide_buffer(bool small)
{
	int stack = small ? small_buffer_stack : large_buffer_stack;

	/* Buffers must be aligned. */
	const unsigned long align = 128;

	/* Note that "dev_alloc_skb()" adds NET_SKB_PAD more bytes,
	 * and also "reserves" that many bytes.
	 */
	int len = sizeof(struct sk_buff **) + align + (small ? 128 : 1664);

	/* Allocate (or fail). */
	struct sk_buff *skb = dev_alloc_skb(len);
	if (skb == NULL)
		return false;

	/* Make room for a back-pointer to 'skb'. */
	skb_reserve(skb, sizeof(struct sk_buff **));

	/* Make sure we are aligned. */
	skb_reserve(skb, -(long)skb->data & (align - 1));

	/* Save a back-pointer to 'skb'. */
	*(struct sk_buff **)(skb->data - sizeof(struct sk_buff **)) = skb;

	/* Make sure "skb" and the back-pointer have been flushed. */
	__insn_mf();

	gxio_mpipe_push_buffer(&context, stack, buf_to_cpa(skb->data));

	return true;
}


/* Provide linux buffers to mPIPE. */
static void tile_net_provide_needed_buffers(struct tile_net_info_t *info)
{
	while (info->num_needed_small_buffers != 0) {
		if (!tile_net_provide_buffer(true))
			goto oops;
		info->num_needed_small_buffers--;
	}

	while (info->num_needed_large_buffers != 0) {
		if (!tile_net_provide_buffer(false))
			goto oops;
		info->num_needed_large_buffers--;
	}

	return;

oops:

	/* Add a description to the page allocation failure dump. */
	pr_notice("Tile %d still needs some buffers\n", info->my_cpu);
}


/* Handle a packet.  Return true if "processed", false if "filtered". */
static bool tile_net_handle_packet(struct tile_net_info_t *info,
				    gxio_mpipe_idesc_t *idesc)
{
	/* NOTE: This can be NULL during shutdown. */
	struct net_device *dev = tile_net_devs_for_channel[idesc->channel];

	void *va;

	uint8_t l2_offset = gxio_mpipe_idesc_get_l2_offset(idesc);

	void *buf;
	unsigned long len;

	int filter = 0;

	/* Drop packets for which no buffer was available.
	 * NOTE: This happens under heavy load.
	 */
	if (idesc->be) {
		gxio_mpipe_iqueue_consume(&info->iqueue, idesc);
		if (net_ratelimit())
			pr_info("Dropping packet (insufficient buffers).\n");
		return false;
	}

	/* Get the raw buffer VA. */
	va = cpa_to_buf(gxio_mpipe_idesc_get_va(idesc));

	/* Get the actual packet start/length. */
	buf = va + l2_offset;
	len = gxio_mpipe_idesc_get_l2_length(idesc);

	/* Point "va" at the raw buffer. */
	va -= NET_IP_ALIGN;

#ifdef TILE_NET_DUMP_PACKETS
	dump_packet(buf, len, "rx");
#endif /* TILE_NET_DUMP_PACKETS */

	if (dev != NULL) {
		/* ISSUE: Is this needed? */
		dev->last_rx = jiffies;
	}

	if (dev == NULL || !(dev->flags & IFF_UP)) {
		/* Filter packets received before we're up. */
		filter = 1;
	} else if (!(dev->flags & IFF_PROMISC)) {
		/* ISSUE: "eth_type_trans()" implies that "IFF_PROMISC"
		 * is set for "all silly devices", however, it appears
		 * to NOT be set for us, so this code here DOES run.
		 * FIXME: The classifier will soon detect "multicast".
		 */
		if (!is_multicast_ether_addr(buf)) {
			/* Filter packets not for our address. */
			const u8 *mine = dev->dev_addr;
			filter = compare_ether_addr(mine, buf);
		}
	}

	if (filter) {

		/* ISSUE: Update "drop" statistics? */

		gxio_mpipe_iqueue_drop(&info->iqueue, idesc);

	} else {

		struct tile_net_priv *priv = netdev_priv(dev);
		struct tile_net_stats_t *stats =
			&info->stats_for_dev[priv->devno];

		/* Acquire the associated "skb". */
		struct sk_buff **skb_ptr = va - sizeof(*skb_ptr);
		struct sk_buff *skb = *skb_ptr;

		/* Paranoia. */
		if (skb->data != va)
			panic("Corrupt linux buffer! "
			      "buf=%p, skb=%p, skb->data=%p\n",
			      buf, skb, skb->data);

		/* Skip headroom, and any custom header. */
		skb_reserve(skb, NET_IP_ALIGN + l2_offset);

		/* Encode the actual packet length. */
		skb_put(skb, len);

		/* NOTE: This call also sets "skb->dev = dev".
		 * ISSUE: The classifier provides us with "eth_type"
		 * (aka "eth->h_proto"), which is basically the value
		 * returned by "eth_type_trans()".
		 * Note that "eth_type_trans()" computes "skb->pkt_type",
		 * which would be useful for the "filter" check above,
		 * if we had a (modifiable) "skb" to work with.
		 */
		skb->protocol = eth_type_trans(skb, dev);

		/* Acknowledge "good" hardware checksums. */
		if (idesc->cs && idesc->csum_seed_val == 0xFFFF)
			skb->ip_summed = CHECKSUM_UNNECESSARY;

		netif_receive_skb(skb);

		/* Update stats. */
		stats->rx_packets++;
		stats->rx_bytes += len;

		/* Need a new buffer. */
		if (idesc->size == GXIO_MPIPE_BUFFER_SIZE_128)
			info->num_needed_small_buffers++;
		else
			info->num_needed_large_buffers++;
	}

	gxio_mpipe_iqueue_consume(&info->iqueue, idesc);

	return !filter;
}


/* Handle some packets for the current CPU.
 *
 * This function handles up to TILE_NET_BATCH idescs per call.
 *
 * ISSUE: Since we do not provide new buffers until this function is
 * complete, we must initially provide enough buffers for each network
 * cpu to fill its iqueue and also its batched idescs.
 *
 * ISSUE: The "rotting packet" race condition occurs if a packet
 * arrives after the queue appears to be empty, and before the
 * hypervisor interrupt is re-enabled.
 */
static int tile_net_poll(struct napi_struct *napi, int budget)
{
	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);

	unsigned int work = 0;

	gxio_mpipe_idesc_t *idesc;
	int i, n;

	/* Process packets. */
	while ((n = gxio_mpipe_iqueue_try_peek(&info->iqueue, &idesc)) > 0) {
		for (i = 0; i < n; i++) {
			if (i == TILE_NET_BATCH)
				goto done;
			if (tile_net_handle_packet(info, idesc + i)) {
				if (++work >= budget)
					goto done;
			}
		}
	}

	/* There are no packets left. */
	napi_complete(&info->napi);

	/* Re-enable hypervisor interrupts. */
	gxio_mpipe_enable_notif_ring_interrupt(&context, info->iqueue.ring);

	/* HACK: Avoid the "rotting packet" problem. */
	if (gxio_mpipe_iqueue_try_peek(&info->iqueue, &idesc) > 0)
		napi_schedule(&info->napi);

	/* ISSUE: Handle completions? */

done:

	tile_net_provide_needed_buffers(info);

	return work;
}


/* Handle an ingress interrupt on the current cpu. */
static irqreturn_t tile_net_handle_ingress_irq(int irq, void *unused)
{
	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);
	napi_schedule(&info->napi);
	return IRQ_HANDLED;
}


/* Free some completions.  This must be called with interrupts blocked. */
static void tile_net_free_comps(struct net_device *dev,
				 struct tile_net_comps *comps,
				 int limit, bool force_update)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	gxio_mpipe_equeue_t *equeue = priv->equeue;

	int n = 0;
	while (comps->comp_last < comps->comp_next) {
		unsigned int cid = comps->comp_last % TILE_NET_MAX_COMPS;
		struct tile_net_comp *comp = &comps->comp_queue[cid];
		if (!gxio_mpipe_equeue_is_complete(equeue, comp->when,
						   force_update || n == 0))
			return;
		dev_kfree_skb_irq(comp->skb);
		comps->comp_last++;
		if (++n == limit)
			return;
	}
}


/* Make sure the egress timer is scheduled.
 *
 * Note that we use "schedule if not scheduled" logic instead of the more
 * obvious "reschedule" logic, because "reschedule" is fairly expensive.
 */
static void tile_net_schedule_egress_timer(struct tile_net_info_t *info)
{
	if (!info->egress_timer_scheduled) {
		mod_timer_pinned(&info->egress_timer, jiffies + 1);
		info->egress_timer_scheduled = true;
	}
}


/* The "function" for "info->egress_timer".
 *
 * This timer will reschedule itself as long as there are any pending
 * completions expected for this tile.
 */
static void tile_net_handle_egress_timer(unsigned long arg)
{
	struct tile_net_info_t *info = (struct tile_net_info_t *)arg;

	unsigned int k;

	bool pending = false;

	unsigned long irqflags;

	local_irq_save(irqflags);

	/* The timer is no longer scheduled. */
	info->egress_timer_scheduled = false;

	/* Free all possible comps for this tile. */
	for (k = 0; k < TILE_NET_DEVS; k++) {
		struct tile_net_comps *comps = info->comps_for_dev[k];
		if (comps->comp_last >= comps->comp_next)
			continue;
		tile_net_free_comps(tile_net_devs[k], comps, -1, true);
		pending = pending || (comps->comp_last < comps->comp_next);
	}

	/* Reschedule timer if needed. */
	if (pending)
		tile_net_schedule_egress_timer(info);

	local_irq_restore(irqflags);
}


/* Prepare each CPU. */
static void tile_net_prepare_cpu(void *unused)
{
	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);

	int my_cpu = smp_processor_id();

	info->has_iqueue = false;

	info->my_cpu = my_cpu;

	/* Initialize the egress timer. */
	init_timer(&info->egress_timer);
	info->egress_timer.data = (long)info;
	info->egress_timer.function = tile_net_handle_egress_timer;

	infos[my_cpu] = info;
}


/* Helper function for "tile_net_update()". */
static void tile_net_update_cpu(void *count_ptr)
{
	long count = *(long *)count_ptr;

	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);

	if (info->has_iqueue) {
		if (count != 0) {
			if (!info->napi_added) {
				/* FIXME: HACK: We use one of the devices.
				 * ISSUE: We never call "netif_napi_del()".
				 */
				netif_napi_add(tile_net_devs[0], &info->napi,
					       tile_net_poll, TILE_NET_WEIGHT);
				info->napi_added = true;
			}
			if (!info->napi_enabled) {
				napi_enable(&info->napi);
				info->napi_enabled = true;
			}
			enable_percpu_irq(ingress_irq, 0);
		} else {
			disable_percpu_irq(ingress_irq);
			if (info->napi_enabled) {
				napi_disable(&info->napi);
				info->napi_enabled = false;
			}
			/* FIXME: Drain the iqueue. */
		}
	}
}


/* Helper function for tile_net_open() and tile_net_stop(). */
static int tile_net_update(void)
{
	int channel;
	long count = 0;
	int cpu;

	/* HACK: This is too big for the linux stack. */
	static gxio_mpipe_rules_t rules;

	gxio_mpipe_rules_init(&rules, &context);

	/* TODO: Add support for "dmac" splitting? */
	for (channel = 0; channel < TILE_NET_DEVS; channel++) {
		if (tile_net_devs_for_channel[channel] == NULL)
			continue;
		if (count++ == 0) {
			gxio_mpipe_rules_begin(&rules, first_bucket,
					       num_buckets, NULL);
			gxio_mpipe_rules_set_headroom(&rules, NET_IP_ALIGN);
		}
		gxio_mpipe_rules_add_channel(&rules, channel);
	}

	/* NOTE: This can happen if there is no classifier.
	 * ISSUE: Can anything else cause it to happen?
	 */
	if (gxio_mpipe_rules_commit(&rules) != 0) {
		pr_warning("Failed to update classifier rules!\n");
		return -EIO;
	}

	/* Update all cpus, sequentially (to protect "netif_napi_add()"). */
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, tile_net_update_cpu, &count, 1);

	/* HACK: Allow packets to flow. */
	if (count != 0)
		sim_enable_mpipe_links(0, -1);

	return 0;
}


/* Helper function for "tile_net_init_cpus()". */
static void tile_net_init_stacks(int network_cpus_count)
{
	int err;
	int i;

	gxio_mpipe_buffer_size_enum_t small_buf_size =
		GXIO_MPIPE_BUFFER_SIZE_128;
	gxio_mpipe_buffer_size_enum_t large_buf_size =
		GXIO_MPIPE_BUFFER_SIZE_1664;

	int num_buffers;

	size_t stack_bytes;

	pte_t pte = { 0 };

	void *mem;

	num_buffers =
		network_cpus_count * (IQUEUE_ENTRIES + TILE_NET_BATCH);

	/* Compute stack bytes, honoring the 64KB minimum alignment. */
	stack_bytes = ROUND_UP(gxio_mpipe_calc_buffer_stack_bytes(num_buffers),
			       64 * 1024);
	if (stack_bytes > HPAGE_SIZE)
		panic("Cannot allocate %d physically contiguous buffers.",
		      num_buffers);

#if 0
	sim_printf("Using %d buffers for %d network cpus.\n",
		   num_buffers, network_cpus_count);
#endif

	/* Allocate two buffer stacks. */
	small_buffer_stack = gxio_mpipe_alloc_buffer_stacks(&context, 2, 0, 0);
	if (small_buffer_stack < 0)
		panic("Failure in 'gxio_mpipe_alloc_buffer_stacks()'");
	large_buffer_stack = small_buffer_stack + 1;

	/* Allocate the small memory stack. */
	mem = alloc_pages_exact(stack_bytes, GFP_KERNEL);
	if (mem == NULL)
		panic("Could not allocate buffer memory!");
	err = gxio_mpipe_init_buffer_stack(&context, small_buffer_stack,
					   small_buf_size,
					   mem, stack_bytes, 0);
	if (err != 0)
		panic("Error %d in 'gxio_mpipe_init_buffer_stack()'.", err);

	/* Allocate the large buffer stack. */
	mem = alloc_pages_exact(stack_bytes, GFP_KERNEL);
	if (mem == NULL)
		panic("Could not allocate buffer memory!");
	err = gxio_mpipe_init_buffer_stack(&context, large_buffer_stack,
					   large_buf_size,
					   mem, stack_bytes, 0);
	if (err != 0)
		panic("Error %d in 'gxio_mpipe_init_buffer_stack()'.", err);

	/* Pin all the client memory. */
	pte = pte_set_home(pte, PAGE_HOME_HASH);
	err = gxio_mpipe_register_client_memory(&context, small_buffer_stack,
						pte, 0);
	if (err != 0)
		panic("Error %d in 'gxio_mpipe_register_buffer_memory()'.",
		      err);
	err = gxio_mpipe_register_client_memory(&context, large_buffer_stack,
						pte, 0);
	if (err != 0)
		panic("Error %d in 'gxio_mpipe_register_buffer_memory()'.",
		      err);

	/* Provide initial buffers. */
	for (i = 0; i < num_buffers; i++) {
		if (!tile_net_provide_buffer(true))
			panic("Cannot provide initial buffers!");
	}
	for (i = 0; i < num_buffers; i++) {
		if (!tile_net_provide_buffer(false))
			panic("Cannot provide initial buffers!");
	}
}


/* Actually initialize the mPIPE state. */
static int tile_net_init_cpus(void)
{
	int network_cpus_count;

	int ring;
	int group;

	int next_ring;

	int cpu;

	int i;

#ifdef TILE_NET_ROUND_ROBIN
	gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_ROUND_ROBIN;
#else
	/* Use random rebalancing. */
	gxio_mpipe_bucket_mode_t mode = GXIO_MPIPE_BUCKET_STICKY_FLOW_LOCALITY;
#endif

	if (!hash_default) {
		pr_warning("Networking requires hash_default!\n");
		goto fail;
	}

	if (gxio_mpipe_init(&context, 0) != 0) {
		pr_warning("Failed to initialize mPIPE!\n");
		goto fail;
	}

	if (!network_cpus_used)
		network_cpus_map = cpu_online_map;

#ifdef CONFIG_DATAPLANE
	/* Remove dataplane cpus. */
	cpus_andnot(network_cpus_map, network_cpus_map, dataplane_map);
#endif

	network_cpus_count = cpus_weight(network_cpus_map);

	/* ISSUE: Handle failures more gracefully. */
	tile_net_init_stacks(network_cpus_count);

	/* Allocate one NotifRing for each network cpu. */
	ring = gxio_mpipe_alloc_notif_rings(&context, network_cpus_count,
					    0, 0);
	if (ring < 0) {
		pr_warning("Failed to allocate notif rings.\n");
		goto fail;
	}

	/* ISSUE: Handle failures below more cleanly. */

	/* Init NotifRings. */
	next_ring = ring;

	for_each_online_cpu(cpu) {

		size_t notif_ring_size =
			IQUEUE_ENTRIES * sizeof(gxio_mpipe_idesc_t);

		int order;
		struct page *page;
		void *addr;

		struct tile_net_info_t *info = infos[cpu];

		size_t comps_size =
			TILE_NET_DEVS * sizeof(struct tile_net_comps);

		/* Allocate the "comps". */
		order = get_order(comps_size);
		page = homecache_alloc_pages(GFP_KERNEL, order, cpu);
		if (page == NULL)
			panic("Failed to allocate comps memory.");
		addr = pfn_to_kaddr(page_to_pfn(page));
		/* ISSUE: Is this needed? */
		memset(addr, 0, comps_size);
		for (i = 0; i < TILE_NET_DEVS; i++)
			info->comps_for_dev[i] =
				addr + i * sizeof(struct tile_net_comps);

		/* Only network cpus can receive packets. */
		if (!cpu_isset(cpu, network_cpus_map))
			continue;

		/* Allocate the actual idescs array. */
		order = get_order(notif_ring_size);
		page = homecache_alloc_pages(GFP_KERNEL, order, cpu);
		if (page == NULL)
			panic("Failed to allocate iqueue memory.");
		addr = pfn_to_kaddr(page_to_pfn(page));

		if (gxio_mpipe_iqueue_init(&info->iqueue, &context, next_ring,
					   addr, notif_ring_size, 0) != 0)
			panic("Failure in 'gxio_mpipe_iqueue_init()'.");

		info->has_iqueue = true;

		next_ring++;
	}

	/* Allocate one NotifGroup. */
	group = gxio_mpipe_alloc_notif_groups(&context, 1, 0, 0);
	if (group < 0)
		panic("Failure in 'gxio_mpipe_alloc_notif_groups()'.");

#ifndef TILE_NET_ROUND_ROBIN
	if (network_cpus_count > 4)
		num_buckets = 256;
	else if (network_cpus_count > 1)
		num_buckets = 16;
#endif

	/* Allocate some buckets. */
	first_bucket = gxio_mpipe_alloc_buckets(&context, num_buckets, 0, 0);
	if (first_bucket < 0)
		panic("Failure in 'gxio_mpipe_alloc_buckets()'.");

	/* Init group and buckets. */
	if (gxio_mpipe_init_notif_group_and_buckets(&context, group, ring,
						    network_cpus_count,
						    first_bucket, num_buckets,
						    mode) != 0)
		panic("Fail in 'gxio_mpipe_init_notif_group_and_buckets().");


	/* Create an irq and register it. */
	ingress_irq = create_irq();
	if (ingress_irq < 0)
		panic("Failed to create irq for ingress.");
	tile_irq_activate(ingress_irq, TILE_IRQ_PERCPU);
	BUG_ON(request_irq(ingress_irq, tile_net_handle_ingress_irq,
			   0, NULL, NULL) != 0);

	for_each_online_cpu(cpu) {

		struct tile_net_info_t *info = infos[cpu];

		int ring = info->iqueue.ring;

		if (!info->has_iqueue)
			continue;

		gxio_mpipe_request_notif_ring_interrupt(&context,
							cpu_x(cpu), cpu_y(cpu),
							1, ingress_irq, ring);
	}

	return 0;

fail:
	return -EIO;
}


/* Create persistent egress info for a given channel.
 *
 * Note that this may be shared between, say, "gbe0" and "xgbe0".
 */
static int tile_net_init_egress(struct tile_net_priv *priv)
{
	int channel =
		((priv->loopify_channel >= 0) ?
		 priv->loopify_channel : priv->channel);

	size_t headers_order;
	struct page *headers_page;
	unsigned char* headers;

	size_t edescs_size;
	int edescs_order;
	struct page *edescs_page;
	gxio_mpipe_edesc_t* edescs;

	int equeue_order;
	struct page *equeue_page;
	gxio_mpipe_equeue_t* equeue;
	int edma;

	/* Allocate memory for the "headers".
	 * ISSUE: Defer this until TSO is actually needed?
	 */
	headers_order = get_order(EQUEUE_ENTRIES * HEADER_BYTES);
	headers_page = alloc_pages(GFP_KERNEL, headers_order);
	if (headers_page == NULL) {
		pr_warning("Could not allocate memory for TSO headers.\n");
		goto fail;
	}
	headers = pfn_to_kaddr(page_to_pfn(headers_page));

	/* Allocate memory for the "edescs". */
	edescs_size = EQUEUE_ENTRIES * sizeof(*edescs);
	edescs_order = get_order(edescs_size);
	edescs_page = alloc_pages(GFP_KERNEL, edescs_order);
	if (edescs_page == NULL) {
		pr_warning("Could not allocate memory for eDMA ring.\n");
		goto fail_headers;
	}
	edescs = pfn_to_kaddr(page_to_pfn(edescs_page));

	/* Allocate memory for the "equeue". */
	equeue_order = get_order(sizeof(*equeue));
	equeue_page = alloc_pages(GFP_KERNEL, equeue_order);
	if (equeue_page == NULL) {
		pr_warning("Could not allocate memory for equeue info.\n");
		goto fail_edescs;
	}
	equeue = pfn_to_kaddr(page_to_pfn(equeue_page));

	/* Allocate an edma ring. */
	edma = gxio_mpipe_alloc_edma_rings(&context, 1, 0, 0);
	if (edma < 0) {
		pr_warning("Could not allocate edma ring.\n");
		goto fail_equeue;
	}

	/* Initialize the equeue.  This should not fail. */
	if (gxio_mpipe_equeue_init(equeue, &context, edma, channel,
				   edescs, edescs_size, 0) != 0)
		panic("Failure in 'gxio_mpipe_equeue_init()'.");

	/* Done. */
	priv->equeue = equeue;
	priv->headers = headers;
	return 0;

fail_equeue:
	__free_pages(equeue_page, equeue_order);

fail_edescs:
	__free_pages(edescs_page, edescs_order);

fail_headers:
	__free_pages(headers_page, headers_order);

fail:
	return -EIO;
}


/* Help the kernel activate the given network interface. */
static int tile_net_open(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	/* Determine if this is the "loopify" device. */
	bool loopify = !strcmp(dev->name, loopify_link_name);

	int result;

	mutex_lock(&tile_net_devs_mutex);

	if (ingress_irq < 0) {
		result = tile_net_init_cpus();
		if (result != 0)
			goto fail;
	}

	if (priv->channel < 0) {
		const char* ln = loopify ? "loop0" : dev->name;
		if (gxio_mpipe_link_open(&priv->link, &context, ln, 0) < 0) {
			netdev_err(dev, "Failed to open '%s'.\n", ln);
			result = -EIO;
			goto fail;
		}
		priv->channel = gxio_mpipe_link_channel(&priv->link);
		BUG_ON(priv->channel < 0 || priv->channel >= 32);
	}

	if (loopify && priv->loopify_channel < 0) {
		if (gxio_mpipe_link_open(&priv->loopify_link,
					 &context, "loop1", 0) < 0) {
			netdev_err(dev, "Failed to open 'loop1'.\n");
			result = -EIO;
			goto fail;
		}
		priv->loopify_channel =
			gxio_mpipe_link_channel(&priv->loopify_link);
		BUG_ON(priv->loopify_channel < 0);
	}

	/* Initialize egress info (if needed). */
	if (priv->equeue == NULL) {
		result = tile_net_init_egress(priv);
		if (result != 0)
			goto fail;
	}

	tile_net_devs_for_channel[priv->channel] = dev;

	result = tile_net_update();
	if (result != 0)
		goto fail_channel;

	mutex_unlock(&tile_net_devs_mutex);

	/* Start our transmit queue. */
	netif_start_queue(dev);

	netif_carrier_on(dev);

	return 0;

fail_channel:
	tile_net_devs_for_channel[priv->channel] = NULL;

fail:
	if (priv->loopify_channel >= 0) {
		if (gxio_mpipe_link_close(&priv->loopify_link) != 0)
			pr_warning("Failed to close loopify link!\n");
		else
			priv->loopify_channel = -1;
	}
	if (priv->channel >= 0) {
		if (gxio_mpipe_link_close(&priv->link) != 0)
			pr_warning("Failed to close link!\n");
		else
			priv->channel = -1;
	}

	mutex_unlock(&tile_net_devs_mutex);
	return result;
}



/* Help the kernel deactivate the given network interface. */
static int tile_net_stop(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	/* Stop our transmit queue. */
	netif_stop_queue(dev);

	mutex_lock(&tile_net_devs_mutex);

	tile_net_devs_for_channel[priv->channel] = NULL;

	(void)tile_net_update();

	if (priv->loopify_channel >= 0) {
		if (gxio_mpipe_link_close(&priv->loopify_link) != 0)
			pr_warning("Failed to close loopify link!\n");
		priv->loopify_channel = -1;
	}

	if (priv->channel >= 0) {
		if (gxio_mpipe_link_close(&priv->link) != 0)
			pr_warning("Failed to close link!\n");
		priv->channel = -1;
	}

	mutex_unlock(&tile_net_devs_mutex);

	return 0;
}


/* Determine the VA for a fragment. */
static inline void *tile_net_frag_buf(skb_frag_t *f)
{
	unsigned long pfn = page_to_pfn(skb_frag_page(f));
	return pfn_to_kaddr(pfn) + f->page_offset;
}


/* This function takes "skb", consisting of a header template and a
 * (presumably) huge payload, and egresses it as one or more segments
 * (aka packets), each consisting of a (possibly modified) copy of the
 * header plus a piece of the payload, via "tcp segmentation offload".
 *
 * Usually, "data" will contain the header template, of size "sh_len",
 * and "sh->frags" will contain "skb->data_len" bytes of payload, and
 * there will be "sh->gso_segs" segments.
 *
 * Sometimes, if "sendfile()" requires copying, we will be called with
 * "data" containing the header and payload, with "frags" being empty.
 *
 * Sometimes, for example when using NFS over TCP, a single segment can
 * span 3 fragments.  This requires special care below.
 *
 * See "emulate_large_send_offload()" for some reference code, which
 * does not handle checksumming.
 */
static int tile_net_tx_tso(struct sk_buff *skb, struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	gxio_mpipe_equeue_t *equeue = priv->equeue;

	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);

	struct tile_net_stats_t *stats;

	unsigned int len = skb->len;
	unsigned char *data = skb->data;

	/* The ip header follows the ethernet header. */
	struct iphdr *ih = ip_hdr(skb);
	unsigned int ih_len = ih->ihl * 4;

	/* Note that "nh == iph", by definition. */
	unsigned char *nh = skb_network_header(skb);
	unsigned int eh_len = nh - data;

	/* The tcp header follows the ip header. */
	struct tcphdr *th = (struct tcphdr *)(nh + ih_len);
	unsigned int th_len = th->doff * 4;

	/* The total number of header bytes. */
	unsigned int sh_len = eh_len + ih_len + th_len;

	/* Help compute "jh->check". */
	unsigned int isum_hack =
		((0xFFFF - ih->check) +
		 (0xFFFF - ih->tot_len) +
		 (0xFFFF - ih->id));

	/* Help compute "uh->check". */
	unsigned int tsum_hack = th->check + (0xFFFF ^ htons(len));

	struct skb_shared_info *sh = skb_shinfo(skb);

	/* The maximum payload size. */
	unsigned int gso_size = sh->gso_size;

	/* The size of the initial segments (including header). */
	unsigned int mtu = sh_len + gso_size;

	/* The size of the final segment (including header). */
	unsigned int mtu2 = len - ((sh->gso_segs - 1) * gso_size);

	/* Track tx stats. */
	unsigned int tx_packets = 0;
	unsigned int tx_bytes = 0;

	/* Which segment are we on. */
	unsigned int segment;

	/* Get the initial ip "id". */
	u16 id = ntohs(ih->id);

	/* Get the initial tcp "seq". */
	u32 seq = ntohl(th->seq);

	/* The id of the current fragment (or -1). */
	long f_id;

	/* The size of the current fragment (or -1). */
	long f_size;

	/* The bytes used from the current fragment (or -1). */
	long f_used;

	/* The size of the current piece of payload. */
	long n;

	/* Prepare checksum info. */
	unsigned int csum_start = skb_checksum_start_offset(skb);

	/* The header/payload edesc's. */
	gxio_mpipe_edesc_t edesc_head = { { 0 } };
	gxio_mpipe_edesc_t edesc_body = { { 0 } };

	/* Total number of edescs needed. */
	unsigned int num_edescs = 0;

	unsigned long irqflags;

	/* First reserved egress slot. */
	s64 slot;

	struct tile_net_comps *comps;

	int cid;

	/* Empty packets (etc) would cause trouble below. */
	BUG_ON(skb->data_len == 0);
	BUG_ON(sh->nr_frags == 0);
	BUG_ON(sh->gso_segs == 0);

	/* We assume the frags contain the entire payload. */
	BUG_ON(skb_headlen(skb) != sh_len);
	BUG_ON(len != sh_len + skb->data_len);

	/* Implicitly verify "gso_segs" and "gso_size". */
	BUG_ON(mtu2 > mtu);

	/* We only have HEADER_BYTES for each header. */
	BUG_ON(NET_IP_ALIGN + sh_len > HEADER_BYTES);

	/* Paranoia. */
	BUG_ON(skb->protocol != htons(ETH_P_IP));
	BUG_ON(ih->protocol != IPPROTO_TCP);
	BUG_ON(skb->ip_summed != CHECKSUM_PARTIAL);
	BUG_ON(csum_start != eh_len + ih_len);

	/* NOTE: ".hwb = 0", so ".size" is unused.
	 * NOTE: ".stack_idx" determines the TLB.
	 */

	/* Prepare to egress the headers. */
	edesc_head.csum = 1;
	edesc_head.csum_start = csum_start;
	edesc_head.csum_dest = csum_start + skb->csum_offset;
	edesc_head.xfer_size = sh_len;
	edesc_head.stack_idx = large_buffer_stack;

	/* Prepare to egress the body. */
	edesc_body.stack_idx = large_buffer_stack;

	/* Reset. */
	f_id = f_size = f_used = -1;

	/* Determine how many edesc's are needed. */
	for (segment = 0; segment < sh->gso_segs; segment++) {

		/* Detect the final segment. */
		bool final = (segment == sh->gso_segs - 1);

		/* The segment size (including header). */
		unsigned int s_len = final ? mtu2 : mtu;

		/* The size of the payload. */
		unsigned int p_len = s_len - sh_len;

		/* The bytes used from the payload. */
		unsigned int p_used = 0;

		/* One edesc for the header. */
		num_edescs++;

		/* One edesc for each piece of the payload. */
		while (p_used < p_len) {

			/* Advance as needed. */
			while (f_used >= f_size) {
				f_id++;
				f_size = sh->frags[f_id].size;
				f_used = 0;
			}

			/* Use bytes from the current fragment. */
			n = p_len - p_used;
			if (n > f_size - f_used)
				n = f_size - f_used;
			f_used += n;
			p_used += n;

			num_edescs++;
		}
	}

	/* Verify all fragments consumed. */
	BUG_ON(f_id + 1 != sh->nr_frags);
	BUG_ON(f_used != f_size);

	local_irq_save(irqflags);

	/* Reserve slots, or return NETDEV_TX_BUSY if "full". */
	slot = gxio_mpipe_equeue_try_reserve(equeue, num_edescs);
	if (slot < 0) {
		if (net_ratelimit())
			pr_info("Egress blocked on '%s'!\n", dev->name);
		local_irq_restore(irqflags);
		return NETDEV_TX_BUSY;
	}

	/* Reset. */
	f_id = f_size = f_used = -1;

	/* Prepare all the headers. */
	for (segment = 0; segment < sh->gso_segs; segment++) {

		/* Detect the final segment. */
		bool final = (segment == sh->gso_segs - 1);

		/* The segment size (including header). */
		unsigned int s_len = final ? mtu2 : mtu;

		/* The size of the payload. */
		unsigned int p_len = s_len - sh_len;

		/* The bytes used from the payload. */
		unsigned int p_used = 0;

		/* Access the header memory for this segment. */
		unsigned int bn = slot % EQUEUE_ENTRIES;
		unsigned char *buf =
			priv->headers + bn * HEADER_BYTES + NET_IP_ALIGN;

		/* The soon-to-be copied "ip" header. */
		struct iphdr *jh = (struct iphdr *)(buf + eh_len);

		/* The soon-to-be copied "tcp" header. */
		struct tcphdr *uh = (struct tcphdr *)(buf + eh_len + ih_len);

		unsigned int jsum, usum;

		/* Copy the header. */
		memcpy(buf, data, sh_len);

		/* The packet size, not including ethernet header. */
		jh->tot_len = htons(s_len - eh_len);

		/* Update the ip "id". */
		jh->id = htons(id);

		/* Compute the "ip checksum". */
		jsum = isum_hack + htons(s_len - eh_len) + htons(id);
		jsum = __insn_v2sadu(jsum, 0);
		jsum = __insn_v2sadu(jsum, 0);
		jsum = (0xFFFF ^ jsum);
		jh->check = jsum;

		/* Update the tcp "seq". */
		uh->seq = htonl(seq);

		/* Update some flags. */
		if (!final)
			uh->fin = uh->psh = 0;

		/* Compute the tcp pseudo-header checksum. */
		usum = tsum_hack + htons(s_len);
		usum = __insn_v2sadu(usum, 0);
		usum = __insn_v2sadu(usum, 0);
		uh->check = usum;

		/* Skip past the header. */
		slot++;

		/* Skip past the payload. */
		while (p_used < p_len) {

			/* Advance as needed. */
			while (f_used >= f_size) {
				f_id++;
				f_size = sh->frags[f_id].size;
				f_used = 0;
			}

			/* Use bytes from the current fragment. */
			n = p_len - p_used;
			if (n > f_size - f_used)
				n = f_size - f_used;
			f_used += n;
			p_used += n;

			slot++;
		}

		id++;
		seq += p_len;
	}

	/* Reset "slot". */
	slot -= num_edescs;

	/* Flush the headers. */
	__insn_mf();

	/* Reset. */
	f_id = f_size = f_used = -1;

	/* Egress all the edescs. */
	for (segment = 0; segment < sh->gso_segs; segment++) {

		/* Detect the final segment. */
		bool final = (segment == sh->gso_segs - 1);

		/* The segment size (including header). */
		unsigned int s_len = final ? mtu2 : mtu;

		/* The size of the payload. */
		unsigned int p_len = s_len - sh_len;

		/* The bytes used from the payload. */
		unsigned int p_used = 0;

		/* Access the header memory for this segment. */
		unsigned int bn = slot % EQUEUE_ENTRIES;
		unsigned char *buf =
			priv->headers + bn * HEADER_BYTES + NET_IP_ALIGN;

		void *va;

		/* Egress the header. */
		edesc_head.va = (ulong)buf_to_cpa(buf);
		gxio_mpipe_equeue_put_at(equeue, edesc_head, slot);
		slot++;

		/* Egress the payload. */
		while (p_used < p_len) {

			/* Advance as needed. */
			while (f_used >= f_size) {
				f_id++;
				f_size = sh->frags[f_id].size;
				f_used = 0;
			}

			va = tile_net_frag_buf(&sh->frags[f_id]) + f_used;

			/* Use bytes from the current fragment. */
			n = p_len - p_used;
			if (n > f_size - f_used)
				n = f_size - f_used;
			f_used += n;
			p_used += n;

			/* Egress a piece of the payload. */
			edesc_body.va = (ulong)buf_to_cpa(va);
			edesc_body.xfer_size = n;
			edesc_body.bound = !(p_used < p_len);
			gxio_mpipe_equeue_put_at(equeue, edesc_body, slot);
			slot++;
		}

		tx_packets++;
		tx_bytes += s_len;
	}

	comps = info->comps_for_dev[priv->devno];
	cid = comps->comp_next % TILE_NET_MAX_COMPS;

	/* Wait for a free completion entry.
	 * ISSUE: Is this the best logic?
	 * ISSUE: Can this cause undesirable "blocking"?
	 */
	while (comps->comp_next - comps->comp_last >= TILE_NET_MAX_COMPS - 1)
		tile_net_free_comps(dev, comps, 32, false);

	/* Update the completions array. */
	comps->comp_queue[cid].when = slot;
	comps->comp_queue[cid].skb = skb;
	comps->comp_next++;

	/* Update stats. */
	stats = &info->stats_for_dev[priv->devno];
	stats->tx_packets += tx_packets;
	stats->tx_bytes += tx_bytes;

	local_irq_restore(irqflags);

	/* Make sure the egress timer is scheduled. */
	tile_net_schedule_egress_timer(info);

	return NETDEV_TX_OK;
}


/* Analyze the body and frags for a transmit request. */
static unsigned int tile_net_tx_frags(struct frag *frags,
				       struct sk_buff *skb,
				       void *b_data, unsigned int b_len)
{
	unsigned int i, n = 0;

	struct skb_shared_info *sh = skb_shinfo(skb);

	if (b_len != 0) {
		frags[n].buf = b_data;
		frags[n++].length = b_len;
	}

	for (i = 0; i < sh->nr_frags; i++) {
		skb_frag_t *f = &sh->frags[i];
		frags[n].buf = tile_net_frag_buf(f);
		frags[n++].length = skb_frag_size(f);
	}

	return n;
}


/* Help the kernel transmit a packet. */
static int tile_net_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	gxio_mpipe_equeue_t *equeue = priv->equeue;

	struct tile_net_info_t *info = &__get_cpu_var(per_cpu_info);

	struct tile_net_stats_t *stats;

	struct skb_shared_info *sh = skb_shinfo(skb);

	unsigned int len = skb->len;
	unsigned char *data = skb->data;

	unsigned int num_frags;
	struct frag frags[MAX_FRAGS];
	gxio_mpipe_edesc_t edescs[MAX_FRAGS];

	struct tile_net_comps *comps;

	unsigned int i;

	int cid;

	s64 slot;

	unsigned long irqflags;

	/* Save the timestamp. */
	dev->trans_start = jiffies;

#ifdef TILE_NET_DUMP_PACKETS
	/* ISSUE: Does not dump the "frags". */
	dump_packet(data, skb_headlen(skb), "tx");
#endif /* TILE_NET_DUMP_PACKETS */

	if (sh->gso_size != 0)
		return tile_net_tx_tso(skb, dev);

	/* NOTE: This is usually 2, sometimes 3, for big writes. */
	num_frags = tile_net_tx_frags(frags, skb, data, skb_headlen(skb));

	/* Prepare the edescs. */
	for (i = 0; i < num_frags; i++) {

		/* NOTE: ".hwb = 0", so ".size" is unused.
		 * NOTE: ".stack_idx" determines the TLB.
		 */

		gxio_mpipe_edesc_t edesc = { { 0 } };

		/* Prepare the basic command. */
		edesc.bound = (i == num_frags - 1);
		edesc.xfer_size = frags[i].length;
		edesc.va = (ulong)buf_to_cpa(frags[i].buf);
		edesc.stack_idx = large_buffer_stack;

		edescs[i] = edesc;
	}

	/* Add checksum info if needed. */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		unsigned int csum_start = skb->csum_start - skb_headroom(skb);
		edescs[0].csum = 1;
		edescs[0].csum_start = csum_start;
		edescs[0].csum_dest = csum_start + skb->csum_offset;
	}

	local_irq_save(irqflags);

	/* Reserve slots, or return NETDEV_TX_BUSY if "full". */
	slot = gxio_mpipe_equeue_try_reserve(equeue, num_frags);
	if (slot < 0) {
		if (net_ratelimit())
			pr_info("Egress blocked on '%s'!\n", dev->name);
		local_irq_restore(irqflags);
		return NETDEV_TX_BUSY;
	}

	for (i = 0; i < num_frags; i++)
		gxio_mpipe_equeue_put_at(equeue, edescs[i], slot + i);

	comps = info->comps_for_dev[priv->devno];
	cid = comps->comp_next % TILE_NET_MAX_COMPS;

	/* Wait for a free completion entry.
	 * ISSUE: Is this the best logic?
	 */
	while (comps->comp_next - comps->comp_last >= TILE_NET_MAX_COMPS - 1)
		tile_net_free_comps(dev, comps, 32, false);

	/* Update the completions array. */
	comps->comp_queue[cid].when = slot + num_frags;
	comps->comp_queue[cid].skb = skb;
	comps->comp_next++;

	/* HACK: Track "expanded" size for short packets (e.g. 42 < 60). */
	stats = &info->stats_for_dev[priv->devno];
	stats->tx_packets++;
	stats->tx_bytes += ((len >= ETH_ZLEN) ? len : ETH_ZLEN);

	local_irq_restore(irqflags);

	/* Make sure the egress timer is scheduled. */
	tile_net_schedule_egress_timer(info);

	return NETDEV_TX_OK;
}


/* Deal with a transmit timeout. */
static void tile_net_tx_timeout(struct net_device *dev)
{
	/* ISSUE: This doesn't seem useful for us. */
	netif_wake_queue(dev);
}


/* Ioctl commands. */
static int tile_net_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	return -EOPNOTSUPP;
}


/* Get System Network Statistics.
 *
 * Returns the address of the device statistics structure.
 */
static struct net_device_stats *tile_net_get_stats(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	int devno = priv->devno;

	u32 rx_packets = 0;
	u32 tx_packets = 0;
	u32 rx_bytes = 0;
	u32 tx_bytes = 0;
	int i;

	for_each_online_cpu(i) {
		rx_packets += infos[i]->stats_for_dev[devno].rx_packets;
		rx_bytes += infos[i]->stats_for_dev[devno].rx_bytes;
		tx_packets += infos[i]->stats_for_dev[devno].tx_packets;
		tx_bytes += infos[i]->stats_for_dev[devno].tx_bytes;
	}

	priv->stats.rx_packets = rx_packets;
	priv->stats.rx_bytes = rx_bytes;
	priv->stats.tx_packets = tx_packets;
	priv->stats.tx_bytes = tx_bytes;

	return &priv->stats;
}


/* Change the "mtu". */
static int tile_net_change_mtu(struct net_device *dev, int new_mtu)
{
	/* Check ranges. */
	if ((new_mtu < 68) || (new_mtu > 1500))
		return -EINVAL;

	/* Accept the value. */
	dev->mtu = new_mtu;

	return 0;
}


/* Change the Ethernet Address of the NIC.
 *
 * The hypervisor driver does not support changing MAC address.  However,
 * the hardware does not do anything with the MAC address, so the address
 * which gets used on outgoing packets, and which is accepted on incoming
 * packets, is completely up to us.
 *
 * Returns 0 on success, negative on failure.
 */
static int tile_net_set_mac_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return 0;
}


#ifdef CONFIG_NET_POLL_CONTROLLER
/* Polling 'interrupt' - used by things like netconsole to send skbs
 * without having to re-enable interrupts. It's not called while
 * the interrupt routine is executing.
 */
static void tile_net_netpoll(struct net_device *dev)
{
	disable_percpu_irq(ingress_irq);
	tile_net_handle_ingress_irq(ingress_irq, NULL);
	enable_percpu_irq(ingress_irq, 0);
}
#endif


static const struct net_device_ops tile_net_ops = {
	.ndo_open = tile_net_open,
	.ndo_stop = tile_net_stop,
	.ndo_start_xmit = tile_net_tx,
	.ndo_do_ioctl = tile_net_ioctl,
	.ndo_get_stats = tile_net_get_stats,
	.ndo_change_mtu = tile_net_change_mtu,
	.ndo_tx_timeout = tile_net_tx_timeout,
	.ndo_set_mac_address = tile_net_set_mac_address,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = tile_net_netpoll,
#endif
};

/* The setup function.
 *
 * This uses ether_setup() to assign various fields in dev, including
 * setting IFF_BROADCAST and IFF_MULTICAST, then sets some extra fields.
 */
static void tile_net_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->netdev_ops      = &tile_net_ops;
	dev->watchdog_timeo  = TILE_NET_TIMEOUT;

	/* We want lockless xmit. */
	dev->features |= NETIF_F_LLTX;

	/* We support hardware tx checksums. */
	dev->features |= NETIF_F_HW_CSUM;

	/* We support scatter/gather. */
	dev->features |= NETIF_F_SG;

#ifdef TILE_NET_GSO
	/* We support GSO. */
	dev->features |= NETIF_F_GSO;
#endif

#ifdef TILE_NET_TSO
	/* We support TSO. */
	dev->features |= NETIF_F_TSO;
#endif

	dev->tx_queue_len = TILE_NET_TX_QUEUE_LEN;

	dev->mtu = 1500;
}


/* Allocate the device structure, register the device, and obtain the
 * MAC address from the hypervisor.
 */
static void tile_net_dev_init(const char *name, const uint8_t* mac)
{
	int ret;
	int devno = 0;
	int i;
	int nz_addr = 0;
	struct net_device *dev;
	struct tile_net_priv *priv;

	/* HACK: Ignore "loop" links. */
	if (strncmp(name, "loop", 4) == 0)
		return;

	/* Find the next available devno. */
	while (tile_net_devs[devno] != NULL)
		devno++;

	/* Allocate the device structure.  This allocates "priv", calls
	 * tile_net_setup(), and saves "name".  Normally, "name" is a
	 * template, instantiated by register_netdev(), but not for us.
	 */
	dev = alloc_netdev(sizeof(*priv), name, tile_net_setup);
	if (!dev) {
		pr_err("alloc_netdev(%s) failed\n", name);
		return;
	}

	priv = netdev_priv(dev);

	/* Initialize "priv". */

	memset(priv, 0, sizeof(*priv));

	priv->dev = dev;
	priv->devno = devno;

	priv->channel = priv->loopify_channel = -1;

	/* Save the device. */
	tile_net_devs[devno] = dev;

	/* Register the network device. */
	ret = register_netdev(dev);
	if (ret) {
		netdev_err(dev, "register_netdev failed %d\n", ret);
		free_netdev(dev);
		tile_net_devs[devno] = NULL;
		return;
	}

	/* Get the MAC address and set it in the device struct; this must
	 * be done before the device is opened.  If the MAC is all zeroes,
	 * we use a random address, since we're probably on the simulator.
	 */
	for (i = 0; i < 6; i++)
		nz_addr |= mac[i];

	if (nz_addr) {
		memcpy(dev->dev_addr, mac, 6);
		dev->addr_len = 6;
	} else {
		random_ether_addr(dev->dev_addr);
	}
}


/* Module cleanup. */
static void __exit tile_net_cleanup(void)
{
	int i;

	for (i = 0; i < TILE_NET_DEVS; i++) {
		struct net_device *dev = tile_net_devs[i];
		if (dev != NULL) {
			unregister_netdev(dev);
			free_netdev(dev);
		}
	}
}


/* Module initialization. */
static int __init tile_net_init_module(void)
{
	int i;
	char name[GXIO_MPIPE_LINK_NAME_LEN];
	uint8_t mac[6];

	pr_info("Tilera Network Driver\n");

	mutex_init(&tile_net_devs_mutex);

	/* Initialize each CPU. */
	on_each_cpu(tile_net_prepare_cpu, NULL, 1);

	/* Find out what devices we have, and initialize them. */
	for (i = 0; gxio_mpipe_link_enumerate_mac(i, name, mac) >= 0; i++)
		tile_net_dev_init(name, mac);

	return 0;
}


#ifndef MODULE
/* The "network_cpus" boot argument specifies the cpus that are dedicated
 * to handle ingress packets.
 *
 * The parameter should be in the form "network_cpus=m-n[,x-y]", where
 * m, n, x, y are integer numbers that represent the cpus that can be
 * neither a dedicated cpu nor a dataplane cpu.
 */
static int __init network_cpus_setup(char *str)
{
	int rc = cpulist_parse_crop(str, &network_cpus_map);
	if (rc != 0) {
		pr_warning("network_cpus=%s: malformed cpu list\n",
		       str);
	} else {

		/* Remove dedicated cpus. */
		cpumask_and(&network_cpus_map, &network_cpus_map,
			    cpu_possible_mask);

#ifdef CONFIG_DATAPLANE
		/* Remove dataplane cpus. */
		cpumask_andnot(&network_cpus_map, &network_cpus_map,
			       &dataplane_map);
#endif

		if (cpumask_empty(&network_cpus_map)) {
			pr_warning("Ignoring network_cpus='%s'.\n", str);
		} else {
			char buf[1024];
			cpulist_scnprintf(buf, sizeof(buf), &network_cpus_map);
			pr_info("Linux network CPUs: %s\n", buf);
			network_cpus_used = true;
		}
	}

	return 0;
}
__setup("network_cpus=", network_cpus_setup);


/* The "loopify=LINK" boot argument causes the named device to
 * actually use "loop0" for ingress, and "loop1" for egress.  This
 * allows an app to sit between the actual link and linux, passing
 * (some) packets along to linux, and forwarding (some) packets sent
 * out by linux.
 */
static int __init loopify_setup(char *str)
{
	strncpy(loopify_link_name, str, sizeof(loopify_link_name) - 1);
	return 0;
}
__setup("loopify=", loopify_setup);

#endif


module_init(tile_net_init_module);
module_exit(tile_net_cleanup);
