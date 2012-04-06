/*
 * Copyright 2012 Tilera Corporation. All Rights Reserved.
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
#include <linux/ip.h>
#include <linux/tcp.h>

#include <asm/checksum.h>
#include <asm/homecache.h>
#include <gxio/mpipe.h>
#include <arch/sim.h>

/* Define to support GSO. */
#undef TILE_NET_GSO

/* Define to support TSO. */
#define TILE_NET_TSO

/* Use 3000 to enable the Linux Traffic Control (QoS) layer, else 0. */
#define TILE_NET_TX_QUEUE_LEN 0

/* Define to dump packets (prints out the whole packet on tx and rx). */
#undef TILE_NET_DUMP_PACKETS

/* Default transmit lockup timeout period, in jiffies. */
#define TILE_NET_TIMEOUT (5 * HZ)

/* The maximum number of distinct channels (idesc.channel is 5 bits). */
#define TILE_NET_CHANNELS 32

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

#define MAX_FRAGS (65536 / PAGE_SIZE + 2 + 1)

MODULE_AUTHOR("Tilera Corporation");
MODULE_LICENSE("GPL");

/* A "packet fragment" (a chunk of memory). */
struct frag {
	void *buf;
	size_t length;
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

/* Info for a specific cpu. */
struct tile_net_info {
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
	/* Comps for each egress channel. */
	struct tile_net_comps *comps_for_echannel[TILE_NET_CHANNELS];
};

/* Info for egress on a particular egress channel. */
struct tile_net_egress {
	/* The "equeue". */
	gxio_mpipe_equeue_t *equeue;
	/* The headers for TSO. */
	unsigned char *headers;
};

/* Info for a specific device. */
struct tile_net_priv {
	/* Our network device. */
	struct net_device *dev;
	/* The primary link. */
	gxio_mpipe_link_t link;
	/* The primary channel, if open, else -1. */
	int channel;
	/* The "loopify" egress link, if needed. */
	gxio_mpipe_link_t loopify_link;
	/* The "loopify" egress channel, if open, else -1. */
	int loopify_channel;
	/* The egress channel (channel or loopify_channel). */
	int echannel;
	/* Total stats. */
	struct net_device_stats stats;
};

/* Egress info, indexed by "priv->echannel" (lazily created as needed). */
static struct tile_net_egress egress_for_echannel[TILE_NET_CHANNELS];

/* Devices currently associated with each channel.
 * NOTE: The array entry can become NULL after ifconfig down, but
 * we do not free the underlying net_device structures, so it is
 * safe to use a pointer after reading it from this array.
 */
static struct net_device *tile_net_devs_for_channel[TILE_NET_CHANNELS];

/* A mutex for "tile_net_devs_for_channel". */
static DEFINE_MUTEX(tile_net_devs_for_channel_mutex);

/* The per-cpu info. */
static DEFINE_PER_CPU(struct tile_net_info, per_cpu_info);

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

/* Text value of tile_net.cpus if passed as a module parameter. */
static char *network_cpus_string;

/* The actual cpus in "network_cpus". */
static struct cpumask network_cpus_map;

/* If "loopify=LINK" was specified, this is "LINK". */
static char *loopify_link_name;

/* The "tile_net.cpus" argument specifies the cpus that are dedicated
 * to handle ingress packets.
 *
 * The parameter should be in the form "tile_net.cpus=m-n[,x-y]", where
 * m, n, x, y are integer numbers that represent the cpus that can be
 * neither a dedicated cpu nor a dataplane cpu.
 */
static bool network_cpus_init(void)
{
	char buf[1024];
	int rc;

	if (network_cpus_string == NULL)
		return false;

	rc = cpulist_parse_crop(network_cpus_string, &network_cpus_map);
	if (rc != 0) {
		pr_warn("tile_net.cpus=%s: malformed cpu list\n",
			network_cpus_string);
		return false;
	}

	/* Remove dedicated cpus. */
	cpumask_and(&network_cpus_map, &network_cpus_map, cpu_possible_mask);

	if (cpumask_empty(&network_cpus_map)) {
		pr_warn("Ignoring empty tile_net.cpus='%s'.\n",
			network_cpus_string);
		return false;
	}

	cpulist_scnprintf(buf, sizeof(buf), &network_cpus_map);
	pr_info("Linux network CPUs: %s\n", buf);
	return true;
}

module_param_named(cpus, network_cpus_string, charp, 0444);
MODULE_PARM_DESC(cpus, "cpulist of cores that handle network interrupts");

/* The "tile_net.loopify=LINK" argument causes the named device to
 * actually use "loop0" for ingress, and "loop1" for egress.  This
 * allows an app to sit between the actual link and linux, passing
 * (some) packets along to linux, and forwarding (some) packets sent
 * out by linux.
 */
module_param_named(loopify, loopify_link_name, charp, 0444);
MODULE_PARM_DESC(loopify, "name the device to use loop0/1 for ingress/egress");

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
	wmb();

	gxio_mpipe_push_buffer(&context, stack,
			       (void *)va_to_tile_io_addr(skb->data));

	return true;
}

static void tile_net_pop_all_buffers(int stack)
{
	void *va;
	while ((va = gxio_mpipe_pop_buffer(&context, stack)) != NULL) {
		struct sk_buff **skb_ptr = va - sizeof(*skb_ptr);
		struct sk_buff *skb = *skb_ptr;
		dev_kfree_skb_irq(skb);
	}
}

/* Provide linux buffers to mPIPE. */
static void tile_net_provide_needed_buffers(struct tile_net_info *info)
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
static bool tile_net_handle_packet(struct tile_net_info *info,
				   gxio_mpipe_idesc_t *idesc)
{
	struct net_device *dev = tile_net_devs_for_channel[idesc->channel];
	uint8_t l2_offset = gxio_mpipe_idesc_get_l2_offset(idesc);
	void *va;
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
	va = tile_io_addr_to_va((unsigned long)gxio_mpipe_idesc_get_va(idesc));

	/* Get the actual packet start/length. */
	buf = va + l2_offset;
	len = gxio_mpipe_idesc_get_l2_length(idesc);

	/* Point "va" at the raw buffer. */
	va -= NET_IP_ALIGN;

#ifdef TILE_NET_DUMP_PACKETS
	dump_packet(buf, len, "rx");
#endif

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

		/* Acquire the associated "skb". */
		struct sk_buff **skb_ptr = va - sizeof(*skb_ptr);
		struct sk_buff *skb = *skb_ptr;

		/* Paranoia. */
		if (skb->data != va) {
			/* Panic here since there's a reasonable chance
			 * that corrupt buffers means generic memory
			 * corruption, with unpredictable system effects.
			 */
			panic("Corrupt linux buffer! "
			      "buf=%p, skb=%p, skb->data=%p",
			      buf, skb, skb->data);
		}

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
		atomic_add(1, (atomic_t *)&priv->stats.rx_packets);
		atomic_add(len, (atomic_t *)&priv->stats.rx_bytes);

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
	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);
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
	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);
	napi_schedule(&info->napi);
	return IRQ_HANDLED;
}

/* Free some completions.  This must be called with interrupts blocked. */
static void tile_net_free_comps(gxio_mpipe_equeue_t *equeue,
				struct tile_net_comps *comps,
				int limit, bool force_update)
{
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
static void tile_net_schedule_egress_timer(struct tile_net_info *info)
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
	struct tile_net_info *info = (struct tile_net_info *)arg;
	unsigned long irqflags;
	bool pending = false;
	int i;

	local_irq_save(irqflags);

	/* The timer is no longer scheduled. */
	info->egress_timer_scheduled = false;

	/* Free all possible comps for this tile. */
	for (i = 0; i < TILE_NET_CHANNELS; i++) {
		struct tile_net_egress *egress = &egress_for_echannel[i];
		struct tile_net_comps *comps = info->comps_for_echannel[i];
		if (comps->comp_last >= comps->comp_next)
			continue;
		tile_net_free_comps(egress->equeue, comps, -1, true);
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
	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);
	int my_cpu = smp_processor_id();

	info->has_iqueue = false;

	info->my_cpu = my_cpu;

	/* Initialize the egress timer. */
	init_timer(&info->egress_timer);
	info->egress_timer.data = (long)info;
	info->egress_timer.function = tile_net_handle_egress_timer;
}

/* Helper function for "tile_net_update()". */
static void tile_net_update_cpu(void *arg)
{
	struct net_device *dev = arg;
	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);

	if (info->has_iqueue) {
		if (dev != NULL) {
			if (!info->napi_added) {
				netif_napi_add(dev, &info->napi,
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

/* Helper function for tile_net_open() and tile_net_stop().
 * Always called under tile_net_devs_for_channel_mutex.
 */
static int tile_net_update(struct net_device *dev)
{
	int channel;
	long count = 0;
	int cpu;
	int rc;
	bool saw_channel;
	static gxio_mpipe_rules_t rules;

	gxio_mpipe_rules_init(&rules, &context);

	saw_channel = false;
	for (channel = 0; channel < TILE_NET_CHANNELS; channel++) {
		if (tile_net_devs_for_channel[channel] == NULL)
			continue;
		if (!saw_channel) {
			saw_channel = true;
			gxio_mpipe_rules_begin(&rules, first_bucket,
					       num_buckets, NULL);
			gxio_mpipe_rules_set_headroom(&rules, NET_IP_ALIGN);
		}
		gxio_mpipe_rules_add_channel(&rules, channel);
	}

	/* NOTE: This can fail if there is no classifier.
	 * ISSUE: Can anything else cause it to fail?
	 */
	rc = gxio_mpipe_rules_commit(&rules);
	if (rc != 0) {
		netdev_warn(dev, "gxio_mpipe_rules_commit failed: %d\n", rc);
		return -EIO;
	}

	/* Update all cpus, sequentially (to protect "netif_napi_add()"). */
	for_each_online_cpu(cpu)
		smp_call_function_single(cpu, tile_net_update_cpu,
					 (saw_channel ? dev : NULL), 1);

	/* HACK: Allow packets to flow in the simulator. */
	if (count != 0)
		sim_enable_mpipe_links(0, -1);

	return 0;
}

/* The first time any tilegx network device is opened, we initialize
 * the global mpipe state.  If this step fails, we fail to open the
 * device, but if it succeeds, we never need to do it again, and since
 * tile_net can't be unloaded, we never undo it.
 *
 * Note that some resources in this path (buffer stack indices,
 * bindings from init_buffer_stack, etc.) are hypervisor resources
 * that are freed simply via gxio_mpipe_destroy().
 */
static int tile_net_init_mpipe(struct net_device *dev)
{
	gxio_mpipe_buffer_size_enum_t small_buf_size =
		GXIO_MPIPE_BUFFER_SIZE_128;
	gxio_mpipe_buffer_size_enum_t large_buf_size =
		GXIO_MPIPE_BUFFER_SIZE_1664;
	size_t stack_bytes;
	pte_t pte = { 0 };
	void *small = NULL;
	void *large = NULL;
	int i, num_buffers, rc;
	int network_cpus_count, cpu;
	int ring, group, next_ring;
	size_t comps_size = 0;
	size_t notif_ring_size = 0;

	if (!hash_default) {
		netdev_err(dev, "Networking requires hash_default!\n");
		return -EIO;
	}

	rc =  gxio_mpipe_init(&context, 0);
	if (rc != 0) {
		netdev_err(dev, "gxio_mpipe_init failed: %d\n", rc);
		return -EIO;
	}

	network_cpus_count = cpus_weight(network_cpus_map);

	num_buffers =
		network_cpus_count * (IQUEUE_ENTRIES + TILE_NET_BATCH);

	/* Compute stack bytes; we round up to 64KB and then use
	 * alloc_pages() so we get the required 64KB alignment as well.
	 */
	stack_bytes = ALIGN(gxio_mpipe_calc_buffer_stack_bytes(num_buffers),
			    64 * 1024);

	/* Allocate two buffer stack indices. */
	rc = gxio_mpipe_alloc_buffer_stacks(&context, 2, 0, 0);
	if (rc < 0) {
		netdev_err(dev, "gxio_mpipe_alloc_buffer_stacks failed: %d\n",
			   rc);
		goto fail;
	}
	small_buffer_stack = rc;
	large_buffer_stack = rc + 1;

	/* Allocate the small memory stack. */
	small = alloc_pages_exact(stack_bytes, GFP_KERNEL);
	if (small == NULL) {
		netdev_err(dev,
			   "Could not alloc %zd bytes for buffer stacks\n",
			   stack_bytes);
		rc = -ENOMEM;
		goto fail;
	}
	rc = gxio_mpipe_init_buffer_stack(&context, small_buffer_stack,
					  small_buf_size,
					  small, stack_bytes, 0);
	if (rc != 0) {
		netdev_err(dev, "gxio_mpipe_init_buffer_stack: %d\n", rc);
		goto fail;
	}

	/* Allocate the large buffer stack. */
	large = alloc_pages_exact(stack_bytes, GFP_KERNEL);
	if (large == NULL) {
		netdev_err(dev,
			   "Could not alloc %zd bytes for buffer stacks\n",
			   stack_bytes);
		rc = -ENOMEM;
		goto fail;
	}
	rc = gxio_mpipe_init_buffer_stack(&context, large_buffer_stack,
					  large_buf_size,
					  large, stack_bytes, 0);
	if (rc != 0) {
		netdev_err(dev, "gxio_mpipe_init_buffer_stack failed: %d\n",
			   rc);
		goto fail;
	}

	/* Register all the client memory in mpipe TLBs. */
	pte = pte_set_home(pte, PAGE_HOME_HASH);
	rc = gxio_mpipe_register_client_memory(&context, small_buffer_stack,
					       pte, 0);
	if (rc != 0) {
		netdev_err(dev,
			   "gxio_mpipe_register_buffer_memory failed: %d\n",
			   rc);
		goto fail;
	}
	rc = gxio_mpipe_register_client_memory(&context, large_buffer_stack,
					       pte, 0);
	if (rc != 0) {
		netdev_err(dev,
			   "gxio_mpipe_register_buffer_memory failed: %d\n",
			   rc);
		goto fail;
	}

	/* Provide initial buffers. */
	rc = -ENOMEM;
	for (i = 0; i < num_buffers; i++) {
		if (!tile_net_provide_buffer(true)) {
			netdev_err(dev, "Cannot allocate initial sk_bufs!\n");
			goto fail_pop;
		}
	}
	for (i = 0; i < num_buffers; i++) {
		if (!tile_net_provide_buffer(false)) {
			netdev_err(dev, "Cannot allocate initial sk_bufs!\n");
			goto fail_pop;
		}
	}

	/* Allocate one NotifRing for each network cpu. */
	rc = gxio_mpipe_alloc_notif_rings(&context, network_cpus_count,
					  0, 0);
	if (rc < 0) {
		netdev_err(dev, "gxio_mpipe_alloc_notif_rings failed %d\n",
			   rc);
		goto fail_pop;
	}

	/* Init NotifRings. */
	ring = rc;
	next_ring = rc;

	/* ISSUE: This is more than strictly necessary. */
	comps_size = TILE_NET_CHANNELS * sizeof(struct tile_net_comps);

	notif_ring_size = IQUEUE_ENTRIES * sizeof(gxio_mpipe_idesc_t);

	for_each_online_cpu(cpu) {

		int order;
		struct page *page;
		void *addr;

		struct tile_net_info *info = &per_cpu(per_cpu_info, cpu);

		/* Allocate the "comps". */
		order = get_order(comps_size);
		page = homecache_alloc_pages(GFP_KERNEL, order, cpu);
		if (page == NULL) {
			netdev_err(dev,
				   "Failed to alloc %zd bytes comps memory\n",
				   comps_size);
			rc = -ENOMEM;
			goto fail_pop;
		}

		addr = pfn_to_kaddr(page_to_pfn(page));
		memset(addr, 0, comps_size);
		for (i = 0; i < TILE_NET_CHANNELS; i++)
			info->comps_for_echannel[i] =
				addr + i * sizeof(struct tile_net_comps);

		/* Only network cpus can receive packets. */
		if (!cpu_isset(cpu, network_cpus_map))
			continue;

		/* Allocate the actual idescs array. */
		order = get_order(notif_ring_size);
		page = homecache_alloc_pages(GFP_KERNEL, order, cpu);
		if (page == NULL) {
			netdev_err(dev,
				   "Failed to alloc %zd bytes iqueue memory\n",
				   notif_ring_size);
			rc = -ENOMEM;
			goto fail_pop;
		}
		addr = pfn_to_kaddr(page_to_pfn(page));
		rc = gxio_mpipe_iqueue_init(&info->iqueue, &context, next_ring,
					    addr, notif_ring_size, 0);
		if (rc != 0) {
			netdev_err(dev,
				   "gxio_mpipe_iqueue_init failed: %d\n", rc);
			goto fail_pop;
		}

		info->has_iqueue = true;

		next_ring++;
	}

	/* Allocate one NotifGroup. */
	rc = gxio_mpipe_alloc_notif_groups(&context, 1, 0, 0);
	if (rc < 0) {
		netdev_err(dev, "gxio_mpipe_alloc_notif_groups failed: %d\n",
			   rc);
		goto fail_pop;
	}
	group = rc;

	if (network_cpus_count > 4)
		num_buckets = 256;
	else if (network_cpus_count > 1)
		num_buckets = 16;

	/* Allocate some buckets. */
	rc = gxio_mpipe_alloc_buckets(&context, num_buckets, 0, 0);
	if (rc < 0) {
		netdev_err(dev, "gxio_mpipe_alloc_buckets failed: %d\n", rc);
		goto fail_pop;
	}
	first_bucket = rc;

	/* Init group and buckets. */
	rc = gxio_mpipe_init_notif_group_and_buckets(
		&context, group, ring, network_cpus_count,
		first_bucket, num_buckets,
		GXIO_MPIPE_BUCKET_STICKY_FLOW_LOCALITY);

	if (rc != 0) {
		netdev_err(
			dev,
			"gxio_mpipe_init_notif_group_and_buckets failed: %d\n",
			rc);
		goto fail_pop;
	}

	/* Create an irq and register it. Note that "ingress_irq" being
	 * initialized is how we know not to call this function again.
	 */
	rc = create_irq();
	if (rc < 0) {
		netdev_err(dev, "create_irq failed: %d\n", rc);
		goto fail_pop;

	}
	ingress_irq = rc;
	tile_irq_activate(ingress_irq, TILE_IRQ_PERCPU);
	rc = request_irq(ingress_irq, tile_net_handle_ingress_irq,
			 0, NULL, NULL);
	if (rc != 0) {
		netdev_err(dev, "request_irq failed: %d\n", rc);
		destroy_irq(ingress_irq);
		ingress_irq = -1;
		goto fail_pop;
	}

	for_each_online_cpu(cpu) {
		struct tile_net_info *info = &per_cpu(per_cpu_info, cpu);
		if (info->has_iqueue) {
			gxio_mpipe_request_notif_ring_interrupt(
				&context, cpu_x(cpu), cpu_y(cpu),
				1, ingress_irq, info->iqueue.ring);
		}
	}

	return 0;

fail_pop:
	/* Do cleanups that require the mpipe context first. */
	tile_net_pop_all_buffers(small_buffer_stack);
	tile_net_pop_all_buffers(large_buffer_stack);

fail:
	/* Destroy mpipe context so the hardware no longer owns any memory. */
	gxio_mpipe_destroy(&context);

	for_each_online_cpu(cpu) {
		struct tile_net_info *info = &per_cpu(per_cpu_info, cpu);
		free_pages((unsigned long)(info->comps_for_echannel[0]),
			   get_order(comps_size));
		info->comps_for_echannel[0] = NULL;
		free_pages((unsigned long)(info->iqueue.idescs),
			   get_order(notif_ring_size));
		info->iqueue.idescs = NULL;
	}

	if (small)
		free_pages_exact(small, stack_bytes);
	if (large)
		free_pages_exact(large, stack_bytes);

	large_buffer_stack = -1;
	small_buffer_stack = -1;
	first_bucket = -1;

	return rc;
}

/* Create persistent egress info for a given egress channel.
 *
 * Note that this may be shared between, say, "gbe0" and "xgbe0".
 *
 * ISSUE: Defer header allocation until TSO is actually needed?
 */
static int tile_net_init_egress(struct net_device *dev, int echannel)
{
	size_t headers_order;
	struct page *headers_page;
	unsigned char *headers;

	size_t edescs_size;
	int edescs_order;
	struct page *edescs_page;
	gxio_mpipe_edesc_t *edescs;

	int equeue_order;
	struct page *equeue_page;
	gxio_mpipe_equeue_t *equeue;
	int edma;

	int rc = -ENOMEM;

	/* Only initialize once. */
	if (egress_for_echannel[echannel].equeue != NULL)
		return 0;

	/* Allocate memory for the "headers". */
	headers_order = get_order(EQUEUE_ENTRIES * HEADER_BYTES);
	headers_page = alloc_pages(GFP_KERNEL, headers_order);
	if (headers_page == NULL) {
		netdev_warn(dev,
			    "Could not alloc %zd bytes for TSO headers.\n",
			    PAGE_SIZE << headers_order);
		goto fail;
	}
	headers = pfn_to_kaddr(page_to_pfn(headers_page));

	/* Allocate memory for the "edescs". */
	edescs_size = EQUEUE_ENTRIES * sizeof(*edescs);
	edescs_order = get_order(edescs_size);
	edescs_page = alloc_pages(GFP_KERNEL, edescs_order);
	if (edescs_page == NULL) {
		netdev_warn(dev,
			    "Could not alloc %zd bytes for eDMA ring.\n",
			    edescs_size);
		goto fail_headers;
	}
	edescs = pfn_to_kaddr(page_to_pfn(edescs_page));

	/* Allocate memory for the "equeue". */
	equeue_order = get_order(sizeof(*equeue));
	equeue_page = alloc_pages(GFP_KERNEL, equeue_order);
	if (equeue_page == NULL) {
		netdev_warn(dev,
			    "Could not alloc %zd bytes for equeue info.\n",
			    PAGE_SIZE << equeue_order);
		goto fail_edescs;
	}
	equeue = pfn_to_kaddr(page_to_pfn(equeue_page));

	/* Allocate an edma ring.  Note that in practice this can't
	 * fail, which is good, because we will leak an edma ring if so.
	 */
	rc = gxio_mpipe_alloc_edma_rings(&context, 1, 0, 0);
	if (rc < 0) {
		netdev_warn(dev, "gxio_mpipe_alloc_edma_rings failed: %d\n",
			    rc);
		goto fail_equeue;
	}
	edma = rc;

	/* Initialize the equeue. */
	rc = gxio_mpipe_equeue_init(equeue, &context, edma, echannel,
				    edescs, edescs_size, 0);
	if (rc != 0) {
		netdev_err(dev, "gxio_mpipe_equeue_init failed: %d\n", rc);
		goto fail_equeue;
	}

	/* Done. */
	egress_for_echannel[echannel].equeue = equeue;
	egress_for_echannel[echannel].headers = headers;
	return 0;

fail_equeue:
	__free_pages(equeue_page, equeue_order);

fail_edescs:
	__free_pages(edescs_page, edescs_order);

fail_headers:
	__free_pages(headers_page, headers_order);

fail:
	return rc;
}

/* Return channel number for a newly-opened link. */
static int tile_net_link_open(struct net_device *dev, gxio_mpipe_link_t *link,
			      const char *link_name)
{
	int rc = gxio_mpipe_link_open(link, &context, link_name, 0);
	if (rc < 0) {
		netdev_err(dev, "Failed to open '%s'\n", link_name);
		return rc;
	}
	rc = gxio_mpipe_link_channel(link);
	if (rc < 0 || rc >= TILE_NET_CHANNELS) {
		netdev_err(dev, "gxio_mpipe_link_channel bad value: %d\n", rc);
		gxio_mpipe_link_close(link);
		return -EINVAL;
	}
	return rc;
}

/* Help the kernel activate the given network interface. */
static int tile_net_open(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);
	int rc;

	mutex_lock(&tile_net_devs_for_channel_mutex);

	/* Do one-time initialization the first time any device is opened. */
	if (ingress_irq < 0) {
		rc = tile_net_init_mpipe(dev);
		if (rc != 0)
			goto fail;
	}

	/* Determine if this is the "loopify" device. */
	if (unlikely((loopify_link_name != NULL) &&
		     !strcmp(dev->name, loopify_link_name))) {
		rc = tile_net_link_open(dev, &priv->link, "loop0");
		if (rc < 0)
			goto fail;
		priv->channel = rc;
		rc = tile_net_link_open(dev, &priv->loopify_link, "loop1");
		if (rc < 0)
			goto fail;
		priv->loopify_channel = rc;
		priv->echannel = rc;
	} else {
		rc = tile_net_link_open(dev, &priv->link, dev->name);
		if (rc < 0)
			goto fail;
		priv->channel = rc;
		priv->echannel = rc;
	}

	/* Initialize egress info (if needed).  Once ever, per echannel. */
	rc = tile_net_init_egress(dev, priv->echannel);
	if (rc != 0)
		goto fail;

	tile_net_devs_for_channel[priv->channel] = dev;

	rc = tile_net_update(dev);
	if (rc != 0)
		goto fail;

	mutex_unlock(&tile_net_devs_for_channel_mutex);

	/* Start our transmit queue. */
	netif_start_queue(dev);

	netif_carrier_on(dev);

	return 0;

fail:
	if (priv->loopify_channel >= 0) {
		if (gxio_mpipe_link_close(&priv->loopify_link) != 0)
			netdev_warn(dev, "Failed to close loopify link!\n");
		priv->loopify_channel = -1;
	}
	if (priv->channel >= 0) {
		if (gxio_mpipe_link_close(&priv->link) != 0)
			netdev_warn(dev, "Failed to close link!\n");
		priv->channel = -1;
	}

	priv->echannel = -1;

	tile_net_devs_for_channel[priv->channel] = NULL;

	mutex_unlock(&tile_net_devs_for_channel_mutex);

	/* Don't return raw gxio error codes to generic Linux. */
	return (rc > -512) ? rc : -EIO;
}

/* Help the kernel deactivate the given network interface. */
static int tile_net_stop(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);

	/* Stop our transmit queue. */
	netif_stop_queue(dev);

	mutex_lock(&tile_net_devs_for_channel_mutex);

	tile_net_devs_for_channel[priv->channel] = NULL;

	(void)tile_net_update(dev);

	if (priv->loopify_channel >= 0) {
		if (gxio_mpipe_link_close(&priv->loopify_link) != 0)
			netdev_warn(dev, "Failed to close loopify link!\n");
		priv->loopify_channel = -1;
	}

	if (priv->channel >= 0) {
		if (gxio_mpipe_link_close(&priv->link) != 0)
			netdev_warn(dev, "Failed to close link!\n");
		priv->channel = -1;
	}

	priv->echannel = -1;

	mutex_unlock(&tile_net_devs_for_channel_mutex);

	return 0;
}

/* Determine the VA for a fragment. */
static inline void *tile_net_frag_buf(skb_frag_t *f)
{
	unsigned long pfn = page_to_pfn(skb_frag_page(f));
	return pfn_to_kaddr(pfn) + f->page_offset;
}

/* Used for paranoia to make sure we handle no ill-formed packets. */
#define TSO_DROP_IF(cond) \
	do { if (WARN_ON(cond)) return NETDEV_TX_OK; } while (0)


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

	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);

	struct tile_net_egress *egress = &egress_for_echannel[priv->echannel];
	gxio_mpipe_equeue_t *equeue = egress->equeue;

	struct tile_net_comps *comps =
		info->comps_for_echannel[priv->echannel];

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

	int cid;

	/* Empty packets (etc) would cause trouble below. */
	TSO_DROP_IF(skb->data_len == 0);
	TSO_DROP_IF(sh->nr_frags == 0);
	TSO_DROP_IF(sh->gso_segs == 0);

	/* We assume the frags contain the entire payload. */
	TSO_DROP_IF(skb_headlen(skb) != sh_len);
	TSO_DROP_IF(len != sh_len + skb->data_len);

	/* Implicitly verify "gso_segs" and "gso_size". */
	TSO_DROP_IF(mtu2 > mtu);

	/* We only have HEADER_BYTES for each header. */
	TSO_DROP_IF(NET_IP_ALIGN + sh_len > HEADER_BYTES);

	/* Paranoia. */
	TSO_DROP_IF(skb->protocol != htons(ETH_P_IP));
	TSO_DROP_IF(ih->protocol != IPPROTO_TCP);
	TSO_DROP_IF(skb->ip_summed != CHECKSUM_PARTIAL);
	TSO_DROP_IF(csum_start != eh_len + ih_len);

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
	f_id = -1;
	f_size = -1;
	f_used = -1;

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
	TSO_DROP_IF(f_id + 1 != sh->nr_frags);
	TSO_DROP_IF(f_used != f_size);

	local_irq_save(irqflags);

	/* Reserve slots, or return NETDEV_TX_BUSY if "full". */
	slot = gxio_mpipe_equeue_try_reserve(equeue, num_edescs);
	if (slot < 0) {
		local_irq_restore(irqflags);
		/* ISSUE: "Virtual device xxx asks to queue packet". */
		return NETDEV_TX_BUSY;
	}

	/* Reset. */
	f_id = -1;
	f_size = -1;
	f_used = -1;

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
			egress->headers + bn * HEADER_BYTES + NET_IP_ALIGN;

		/* The soon-to-be copied "ip" header. */
		struct iphdr *jh = (struct iphdr *)(buf + eh_len);

		/* The soon-to-be copied "tcp" header. */
		struct tcphdr *uh = (struct tcphdr *)(buf + eh_len + ih_len);

		unsigned int jsum;

		/* Copy the header. */
		memcpy(buf, data, sh_len);

		/* The packet size, not including ethernet header. */
		jh->tot_len = htons(s_len - eh_len);

		/* Update the ip "id". */
		jh->id = htons(id);

		/* Compute the "ip checksum". */
		jsum = isum_hack + htons(s_len - eh_len) + htons(id);
		jh->check = csum_long(jsum) ^ 0xffff;

		/* Update the tcp "seq". */
		uh->seq = htonl(seq);

		/* Update some flags. */
		if (!final) {
			uh->fin = 0;
			uh->psh = 0;
		}

		/* Compute the tcp pseudo-header checksum. */
		uh->check = csum_long(tsum_hack + htons(s_len));

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
	wmb();

	/* Reset. */
	f_id = -1;
	f_size = -1;
	f_used = -1;

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
			egress->headers + bn * HEADER_BYTES + NET_IP_ALIGN;

		void *va;

		/* Egress the header. */
		edesc_head.va = va_to_tile_io_addr(buf);
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
			edesc_body.va = va_to_tile_io_addr(va);
			edesc_body.xfer_size = n;
			edesc_body.bound = !(p_used < p_len);
			gxio_mpipe_equeue_put_at(equeue, edesc_body, slot);
			slot++;
		}

		tx_packets++;
		tx_bytes += s_len;
	}

	/* Wait for a free completion entry.
	 * ISSUE: Is this the best logic?
	 * ISSUE: Can this cause undesirable "blocking"?
	 */
	while (comps->comp_next - comps->comp_last >= TILE_NET_MAX_COMPS - 1)
		tile_net_free_comps(equeue, comps, 32, false);

	/* Update the completions array. */
	cid = comps->comp_next % TILE_NET_MAX_COMPS;
	comps->comp_queue[cid].when = slot;
	comps->comp_queue[cid].skb = skb;
	comps->comp_next++;

	/* Update stats. */
	atomic_add(tx_packets, (atomic_t *)&priv->stats.tx_packets);
	atomic_add(tx_bytes, (atomic_t *)&priv->stats.tx_bytes);

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

	struct tile_net_info *info = &__get_cpu_var(per_cpu_info);

	struct tile_net_egress *egress = &egress_for_echannel[priv->echannel];
	gxio_mpipe_equeue_t *equeue = egress->equeue;

	struct tile_net_comps *comps =
		info->comps_for_echannel[priv->echannel];

	struct skb_shared_info *sh = skb_shinfo(skb);

	unsigned int len = skb->len;
	unsigned char *data = skb->data;

	unsigned int num_frags;
	struct frag frags[MAX_FRAGS];
	gxio_mpipe_edesc_t edescs[MAX_FRAGS];

	unsigned int i;

	int cid;

	s64 slot;

	unsigned long irqflags;

	/* Save the timestamp. */
	dev->trans_start = jiffies;

#ifdef TILE_NET_DUMP_PACKETS
	/* ISSUE: Does not dump the "frags". */
	dump_packet(data, skb_headlen(skb), "tx");
#endif

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
		edesc.va = va_to_tile_io_addr(frags[i].buf);
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
		local_irq_restore(irqflags);
		/* ISSUE: "Virtual device xxx asks to queue packet". */
		return NETDEV_TX_BUSY;
	}

	for (i = 0; i < num_frags; i++)
		gxio_mpipe_equeue_put_at(equeue, edescs[i], slot + i);

	/* Wait for a free completion entry.
	 * ISSUE: Is this the best logic?
	 * ISSUE: Can this cause undesirable "blocking"?
	 */
	while (comps->comp_next - comps->comp_last >= TILE_NET_MAX_COMPS - 1)
		tile_net_free_comps(equeue, comps, 32, false);

	/* Update the completions array. */
	cid = comps->comp_next % TILE_NET_MAX_COMPS;
	comps->comp_queue[cid].when = slot + num_frags;
	comps->comp_queue[cid].skb = skb;
	comps->comp_next++;

	/* HACK: Track "expanded" size for short packets (e.g. 42 < 60). */
	atomic_add(1, (atomic_t *)&priv->stats.tx_packets);
	atomic_add((len >= ETH_ZLEN) ? len : ETH_ZLEN,
		   (atomic_t *)&priv->stats.tx_bytes);

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

/* Get system network statistics for device. */
static struct net_device_stats *tile_net_get_stats(struct net_device *dev)
{
	struct tile_net_priv *priv = netdev_priv(dev);
	return &priv->stats;
}

/* Change the MTU. */
static int tile_net_change_mtu(struct net_device *dev, int new_mtu)
{
	/* Check ranges. */
	if ((new_mtu < 68) || (new_mtu > 1500))
		return -EINVAL;

	/* Accept the value. */
	dev->mtu = new_mtu;

	return 0;
}

/* Change the Ethernet address of the NIC.
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

	dev->netdev_ops = &tile_net_ops;
	dev->watchdog_timeo = TILE_NET_TIMEOUT;

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
static void tile_net_dev_init(const char *name, const uint8_t *mac)
{
	int ret;
	int i;
	int nz_addr = 0;
	struct net_device *dev;
	struct tile_net_priv *priv;

	/* HACK: Ignore "loop" links. */
	if (strncmp(name, "loop", 4) == 0)
		return;

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

	priv->channel = -1;
	priv->loopify_channel = -1;
	priv->echannel = -1;

	/* Register the network device. */
	ret = register_netdev(dev);
	if (ret) {
		netdev_err(dev, "register_netdev failed %d\n", ret);
		free_netdev(dev);
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

/* Module initialization. */
static int __init tile_net_init_module(void)
{
	int i;
	char name[GXIO_MPIPE_LINK_NAME_LEN];
	uint8_t mac[6];

	pr_info("Tilera Network Driver\n");

	mutex_init(&tile_net_devs_for_channel_mutex);

	/* Initialize each CPU. */
	on_each_cpu(tile_net_prepare_cpu, NULL, 1);

	/* Find out what devices we have, and initialize them. */
	for (i = 0; gxio_mpipe_link_enumerate_mac(i, name, mac) >= 0; i++)
		tile_net_dev_init(name, mac);

	if (!network_cpus_init())
		network_cpus_map = *cpu_online_mask;

	return 0;
}

module_init(tile_net_init_module);
