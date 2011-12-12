/*
 * Copyright (C) ST-Ericsson AB 2010
 * Author:	Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": %s :" fmt, __func__
#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/crc-ccitt.h>
#include <linux/kdev_t.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/xshm/xshm_ipctoc.h>
#include <linux/xshm/xshm_pdev.h>
#include <linux/xshm/xshm_netlink.h>
#include <linux/c2c_genio.h>

#define XSHM_VERSION	0x1
#define XSHM_SUBVER	0x0
#define TOC_SZ		512
#define IMG_MAX_SZ	65536
#define XSHM_ALIGNMT	sizeof(u32)
#define XSHM_MAX_CHANNELS 7
#define XSHM_MIN_CHSZ 3
#define XSHM_PAYL_ALIGN max(32, L1_CACHE_BYTES)

#define GET_OFFSET(base, ptr) (((u8 *)(ptr)) - ((u8 *)(base)))
#define OFFS2PTR(base, offs) ((void *) ((u8 *)base + offs))
#define LEOFFS2PTR(base, offs) ((void *) ((u8 *)base + le32_to_cpu(offs)))

/* Structure use in debug mode for integrity checking */
struct ipctoc_hash {
	u16 img_hash;
	u16 ch_hash;
	u16 ch_size;
};

static bool config_error;
static bool commited;
static bool registered;
static bool addr_set;
static u32 modem_bootimg_size;
static void *shm_start;
static u32 xshm_channels;
static struct xshm_dev *xshmdevs[XSHM_MAX_CHANNELS + 1];
static struct xshm_ipctoc *ipctoc;
static struct device _parentdev;
static struct device *parentdev;

static unsigned long xshm_start;
module_param(xshm_start, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xshm_start, "Address for memory shared by host/modem.");

static unsigned long xshm_c2c_bootaddr;
module_param(xshm_c2c_bootaddr, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xshm_c2c_bootaddr, "Address given to modem (through GENI register)");

static long xshm_size;
module_param(xshm_size, long, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(xshm_size, "Size of SHM area");

#ifdef DEBUG

/* In debug mode we pad around all payload area in order to detect overwrite */
#define MAGIC_PAD_LEN 32
#define MAGIC_PAD 0xbc

/* Verify a magic-pad area */
static inline bool padok(void *mag)
{
	u32 *p = mag, v = 0xbcbcbcbc;
	int i;

	for (i = 0; i < 8; i++)
		if (*p++ != v)
			return false;
	return true;
}

/* Insert a magic-pad area */
static inline void add_magic_pad(u32 *offset, void *base)
{
	if (*offset < xshm_size)
		memset(base + *offset, MAGIC_PAD, MAGIC_PAD_LEN);
	*offset += MAGIC_PAD_LEN;
}

/* Abuse the pad area to create a checksum of the ipc-toc and descriptors */
static inline void store_checksum(struct xshm_ipctoc *ipctoc, u32 size)
{
	struct ipctoc_hash *hash = (void *)ipctoc;
	--hash;
	hash->img_hash =
		crc_ccitt(0xffff, (u8 *) shm_start, modem_bootimg_size);
	hash->ch_hash = crc_ccitt(0xffff, (u8 *) ipctoc, size);
	hash->ch_size = size;
}

/* Verify that shm config has not been accidently tampered. */
static inline bool ok_checksum(struct xshm_ipctoc *ipctoc)
{
	struct ipctoc_hash *hash = (void *) ipctoc;
	u16 new_hash, new_imghash;
	int i;
	u8 *p;

	if (!commited)
		return false;

	for (i = 0; i < xshm_channels; i++) {
		struct xshm_ipctoc_channel *ch;

		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].rx);
		p = LEOFFS2PTR(shm_start, ch->ipc);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		p = LEOFFS2PTR(shm_start, ch->offset);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].tx);
		p = LEOFFS2PTR(shm_start, ch->ipc);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		p = LEOFFS2PTR(shm_start, ch->offset);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
	}

	--hash;
	new_hash = crc_ccitt(0xffff, (u8 *) ipctoc, hash->ch_size);
	new_imghash =
		crc_ccitt(0xffff, (u8 *) shm_start, modem_bootimg_size);
	pr_debug("Hash result:size:%d chksm:%u/%u img:%u/%u\n",
			hash->ch_size, hash->ch_hash, new_hash,
			hash->img_hash, new_imghash);
	return hash->ch_hash == new_hash && hash->img_hash == new_imghash;
}

static inline void init_data(u32 offset, int ch, u32 size)
{
	memset((u8 *)shm_start + offset, ch + 1, size);
}
#else
#define MAGIC_PAD_LEN 0
static inline void add_magic_pad(u32 *offset, void *base)
{
}
static inline void store_checksum(void *ipctoc, u32 size)
{
}
static inline bool ok_checksum(void *ipctoc)
{
	return true;
}
static inline void init_data(u32 offs, int ch, u32 size)
{
}
#endif

/* write_to_shm - Write SHM Channel descriptors to SHM.
 *
 * Based on the configuration data channel configuration
 * is written to the shared memory area.
 * This is the data layout:
 *
 * +------------+  <---- xshm_start
 * |	TOC	|
 * +------------+
 * | Boot IMG	|
 * +------------+ <---- rw_start
 * | RW Data	|
 * +------------+
 * | RW Buf idx |
 * +------------+ <---- ipctoc
 * | IPC TOC	|
 * +------------+
 * | RW Ch Decr |
 * +------------+ <---- ro_start
 * | RO Ch Decr |
 * +------------+
 * | RO Buf idx |
 * +------------+
 * | RO Data	|
 * +------------+
 */

static int write_to_shm(void)
{
	int i, pri, bitno;
	u32 offset, ro_start, rw_start, ipctoc_offs, ipcro_offs;
	bool found;
	struct xshm_ipctoc_channel *ch;
	struct toc_entry *toc_entry;
	struct xshm_bufidx *bix;

	/*
	 * Find where to put IPC-TOC by adding up
	 * the size of Payload buffers pluss buf-indices
	 */
	ipctoc_offs = ALIGN(modem_bootimg_size, XSHM_PAYL_ALIGN);
	rw_start = ipctoc_offs;
	for (i = 0; i < xshm_channels; i++) {
		int n = xshmdevs[i]->cfg.tx.buffers;
		ipctoc_offs += MAGIC_PAD_LEN;
		ipctoc_offs += offsetof(struct xshm_bufidx, size[n + 2]);
		ipctoc_offs = ALIGN(ipctoc_offs, XSHM_PAYL_ALIGN);
		ipctoc_offs += MAGIC_PAD_LEN;
		ipctoc_offs += xshmdevs[i]->cfg.tx.ch_size;
		ipctoc_offs = ALIGN(ipctoc_offs, XSHM_PAYL_ALIGN);
	}
	add_magic_pad(&ipctoc_offs, shm_start);
	pr_debug("IPC toc @ %08x\n", ipctoc_offs);

	/*
	 * Allocate the IPC-TOC and, initiatlize it.
	 * The IPC toc will be located after the RW Data and
	 * buffer indices.
	 */
	offset = ipctoc_offs;
	ipctoc = OFFS2PTR(shm_start, ipctoc_offs);
	ipctoc->magic[0] = XSHM_IPCTOC_MAGIC1;
	ipctoc->magic[1] = XSHM_IPCTOC_MAGIC2;
	ipctoc->version = XSHM_VERSION;
	ipctoc->subver = XSHM_SUBVER;
	memset(ipctoc->channel_offsets, 0, sizeof(ipctoc->channel_offsets));

	/* Find start of first channel descriptor */
	offset += sizeof(struct xshm_ipctoc);

	/*
	 * Allocate the location for the RW Channel descriptors.
	 * It will be located after the IPC-TOC.
	 */
	offset = ALIGN(offset, XSHM_ALIGNMT);
	for (i = 0; i < xshm_channels; i++) {
		pr_debug("Channel descriptor %d RW @ 0x%08x\n", i, offset);
		ipctoc->channel_offsets[i].tx = cpu_to_le32(offset);
		offset += sizeof(struct xshm_ipctoc_channel);
		offset = ALIGN(offset, XSHM_ALIGNMT);
		if (offset > xshm_size)
			goto badsize;
	}
	ro_start = offset;

	/*
	 * Allocate the location for the RO Channel descriptors.
	 * It will be located after the RW Channels.
	 */
	for (i = 0; i < xshm_channels; i++) {
		pr_debug("Channel descriptor %d RO @ 0x%08x\n", i, offset);
		ipctoc->channel_offsets[i].rx = cpu_to_le32(offset);
		offset += sizeof(struct xshm_ipctoc_channel);
		offset = ALIGN(offset, XSHM_ALIGNMT);
		if (offset > xshm_size)
			goto badsize;
	}

	/*
	 * Allocate the location for the RO Buffer Indices.
	 * It will be located after the RO Channels.
	 */
	offset = ALIGN(offset, XSHM_PAYL_ALIGN);
	ipcro_offs = offset;
	for (i = 0; i < xshm_channels; i++) {
		int n = xshmdevs[i]->cfg.rx.buffers;
		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].rx);
		add_magic_pad(&offset, shm_start);
		ch->ipc = cpu_to_le32(offset);

		bix = OFFS2PTR(shm_start, offset);
		bix->read_index = cpu_to_le32(0);
		bix->write_index = cpu_to_le32(0);
		bix->state = cpu_to_le32(XSHM_CLOSED);
		bix->size[0] = cpu_to_le32(0);

		pr_debug("IPC RO[%d] @: 0x%08x\n",  i, offset);
		offset += offsetof(struct xshm_bufidx, size[n + 2]);
		offset = ALIGN(offset, XSHM_PAYL_ALIGN);
		if (offset > xshm_size)
			goto badsize;
	}

	/*
	 * Allocate RO Data Area. This will located after
	 * the RO Buffer Indices at the end of the Share Memory
	 * area.
	 */
	offset = ALIGN(offset, XSHM_PAYL_ALIGN);
	for (i = 0; i < xshm_channels; i++) {
		u8 align;
		u32 size;
		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].rx);
		add_magic_pad(&offset, shm_start);
		ch->offset = cpu_to_le32(offset);

		BUILD_BUG_ON(sizeof(ch->mode) != 1);
		ch->mode = xshmdevs[i]->cfg.mode & XSHM_MODE_MASK;
		ch->buffers = cpu_to_le32(xshmdevs[i]->cfg.rx.buffers);
		align = rounddown_pow_of_two(xshmdevs[i]->cfg.rx.alignment);
		ch->alignment =	align;
		ch->packets = xshmdevs[i]->cfg.rx.packets;
		ch->mtu = xshmdevs[i]->cfg.rx.mtu;
		size = xshmdevs[i]->cfg.tx.ch_size;
		if (xshmdevs[i]->cfg.mode & XSHM_PACKET_MODE) {
			u32 buf_size;
			buf_size = size / xshmdevs[i]->cfg.tx.buffers;
			buf_size = rounddown(buf_size, align);
			size = buf_size * xshmdevs[i]->cfg.tx.buffers;
		}
		pr_debug("Buffer area RO for Channel[%d] at: 0x%08x size:%d\n",
				i, offset, size);
		ch->size = cpu_to_le32(size);

		init_data(offset, i, xshmdevs[i]->cfg.rx.ch_size);
		offset += xshmdevs[i]->cfg.rx.ch_size;
		offset = ALIGN(offset, XSHM_PAYL_ALIGN);
		if (offset > xshm_size)
			goto badsize;
	}

	/*
	 * Allocate RW Data Area. This will located in the beginning
	 * just after the Modem Boot Image.
	 */
	offset = rw_start;
	for (i = 0; i < xshm_channels; i++) {
		u8 align;
		u32 size;
		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].tx);
		add_magic_pad(&offset, shm_start);
		ch->offset = cpu_to_le32(offset);
		init_data(offset, i, xshmdevs[i]->cfg.tx.ch_size);
		ch->mode = xshmdevs[i]->cfg.mode &
				XSHM_MODE_MASK;
		ch->buffers = cpu_to_le32(xshmdevs[i]->cfg.tx.buffers);
		align = rounddown_pow_of_two(xshmdevs[i]->cfg.rx.alignment);
		ch->alignment =	align;
		ch->packets = xshmdevs[i]->cfg.rx.packets;
		ch->mtu = xshmdevs[i]->cfg.rx.mtu;
		size = xshmdevs[i]->cfg.tx.ch_size;
		if (xshmdevs[i]->cfg.mode & XSHM_PACKET_MODE) {
			u32 buf_size;
			buf_size = size / xshmdevs[i]->cfg.tx.buffers;
			buf_size = rounddown(buf_size, align);
			size = buf_size * xshmdevs[i]->cfg.tx.buffers;
		}
		ch->size = cpu_to_le32(size);
		pr_debug("Buffer area RW for Channel[%d] at: 0x%08x size:%d\n",
				i, offset, size);
		offset += xshmdevs[i]->cfg.tx.ch_size;
		offset = ALIGN(offset, XSHM_PAYL_ALIGN);
		if (offset > ro_start)
			goto badsize;
	}

	/*
	 * Allocate RW IPC Area. This will located after RW data area,
	 * just before the IPC-TOC.
	 */
	offset = ALIGN(offset, XSHM_PAYL_ALIGN);
	for (i = 0; i < xshm_channels; i++) {
		int n = xshmdevs[i]->cfg.tx.buffers;
		ch = LEOFFS2PTR(shm_start, ipctoc->channel_offsets[i].tx);
		add_magic_pad(&offset, shm_start);
		ch->ipc = cpu_to_le32(offset);
		bix = OFFS2PTR(shm_start, offset);
		bix->read_index = cpu_to_le32(0);
		bix->write_index = cpu_to_le32(0);
		bix->state = cpu_to_le32(XSHM_CLOSED);
		bix->size[0] = cpu_to_le32(0);

		pr_debug("IPC RW[%d] @: 0x%08x\n",  i, offset);
		offset += offsetof(struct xshm_bufidx, size[n + 2]);
		offset = ALIGN(offset, XSHM_PAYL_ALIGN);
		if (offset > xshm_size)
			goto badsize;
	}

	/* Allocate genio bits for each channel according to priority*/
	bitno = 0;
	for (pri = 0; pri < 8; pri++) {
		for (i = 0; i < xshm_channels; i++) {
			if (xshmdevs[i]->cfg.priority == pri) {
				ch = LEOFFS2PTR(shm_start,
						ipctoc->channel_offsets[i].tx);
				ch->write_bit = cpu_to_le16(bitno * 4);
				ch->read_bit = cpu_to_le16(bitno * 4 + 2);
				ch = LEOFFS2PTR(shm_start,
						ipctoc->channel_offsets[i].rx);
				ch->write_bit = cpu_to_le16(bitno * 4 + 1);
				ch->read_bit = cpu_to_le16(bitno * 4 + 3);
				bitno++;
			}
		}
	}

	/*
	 * The Master TOC points out the boot images for the modem,
	 * Use the first avilable entry in the toc to write the pointer,
	 * to the IPC-TOC defined above.
	 */
	found = false;
	for (toc_entry = shm_start, i = 0; i < 16; i++, toc_entry++)
		if (toc_entry->start == cpu_to_le32(0xffffffff)) {
			pr_debug("IPCTOC address written into Master TOC"
					" @ 0x%08x\n", i * 32);
			toc_entry->start =
				cpu_to_le32(GET_OFFSET(shm_start, ipctoc));
			toc_entry->size = cpu_to_le32(0);
			toc_entry->flags = cpu_to_le32(0);
			toc_entry->entry_point = cpu_to_le32(0);
			toc_entry->load_addr = cpu_to_le32(0xffffffff);
			memset(toc_entry->name, 0, sizeof(toc_entry->name));
			sprintf(toc_entry->name, "ipc-toc");
			found = true;
			break;
		}
	if (!found) {
		pr_debug("Cannot insert IPC-TOC in toc\n");
		goto bad_config;
	}

	store_checksum(ipctoc, ipcro_offs - ipctoc_offs);

	return 0;

badsize:
	pr_debug("IPCTOC not enough space offset (size:0x%lx offset:0x%x\n",
			xshm_size, offset);
	return -ENOSPC;

bad_config:
	pr_debug("IPCTOC bad configuration data\n");
	return -EINVAL;
}

static int xshm_verify_config(struct xshm_channel *xcfg)
{
	int j;

	if ((xcfg->mode & XSHM_MODE_MASK) != XSHM_PACKET_MODE &&
			(xcfg->mode & XSHM_MODE_MASK) != XSHM_STREAM_MODE) {
		pr_debug("Bad config:"
				"channel mode must be set\n");
		return -EINVAL;
	}
	if (xcfg->mode & XSHM_PACKET_MODE && xcfg->rx.buffers < 2) {
		pr_debug("Bad config:minimum 2 buffers "
				"must be set for packet mode\n");
		return -EINVAL;
	}

	if (xcfg->rx.ch_size < XSHM_MIN_CHSZ) {
		pr_debug("Bad config:"
				"Channel size must be larger than %d\n",
				XSHM_MIN_CHSZ);
		return -EINVAL;
	}

	if (xcfg->mode & XSHM_PACKET_MODE) {
		if (xcfg->tx.buffers < 2) {
			pr_debug("Bad config:"
				"buffers must be minimum 2 packet mode\n");
			return -EINVAL;
		}
		if (xcfg->tx.packets < 1) {
			pr_debug("Bad config:"
				"packets must be set for packet mode\n");
			return -EINVAL;
		}
	}

	if (xcfg->tx.ch_size < XSHM_MIN_CHSZ) {
		pr_debug("Bad config:"
				"Channel size must be larger than %d\n",
				XSHM_MIN_CHSZ);
		return -EINVAL;
	}

	if (xcfg->name[0] == '\0') {
		pr_debug("Channel must be named\n");
		return -EINVAL;
	}
	for (j = 0; j < xshm_channels; j++) {
		struct xshm_channel *xcfg2 = &xshmdevs[j]->cfg;
		if (xcfg != xcfg2 && strcmp(xcfg->name, xcfg2->name) == 0) {
			pr_debug("Channels has same name:%s\n",
					 xcfg->name);
			return -EINVAL;
		}
	}
	return 0;
}

static int verify_config(void)
{
	int i;

	if (xshm_channels == 0) {
		pr_debug("Bad config: minimum one channel must be defined\n");
		return -EINVAL;
	}
	for (i = 0; i < xshm_channels; i++) {
		int err = xshm_verify_config(&xshmdevs[i]->cfg);
		if (err)
			return err;
	}
	return 0;
}

/*
 * Create Configuration data for the platform devices.
 */
static void create_devs(void)
{
	int i;

	for (i = 0; i < xshm_channels; i++) {
		struct xshm_bufidx *buf_rx, *buf_tx;
		struct xshm_ipctoc_channel *ch_rx, *ch_tx;
		struct xshm_channel *xcfg = &xshmdevs[i]->cfg;
		ch_rx = LEOFFS2PTR(shm_start,
				ipctoc->channel_offsets[i].rx);
		buf_rx = LEOFFS2PTR(shm_start, ch_rx->ipc);
		ch_tx = LEOFFS2PTR(shm_start,
				ipctoc->channel_offsets[i].tx);
		buf_tx = LEOFFS2PTR(shm_start, ch_tx->ipc);

		/*
		 * Due to restricted read-only access
		 * we swap positions for read/write
		 * pointers.
		 */
		xcfg->tx.write = &buf_tx->write_index;
		xcfg->tx.read = &buf_rx->read_index;

		xcfg->rx.write = &buf_rx->write_index;
		xcfg->rx.read = &buf_tx->read_index;

		xcfg->rx.addr = LEOFFS2PTR(shm_start, ch_rx->offset);
		xcfg->tx.addr = LEOFFS2PTR(shm_start, ch_tx->offset);
		xcfg->rx.state = &buf_rx->state;
		xcfg->tx.state = &buf_tx->state;
		xcfg->tx.buf_size = buf_tx->size;
		xcfg->rx.buf_size = buf_rx->size;

		xcfg->rx.xfer_bit = le16_to_cpu(ch_rx->write_bit);
		xcfg->tx.xfer_bit = le16_to_cpu(ch_tx->write_bit);
		xcfg->rx.xfer_done_bit = le16_to_cpu(ch_rx->read_bit);
		xcfg->tx.xfer_done_bit = le16_to_cpu(ch_tx->read_bit);

		if (xcfg->mode & XSHM_PAIR_MODE) {
			struct xshm_channel *pair;
			pr_debug("Channel[%d] is in PAIR mode\n", i);
			if (i < 1) {
				pr_debug("No channel to pair with\n");
				continue;
			}
			/* Cross couple rx/tx on the pair */
			pair = &xshmdevs[i - 1]->cfg;

			/* Copy everything but the kobj which is at the end */
			memcpy(&xcfg->tx, &pair->rx,
					offsetof(struct xshm_udchannel, kobj));
			memcpy(&xcfg->rx, &pair->tx,
					offsetof(struct xshm_udchannel, kobj));
		} else if (xcfg->mode & XSHM_LOOP_MODE) {
			pr_debug("Channel[%d] is in LOOP mode\n", i);
			/*
			 * Connect rx/tx in a pair. Copy everything,
			 * but the kobj which is at the end
			 */
			memcpy(&xcfg->tx, &xcfg->rx,
					offsetof(struct xshm_udchannel, kobj));
		}

		pr_devel("RX[%d] wi:%p ri:%p\n", i, xcfg->rx.read,
				xcfg->rx.write);
		pr_devel("TX[%d] wi:%p ri:%p\n", i, xcfg->tx.read,
				xcfg->tx.write);
	}
}

static int do_commit(void)
{
	int err;

	if (config_error) {
		pr_devel("config error detected\n");
		return -EINVAL;
	}

	if (commited) {
		pr_devel("already commited\n");
		config_error = true;
		return -EINVAL;
	}
	err = verify_config();
	if (err) {
		pr_devel("bad config\n");
		config_error = true;
		return err;
	}
	err = write_to_shm();
	if (err) {
		pr_devel("writei to SHM failed\n");
		config_error = true;
		return err;
	}
	commited = true;
	create_devs();
	return 0;
}

static int do_register(void)
{
	int i, err;

	if (!commited || registered || config_error) {
		pr_devel("bad sequence of requests\n");
		config_error = true;
		return -EINVAL;
	}

	err = verify_config();
	if (err) {
		config_error = true;
		pr_devel("bad config\n");
		return err;
	}
	registered = true;

	for (i = 0; i < xshm_channels; i++)
		xshm_register_dev(xshmdevs[i]);

	return 0;
}

static void do_reset(void)
{
	xshm_reset();
	config_error = false;
	ready_for_ipc = false;
	ready_for_caif = false;
	registered = false;
	commited = false;
	addr_set = false;
	modem_bootimg_size = TOC_SZ;
	xshm_channels = 0;
}

static int do_set_addr(void)
{
	int err;
	if (!commited || addr_set || config_error) {
		pr_devel("bad sequence of requests\n");
		config_error = true;
		return -EINVAL;
	}
	err = verify_config();
	if (err) {
		config_error = true;
		pr_devel("bad config\n");
		return err;
	}
	addr_set = true;
	return genio_set_shm_addr(xshm_c2c_bootaddr, genio_ipc_ready_cb);
}

static void parent_release(struct device *dev)
{
}

static int copy_name(const char *src, char *d, size_t count)
{
	const char *s, *end = src + count;
	for (s = src; *s && s < end; s++, d++)
		if (*s == '\0' || *s == '\n')
			break;
		else if (!isalnum(*s)) {
			pr_debug("Illegal chr:'%c' in name:'%s'\n", *s, src);
			return -EINVAL;
		} else if (s - src >= XSHM_NAMESZ - 1) {
			pr_debug("Name '%s'too long\n", src);
			return -EINVAL;
		} else
			*d = *s;
	*d = '\0';

	return count;
}

inline struct xshm_dev *get_dev2xshm(struct device *dev)
{
       struct platform_device *pdev;
       struct xshm_dev *xshmdev;
       pdev = container_of(dev, struct platform_device, dev);
       xshmdev = container_of(pdev, struct xshm_dev, pdev);
       return xshmdev;
}

static void xshmdev_release(struct device *dev)
{
	struct xshm_dev *xshm = get_dev2xshm(dev);
	kfree(xshm);
}

/* sysfs: Read the modem firmware (actually the whole shared memory area) */
static ssize_t modemfw_read(struct file *file, struct kobject *kobj,
			struct bin_attribute *attr,
			char *buf, loff_t off, size_t count)
{
#ifdef DEBUG
	/* Read shm area is usefull for debug */
	if (off > xshm_size)
		return 0;
	if (off + count > xshm_size)
		count = xshm_size - off;
	memcpy(buf, shm_start + off, count);
	return count;
#else
	return -EINVAL;
#endif
}

/* sysfs: Write the modem firmware including TOC */
static ssize_t modemfw_write(struct file *f, struct kobject *kobj,
			struct bin_attribute *attr,
			char *buf, loff_t off, size_t count)
{
	if (commited)
		return -EBUSY;

	if (off + count > xshm_size)
		return -ENOSPC;
	memcpy(shm_start + off, buf, count);
	modem_bootimg_size = off + count;
	return count;
}

/* sysfs: Modem firmware attribute */
static struct bin_attribute modemfw_attr = {
	.attr = {
		 .name = "bootimg",
		 .mode = S_IRUGO | S_IWUSR,
		 },
	.size = IMG_MAX_SZ,
	.read = modemfw_read,
	.write = modemfw_write
};

/* sysfs: ipc_ready file */
static ssize_t ipc_ready_show(struct device *dev, struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", ready_for_ipc);
}

/* sysfs: ipc_ready file */
static ssize_t caif_ready_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ready_for_caif);
}

static DEVICE_ATTR(ipc_ready, S_IRUSR | S_IRUGO, ipc_ready_show, NULL);
static DEVICE_ATTR(caif_ready, S_IRUSR | S_IRUGO, caif_ready_show, NULL);

/* sysfs: notification on change of ipc_ready to user space */
void xshm_ipc_ready(void)
{
	sysfs_notify(&parentdev->kobj, NULL, dev_attr_ipc_ready.attr.name);
}

/* sysfs: notification on change of caif_ready to user space */
void xshm_caif_ready(void)
{
	sysfs_notify(&parentdev->kobj, NULL, dev_attr_caif_ready.attr.name);
}

/* XSHM Generic NETLINK family */
static struct genl_family xshm_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "XSHM",
	.version = XSHM_PROTO_VERSION,
	.maxattr = XSHM_A_MAX,
};

/* XSHM Netlink attribute policy */
static const struct nla_policy xshm_genl_policy[XSHM_A_MAX + 1] = {
	[XSHM_A_VERSION] = { .type = NLA_U8 },
	[XSHM_A_SUB_VERSION] = { .type = NLA_U8 },
	[__XSHM_A_FLAGS] = { .type = NLA_U32 },
	[XSHM_A_NAME] = { .type = NLA_NUL_STRING, .len = XSHM_NAMESZ},
	[XSHM_A_RX_CHANNEL] = { .type = NLA_NESTED },
	[XSHM_A_TX_CHANNEL] = { .type = NLA_NESTED },
	[XSHM_A_PRIORITY] = { .type = NLA_U8 },
	[XSHM_A_LATENCY] = { .type = NLA_U8 },
};

/* Policy for uni-directional attributes for stream */
static const struct nla_policy stream_policy[XSHM_A_MAX + 1] = {
	[XSHM_A_CHANNEL_SIZE] = { .type = NLA_U32 },
};

/* Policy for uni-directional attributes for packet */
static const struct nla_policy packet_policy[XSHM_A_MAX + 1] = {
	[XSHM_A_CHANNEL_SIZE] = { .type = NLA_U32 },
	[XSHM_A_CHANNEL_BUFFERS] = { .type = NLA_U32 },
	[XSHM_A_MTU] = { .type = NLA_U16 },
	[XSHM_A_ALIGNMENT] = { .type = NLA_U8 },
	[XSHM_A_PACKETS] = { .type = NLA_U8 },
};

static int xshm_add_udchannel(struct xshm_udchannel *chn, int attr,
			struct genl_info *info, struct nla_policy const *policy)
{
	struct nlattr *nla;
	int nla_rem;

	if (!info->attrs[attr])
		return -EINVAL;

	if (nla_validate_nested(info->attrs[attr],
					XSHM_A_MAX,
					policy) != 0) {
		pr_info("Invalid RX channel attributes\n");
		return -EINVAL;
	}

	nla_for_each_nested(nla, info->attrs[attr], nla_rem) {

		if (nla_type(nla) == XSHM_A_CHANNEL_SIZE)
			chn->ch_size = nla_get_u32(nla);

		if (nla_type(nla) == XSHM_A_CHANNEL_BUFFERS)
			chn->buffers = nla_get_u32(nla);

		if (nla_type(nla) == XSHM_A_MTU)
			chn->mtu = nla_get_u16(nla);

		if (nla_type(nla) == XSHM_A_PACKETS)
			chn->packets = nla_get_u8(nla);

		if (nla_type(nla) == XSHM_A_ALIGNMENT) {
			chn->alignment = nla_get_u8(nla);
			chn->alignment = rounddown_pow_of_two(chn->alignment);
		}

	}
	return 0;
}

static int xshm_add_channel(struct xshm_channel *cfg, struct genl_info *info,
			int mode)
{
	int len, err;
	struct nla_policy const *policy;
	char name[XSHM_NAMESZ];

	policy = (mode == XSHM_PACKET_MODE) ? packet_policy : stream_policy;

	if (info->attrs[XSHM_A_VERSION]) {
		u8 version;
		u8 sub_version;

		version = nla_get_u8(info->attrs[XSHM_A_VERSION]);
		if (!info->attrs[XSHM_A_SUB_VERSION])
			return -EINVAL;
		sub_version = nla_get_u8(info->attrs[XSHM_A_SUB_VERSION]);
		if (version != 1 || sub_version != 0) {
			pr_info("Bad version or sub_version\n");
			return -EINVAL;
		}
	}

	if (!info->attrs[XSHM_A_NAME]) {
		pr_debug("Name not specified\n");
		return -EINVAL;
	}

	len = nla_strlcpy(name, info->attrs[XSHM_A_NAME],
			XSHM_NAMESZ);

	if (len > XSHM_NAMESZ)
		return -EINVAL;

	err = copy_name(name, cfg->name, sizeof(name));
	if (err < 0)
		return err;

	cfg->excl_group = 1;
	if (info->attrs[XSHM_A_EXCL_GROUP])
		cfg->excl_group = nla_get_u8(info->attrs[XSHM_A_EXCL_GROUP]);

	err = xshm_add_udchannel(&cfg->rx, XSHM_A_RX_CHANNEL, info, policy);

	if (err)
		return err;
	err = xshm_add_udchannel(&cfg->tx, XSHM_A_TX_CHANNEL, info, policy);

	if (err)
		return err;

	if (info->attrs[XSHM_A_PRIORITY]) {
		cfg->priority = nla_get_u8(info->attrs[XSHM_A_PRIORITY]);
		/* silently fixup bad value */
		if (cfg->priority > 7)
			cfg->priority = 0;
	}

	if (info->attrs[XSHM_A_LATENCY])
		cfg->latency = nla_get_u8(info->attrs[XSHM_A_LATENCY]);

	if (info->attrs[__XSHM_A_FLAGS])
		cfg->mode |= nla_get_u32(info->attrs[__XSHM_A_FLAGS]);


	return 0;
}

static int do_reply(struct genl_info *info, int result)
{
	struct sk_buff *msg;
	int err;
	void *reply;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (msg == NULL)
		return -ENOMEM;

	reply = genlmsg_put_reply(msg, info, &xshm_gnl_family, 0, result);
	if (reply == NULL) {
		kfree_skb(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, reply);
	err = genlmsg_reply(msg, info);
	return err;
}

static int xshm_add_ch(struct sk_buff *skb, struct genl_info *info, int mode)
{
	int err;
	struct xshm_channel cfg;
	struct xshm_dev *xshmdev;

	if (xshm_channels + 1 > XSHM_MAX_CHANNELS) {
		pr_debug("Too many channels added\n");
		return -EINVAL;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = mode;
	err = xshm_add_channel(&cfg, info, mode);
	if (err)
		return err;

	xshmdev = kzalloc(sizeof(*xshmdev), GFP_KERNEL);
	if (xshmdev == NULL)
		return -ENOMEM;

	if (mode == XSHM_PACKET_MODE)
		xshmdev->pdev.name = "xshmp";
	else
		xshmdev->pdev.name = "xshms";

	xshmdevs[xshm_channels] = xshmdev;
	xshmdevs[xshm_channels]->cfg = cfg;
	xshmdev->pdev.id = xshm_channels;
	xshmdev->pdev.dev.parent = parentdev;
	xshmdev->pdev.dev.release = xshmdev_release;
	xshmdevs[xshm_channels] = xshmdev;

	++xshm_channels;

	err = xshm_verify_config(&xshmdev->cfg);
	if (err)
		goto error;
	err = do_reply(info, 0);
	if (err)
		goto error;
	return err;

error:
	--xshm_channels;
	kfree(xshmdev);
	return err;
}

static int xshm_add_packet_ch(struct sk_buff *skb, struct genl_info *info)
{
	return xshm_add_ch(skb, info, XSHM_PACKET_MODE);
}

static int xshm_add_stream_ch(struct sk_buff *skb, struct genl_info *info)
{
	return xshm_add_ch(skb, info, XSHM_STREAM_MODE);
}


static int xshm_c_commit(struct sk_buff *skb, struct genl_info *info)
{
	int err = do_commit();
	if (!err)
		do_reply(info, 0);
	return err;
}

static int xshm_c_register(struct sk_buff *skb, struct genl_info *info)
{
	int err = do_register();
	if (!err)
		do_reply(info, 0);
	return err;
}

static int xshm_c_set_addr(struct sk_buff *skb, struct genl_info *info)
{
	int err = do_set_addr();
	if (!err)
		do_reply(info, 0);
	return err;
}

static int xshm_c_reset(struct sk_buff *skb, struct genl_info *info)
{
	do_reset();
	do_reply(info, 0);
	return 0;
}

static int xshm_c_verify(struct sk_buff *skb, struct genl_info *info)
{
	int err = verify_config();
	if (!err)
		do_reply(info, 0);
	return err;
}

static struct genl_ops xshm_genl_ops[] = {
	{
	.cmd = XSHM_C_ADD_STREAM_CHANNEL,
	.flags = GENL_ADMIN_PERM,
	.policy = xshm_genl_policy,
	.doit = xshm_add_stream_ch,
	.dumpit = NULL,
	},
	{
	.cmd = XSHM_C_ADD_PACKET_CHANNEL,
	.flags = GENL_ADMIN_PERM,
	.policy = xshm_genl_policy,
	.doit = xshm_add_packet_ch,
	.dumpit = NULL,
	},
	{
	.cmd = XSHM_C_COMMIT,
	.flags = GENL_ADMIN_PERM,
	.doit = xshm_c_commit,
	.dumpit = NULL,
	},
	{
	.cmd = XSHM_C_REGISTER,
	.flags = GENL_ADMIN_PERM,
	.doit = xshm_c_register,
	.dumpit = NULL,
	},
	{
	.cmd = XSHM_C_SET_ADDR,
	.flags = GENL_ADMIN_PERM,
	.doit = xshm_c_set_addr,
	.dumpit = NULL,
	},
	{
	.cmd = XSHM_C_RESET,
	.flags = GENL_ADMIN_PERM,
	.doit = xshm_c_reset,
	.dumpit = NULL,
	},
	{
	.cmd = __XSHM_C_VERIFY,
	.flags = GENL_ADMIN_PERM,
	.doit = xshm_c_verify,
	.dumpit = NULL,
	},

};

static bool gennetl_reg;

/* Initialize boot handling and create sysfs entries*/
int xshm_boot_init(void)
{
	int err = -EINVAL;
	bool xshm_fake = false;

	/* Negative xshm_size indicates module test without real SHM */
	if (xshm_size < 0) {
		xshm_fake = true;
		xshm_size = abs(xshm_size);
	}

	if (xshm_size < TOC_SZ)
		goto bad_config;

	if (xshm_fake) {
		shm_start = kzalloc(xshm_size, GFP_KERNEL);
		err = -ENOMEM;
		if (!shm_start)
			goto error_nodev;
		xshm_start = (unsigned long) shm_start;
		memset(shm_start, 0xaa, xshm_size);
	} else {
		if (xshm_start == 0)
			goto bad_config;
		shm_start = ioremap(xshm_start, xshm_size);
	}

	/* Initiate the Master TOC to 0xff for the first 512 bytes */
	if (xshm_size > TOC_SZ)
		memset(shm_start, 0xff, TOC_SZ);

	modem_bootimg_size = TOC_SZ;

	pr_debug("Boot image addr: %p size:%d\n", shm_start,
			modem_bootimg_size);

	parentdev = &_parentdev;
	memset(parentdev, 0, sizeof(parentdev));
	dev_set_name(parentdev, "xshm");
	parentdev->release = parent_release;
	err = device_register(parentdev);
	if (err)
		goto error_nodev;

	err = device_create_bin_file(parentdev, &modemfw_attr);
	if (err)
		goto error;
	err = device_create_file(parentdev, &dev_attr_ipc_ready);
	if (err)
		goto error;
	err = device_create_file(parentdev, &dev_attr_caif_ready);
	if (err)
		goto error;

	err = genl_register_family_with_ops(&xshm_gnl_family,
		xshm_genl_ops, ARRAY_SIZE(xshm_genl_ops));
	if (err)
		goto error;

	gennetl_reg = 1;
	return err;
error:
	pr_debug("initialization failed\n");
	device_unregister(parentdev);

error_nodev:
	if (xshm_fake)
		kfree(shm_start);
	return err;
bad_config:
	pr_err("Bad module configuration:"
			" xshm_base_address:%lu xshm_size:%lu err:%d\n",
			xshm_start, xshm_size, err);
	/* Buildin module should not return error */
	return -EINVAL;
}

void xshm_boot_exit(void)
{
	device_unregister(parentdev);

	if (gennetl_reg)
		genl_unregister_family(&xshm_gnl_family);
	gennetl_reg = 0;
}
