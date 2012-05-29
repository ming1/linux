/*
 * Copyright (C) ST-Ericsson AB 2012
 * Author:	Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#define pr_fmt(fmt) KBUILD_MODNAME ":" fmt
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
#include "shm_ipctoc.h"
#include <linux/modem_shm/shm_dev.h>
#include <linux/modem_shm/modem_shm_netlink.h>
#include <linux/c2c_genio.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sjur Brændland <sjur.brandeland@stericsson.com>");

#define SHM_VERSION	0x1
#define SHM_SUBVER	0x0
#define TOC_SZ		512
#define IMG_MAX_SZ	65536
#define SHM_ALIGNMT	sizeof(u32)
#define SHM_MIN_CHSZ 3
#define SHM_PAYL_ALIGN max(32, L1_CACHE_BYTES)
#define STE_BOOTIMG_NAME "ste-bootimg.bin"

#define GET_OFFSET(base, ptr) (((u8 *)(ptr)) - ((u8 *)(base)))
#define OFFS2PTR(base, offs) ((void *) ((u8 *)base + offs))
#define LEOFFS2PTR(base, offs) ((void *) ((u8 *)base + le32_to_cpu(offs)))

/* Structure use in debug mode for integrity checking */
struct ipctoc_hash {
	u16 img_hash;
	u16 ch_hash;
	u16 ch_size;
};
struct shm_modem {
	bool config_error;
	bool commited;
	bool registered;
	bool addr_set;
	bool fw_requested;
	u32 modem_bootimg_size;
	void *shm_start;
	u32 channels;
	struct shm_channel *channel[SHM_MAX_CHANNELS + 1];
	struct shm_ipctoc *ipctoc;
	bool gennetl_reg;
};

static unsigned long shm_start;
module_param(shm_start, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(shm_start, "Address for memory shared by host/modem.");

static unsigned long shm_c2c_bootaddr;
module_param(shm_c2c_bootaddr, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(shm_c2c_bootaddr,
			"Address given to modem (through GENI register)");

static long shm_size;
module_param(shm_size, long, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(shm_size, "Size of SHM area");

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
	if (*offset < shm_size)
		memset(base + *offset, MAGIC_PAD, MAGIC_PAD_LEN);
	*offset += MAGIC_PAD_LEN;
}

/* Abuse the pad area to create a checksum of the ipc-toc and descriptors */
static inline void store_checksum(struct shm_modem *modem, u32 size)
{
	struct ipctoc_hash *hash = (void *)modem->ipctoc;
	--hash;
	hash->img_hash =
		crc_ccitt(0xffff, (u8 *) modem->shm_start,
				modem->modem_bootimg_size);
	hash->ch_hash = crc_ccitt(0xffff, (u8 *) modem->ipctoc, size);
	hash->ch_size = size;
}

/* Verify that shm config has not been accidently tampered. */
static inline bool ok_checksum(struct shm_modem *modem,
				struct shm_ipctoc *ipctoc)
{
	struct ipctoc_hash *hash = (void *) ipctoc;
	u16 new_hash, new_imghash;
	int i;
	u8 *p;

	if (!modem->commited)
		return false;

	for (i = 0; i < modem->channels; i++) {
		struct shm_ipctoc_channel *ch;

		ch = LEOFFS2PTR(modem->shm_start,
				ipctoc->channel_offsets[i].rx);
		p = LEOFFS2PTR(modem->shm_start, ch->ipc);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		p = LEOFFS2PTR(modem->shm_start, ch->offset);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		ch = LEOFFS2PTR(modem->shm_start,
				ipctoc->channel_offsets[i].tx);
		p = LEOFFS2PTR(modem->shm_start, ch->ipc);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
		p = LEOFFS2PTR(modem->shm_start, ch->offset);
		if (!padok(p - MAGIC_PAD_LEN))
			return false;
	}

	--hash;
	new_hash = crc_ccitt(0xffff, (u8 *) ipctoc, hash->ch_size);
	new_imghash =
		crc_ccitt(0xffff, (u8 *) modem->shm_start,
				modem->modem_bootimg_size);
	pr_debug("Hash result:size:%d chksm:%u/%u img:%u/%u\n",
			hash->ch_size, hash->ch_hash, new_hash,
			hash->img_hash, new_imghash);
	return hash->ch_hash == new_hash && hash->img_hash == new_imghash;
}

static inline void init_data(void *shm_start, u32 offset,
				int ch, u32 size)
{
	memset((u8 *)shm_start + offset, ch + 1, size);
}
#else
#define MAGIC_PAD_LEN 0
static inline void add_magic_pad(u32 *offset, void *base)
{
}
static inline void store_checksum(struct shm_modem *modem, u32 size)
{
}
static inline bool ok_checksum(struct shm_modem *modem, void *ipctoc)
{
	return true;
}
static inline void init_data(struct shm_modem *modem, u32 offs, int ch,
				u32 size)
{
}
#endif

/* write_to_shm - Write SHM Channel descriptors to SHM.
 *
 * Based on the configuration data channel configuration
 * is written to the shared memory area.
 * This is the data layout:
 *
 * +------------+  <---- shm_start
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

static int write_to_shm(struct shm_modem *modem)
{
	int i, pri, bitno;
	u32 offset, ro_start, rw_start, ipctoc_offs, ipcro_offs;
	bool found;
	struct shm_ipctoc_channel *ch;
	struct toc_entry *toc_entry;
	struct shm_bufidx *bix;

	/*
	 * Find where to put IPC-TOC by adding up
	 * the size of Payload buffers pluss buf-indices
	 */
	ipctoc_offs = ALIGN(modem->modem_bootimg_size, SHM_PAYL_ALIGN);
	rw_start = ipctoc_offs;
	for (i = 0; i < modem->channels; i++) {
		int n = modem->channel[i]->tx.buffers;
		ipctoc_offs += MAGIC_PAD_LEN;
		ipctoc_offs += offsetof(struct shm_bufidx, size[n + 2]);
		ipctoc_offs = ALIGN(ipctoc_offs, SHM_PAYL_ALIGN);
		ipctoc_offs += MAGIC_PAD_LEN;
		ipctoc_offs += modem->channel[i]->tx.ch_size;
		ipctoc_offs = ALIGN(ipctoc_offs, SHM_PAYL_ALIGN);
	}
	add_magic_pad(&ipctoc_offs, modem->shm_start);
	pr_debug("IPC toc @ %08x\n", ipctoc_offs);

	/*
	 * Allocate the IPC-TOC and, initiatlize it.
	 * The IPC toc will be located after the RW Data and
	 * buffer indices.
	 */
	offset = ipctoc_offs;
	modem->ipctoc = OFFS2PTR(modem->shm_start, ipctoc_offs);
	modem->ipctoc->magic[0] = SHM_IPCTOC_MAGIC1;
	modem->ipctoc->magic[1] = SHM_IPCTOC_MAGIC2;
	modem->ipctoc->version = SHM_VERSION;
	modem->ipctoc->subver = SHM_SUBVER;
	memset(modem->ipctoc->channel_offsets, 0,
		sizeof(modem->ipctoc->channel_offsets));

	/* Find start of first channel descriptor */
	offset += sizeof(struct shm_ipctoc);

	/*
	 * Allocate the location for the RW Channel descriptors.
	 * It will be located after the IPC-TOC.
	 */
	offset = ALIGN(offset, SHM_ALIGNMT);
	for (i = 0; i < modem->channels; i++) {
		pr_debug("Channel descriptor %d RW @ 0x%08x\n", i, offset);
		modem->ipctoc->channel_offsets[i].tx = cpu_to_le32(offset);
		offset += sizeof(struct shm_ipctoc_channel);
		offset = ALIGN(offset, SHM_ALIGNMT);
		if (offset > shm_size)
			goto badsize;
	}
	ro_start = offset;

	/*
	 * Allocate the location for the RO Channel descriptors.
	 * It will be located after the RW Channels.
	 */
	for (i = 0; i < modem->channels; i++) {
		pr_debug("Channel descriptor %d RO @ 0x%08x\n", i, offset);
		modem->ipctoc->channel_offsets[i].rx = cpu_to_le32(offset);
		offset += sizeof(struct shm_ipctoc_channel);
		offset = ALIGN(offset, SHM_ALIGNMT);
		if (offset > shm_size)
			goto badsize;
	}

	/*
	 * Allocate the location for the RO Buffer Indices.
	 * It will be located after the RO Channels.
	 */
	offset = ALIGN(offset, SHM_PAYL_ALIGN);
	ipcro_offs = offset;
	for (i = 0; i < modem->channels; i++) {
		int n = modem->channel[i]->rx.buffers;
		ch = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].rx);
		add_magic_pad(&offset, modem->shm_start);
		ch->ipc = cpu_to_le32(offset);

		bix = OFFS2PTR(modem->shm_start, offset);
		bix->read_index = cpu_to_le32(0);
		bix->write_index = cpu_to_le32(0);
		bix->state = cpu_to_le32(SHM_CLOSED);
		bix->size[0] = cpu_to_le32(0);

		pr_debug("IPC RO[%d] @: 0x%08x\n",  i, offset);
		offset += offsetof(struct shm_bufidx, size[n + 2]);
		offset = ALIGN(offset, SHM_PAYL_ALIGN);
		if (offset > shm_size)
			goto badsize;
	}

	/*
	 * Allocate RO Data Area. This will located after
	 * the RO Buffer Indices at the end of the Share Memory
	 * area.
	 */
	offset = ALIGN(offset, SHM_PAYL_ALIGN);
	for (i = 0; i < modem->channels; i++) {
		u8 align;
		u32 size;
		ch = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].rx);
		add_magic_pad(&offset, modem->shm_start);
		ch->offset = cpu_to_le32(offset);

		BUILD_BUG_ON(sizeof(ch->mode) != 1);
		ch->mode = modem->channel[i]->mode & SHM_MODE_MASK;
		ch->buffers = cpu_to_le32(modem->channel[i]->rx.buffers);
		align = rounddown_pow_of_two(modem->channel[i]->rx.alignment);
		ch->alignment = align;
		ch->packets = modem->channel[i]->rx.packets;
		ch->mtu = modem->channel[i]->rx.mtu;
		size = modem->channel[i]->tx.ch_size;
		if (modem->channel[i]->mode & SHM_PACKET_MODE) {
			u32 buf_size;
			buf_size = size / modem->channel[i]->tx.buffers;
			buf_size = rounddown(buf_size, align);
			size = buf_size * modem->channel[i]->tx.buffers;
		}
		pr_debug("Buffer area RO for Channel[%d] at: 0x%08x size:%d\n",
				i, offset, size);
		ch->size = cpu_to_le32(size);

		init_data(modem->shm_start, offset, i,
				modem->channel[i]->rx.ch_size);
		offset += modem->channel[i]->rx.ch_size;
		offset = ALIGN(offset, SHM_PAYL_ALIGN);
		if (offset > shm_size)
			goto badsize;
	}

	/*
	 * Allocate RW Data Area. This will located in the beginning
	 * just after the Modem Boot Image.
	 */
	offset = rw_start;
	for (i = 0; i < modem->channels; i++) {
		u8 align;
		u32 size;
		ch = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].tx);
		add_magic_pad(&offset, modem->shm_start);
		ch->offset = cpu_to_le32(offset);
		init_data(modem->shm_start, offset, i,
				modem->channel[i]->tx.ch_size);
		ch->mode = modem->channel[i]->mode &
				SHM_MODE_MASK;
		ch->buffers = cpu_to_le32(modem->channel[i]->tx.buffers);
		align = rounddown_pow_of_two(modem->channel[i]->rx.alignment);
		ch->alignment = align;
		ch->packets = modem->channel[i]->rx.packets;
		ch->mtu = modem->channel[i]->rx.mtu;
		size = modem->channel[i]->tx.ch_size;
		if (modem->channel[i]->mode & SHM_PACKET_MODE) {
			u32 buf_size;
			buf_size = size / modem->channel[i]->tx.buffers;
			buf_size = rounddown(buf_size, align);
			size = buf_size * modem->channel[i]->tx.buffers;
		}
		ch->size = cpu_to_le32(size);
		pr_debug("Buffer area RW for Channel[%d] at: 0x%08x size:%d\n",
				i, offset, size);
		offset += modem->channel[i]->tx.ch_size;
		offset = ALIGN(offset, SHM_PAYL_ALIGN);
		if (offset > ro_start)
			goto badsize;
	}

	/*
	 * Allocate RW IPC Area. This will located after RW data area,
	 * just before the IPC-TOC.
	 */
	offset = ALIGN(offset, SHM_PAYL_ALIGN);
	for (i = 0; i < modem->channels; i++) {
		int n = modem->channel[i]->tx.buffers;
		ch = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].tx);
		add_magic_pad(&offset, modem->shm_start);
		ch->ipc = cpu_to_le32(offset);
		bix = OFFS2PTR(modem->shm_start, offset);
		bix->read_index = cpu_to_le32(0);
		bix->write_index = cpu_to_le32(0);
		bix->state = cpu_to_le32(SHM_CLOSED);
		bix->size[0] = cpu_to_le32(0);

		pr_debug("IPC RW[%d] @: 0x%08x\n",  i, offset);
		offset += offsetof(struct shm_bufidx, size[n + 2]);
		offset = ALIGN(offset, SHM_PAYL_ALIGN);
		if (offset > shm_size)
			goto badsize;
	}

	/* Allocate genio bits for each channel according to priority*/
	bitno = 0;
	for (pri = 0; pri < 8; pri++) {
		for (i = 0; i < modem->channels; i++) {
			if (modem->channel[i]->priority == pri) {
				ch = LEOFFS2PTR(modem->shm_start,
					modem->ipctoc->channel_offsets[i].tx);
				ch->write_bit = cpu_to_le16(bitno * 4);
				ch->read_bit = cpu_to_le16(bitno * 4 + 2);
				ch = LEOFFS2PTR(modem->shm_start,
					modem->ipctoc->channel_offsets[i].rx);
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
	for (toc_entry = modem->shm_start, i = 0; i < 16; i++, toc_entry++)
		if (toc_entry->start == cpu_to_le32(0xffffffff)) {
			pr_debug("IPCTOC address written into Master TOC"
					" @ 0x%08x\n", i * 32);
			toc_entry->start =
				cpu_to_le32(GET_OFFSET(modem->shm_start,
							modem->ipctoc));
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

	store_checksum(modem, ipcro_offs - ipctoc_offs);

	return 0;

badsize:
	pr_debug("IPCTOC not enough space offset (size:0x%lx offset:0x%x\n",
			shm_size, offset);
	return -ENOSPC;

bad_config:
	pr_debug("IPCTOC bad configuration data\n");
	return -EINVAL;
}

static int shm_verify_config(struct shm_modem *modem,
				struct shm_channel *xcfg)
{
	int j;
	u32 size;

	if (modem->channels <= 0 || modem->channels > SHM_MAX_CHANNELS) {
		pr_debug("Bad config: channel mode must be set\n");
		return -EINVAL;
	}

	if ((xcfg->mode & SHM_MODE_MASK) != SHM_PACKET_MODE &&
			(xcfg->mode & SHM_MODE_MASK) != SHM_STREAM_MODE) {
		pr_debug("Bad config: channel mode must be set\n");
		return -EINVAL;
	}
	if (xcfg->mode & SHM_PACKET_MODE && xcfg->rx.buffers < 2) {
		pr_debug("Bad config:minimum 2 buffers "
				"must be set for packet mode\n");
		return -EINVAL;
	}

	if (xcfg->rx.ch_size < SHM_MIN_CHSZ) {
		pr_debug("Bad config:"
				"Channel size must be larger than %d\n",
				SHM_MIN_CHSZ);
		return -EINVAL;
	}

	if (xcfg->mode & SHM_PACKET_MODE) {
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

	if (xcfg->tx.ch_size < SHM_MIN_CHSZ) {
		pr_debug("Bad config:"
				"Channel size must be larger than %d\n",
				SHM_MIN_CHSZ);
		return -EINVAL;
	}

	if (xcfg->name[0] == '\0') {
		pr_debug("Channel must be named\n");
		return -EINVAL;
	}

	size = modem->modem_bootimg_size;

	for (j = 0; j < modem->channels; j++) {
		struct shm_channel *xcfg2 = modem->channel[j];
		size = xcfg2->tx.ch_size + xcfg2->rx.ch_size;
		if (xcfg != xcfg2 && strcmp(xcfg->name, xcfg2->name) == 0) {
			pr_debug("Channels has same name:%s\n",
					 xcfg->name);
			return -EINVAL;
		}
	}

	if (size > shm_size) {
		pr_debug("Channel size too big\n");
		return -EINVAL;
	}

	return 0;
}

static int verify_config(struct shm_modem *modem)
{
	int i;

	if (modem->channels == 0) {
		pr_debug("Bad config: minimum one channel must be defined\n");
		return -EINVAL;
	}
	for (i = 0; i < modem->channels; i++) {
		int err = shm_verify_config(modem, modem->channel[i]);
		if (err)
			return err;
	}
	return 0;
}

/*
 * Create Configuration data for the shm devices.
 */
static void create_devs(struct shm_modem *modem)
{
	int i;

	for (i = 0; i < modem->channels; i++) {
		struct shm_bufidx *buf_rx, *buf_tx;
		struct shm_ipctoc_channel *ch_rx, *ch_tx;
		struct shm_channel *xcfg = modem->channel[i];
		ch_rx = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].rx);
		buf_rx = LEOFFS2PTR(modem->shm_start, ch_rx->ipc);
		ch_tx = LEOFFS2PTR(modem->shm_start,
				modem->ipctoc->channel_offsets[i].tx);
		buf_tx = LEOFFS2PTR(modem->shm_start, ch_tx->ipc);

		/*
		 * Due to restricted read-only access
		 * we swap positions for read/write
		 * pointers.
		 */
		xcfg->tx.write = &buf_tx->write_index;
		xcfg->tx.read = &buf_rx->read_index;

		xcfg->rx.write = &buf_rx->write_index;
		xcfg->rx.read = &buf_tx->read_index;

		xcfg->rx.addr = LEOFFS2PTR(modem->shm_start, ch_rx->offset);
		xcfg->tx.addr = LEOFFS2PTR(modem->shm_start, ch_tx->offset);
		xcfg->rx.state = &buf_rx->state;
		xcfg->tx.state = &buf_tx->state;
		xcfg->tx.buf_size = buf_tx->size;
		xcfg->rx.buf_size = buf_rx->size;

		xcfg->rx.xfer_bit = le16_to_cpu(ch_rx->write_bit);
		xcfg->tx.xfer_bit = le16_to_cpu(ch_tx->write_bit);
		xcfg->rx.xfer_done_bit = le16_to_cpu(ch_rx->read_bit);
		xcfg->tx.xfer_done_bit = le16_to_cpu(ch_tx->read_bit);

		if (xcfg->mode & SHM_PAIR_MODE) {
			struct shm_channel *pair;
			pr_debug("Channel[%d] is in PAIR mode\n", i);
			if (i < 1) {
				pr_debug("No channel to pair with\n");
				continue;
			}
			/* Cross couple rx/tx on the pair */
			pair = modem->channel[i - 1];

			/* Copy everything but the kobj which is at the end */
			memcpy(&xcfg->tx, &pair->rx,
					offsetof(struct shm_udchannel, kobj));
			memcpy(&xcfg->rx, &pair->tx,
					offsetof(struct shm_udchannel, kobj));
		} else if (xcfg->mode & SHM_LOOP_MODE) {
			pr_debug("Channel[%d] is in LOOP mode\n", i);
			/*
			 * Connect rx/tx in a pair. Copy everything,
			 * but the kobj which is at the end
			 */
			memcpy(&xcfg->tx, &xcfg->rx,
					offsetof(struct shm_udchannel, kobj));
		}

		pr_devel("RX[%d] wi:%p ri:%p\n", i, xcfg->rx.read,
				xcfg->rx.write);
		pr_devel("TX[%d] wi:%p ri:%p\n", i, xcfg->tx.read,
				xcfg->tx.write);
	}
}

struct shm_modem *modem;

struct shm_modem *get_modem(struct sk_buff *skb, struct genl_info *info)
{
	return modem;
}

static int do_commit(struct shm_modem *modem)
{
	int err;

	if (modem->config_error) {
		pr_devel("config error detected\n");
		return -EINVAL;
	}

	if (modem->commited) {
		pr_devel("already commited\n");
		modem->config_error = true;
		return -EINVAL;
	}
	err = verify_config(modem);
	if (err) {
		pr_devel("bad config\n");
		modem->config_error = true;
		return err;
	}
	err = write_to_shm(modem);
	if (err) {
		pr_devel("writei to SHM failed\n");
		modem->config_error = true;
		return err;
	}
	modem->commited = true;
	create_devs(modem);
	return 0;
}

static int do_register(struct shm_modem *modem)
{
	int err;

	if (!modem->commited || modem->registered || modem->config_error) {
		pr_devel("bad sequence of requests\n");
		modem->config_error = true;
		return -EINVAL;
	}

	err = verify_config(modem);
	if (err) {
		modem->config_error = true;
		pr_devel("bad config\n");
		return err;
	}
	modem->registered = true;

	modem_shm_register_devices(modem->channel, modem->channels);

	return 0;
}

static void shm_firmware(const struct firmware *fw, void *context)
{
	struct shm_modem *modem = context;
	struct toc_entry *toc_entry;
	int i;

	modem->fw_requested = false;

	pr_debug("recevied firmware\n");
	if (fw == NULL) {
		pr_warn("No boot-img provided\n");
		goto out;
	}

	if (modem->commited) {
		pr_warn("Received firmware too late in modem boot\n");
		goto out;
	}

	toc_entry = (void *)fw->data;
	if (fw->size < TOC_SZ) {
		pr_debug("Modem image too short\n");
		goto bad_img;
	}

	for (i = 0; i < 16; i++, toc_entry++)
		if (toc_entry->start == cpu_to_le32(0xffffffff))
			break;

	if (i == 0) {
		pr_debug("Empty TOC in firmware image\n");
		goto bad_img;
	}

	if (i >= 15) {
		pr_debug("No free slot for IPC-TOC in received image\n");
		goto bad_img;
	}

	modem->modem_bootimg_size = fw->size;
	memcpy(modem->shm_start, fw->data, fw->size);
out:
	release_firmware(fw);
	return;
bad_img:
	pr_warn("Bad modem firmware received\n");
	modem->config_error = true;
	release_firmware(fw);
}

static void do_reset(struct shm_modem *modem)
{
	int i;

	modem_shm_reset();
	modem->config_error = false;
	modem->registered = false;
	modem->commited = false;
	modem->addr_set = false;
	modem->modem_bootimg_size = TOC_SZ;
	for (i = 0; i < modem->channels; i++) {
		kfree(modem->channel[i]);
		modem->channel[i] = NULL;
	}
	modem->channels = 0;

	/* Initiate the Master TOC to 0xff for the first 512 bytes */
	memset(modem->shm_start, 0xff, TOC_SZ);

	if (!modem->fw_requested)
		modem_shm_request_firmware(modem, THIS_MODULE,
				STE_BOOTIMG_NAME, shm_firmware);
	modem->fw_requested = true;
}

static int do_set_addr(struct shm_modem *modem)
{
	int err;
	if (!modem->commited || modem->addr_set || modem->config_error) {
		pr_devel("bad sequence of requests\n");
		modem->config_error = true;
		return -EINVAL;
	}
	err = verify_config(modem);
	if (err) {
		modem->config_error = true;
		pr_devel("bad config\n");
		return err;
	}
	modem->addr_set = true;
	return genio_set_shm_addr(shm_c2c_bootaddr, genio_ipc_ready_cb);
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
		} else if (s - src >= SHM_NAMESZ - 1) {
			pr_debug("Name '%s'too long\n", src);
			return -EINVAL;
		} else
			*d = *s;
	*d = '\0';

	return count;
}

/* SHM Generic NETLINK family */
static struct genl_family shm_gnl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "modem_shm",
	.version = SHM_PROTO_VERSION,
	.maxattr = SHM_A_MAX,
};

/* SHM Netlink attribute policy */
static const struct nla_policy shm_genl_policy[SHM_A_MAX + 1] = {
	[SHM_A_VERSION] = { .type = NLA_U8 },
	[SHM_A_SUB_VERSION] = { .type = NLA_U8 },
	[__SHM_A_FLAGS] = { .type = NLA_U32 },
	[SHM_A_NAME] = { .type = NLA_NUL_STRING, .len = SHM_NAMESZ},
	[SHM_A_RX_CHANNEL] = { .type = NLA_NESTED },
	[SHM_A_TX_CHANNEL] = { .type = NLA_NESTED },
	[SHM_A_PRIORITY] = { .type = NLA_U8 },
	[SHM_A_LATENCY] = { .type = NLA_U8 },
};

/* Policy for uni-directional attributes for stream */
static const struct nla_policy stream_policy[SHM_A_MAX + 1] = {
	[SHM_A_CHANNEL_SIZE] = { .type = NLA_U32 },
};

/* Policy for uni-directional attributes for packet */
static const struct nla_policy packet_policy[SHM_A_MAX + 1] = {
	[SHM_A_CHANNEL_SIZE] = { .type = NLA_U32 },
	[SHM_A_CHANNEL_BUFFERS] = { .type = NLA_U32 },
	[SHM_A_MTU] = { .type = NLA_U16 },
	[SHM_A_ALIGNMENT] = { .type = NLA_U8 },
	[SHM_A_PACKETS] = { .type = NLA_U8 },
};

static int shm_add_udchannel(struct shm_udchannel *chn, int attr,
			struct genl_info *info, struct nla_policy const *policy)
{
	struct nlattr *nla;
	int nla_rem;

	if (!info->attrs[attr])
		return -EINVAL;

	if (nla_validate_nested(info->attrs[attr],
					SHM_A_MAX,
					policy) != 0) {
		pr_info("Invalid RX channel attributes\n");
		return -EINVAL;
	}

	nla_for_each_nested(nla, info->attrs[attr], nla_rem) {

		if (nla_type(nla) == SHM_A_CHANNEL_SIZE)
			chn->ch_size = nla_get_u32(nla);

		if (nla_type(nla) == SHM_A_CHANNEL_BUFFERS)
			chn->buffers = nla_get_u32(nla);

		if (nla_type(nla) == SHM_A_MTU)
			chn->mtu = nla_get_u16(nla);

		if (nla_type(nla) == SHM_A_PACKETS)
			chn->packets = nla_get_u8(nla);

		if (nla_type(nla) == SHM_A_ALIGNMENT) {
			chn->alignment = nla_get_u8(nla);
			chn->alignment = rounddown_pow_of_two(chn->alignment);
		}

	}
	return 0;
}

static int shm_add_channel(struct shm_channel *cfg, struct genl_info *info,
			int mode)
{
	int len, err;
	struct nla_policy const *policy;
	char name[SHM_NAMESZ];

	policy = (mode == SHM_PACKET_MODE) ? packet_policy : stream_policy;

	if (info->attrs[SHM_A_VERSION]) {
		u8 version;
		u8 sub_version;

		version = nla_get_u8(info->attrs[SHM_A_VERSION]);
		if (!info->attrs[SHM_A_SUB_VERSION])
			return -EINVAL;
		sub_version = nla_get_u8(info->attrs[SHM_A_SUB_VERSION]);
		if (version != 1 || sub_version != 0) {
			pr_info("Bad version or sub_version\n");
			return -EINVAL;
		}
	}

	if (!info->attrs[SHM_A_NAME]) {
		pr_debug("Name not specified\n");
		return -EINVAL;
	}

	len = nla_strlcpy(name, info->attrs[SHM_A_NAME],
			SHM_NAMESZ);

	if (len > SHM_NAMESZ)
		return -EINVAL;

	err = copy_name(name, cfg->name, sizeof(name));
	if (err < 0)
		return err;

	cfg->excl_group = 1;
	if (info->attrs[SHM_A_EXCL_GROUP])
		cfg->excl_group = nla_get_u8(info->attrs[SHM_A_EXCL_GROUP]);

	err = shm_add_udchannel(&cfg->rx, SHM_A_RX_CHANNEL, info, policy);
	if (err)
		return err;

	err = shm_add_udchannel(&cfg->tx, SHM_A_TX_CHANNEL, info, policy);
	if (err)
		return err;

	if (cfg->tx.ch_size + cfg->rx.ch_size > shm_size) {
		pr_debug("Channel size too big\n");
		return -EINVAL;
	}

	if (info->attrs[SHM_A_PRIORITY]) {
		cfg->priority = nla_get_u8(info->attrs[SHM_A_PRIORITY]);
		/* silently fixup bad value */
		if (cfg->priority > 7)
			cfg->priority = 0;
	}

	if (info->attrs[SHM_A_LATENCY])
		cfg->latency = nla_get_u8(info->attrs[SHM_A_LATENCY]);

	if (info->attrs[__SHM_A_FLAGS])
		cfg->mode |= nla_get_u32(info->attrs[__SHM_A_FLAGS]);

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

	reply = genlmsg_put_reply(msg, info, &shm_gnl_family, 0, result);
	if (reply == NULL) {
		kfree_skb(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, reply);
	err = genlmsg_reply(msg, info);
	return err;
}

static int shm_add_ch(struct sk_buff *skb, struct genl_info *info, int mode)
{
	int err;
	struct shm_channel *cfg;
	struct shm_modem *modem = get_modem(skb, info);
	if (!modem)
		return -EINVAL;

	if (modem->channels + 1 > SHM_MAX_CHANNELS) {
		pr_debug("Too many channels added\n");
		return -EINVAL;
	}


	cfg = kzalloc(sizeof(*cfg), GFP_KERNEL);
	if (cfg == NULL)
		return -ENOMEM;

	cfg->mode = mode;
	err = shm_add_channel(cfg, info, mode);
	if (err)
		goto error;

	modem->channel[modem->channels] = cfg;
	++modem->channels;

	err = shm_verify_config(modem, cfg);
	if (err)
		goto error_remove;

	err = do_reply(info, 0);
	if (err)
		goto error_remove;
	return err;

error_remove:
	--modem->channels;
error:
	kfree(cfg);
	return err;
}

static int shm_add_packet_ch(struct sk_buff *skb, struct genl_info *info)
{
	return shm_add_ch(skb, info, SHM_PACKET_MODE);
}

static int shm_add_stream_ch(struct sk_buff *skb, struct genl_info *info)
{
	return shm_add_ch(skb, info, SHM_STREAM_MODE);
}


static int shm_c_commit(struct sk_buff *skb, struct genl_info *info)
{
	struct shm_modem *modem = get_modem(skb, info);
	int err;
	if (!modem)
		return -EINVAL;

	err = do_commit(modem);
	if (!err)
		do_reply(info, 0);
	return err;
}

static int shm_c_register(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct shm_modem *modem = get_modem(skb, info);
	if (!modem)
		return -EINVAL;

	err = do_register(modem);
	if (!err)
		do_reply(info, 0);
	return err;
}

static int shm_c_set_addr(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct shm_modem *modem = get_modem(skb, info);
	if (!modem)
		return -EINVAL;

	err = do_set_addr(modem);
	if (!err)
		do_reply(info, 0);
	return err;
}

static int shm_c_reset(struct sk_buff *skb, struct genl_info *info)
{
	struct shm_modem *modem = get_modem(skb, info);
	if (!modem)
		return -EINVAL;

	do_reset(modem);
	do_reply(info, 0);
	return 0;
}

static int shm_c_verify(struct sk_buff *skb, struct genl_info *info)
{
	int err;
	struct shm_modem *modem = get_modem(skb, info);
	if (!modem)
		return -EINVAL;

	err = verify_config(modem);
	if (!err)
		do_reply(info, 0);
	return err;
}

static struct genl_ops shm_genl_ops[] = {
	{
	.cmd = SHM_C_ADD_STREAM_CHANNEL,
	.flags = GENL_ADMIN_PERM,
	.policy = shm_genl_policy,
	.doit = shm_add_stream_ch,
	.dumpit = NULL,
	},
	{
	.cmd = SHM_C_ADD_PACKET_CHANNEL,
	.flags = GENL_ADMIN_PERM,
	.policy = shm_genl_policy,
	.doit = shm_add_packet_ch,
	.dumpit = NULL,
	},
	{
	.cmd = SHM_C_COMMIT,
	.flags = GENL_ADMIN_PERM,
	.doit = shm_c_commit,
	.dumpit = NULL,
	},
	{
	.cmd = SHM_C_REGISTER,
	.flags = GENL_ADMIN_PERM,
	.doit = shm_c_register,
	.dumpit = NULL,
	},
	{
	.cmd = SHM_C_SET_ADDR,
	.flags = GENL_ADMIN_PERM,
	.doit = shm_c_set_addr,
	.dumpit = NULL,
	},
	{
	.cmd = SHM_C_RESET,
	.flags = GENL_ADMIN_PERM,
	.doit = shm_c_reset,
	.dumpit = NULL,
	},
	{
	.cmd = __SHM_C_VERIFY,
	.flags = GENL_ADMIN_PERM,
	.doit = shm_c_verify,
	.dumpit = NULL,
	},

};

/* Initialize boot handling and create sysfs entries*/
int __init shm_boot_init(void)
{
	int err = -EINVAL;
	bool shm_fake = false;

	modem = kzalloc(sizeof(struct shm_modem), GFP_KERNEL);
	if (modem == NULL)
		return -ENOMEM;

	/* Negative shm_size indicates module test without real SHM */
	if (shm_size < 0) {
		shm_fake = true;
		shm_size = abs(shm_size);
	}

	if (shm_size < TOC_SZ)
		goto bad_config;

	if (shm_fake) {
		modem->shm_start = kzalloc(shm_size, GFP_KERNEL);
		err = -ENOMEM;
		if (!modem->shm_start)
			goto error;
		shm_start = (unsigned long) modem->shm_start;
		memset(modem->shm_start, 0xaa, shm_size);
	} else {
		if (shm_start == 0)
			goto bad_config;
		modem->shm_start = ioremap(shm_start, shm_size);
	}

	/* Initiate the Master TOC to 0xff for the first 512 bytes */
	if (shm_size > TOC_SZ)
		memset(modem->shm_start, 0xff, TOC_SZ);

	modem->modem_bootimg_size = TOC_SZ;

	pr_debug("Boot image addr: %p size:%d\n", modem->shm_start,
			modem->modem_bootimg_size);

	err = genl_register_family_with_ops(&shm_gnl_family,
		shm_genl_ops, ARRAY_SIZE(shm_genl_ops));
	if (err)
		goto error;

	modem->gennetl_reg = true;
	modem->fw_requested = true;
	err = modem_shm_request_firmware(modem, THIS_MODULE,
			STE_BOOTIMG_NAME, shm_firmware);
	if (err)
		goto error;

	return err;
error:
	pr_debug("initialization failed\n");

	if (shm_fake)
		kfree(modem->shm_start);
	return err;
bad_config:
	pr_err("Bad module configuration:"
			" shm_base_address:%lu shm_size:%lu err:%d\n",
			shm_start, shm_size, err);
	/* Buildin module should not return error */
	return -EINVAL;
}

void __exit shm_boot_exit(void)
{

	if (modem->gennetl_reg)
		genl_unregister_family(&shm_gnl_family);
	modem->gennetl_reg = false;
}
module_init(shm_boot_init);
module_exit(shm_boot_exit);
