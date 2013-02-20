/*
 * Copyright (C) ST-Ericsson AB 2012
 * Contact: Sjur Brendeland / sjur.brandeland@stericsson.com
 * Authors: Vicram Arv / vikram.arv@stericsson.com,
 *	    Dmitry Tarnyagin / dmitry.tarnyagin@stericsson.com
 *	    Sjur Brendeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/virtio_caif.h>
#include <linux/virtio_ring.h>
#include <linux/vringh.h>
#include <linux/remoteproc.h>
#include <net/caif/caif_dev.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Vicram Arv <vikram.arv@stericsson.com>");
MODULE_AUTHOR("Sjur Brendeland <sjur.brandeland@stericsson.com");
MODULE_DESCRIPTION("Virtio CAIF Driver");

/* Virtio Ring used in receive direction */
#define RX_RING_INDEX 0

#define CFV_DEFAULT_QUOTA 32

/* struct cfv_napi_contxt - NAPI context info
 * @riov: IOV holding data read from the ring. Note that riov may
 *	  still hold data when cfv_rx_poll() returns.
 * @head: Last descriptor ID we received from vringh_getdesc_kern.
 *	  We use this to put descriptor back on the used ring. USHRT_MAX is
 *	  used to indicate invalid head-id.
 */
struct cfv_napi_context {
	struct vringh_kiov riov;
	unsigned short head;
};

/* struct cfv_info - Caif Virtio control structure
 * @cfdev:	caif common header
 * @vdev:	Associated virtio device
 * @vq_rx:	rx/downlink virtqueue
 * @vq_tx:	tx/uplink virtqueue
 * @ndev:	associated netdevice
 * @queued_tx:	number of buffers queued in the tx virtqueue
 * @watermark_tx: indicates number of buffers the tx queue
 *		should shrink to to unblock datapath
 * @tx_lock:	protects vq_tx to allow concurrent senders
 * @tx_hr:	transmit headroom
 * @rx_hr:	receive headroom
 * @tx_tr:	transmit tailroom
 * @rx_tr:	receive tailroom
 * @mtu:	transmit max size
 * @mru:	receive max size
 */
struct cfv_info {
	struct caif_dev_common cfdev;
	struct virtio_device *vdev;
	struct vringh *vr_rx;
	struct virtqueue *vq_tx;
	struct net_device *ndev;
	unsigned int queued_tx;
	unsigned int watermark_tx;
	/* Protect access to vq_tx */
	spinlock_t tx_lock;
	struct tasklet_struct tx_release_tasklet;
	struct napi_struct napi;
	struct cfv_napi_context ctx;
	/* Copied from Virtio config space */
	u16 tx_hr;
	u16 rx_hr;
	u16 tx_tr;
	u16 rx_tr;
	u32 mtu;
	u32 mru;
};

/* struct token_info - maintains Transmit buffer data handle
 * @size:	size of transmit buffer
 * @dma_handle: handle to allocated dma device memory area
 * @vaddr:	virtual address mapping to allocated memory area
 */
struct token_info {
	size_t size;
	u8 *vaddr;
	dma_addr_t dma_handle;
};

/* Default if virtio config space is unavailable */
#define CFV_DEF_MTU_SIZE 4096
#define CFV_DEF_HEADROOM 32
#define CFV_DEF_TAILROOM 32

/* Require IP header to be 4-byte aligned. */
#define IP_HDR_ALIGN 4

static void cfv_release_cb(struct virtqueue *vq_tx)
{
	struct cfv_info *cfv = vq_tx->vdev->priv;
	tasklet_schedule(&cfv->tx_release_tasklet);
}

/* This is invoked whenever the remote processor completed processing
 * a TX msg we just sent it, and the buffer is put back to the used ring.
 */
static void cfv_release_used_buf(struct virtqueue *vq_tx)
{
	struct cfv_info *cfv = vq_tx->vdev->priv;
	unsigned long flags;

	BUG_ON(vq_tx != cfv->vq_tx);
	WARN_ON_ONCE(irqs_disabled());

	for (;;) {
		unsigned int len;
		struct token_info *buf_info;

		/* Get used buffer from used ring to recycle used descriptors */
		spin_lock_irqsave(&cfv->tx_lock, flags);
		buf_info = virtqueue_get_buf(vq_tx, &len);

		if (!buf_info)
			goto out;

		BUG_ON(!cfv->queued_tx);
		if (--cfv->queued_tx <= cfv->watermark_tx) {
			cfv->watermark_tx = 0;
			netif_tx_wake_all_queues(cfv->ndev);
		}
		spin_unlock_irqrestore(&cfv->tx_lock, flags);

		dma_free_coherent(vq_tx->vdev->dev.parent->parent,
				  buf_info->size, buf_info->vaddr,
				  buf_info->dma_handle);
		kfree(buf_info);
	}
	return;
out:
	spin_unlock_irqrestore(&cfv->tx_lock, flags);
}

static struct sk_buff *cfv_alloc_and_copy_skb(int *err,
					      struct cfv_info *cfv,
					      u8 *frm, u32 frm_len)
{
	struct sk_buff *skb;
	u32 cfpkt_len, pad_len;

	*err = 0;
	/* Verify that packet size with down-link header and mtu size */
	if (frm_len > cfv->mru || frm_len <= cfv->rx_hr + cfv->rx_tr) {
		netdev_err(cfv->ndev,
			   "Invalid frmlen:%u  mtu:%u hr:%d tr:%d\n",
			   frm_len, cfv->mru,  cfv->rx_hr,
			   cfv->rx_tr);
		*err = -EPROTO;
		return NULL;
	}

	cfpkt_len = frm_len - (cfv->rx_hr + cfv->rx_tr);

	pad_len = (unsigned long)(frm + cfv->rx_hr) & (IP_HDR_ALIGN - 1);

	skb = netdev_alloc_skb(cfv->ndev, frm_len + pad_len);
	if (!skb) {
		*err = -ENOMEM;
		return NULL;
	}
	/* Reserve space for headers. */
	skb_reserve(skb, cfv->rx_hr + pad_len);

	memcpy(skb_put(skb, cfpkt_len), frm + cfv->rx_hr, cfpkt_len);
	return skb;
}

static int cfv_rx_poll(struct napi_struct *napi, int quota)
{
	struct cfv_info *cfv = container_of(napi, struct cfv_info, napi);
	int rxcnt = 0;
	int err = 0;
	void *buf;
	struct sk_buff *skb;
	struct vringh_kiov *riov = &cfv->ctx.riov;

	do {
		skb = NULL;
		if (riov->i == riov->used) {
			if (cfv->ctx.head != USHRT_MAX) {
				vringh_complete_kern(cfv->vr_rx,
						     cfv->ctx.head,
						     0);
				cfv->ctx.head = USHRT_MAX;
			}

			err = vringh_getdesc_kern(
				cfv->vr_rx,
				riov,
				NULL,
				&cfv->ctx.head,
				GFP_ATOMIC);

			if (err <= 0)
				goto out;

		}

		buf = phys_to_virt((unsigned long) riov->iov[riov->i].iov_base);
		/* TODO: Add check on valid buffer address */

		skb = cfv_alloc_and_copy_skb(&err, cfv, buf,
					     riov->iov[riov->i].iov_len);
		if (unlikely(err))
			goto out;

		/* Push received packet up the stack. */
		skb->protocol = htons(ETH_P_CAIF);
		skb_reset_mac_header(skb);
		skb->dev = cfv->ndev;
		err = netif_receive_skb(skb);
		if (unlikely(err)) {
			++cfv->ndev->stats.rx_dropped;
		} else {
			++cfv->ndev->stats.rx_packets;
			cfv->ndev->stats.rx_bytes += skb->len;
		}

		++riov->i;
		++rxcnt;
	} while (rxcnt < quota);

	return rxcnt;

out:
	switch (err) {
	case 0:
		/* Empty ring, enable notifications and stop NAPI polling */
		if (!vringh_notify_enable_kern(cfv->vr_rx))
			napi_complete(napi);

		return rxcnt;

	case -ENOMEM:
		dev_kfree_skb(skb);
		/* Stop NAPI poll on OOM, we hope to be polled later */
		napi_complete(napi);
		vringh_notify_enable_kern(cfv->vr_rx);
		break;

	default:
		/* We're doomed, any modem fault is fatal */
		netdev_warn(cfv->ndev, "Bad ring, disable device\n");
		cfv->ndev->stats.rx_dropped = riov->used - riov->i;
		napi_complete(napi);
		vringh_notify_disable_kern(cfv->vr_rx);
		netif_carrier_off(cfv->ndev);
		break;
	}

	return rxcnt;
}

static irqreturn_t cfv_recv(struct virtio_device *vdev, struct vringh *vr_rx)
{
	struct cfv_info *cfv = vdev->priv;

	vringh_notify_disable_kern(cfv->vr_rx);
	napi_schedule(&cfv->napi);
	return IRQ_HANDLED;
}

static int cfv_netdev_open(struct net_device *netdev)
{
	struct cfv_info *cfv = netdev_priv(netdev);

	netif_carrier_on(netdev);
	napi_enable(&cfv->napi);
	return 0;
}

static int cfv_netdev_close(struct net_device *netdev)
{
	struct cfv_info *cfv = netdev_priv(netdev);

	netif_carrier_off(netdev);
	napi_disable(&cfv->napi);
	return 0;
}

static struct token_info *cfv_alloc_and_copy_to_dmabuf(struct cfv_info *cfv,
						       struct sk_buff *skb,
						       struct scatterlist *sg)
{
	struct caif_payload_info *info = (void *)&skb->cb;
	struct token_info *buf_info = NULL;
	u8 pad_len, hdr_ofs;

	if (unlikely(cfv->tx_hr + skb->len + cfv->tx_tr > cfv->mtu)) {
		netdev_warn(cfv->ndev, "Invalid packet len (%d > %d)\n",
			    cfv->tx_hr + skb->len + cfv->tx_tr, cfv->mtu);
		goto err;
	}

	buf_info = kmalloc(sizeof(struct token_info), GFP_ATOMIC);
	if (unlikely(!buf_info))
		goto err;

	/* Make the IP header aligned in tbe buffer */
	hdr_ofs = cfv->tx_hr + info->hdr_len;
	pad_len = hdr_ofs & (IP_HDR_ALIGN - 1);
	buf_info->size = cfv->tx_hr + skb->len + cfv->tx_tr + pad_len;

	if (WARN_ON_ONCE(!cfv->vdev->dev.parent))
		goto err;

	/* allocate coherent memory for the buffers */
	buf_info->vaddr =
		dma_alloc_coherent(cfv->vdev->dev.parent->parent,
				   buf_info->size, &buf_info->dma_handle,
				   GFP_ATOMIC);
	if (unlikely(!buf_info->vaddr)) {
		netdev_warn(cfv->ndev,
			    "Out of DMA memory (alloc %zu bytes)\n",
			    buf_info->size);
		goto err;
	}

	/* copy skbuf contents to send buffer */
	skb_copy_bits(skb, 0, buf_info->vaddr + cfv->tx_hr + pad_len, skb->len);
	sg_init_one(sg, buf_info->vaddr + pad_len,
		    skb->len + cfv->tx_hr + cfv->rx_hr);

	return buf_info;
err:
	kfree(buf_info);
	return NULL;
}

/* This is invoked whenever the host processor application has sent
 * up-link data. Send it in the TX VQ avail ring.
 *
 * CAIF Virtio sends does not use linked descriptors in the tx direction.
 */
static int cfv_netdev_tx(struct sk_buff *skb, struct net_device *netdev)
{
	struct cfv_info *cfv = netdev_priv(netdev);
	struct token_info *buf_info;
	struct scatterlist sg;
	unsigned long flags;
	int ret;

	buf_info = cfv_alloc_and_copy_to_dmabuf(cfv, skb, &sg);

	spin_lock_irqsave(&cfv->tx_lock, flags);
	if (unlikely(!buf_info))
		goto flow_off;

	/* Add buffer to avail ring. Flow control below should ensure
	 * that this always succeedes
	 */
	ret = virtqueue_add_buf(cfv->vq_tx, &sg, 1, 0,
				buf_info, GFP_ATOMIC);

	if (unlikely(WARN_ON(ret < 0))) {
		kfree(buf_info);
		goto flow_off;
	}


	/* update netdev statistics */
	cfv->queued_tx++;
	cfv->ndev->stats.tx_packets++;
	cfv->ndev->stats.tx_bytes += skb->len;

	/* tell the remote processor it has a pending message to read */
	virtqueue_kick(cfv->vq_tx);

	/* Flow-off check takes into account number of cpus to make sure
	 * virtqueue will not be overfilled in any possible smp conditions.
	 *
	 * Flow-on is triggered when sufficient buffers are freed
	 */
	if (ret <= num_present_cpus()) {
flow_off:
		cfv->watermark_tx = cfv->queued_tx >> 1;
		netif_tx_stop_all_queues(netdev);
	}

	spin_unlock_irqrestore(&cfv->tx_lock, flags);

	dev_kfree_skb(skb);
	tasklet_schedule(&cfv->tx_release_tasklet);
	return NETDEV_TX_OK;
}

static void cfv_tx_release_tasklet(unsigned long drv)
{
	struct cfv_info *cfv = (struct cfv_info *)drv;
	cfv_release_used_buf(cfv->vq_tx);
}

static const struct net_device_ops cfv_netdev_ops = {
	.ndo_open = cfv_netdev_open,
	.ndo_stop = cfv_netdev_close,
	.ndo_start_xmit = cfv_netdev_tx,
};

static void cfv_netdev_setup(struct net_device *netdev)
{
	netdev->netdev_ops = &cfv_netdev_ops;
	netdev->type = ARPHRD_CAIF;
	netdev->tx_queue_len = 100;
	netdev->flags = IFF_POINTOPOINT | IFF_NOARP;
	netdev->mtu = CFV_DEF_MTU_SIZE;
	netdev->destructor = free_netdev;
}

static int cfv_probe(struct virtio_device *vdev)
{
	vq_callback_t *vq_cbs = cfv_release_cb;
	const char *names =  "output";
	const char *cfv_netdev_name = "cfvrt";
	struct net_device *netdev;
	struct virtqueue *vqs;

	struct cfv_info *cfv;
	int err = 0;

	netdev = alloc_netdev(sizeof(struct cfv_info), cfv_netdev_name,
			      cfv_netdev_setup);
	if (!netdev)
		return -ENOMEM;

	cfv = netdev_priv(netdev);
	cfv->vdev = vdev;
	cfv->ndev = netdev;

	spin_lock_init(&cfv->tx_lock);

	cfv->vr_rx = rproc_virtio_new_vringh(vdev, RX_RING_INDEX, cfv_recv);
	if (!cfv->vr_rx)
		goto free_cfv;

	/* Get the TX (uplink) virtque */
	err = vdev->config->find_vqs(vdev, 1, &vqs, &vq_cbs, &names);
	if (err)
		goto free_cfv;

	cfv->vq_tx = vqs;

#define GET_VIRTIO_CONFIG_OPS(_v, _var, _f) \
	((_v)->config->get(_v, offsetof(struct virtio_caif_transf_config, _f), \
			   &_var, \
			   FIELD_SIZEOF(struct virtio_caif_transf_config, _f)))

	if (vdev->config->get) {
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->tx_hr, headroom);
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->rx_hr, headroom);
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->tx_tr, tailroom);
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->rx_tr, tailroom);
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->mtu, mtu);
		GET_VIRTIO_CONFIG_OPS(vdev, cfv->mru, mtu);
	} else {
		cfv->tx_hr = CFV_DEF_HEADROOM;
		cfv->rx_hr = CFV_DEF_HEADROOM;
		cfv->tx_tr = CFV_DEF_TAILROOM;
		cfv->rx_tr = CFV_DEF_TAILROOM;
		cfv->mtu = CFV_DEF_MTU_SIZE;
		cfv->mru = CFV_DEF_MTU_SIZE;
	}

	netdev->needed_headroom = cfv->tx_hr;
	netdev->needed_tailroom = cfv->tx_tr;

	/* Subtract needed tailroom from MTU to ensure enough room */
	netdev->mtu = cfv->mtu - cfv->tx_tr;

	vdev->priv = cfv;

	vringh_kiov_init(&cfv->ctx.riov, NULL, 0);
	cfv->ctx.head = USHRT_MAX;

	netif_napi_add(netdev, &cfv->napi, cfv_rx_poll, CFV_DEFAULT_QUOTA);
	tasklet_init(&cfv->tx_release_tasklet,
		     cfv_tx_release_tasklet,
		     (unsigned long)cfv);

	netif_carrier_off(netdev);

	/* register Netdev */
	err = register_netdev(netdev);
	if (err) {
		dev_err(&vdev->dev, "Unable to register netdev (%d)\n", err);
		goto vqs_del;
	}

	/* tell the remote processor it can start sending messages */
	rproc_virtio_kick_vringh(vdev, RX_RING_INDEX);

	return 0;

vqs_del:
	vdev->config->del_vqs(cfv->vdev);
free_cfv:
	free_netdev(netdev);
	return err;
}

static void cfv_remove(struct virtio_device *vdev)
{
	struct cfv_info *cfv = vdev->priv;

	tasklet_kill(&cfv->tx_release_tasklet);
	vringh_kiov_cleanup(&cfv->ctx.riov);
	vdev->config->reset(vdev);
	rproc_virtio_del_vringh(vdev, RX_RING_INDEX);
	cfv->vr_rx = NULL;
	vdev->config->del_vqs(cfv->vdev);
	unregister_netdev(cfv->ndev);
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_CAIF, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
};

static struct virtio_driver caif_virtio_driver = {
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.probe			= cfv_probe,
	.remove			= cfv_remove,
};

module_virtio_driver(caif_virtio_driver);
MODULE_DEVICE_TABLE(virtio, id_table);
