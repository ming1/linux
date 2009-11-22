/*
 * drivers/net/wireless/mwl8k.c
 * Driver for Marvell TOPDOG 802.11 Wireless cards
 *
 * Copyright (C) 2008-2009 Marvell Semiconductor Inc.
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "mwl8k.h"
#include <linux/pci.h>

#define MWL8366_DESC	MWL8K_DESC " for 88w8366-based devices"

/*
 * Receive descriptor
 */
struct mwl8k_rxd_8366 {
	__le16 pkt_len;
	__u8 sq2;
	__u8 rate;
	__le32 pkt_phys_addr;
	__le32 next_rxd_phys_addr;
	__le16 qos_control;
	__le16 htsig2;
	__le32 hw_rssi_info;
	__le32 hw_noise_floor_info;
	__u8 noise_floor;
	__u8 pad0[3];
	__u8 rssi;
	__u8 rx_status;
	__u8 channel;
	__u8 rx_ctrl;
} __attribute__((packed));

#define MWL8K_8366_RX_CTRL_OWNED_BY_HOST	0x80

static void mwl8k_rxd_8366_init(void *_rxd, dma_addr_t next_dma_addr)
{
	struct mwl8k_rxd_8366 *rxd = _rxd;

	rxd->next_rxd_phys_addr = cpu_to_le32(next_dma_addr);
	rxd->rx_ctrl = MWL8K_8366_RX_CTRL_OWNED_BY_HOST;
}

static void mwl8k_rxd_8366_refill(void *_rxd, dma_addr_t addr, int len)
{
	struct mwl8k_rxd_8366 *rxd = _rxd;

	rxd->pkt_len = cpu_to_le16(len);
	rxd->pkt_phys_addr = cpu_to_le32(addr);
	wmb();
	rxd->rx_ctrl = 0;
}

static int
mwl8k_rxd_8366_process(void *_rxd, struct ieee80211_rx_status *status)
{
	struct mwl8k_rxd_8366 *rxd = _rxd;

	if (!(rxd->rx_ctrl & MWL8K_8366_RX_CTRL_OWNED_BY_HOST))
		return -1;
	rmb();

	memset(status, 0, sizeof(*status));

	status->signal = -rxd->rssi;
	status->noise = -rxd->noise_floor;

	if (rxd->rate & 0x80) {
		status->flag |= RX_FLAG_HT;
		status->rate_idx = rxd->rate & 0x7f;
	} else {
		int i;

		for (i = 0; i < ARRAY_SIZE(mwl8k_rates); i++) {
			if (mwl8k_rates[i].hw_value == rxd->rate) {
				status->rate_idx = i;
				break;
			}
		}
	}

	status->band = IEEE80211_BAND_2GHZ;
	status->freq = ieee80211_channel_to_frequency(rxd->channel);

	return le16_to_cpu(rxd->pkt_len);
}

static struct rxd_ops rxd_8366_ops = {
	.rxd_size	= sizeof(struct mwl8k_rxd_8366),
	.rxd_init	= mwl8k_rxd_8366_init,
	.rxd_refill	= mwl8k_rxd_8366_refill,
	.rxd_process	= mwl8k_rxd_8366_process,
};

static struct mwl8k_device_info mwl8366_info __devinitdata = {
	.part_name	= "88w8366",
	.helper_image	= "mwl8k/helper_8366.fw",
	.fw_image	= "mwl8k/fmimage_8366.fw",
	.rxd_ops	= &rxd_8366_ops,
	.modes		= 0,
};

static int __devinit mwl8366_probe(struct pci_dev *pdev,
				   const struct pci_device_id *id)
{
	return mwl8k_probe(pdev, &mwl8366_info);
}

static void __devexit mwl8366_shutdown(struct pci_dev *pdev)
{
	mwl8k_shutdown(pdev);
}

static void __devexit mwl8366_remove(struct pci_dev *pdev)
{
	mwl8k_remove(pdev);
}

static DEFINE_PCI_DEVICE_TABLE(mwl8366_pci_id_table) = {
	{ PCI_VDEVICE(MARVELL, 0x2a40), 0 },
	{ },
};
MODULE_DEVICE_TABLE(pci, mwl8366_pci_id_table);

static struct pci_driver mwl8366_driver = {
	.name		= MWL8K_NAME,
	.id_table	= mwl8366_pci_id_table,
	.probe		= mwl8366_probe,
	.remove		= __devexit_p(mwl8366_remove),
	.shutdown	= __devexit_p(mwl8366_shutdown),
};

static int __init mwl8366_init(void)
{
	return pci_register_driver(&mwl8366_driver);
}

static void __exit mwl8366_exit(void)
{
	pci_unregister_driver(&mwl8366_driver);
}

module_init(mwl8366_init);
module_exit(mwl8366_exit);

MODULE_DESCRIPTION(MWL8366_DESC);
MODULE_VERSION(MWL8K_VERSION);
MODULE_AUTHOR("Lennert Buytenhek <buytenh@marvell.com>");
MODULE_LICENSE("GPL");
