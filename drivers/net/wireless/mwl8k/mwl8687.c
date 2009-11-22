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

#define MWL8687_DESC	MWL8K_DESC " for 88w8687-based devices"

/*
 * Receive descriptor
 */
struct mwl8k_rxd_8687 {
	__le16 pkt_len;
	__u8 link_quality;
	__u8 noise_level;
	__le32 pkt_phys_addr;
	__le32 next_rxd_phys_addr;
	__le16 qos_control;
	__le16 rate_info;
	__le32 pad0[4];
	__u8 rssi;
	__u8 channel;
	__le16 pad1;
	__u8 rx_ctrl;
	__u8 rx_status;
	__u8 pad2[2];
} __attribute__((packed));

static void mwl8k_rxd_8687_init(void *_rxd, dma_addr_t next_dma_addr)
{
	struct mwl8k_rxd_8687 *rxd = _rxd;

	rxd->next_rxd_phys_addr = cpu_to_le32(next_dma_addr);
	rxd->rx_ctrl = MWL8K_8361_8687_RX_CTRL_OWNED_BY_HOST;
}

static void mwl8k_rxd_8687_refill(void *_rxd, dma_addr_t addr, int len)
{
	struct mwl8k_rxd_8687 *rxd = _rxd;

	rxd->pkt_len = cpu_to_le16(len);
	rxd->pkt_phys_addr = cpu_to_le32(addr);
	wmb();
	rxd->rx_ctrl = 0;
}

static int
mwl8k_rxd_8687_process(void *_rxd, struct ieee80211_rx_status *status)
{
	struct mwl8k_rxd_8687 *rxd = _rxd;
	u16 rate_info;

	if (!(rxd->rx_ctrl & MWL8K_8361_8687_RX_CTRL_OWNED_BY_HOST))
		return -1;
	rmb();

	rate_info = le16_to_cpu(rxd->rate_info);

	memset(status, 0, sizeof(*status));

	status->signal = -rxd->rssi;
	status->noise = -rxd->noise_level;
	status->qual = rxd->link_quality;
	status->antenna = MWL8K_8361_8687_RATE_INFO_ANTSELECT(rate_info);
	status->rate_idx = MWL8K_8361_8687_RATE_INFO_RATEID(rate_info);

	if (rate_info & MWL8K_8361_8687_RATE_INFO_SHORTPRE)
		status->flag |= RX_FLAG_SHORTPRE;
	if (rate_info & MWL8K_8361_8687_RATE_INFO_40MHZ)
		status->flag |= RX_FLAG_40MHZ;
	if (rate_info & MWL8K_8361_8687_RATE_INFO_SHORTGI)
		status->flag |= RX_FLAG_SHORT_GI;
	if (rate_info & MWL8K_8361_8687_RATE_INFO_MCS_FORMAT)
		status->flag |= RX_FLAG_HT;

	status->band = IEEE80211_BAND_2GHZ;
	status->freq = ieee80211_channel_to_frequency(rxd->channel);

	return le16_to_cpu(rxd->pkt_len);
}

static struct rxd_ops rxd_8687_ops = {
	.rxd_size	= sizeof(struct mwl8k_rxd_8687),
	.rxd_init	= mwl8k_rxd_8687_init,
	.rxd_refill	= mwl8k_rxd_8687_refill,
	.rxd_process	= mwl8k_rxd_8687_process,
};

static struct mwl8k_device_info mwl8687_info __devinitdata = {
	.part_name	= "88w8687",
	.helper_image	= "mwl8k/helper_8687.fw",
	.fw_image	= "mwl8k/fmimage_8687.fw",
	.rxd_ops	= &rxd_8687_ops,
	.modes		= BIT(NL80211_IFTYPE_STATION),
};

static int __devinit mwl8687_probe(struct pci_dev *pdev,
				   const struct pci_device_id *id)
{
	return mwl8k_probe(pdev, &mwl8687_info);
}

static void __devexit mwl8687_shutdown(struct pci_dev *pdev)
{
	mwl8k_shutdown(pdev);
}

static void __devexit mwl8687_remove(struct pci_dev *pdev)
{
	mwl8k_remove(pdev);
}

static DEFINE_PCI_DEVICE_TABLE(mwl8687_pci_id_table) = {
	{ PCI_VDEVICE(MARVELL, 0x2a2b), 0 },
	{ PCI_VDEVICE(MARVELL, 0x2a30), 0 },
	{ },
};
MODULE_DEVICE_TABLE(pci, mwl8687_pci_id_table);

static struct pci_driver mwl8687_driver = {
	.name		= MWL8K_NAME,
	.id_table	= mwl8687_pci_id_table,
	.probe		= mwl8687_probe,
	.remove		= __devexit_p(mwl8687_remove),
	.shutdown	= __devexit_p(mwl8687_shutdown),
};

static int __init mwl8687_init(void)
{
	return pci_register_driver(&mwl8687_driver);
}

static void __exit mwl8687_exit(void)
{
	pci_unregister_driver(&mwl8687_driver);
}

module_init(mwl8687_init);
module_exit(mwl8687_exit);

MODULE_DESCRIPTION(MWL8687_DESC);
MODULE_VERSION(MWL8K_VERSION);
MODULE_AUTHOR("Lennert Buytenhek <buytenh@marvell.com>");
MODULE_LICENSE("GPL");
