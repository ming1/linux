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

#include <linux/etherdevice.h>
#include <net/mac80211.h>

#define MWL8K_DESC     "Marvell TOPDOG(R) 802.11 Wireless Network Driver"
#define MWL8K_NAME     KBUILD_MODNAME
#define MWL8K_VERSION  "0.10"

/* Register definitions */
#define MWL8K_HIU_GEN_PTR			0x00000c10
#define  MWL8K_MODE_STA				 0x0000005a
#define  MWL8K_MODE_AP				 0x000000a5
#define MWL8K_HIU_INT_CODE			0x00000c14
#define  MWL8K_FWSTA_READY			 0xf0f1f2f4
#define  MWL8K_FWAP_READY			 0xf1f2f4a5
#define  MWL8K_INT_CODE_CMD_FINISHED		 0x00000005
#define MWL8K_HIU_SCRATCH			0x00000c40

/* Host->device communications */
#define MWL8K_HIU_H2A_INTERRUPT_EVENTS		0x00000c18
#define MWL8K_HIU_H2A_INTERRUPT_STATUS		0x00000c1c
#define MWL8K_HIU_H2A_INTERRUPT_MASK		0x00000c20
#define MWL8K_HIU_H2A_INTERRUPT_CLEAR_SEL	0x00000c24
#define MWL8K_HIU_H2A_INTERRUPT_STATUS_MASK	0x00000c28
#define  MWL8K_H2A_INT_DUMMY			 (1 << 20)
#define  MWL8K_H2A_INT_RESET			 (1 << 15)
#define  MWL8K_H2A_INT_DOORBELL			 (1 << 1)
#define  MWL8K_H2A_INT_PPA_READY		 (1 << 0)

/* Device->host communications */
#define MWL8K_HIU_A2H_INTERRUPT_EVENTS		0x00000c2c
#define MWL8K_HIU_A2H_INTERRUPT_STATUS		0x00000c30
#define MWL8K_HIU_A2H_INTERRUPT_MASK		0x00000c34
#define MWL8K_HIU_A2H_INTERRUPT_CLEAR_SEL	0x00000c38
#define MWL8K_HIU_A2H_INTERRUPT_STATUS_MASK	0x00000c3c
#define  MWL8K_A2H_INT_DUMMY			 (1 << 20)
#define  MWL8K_A2H_INT_CHNL_SWITCHED		 (1 << 11)
#define  MWL8K_A2H_INT_QUEUE_EMPTY		 (1 << 10)
#define  MWL8K_A2H_INT_RADAR_DETECT		 (1 << 7)
#define  MWL8K_A2H_INT_RADIO_ON			 (1 << 6)
#define  MWL8K_A2H_INT_RADIO_OFF		 (1 << 5)
#define  MWL8K_A2H_INT_MAC_EVENT		 (1 << 3)
#define  MWL8K_A2H_INT_OPC_DONE			 (1 << 2)
#define  MWL8K_A2H_INT_RX_READY			 (1 << 1)
#define  MWL8K_A2H_INT_TX_DONE			 (1 << 0)

#define MWL8K_A2H_EVENTS	(MWL8K_A2H_INT_DUMMY | \
				 MWL8K_A2H_INT_CHNL_SWITCHED | \
				 MWL8K_A2H_INT_QUEUE_EMPTY | \
				 MWL8K_A2H_INT_RADAR_DETECT | \
				 MWL8K_A2H_INT_RADIO_ON | \
				 MWL8K_A2H_INT_RADIO_OFF | \
				 MWL8K_A2H_INT_MAC_EVENT | \
				 MWL8K_A2H_INT_OPC_DONE | \
				 MWL8K_A2H_INT_RX_READY | \
				 MWL8K_A2H_INT_TX_DONE)

#define MWL8K_RX_QUEUES		1
#define MWL8K_TX_QUEUES		4

/* Set or get info from Firmware */
#define MWL8K_CMD_SET			0x0001
#define MWL8K_CMD_GET			0x0000

/* Firmware command codes */
#define MWL8K_CMD_CODE_DNLD		0x0001
#define MWL8K_CMD_GET_HW_SPEC		0x0003
#define MWL8K_CMD_SET_HW_SPEC		0x0004
#define MWL8K_CMD_MAC_MULTICAST_ADR	0x0010
#define MWL8K_CMD_GET_STAT		0x0014
#define MWL8K_CMD_RADIO_CONTROL		0x001c
#define MWL8K_CMD_RF_TX_POWER		0x001e
#define MWL8K_CMD_RF_ANTENNA		0x0020
#define MWL8K_CMD_SET_PRE_SCAN		0x0107
#define MWL8K_CMD_SET_POST_SCAN		0x0108
#define MWL8K_CMD_SET_RF_CHANNEL	0x010a
#define MWL8K_CMD_SET_AID		0x010d
#define MWL8K_CMD_SET_RATE		0x0110
#define MWL8K_CMD_SET_FINALIZE_JOIN	0x0111
#define MWL8K_CMD_RTS_THRESHOLD		0x0113
#define MWL8K_CMD_SET_SLOT		0x0114
#define MWL8K_CMD_SET_EDCA_PARAMS	0x0115
#define MWL8K_CMD_SET_WMM_MODE		0x0123
#define MWL8K_CMD_MIMO_CONFIG		0x0125
#define MWL8K_CMD_USE_FIXED_RATE	0x0126
#define MWL8K_CMD_ENABLE_SNIFFER	0x0150
#define MWL8K_CMD_SET_MAC_ADDR		0x0202
#define MWL8K_CMD_SET_RATEADAPT_MODE	0x0203
#define MWL8K_CMD_UPDATE_STADB		0x1123

/* Defines common to 8361 and 8687 */
#define MWL8K_8361_8687_RATE_INFO_SHORTPRE	0x8000
#define MWL8K_8361_8687_RATE_INFO_ANTSELECT(x)	(((x) >> 11) & 0x3)
#define MWL8K_8361_8687_RATE_INFO_RATEID(x)	(((x) >> 3) & 0x3f)
#define MWL8K_8361_8687_RATE_INFO_40MHZ		0x0004
#define MWL8K_8361_8687_RATE_INFO_SHORTGI	0x0002
#define MWL8K_8361_8687_RATE_INFO_MCS_FORMAT	0x0001

#define MWL8K_8361_8687_RX_CTRL_OWNED_BY_HOST	0x02


static const struct ieee80211_rate mwl8k_rates[] = {
	{ .bitrate = 10, .hw_value = 2, },
	{ .bitrate = 20, .hw_value = 4, },
	{ .bitrate = 55, .hw_value = 11, },
	{ .bitrate = 110, .hw_value = 22, },
	{ .bitrate = 220, .hw_value = 44, },
	{ .bitrate = 60, .hw_value = 12, },
	{ .bitrate = 90, .hw_value = 18, },
	{ .bitrate = 120, .hw_value = 24, },
	{ .bitrate = 180, .hw_value = 36, },
	{ .bitrate = 240, .hw_value = 48, },
	{ .bitrate = 360, .hw_value = 72, },
	{ .bitrate = 480, .hw_value = 96, },
	{ .bitrate = 540, .hw_value = 108, },
};

struct rxd_ops {
	int rxd_size;
	void (*rxd_init)(void *rxd, dma_addr_t next_dma_addr);
	void (*rxd_refill)(void *rxd, dma_addr_t addr, int len);
	int (*rxd_process)(void *rxd, struct ieee80211_rx_status *status);
};

struct mwl8k_device_info {
	char *part_name;
	char *helper_image;
	char *fw_image;
	struct rxd_ops *rxd_ops;
	u16 modes;
};

int mwl8k_probe(struct pci_dev *pdev, struct mwl8k_device_info *info);
void mwl8k_remove(struct pci_dev *pdev);
void mwl8k_shutdown(struct pci_dev *pdev);

