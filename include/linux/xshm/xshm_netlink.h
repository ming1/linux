/*
 * Copyright (C) ST-Ericsson AB 2011
 * Author: Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#ifndef XSHM_NL_H_
#define XSHM_NL_H_

#define XSHM_PROTO_VERSION 1
#define XSHM_PROTO_SUB_VERSION 0
#define XSHM_NETLINK_VERSION 1
/**
 * enum XSHM_COMMANDS - Attributes used for configuring XSHM device.
 *
 * @XSHM_C_ADD_STREAM_CHANNEL: Adds a Stream Channel.
 * This will cause an instance of XSHM-CHR to be created.
 * @XSHM_C_ADD_PACKET_CHANNEL: Adds a Packet Channel.
 * This will cause an instance of CAIF-SHM to be created.
 * @XSHM_C_COMMIT: formats and write Channel configuration data to
 *	Shared Memory.
 * @XSHM_C_SET_ADDR: Writes the TOC address to GENO register.
 * @XSHM_C_REGISTER:  Initiates registration of the channel devices.
 *	This will cause xshm - character devices or
 *	CAIF network instances to be created.
 * @XSHM_C_RESET:  Reset the configuration data and removes the
 *	platform devices and their associated channel configuration.
 *	ipc_ready and caif_ready is set to false.
 *
 * A normal sequence of events is: [XSHM_C_RESET], [XSHM_C_ADD_X_CHANNEL],
 *	XSHM_C_COMMIT, XSHM_C_REGISTER, XSHM_C_SET_ADDR.
 */
enum XSHM_COMMANDS {
	XSHM_C_ADD_STREAM_CHANNEL = 1,
	XSHM_C_ADD_PACKET_CHANNEL,
	XSHM_C_RESET,
	XSHM_C_SET_ADDR,
	XSHM_C_COMMIT,
	XSHM_C_REGISTER,
	__XSHM_C_VERIFY,
	__XSHM_C_MAX
};

/**
 * enum XSHM_ATTRIBUTES - Attributes used for configuring XSHM device.
 * @XSHM_A_VERSION: Version of XSHM netlink protocol. Type NLA_U8
 * @XSHM_A_SUB_VERSION: Sub-version of XSHM netlink protocol. Type NLA_U8
 * @XSHM_A_NAME: Name of the channel, max 15 characters. Type NLA_NUL_STRING
 * @XSHM_A_EXCL_GROUP: Devices may be part of a group. Devices from the
 *	same group are allowed to be open simultaneously,
 *	but devices from different groups cannot be opened
 *	at the same time. Type NLA_U8.
 * @XSHM_A_RX_CHANNEL: The RX direction attributes. Type NLA_NESTED.
 *	Each channel may contain the attributes - XSHM_A_CHANNEL_SIZE,
 *	XSHM_A_CHANNEL_BUFFERS, XSHM_A_ALIGNMENT, XSHM_A_MTU.
 *
 * @XSHM_A_TX_CHANNEL: The TX direction attributes. Type NLA_NESTED.
 *
 * @XSHM_A_CHANNEL_SIZE: Size of the data area for a channel. Specified
 *	for RX, TX. Type NLA_U32,
 * @XSHM_A_CHANNEL_BUFFERS: Numer of buffers for a packet channel.
 *	This attribute is only used for packet channels.  Specified for RX, TX.
 *	Type NLA_U32,
 * @XSHM_A_ALIGNMENT: Alignment for each packet in a buffer. This attribute
 *	 is only used for packet channels.  Specified for RX, TX.Type NLA_U8,
 * @XSHM_A_MTU: Maximum Transfer Unit for packets in a buffer.
 *	This is only appplicable for packet channels.
 *	Specified for RX, TX.Type NLA_U16,
 * @XSHM_A_PACKETS: Maximum number of packets in a buffer. Type NLA_U8
 * @XSHM_A_PRIORITY: Priority of the channel, legal range is 0-7 where
 *	0 is lowest priority. Type NLA_U8.
 * @XSHM_A_LATENCY: Latency for channel, value:0 means low latency
 *	 and low bandwidth,
 *	 value 1 means high latency and high bandwidth. Type NLA_U8.
 */
enum XSHM_ATTRIBUTES {
	__XSHM_A_FLAGS = 1,		/* Test flags: NLA_U32 */
	XSHM_A_VERSION,
	XSHM_A_SUB_VERSION,
	XSHM_A_NAME,
	XSHM_A_EXCL_GROUP,
	XSHM_A_RX_CHANNEL,
	XSHM_A_TX_CHANNEL,
	XSHM_A_CHANNEL_SIZE,
	XSHM_A_CHANNEL_BUFFERS,
	XSHM_A_ALIGNMENT,
	XSHM_A_MTU,
	XSHM_A_PACKETS,
	XSHM_A_PRIORITY,
	XSHM_A_LATENCY,
	__XSHM_A_MAX,
};
#define XSHM_A_MAX (__XSHM_A_MAX - 1)

#endif /* XSHM_NL_H_ */
