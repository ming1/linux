/*
 * Copyright (C) ST-Ericsson AB 2012
 * Author: Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

#ifndef SHM_NL_H_
#define SHM_NL_H_

#define SHM_PROTO_VERSION 1
#define SHM_PROTO_SUB_VERSION 0
#define SHM_NETLINK_VERSION 1
/**
 * enum SHM_COMMANDS - Attributes used for configuring SHM device.
 *
 * @SHM_C_ADD_STREAM_CHANNEL: Adds a Stream Channel.
 * This will cause an instance of SHM-CHR to be created.
 * @SHM_C_ADD_PACKET_CHANNEL: Adds a Packet Channel.
 * This will cause an instance of CAIF-SHM to be created.
 * @SHM_C_COMMIT: formats and write Channel configuration data to
 *	Shared Memory.
 * @SHM_C_SET_ADDR: Writes the TOC address to GENO register.
 * @SHM_C_REGISTER:  Initiates registration of the channel devices.
 *	This will cause shm - character devices or
 *	CAIF network instances to be created.
 * @SHM_C_RESET:  Reset the configuration data and removes the
 *	platform devices and their associated channel configuration.
 *	ipc_ready and caif_ready is set to false.
 *
 * A normal sequence of events is: [SHM_C_RESET], [SHM_C_ADD_X_CHANNEL],
 *	SHM_C_COMMIT, SHM_C_REGISTER, SHM_C_SET_ADDR.
 */
enum SHM_COMMANDS {
	SHM_C_ADD_STREAM_CHANNEL = 1,
	SHM_C_ADD_PACKET_CHANNEL,
	SHM_C_RESET,
	SHM_C_SET_ADDR,
	SHM_C_COMMIT,
	SHM_C_REGISTER,
	__SHM_C_VERIFY,
	__SHM_C_MAX
};

/**
 * enum SHM_ATTRIBUTES - Attributes used for configuring SHM device.
 * @SHM_A_VERSION: Version of SHM netlink protocol. Type NLA_U8
 * @SHM_A_SUB_VERSION: Sub-version of SHM netlink protocol. Type NLA_U8
 * @SHM_A_NAME: Name of the channel, max 15 characters. Type NLA_NUL_STRING
 * @SHM_A_EXCL_GROUP: Devices may be part of a group. Devices from the
 *	same group are allowed to be open simultaneously,
 *	but devices from different groups cannot be opened
 *	at the same time. Type NLA_U8.
 * @SHM_A_RX_CHANNEL: The RX direction attributes. Type NLA_NESTED.
 *	Each channel may contain the attributes - SHM_A_CHANNEL_SIZE,
 *	SHM_A_CHANNEL_BUFFERS, SHM_A_ALIGNMENT, SHM_A_MTU.
 *
 * @SHM_A_TX_CHANNEL: The TX direction attributes. Type NLA_NESTED.
 *
 * @SHM_A_CHANNEL_SIZE: Size of the data area for a channel. Specified
 *	for RX, TX. Type NLA_U32,
 * @SHM_A_CHANNEL_BUFFERS: Numer of buffers for a packet channel.
 *	This attribute is only used for packet channels.  Specified for RX, TX.
 *	Type NLA_U32,
 * @SHM_A_ALIGNMENT: Alignment for each packet in a buffer. This attribute
 *	 is only used for packet channels.  Specified for RX, TX.Type NLA_U8,
 * @SHM_A_MTU: Maximum Transfer Unit for packets in a buffer.
 *	This is only appplicable for packet channels.
 *	Specified for RX, TX.Type NLA_U16,
 * @SHM_A_PACKETS: Maximum number of packets in a buffer. Type NLA_U8
 * @SHM_A_PRIORITY: Priority of the channel, legal range is 0-7 where
 *	0 is lowest priority. Type NLA_U8.
 * @SHM_A_LATENCY: Latency for channel, value:0 means low latency
 *	 and low bandwidth,
 *	 value 1 means high latency and high bandwidth. Type NLA_U8.
 */
enum SHM_ATTRIBUTES {
	__SHM_A_FLAGS = 1,		/* Test flags: NLA_U32 */
	SHM_A_VERSION,
	SHM_A_SUB_VERSION,
	SHM_A_NAME,
	SHM_A_EXCL_GROUP,
	SHM_A_RX_CHANNEL,
	SHM_A_TX_CHANNEL,
	SHM_A_CHANNEL_SIZE,
	SHM_A_CHANNEL_BUFFERS,
	SHM_A_ALIGNMENT,
	SHM_A_MTU,
	SHM_A_PACKETS,
	SHM_A_PRIORITY,
	SHM_A_LATENCY,
	__SHM_A_MAX,
};
#define SHM_A_MAX (__SHM_A_MAX - 1)

#endif /* SHM_NL_H_ */
