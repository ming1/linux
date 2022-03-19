#ifndef FIO_UBDSRV_INC_H
#define FIO_UBDSRV_INC_H

/* ubd server command definition */

/* CMD result code */
#define UBD_CTRL_CMD_RES_OK		0
#define UBD_CTRL_CMD_RES_FAILED		-1

/*
 * Admin commands, issued by ubd server, and handled by ubd driver.
 */
#define	UBD_CMD_SET_DEV_INFO	0x01
#define	UBD_CMD_GET_DEV_INFO	0x02
#define	UBD_CMD_ADD_DEV		0x04
#define	UBD_CMD_DEL_DEV		0x05
#define	UBD_CMD_START_DEV	0x06
#define	UBD_CMD_STOP_DEV	0x07

/*
 * IO commands, issued by ubd server, and handled by ubd driver.
 *
 * FETCH_REQ: issued via sqe(URING_CMD_FIXED) beforehand for fetching IO
 * 	request from ubd driver. Once returnd, cqe->res stores the rq->tag,
 * 	-1 means the command fails. For WRITE IO, kernel request's data is
 * 	written to fixed buffer; For READ IO, the fixed buffer will be used
 * 	to fill data by ubd server's read handling.
 *
 * COMMIT_REQ: issued via sqe(URING_CMD_FIXED) after ubdserver handed the
 * 	requested IO. For READ IO, fixed buffer has been filled with request
 * 	IO data. After this request is commited to dirver, the command
 * 	also implied FETCH_REQ. So it won't be returned until new req with
 * 	same tag comes.
 */
#define	UBD_IO_FETCH_REQ	0x20
#define	UBD_IO_COMMIT_REQ	0x21

#define UBD_DEV_STATE_STARTED		0x01
#define UBD_DEV_STATE_QUEUE_SETUP	0x02

#define UBDSRV_CMD_BUF_OFFSET  0

struct ubdsrv_ctrl_dev_info {
	__u16	nr_hw_queues;
	__u16	queue_depth;
	__u16	block_size;
	__u16	state;

	__u32	rq_max_blocks;
	__u32	dev_id;

	__u64   dev_blocks;
	__u64	flags;

	/*
	 * Only valid for READ kind of ctrl command, and driver can
	 * get the userspace buffer adddress here, then write data
	 * into this buffer.
	 *
	 * And the buffer has to be inside one single page.
	 */
	__u64	addr;
	__u32	len;
	__u32	reserved0;
	__u64	reserved1[2];
};

struct ubdsrv_io_desc {
	/* op: bit 0-7, flags: bit 8-31 */
	__u32		op_flags;

	/*
	 * tag: bit 0 - 11, max: 4096
	 *
	 * blocks: bit 12 ~ 31, max: 1M blocks
	 */
	__u32		tag_blocks;

	/* start block for this io */
	__u64		start_block;

	/* buffer address in ubdsrv daemon vm space */
	__u64		addr;
};

/* issued to ubd driver for fetching io request from /dev/ubdbN */
struct ubdsrv_io_cmd_fetch_req {
	/*
	 * how to support MQ ?
	 *
	 * Each hw queue is served by dedicated daemon? Or pthread
	 * of this daemon?
	 */
	__u16	q_id;

	/* for fetch request with this tag */
	__u16	tag;
	__u32	rsv0;
};

/*
 * issued to ubd driver for committing io result and fetching io request
 * again
 */
struct ubdsrv_io_cmd_commit_and_fetch_req {
	/* iod of the completed request */
	struct ubdsrv_io_desc iod;

	/* result of the completed request */
	__u32	result;
	__u32	rsv0;

	/*
	 * Piggyback with committing cmd, the same sqe covers both fetch
	 * and commit, since the tag can't be reused before completion.
	 *
	 * Tag needs to be matched with iod's tag field.
	 *
	 * Fetching request needs to be done before completing request for
	 * /dev/ubdbN, since the block request can be reused immediately.
	 */
	struct ubdsrv_io_cmd_fetch_req rq;
};

struct ubdsrv_io_cmd {
	union {
		struct ubdsrv_io_cmd_fetch_req			fetch;
		struct ubdsrv_io_cmd_commit_and_fetch_req	commit;
	};
};

#endif
