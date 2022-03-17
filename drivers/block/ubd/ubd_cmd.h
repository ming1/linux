#ifndef FIO_UBDSRV_INC_H
#define FIO_UBDSRV_INC_H

/* ubd server command definition */

/* CMD result code */
#define UBD_CMD_RES_OK		0
#define UBD_CMD_RES_FAILED     -1

/*
 * Admin commands, issued by ubd server, and handled by ubd driver.
 */
#define	UBD_CMD_SET_DEV_INFO	0x01
#define	UBD_CMD_GET_DEV_INFO	0x02
#define	UBD_CMD_SETUP_QUEUE	0x03
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

struct ubdsrv_dev_info {
	__u16	nr_hw_queues;
	__u16	queue_depth;
	__u16	block_size;
	__u16	state;

	__u32	rq_max_blocks;
	__u32	dev_id;

	__u64   dev_blocks;
	__u64	flags;
	__u64	reserved[4];
};

/* for setup each queue */
struct ubdsrv_queue_info {
	__u32	dev_id;
	__u16	q_id;
	__u16	rsv0;

	__u32	queue_buf_sz;
	__u32	queue_buf_idx;	//has to point to fixed buffer
};

struct ubdsrv_io_description {
	__u16		cmd_op;
	__u16		rsv0;
	__u16		q_id;
	__u16		tag;
	__u32		flags;
	__u32		blocks;
	__u64		start_block;
};

struct ubdsrv_io_cmd_fetch_req {
	__u32	dev_id;
	__u16	q_id;
	__u16	tag;		//for fetching from request with this tag
	__u32	buf_idx;
	__u32	rsv0;
};

struct ubdsrv_io_cmd_commit_req {
	struct ubdsrv_io_description iod;

	/* which buffer holds the data READ from ubd server */
	__u32	buf_idx;
};

struct ubdsrv_io_cmd {
	union {
		struct ubdsrv_io_cmd_fetch_req	fetch_cmd;
		struct ubdsrv_io_cmd_commit_req	commit_cmd;
	};
};

#endif
