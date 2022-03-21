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
 * FETCH_REQ: issued via sqe(URING_CMD) beforehand for fetching IO request
 *      from ubd driver, should be issued only when starting device. After
 *      the associated cqe is returned, request's tag can be retrieved via
 *      cqe->userdata.
 *
 * COMMIT_AND_FETCH_REQ: issued via sqe(URING_CMD) after ubdserver handled
 *      this IO request, request's handling result is committed to ubd
 *      driver, meantime FETCH_REQ is piggyback, and FETCH_REQ has to be
 *      handled before completing io request.
 *
 * COMMIT_REQ: issued via sqe(URING_CMD) after ubdserver handled this IO
 *      request, request's handling result is committed to ubd driver.
 */
#define	UBD_IO_FETCH_REQ		0x20
#define	UBD_IO_COMMIT_AND_FETCH_REQ	0x21
#define	UBD_IO_COMMIT_REQ		0x22

/*
 * When got RESULT_FETCH, after this io command is completed by ubdsrv,
 * its result will be committed via UBD_IO_COMMIT_AND_FETCH_REQ.
 *
 * When got RESULT_NO_FETCH, after this io command is completed by
 * ubdsrv, its result will be committed via UBD_IO_COMMIT_REQ.
 * Typically, after ubd driver gets STOP DEV ctrl command, it will
 * complete io command with this status via cqe->res.
 */
#define UBD_IO_RESULT_NO_FETCH	0x0
#define UBD_IO_RESULT_FETCH	0x1

#define UBD_IO_RES_INVALID_SQE		0xff
#define UBD_IO_RES_INVALID_TAG		0xfe
#define UBD_IO_RES_INVALID_QUEUE	0xfd
#define UBD_IO_RES_BUSY			0xfc
#define UBD_IO_RES_DUP_FETCH		0xfb
#define UBD_IO_RES_UNEXPECTED_CMD	0xfa
#define UBD_IO_RES_ABORT		0xf9

#define UBDSRV_CMD_BUF_OFFSET	0

/* tag bit is 12bit, so at most 4096 IOs for each queue */
#define UBD_MAX_QUEUE_DEPTH	4096

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
	__s32	ubdsrv_pid;
	__u64	reserved0[2];
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

	/* buffer address in ubdsrv daemon vm space, from ubd driver */
	__u64		addr;
};

/* issued to ubd driver via /dev/ubdcN */
struct ubdsrv_io_cmd {
	/*
	 * how to support MQ ?
	 *
	 * Each hw queue is served by dedicated daemon? Or pthread
	 * of this daemon?
	 *
	 * Served as reserved field.
	 */
	__u16	q_id;

	/* for fetch/commit which result */
	__u16	tag;

	/* io result, it is valid for COMMIT* command only */
	__u32	result;

	/*
	 * userspace buffer address in ubdsrv daemon process, valid for
	 * FETCH* command only
	 */
	__u64	addr;
};

#endif
