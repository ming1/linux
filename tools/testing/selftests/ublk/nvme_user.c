// SPDX-License-Identifier: GPL-2.0

#include "kublk.h"
#include <linux/nvme_ioctl.h>
#include <sys/stat.h>
#include <endian.h>
#include <string.h>

/*
 * If the uapi headers installed on the system lacks nvme uring command
 * support, use the local version to prevent compilation issues.
 */
#ifndef NVME_URING_CMD_IO
struct nvme_uring_cmd {
	__u8	opcode;
	__u8	flags;
	__u16	rsvd1;
	__u32	nsid;
	__u32	cdw2;
	__u32	cdw3;
	__u64	metadata;
	__u64	addr;
	__u32	metadata_len;
	__u32	data_len;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
	__u32	timeout_ms;
	__u32	rsvd2;
};

#define NVME_URING_CMD_IO	_IOWR('N', 0x80, struct nvme_uring_cmd)
#define NVME_URING_CMD_IO_VEC	_IOWR('N', 0x81, struct nvme_uring_cmd)
#endif

enum nvme_io_opcode {
	nvme_cmd_flush		= 0x00,
	nvme_cmd_write		= 0x01,
	nvme_cmd_read		= 0x02,
	nvme_cmd_write_zeroes	= 0x08,
	nvme_cmd_dsm		= 0x09,
};

enum {
	NVME_RW_FUA		= 1 << 14,
	NVME_WZ_DEAC		= 1 << 9,
};

enum {
	NVME_DSMGMT_IDR		= 1 << 0,
	NVME_DSMGMT_IDW		= 1 << 1,
	NVME_DSMGMT_AD		= 1 << 2,
};

enum {
	NVME_CTRL_ONCS_DSM	= 1 << 2,
};

struct nvme_dsm_range {
	__le32			cattr;
	__le32			nlb;
	__le64			slba;
};

struct nvme_lbaf {
	__le16		ms;
	__u8		ds;
	__u8		rp;
};

struct nvme_id_ns {
	__le64		nsze;
	__le64		ncap;
	__le64		nuse;
	__u8		nsfeat;
	__u8		nlbaf;
	__u8		flbas;
	__u8		mc;
	__u8		dpc;
	__u8		dps;
	__u8		nmic;
	__u8		rescap;
	__u8		fpi;
	__u8		dlfeat;
	__le16		nawun;
	__le16		nawupf;
	__le16		nacwu;
	__le16		nabsn;
	__le16		nabo;
	__le16		nabspf;
	__le16		noiob;
	__u8		nvmcap[16];
	__le16		npwg;
	__le16		npwa;
	__le16		npdg;
	__le16		npda;
	__le16		nows;
	__le16		mssrl;
	__le32		mcl;
	__u8		msrc;
	__u8		rsvd81[11];
	__le32		anagrpid;
	__u8		rsvd96[3];
	__u8		nsattr;
	__le16		nvmsetid;
	__le16		endgid;
	__u8		nguid[16];
	__u8		eui64[8];
	struct nvme_lbaf	lbaf[16];
	__u8		rsvd192[192];
	__u8		vs[3712];
};

struct nvme_id_ctrl {
	__le16		vid;
	__le16		ssvid;
	__u8		sn[20];
	__u8		mn[40];
	__u8		fr[8];
	__u8		rab;
	__u8		ieee[3];
	__u8		cmic;
	__u8		mdts;
	__le16		cntlid;
	__le32		ver;
	__le32		rtd3r;
	__le32		rtd3e;
	__le32		oaes;
	__le32		ctratt;
	__u8		rsvd100[11];
	__u8		cntrltype;
	__u8		fguid[16];
	__le16		crdt1;
	__le16		crdt2;
	__le16		crdt3;
	__u8		rsvd134[122];
	__le16		oacs;
	__u8		acl;
	__u8		aerl;
	__u8		frmw;
	__u8		lpa;
	__u8		elpe;
	__u8		npss;
	__u8		avscc;
	__u8		apsta;
	__le16		wctemp;
	__le16		cctemp;
	__le16		mtfa;
	__le32		hmpre;
	__le32		hmmin;
	__u8		tnvmcap[16];
	__u8		unvmcap[16];
	__le32		rpmbs;
	__le16		edstt;
	__u8		dsto;
	__u8		fwug;
	__le16		kas;
	__le16		hctma;
	__le16		mntmt;
	__le16		mxtmt;
	__le32		sanicap;
	__le32		hmminds;
	__le16		hmmaxd;
	__le16		nvmsetidmax;
	__le16		endgidmax;
	__u8		anatt;
	__u8		anacap;
	__le32		anagrpmax;
	__le32		nanagrpid;
	__u8		rsvd352[160];
	__u8		sqes;
	__u8		cqes;
	__le16		maxcmd;
	__le32		nn;
	__le16		oncs;
	__le16		fuses;
	__u8		fna;
	__u8		vwc;
	__le16		awun;
	__le16		awupf;
	__u8		nvscc;
	__u8		nwpc;
	__le16		acwu;
	__u8		rsvd534[2];
	__le32		sgls;
	__le32		mnan;
	__u8		rsvd544[224];
	__u8		subnqn[256];
	__u8		rsvd1024[768];
	__le32		ioccsz;
	__le32		iorcsz;
	__le16		icdoff;
	__u8		ctrattr;
	__u8		msdbd;
	__u8		rsvd1804[2];
	__u8		dctype;
	__u8		rsvd1807[241];
	__u8		psd[1024];
	__u8		vs[1024];
};

enum {
	NVME_CTRL_VWC_PRESENT		= 1 << 0,
	NVME_NS_VWC_NOT_PRESENT		= 1 << 5,
	NVME_CTRL_SGLS_BYTE_ALIGNED	= 1 << 0,
	NVME_CTRL_SGLS_DWORD_ALIGNED	= 1 << 20,
};

#define NVME_CTRL_PAGE_SIZE		4096
#define NVME_MAX_SEGS			256

struct nvme_user_tgt_data {
	__u32 nsid;
	__u32 lba_shift;
};

struct nvme_seg_limits {
	__u32 max_segment_size;
	__u16 max_segments;
	__u64 virt_boundary_mask;
};

struct nvme_discard_limits {
	__u64 discard_max_bytes;
};

struct nvme_id_ctrl_nvm {
	__u8	vsl;
	__u8	wzsl;
	__u8	wusl;
	__u8	dmrl;
	__le32	dmrsl;
	__le64	dmsl;
	__u8	rsvd16[4080];
};

/*
 * Convert NVMe char device path to block device name
 * /dev/ng0n1 -> nvme0n1
 */
static int nvme_char_to_block_name(const char *char_dev, char *block_name, size_t len)
{
	const char *name = strrchr(char_dev, '/');

	if (!name)
		name = char_dev;
	else
		name++;

	/* Check if it starts with "ng" and convert to "nvme" */
	if (strncmp(name, "ng", 2) != 0)
		return -EINVAL;

	snprintf(block_name, len, "nvme%s", name + 2);
	return 0;
}

/*
 * Read queue limits from sysfs of the corresponding NVMe block device.
 * These limits depend on platform-specific factors (DMA limits, CAP register,
 * driver limits) that cannot be determined from NVMe ioctl alone.
 */
static int nvme_read_queue_limits_sysfs(const char *char_dev,
					__u32 *max_sectors_kb,
					struct nvme_seg_limits *seg)
{
	char block_name[64];
	char path[256];
	FILE *fp;
	int ret;

	ret = nvme_char_to_block_name(char_dev, block_name, sizeof(block_name));
	if (ret)
		return ret;

	/* Read max_sectors_kb */
	snprintf(path, sizeof(path), "/sys/block/%s/queue/max_sectors_kb", block_name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	ret = fscanf(fp, "%u", max_sectors_kb);
	fclose(fp);
	if (ret != 1)
		return -EIO;

	/* Read max_segments */
	snprintf(path, sizeof(path), "/sys/block/%s/queue/max_segments", block_name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	ret = fscanf(fp, "%hu", &seg->max_segments);
	fclose(fp);
	if (ret != 1)
		return -EIO;

	/* Read max_segment_size */
	snprintf(path, sizeof(path), "/sys/block/%s/queue/max_segment_size", block_name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	ret = fscanf(fp, "%u", &seg->max_segment_size);
	fclose(fp);
	if (ret != 1)
		return -EIO;

	/* Read virt_boundary_mask */
	snprintf(path, sizeof(path), "/sys/block/%s/queue/virt_boundary_mask", block_name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;
	ret = fscanf(fp, "%llu", &seg->virt_boundary_mask);
	fclose(fp);
	if (ret != 1)
		return -EIO;

	return 0;
}

static int nvme_get_info(const char *file, __u32 *nsid, __u32 *lba_shift,
			 __u64 *dev_size, __u32 *max_sectors_kb, bool *has_vwc,
			 struct nvme_seg_limits *seg, __u32 *chunk_sectors,
			 struct nvme_discard_limits *discard)
{
	struct nvme_passthru_cmd cmd = {};
	struct nvme_id_ns ns;
	struct nvme_id_ctrl ctrl;
	struct nvme_id_ctrl_nvm ctrl_nvm;
	int fd, ret;
	__u32 lba_size;
	__u16 oncs;
	__u32 dmrsl;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -errno;

	*nsid = ioctl(fd, NVME_IOCTL_ID);
	if ((int)*nsid < 0) {
		close(fd);
		return -errno;
	}

	/* Query controller identify to check VWC support */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = 0x06; // nvme_admin_identify
	cmd.nsid = 0;
	cmd.cdw10 = 1; // CNS=1 for controller identify
	cmd.addr = (__u64)(uintptr_t)&ctrl;
	cmd.data_len = sizeof(ctrl);
	cmd.timeout_ms = 0;

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (ret) {
		close(fd);
		return ret;
	}

	/* Query namespace identify */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = 0x06; // nvme_admin_identify
	cmd.nsid = *nsid;
	cmd.cdw10 = 0; // CNS=0 for namespace identify
	cmd.addr = (__u64)(uintptr_t)&ns;
	cmd.data_len = sizeof(ns);
	cmd.timeout_ms = 0;

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (ret) {
		close(fd);
		return ret;
	}

	lba_size = 1 << ns.lbaf[(ns.flbas & 0x0f)].ds;
	*lba_shift = ilog2(lba_size);
	*dev_size = le64toh(ns.nsze) * lba_size;

	/* Check VWC: controller supports it AND namespace doesn't disable it */
	*has_vwc = (ctrl.vwc & NVME_CTRL_VWC_PRESENT) &&
		   !(ns.nsattr & NVME_NS_VWC_NOT_PRESENT);

	/* Get ONCS for discard support check */
	oncs = le16toh(ctrl.oncs);

	/*
	 * Read queue limits from sysfs since they depend on platform-specific
	 * factors (DMA limits, CAP.MPSMIN, driver limits) not available via ioctl
	 */
	ret = nvme_read_queue_limits_sysfs(file, max_sectors_kb, seg);
	if (ret) {
		close(fd);
		return ret;
	}

	/* Get chunk_sectors from namespace optimal I/O boundary (noiob) */
	*chunk_sectors = 0;
	if (ns.noiob) {
		__u32 iob = le16toh(ns.noiob) << (*lba_shift - 9);
		/* Only set if it's a power of 2 */
		if (iob && (iob & (iob - 1)) == 0)
			*chunk_sectors = iob;
	}

	/*
	 * Read NVM Command Set Specific Controller Identify (CNS=06h)
	 * to get DMRSL and DMRL for discard limits
	 */
	memset(&cmd, 0, sizeof(cmd));
	memset(&ctrl_nvm, 0, sizeof(ctrl_nvm));
	cmd.opcode = 0x06; // nvme_admin_identify
	cmd.nsid = 0;
	cmd.cdw10 = 0x06; // NVME_ID_CNS_CS_CTRL
	cmd.cdw11 = 0x00; // NVME_CSI_NVM
	cmd.addr = (__u64)(uintptr_t)&ctrl_nvm;
	cmd.data_len = sizeof(ctrl_nvm);

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	if (ret == 0) {
		dmrsl = le32toh(ctrl_nvm.dmrsl);
		/* dmrl (max discard ranges) is available but not used yet */
	} else {
		/* Older devices may not support CNS=06h */
		dmrsl = 0;
	}

	/*
	 * Calculate max_discard_bytes following kernel logic:
	 * - If DMRSL is set and valid, use it
	 * - Else if DSM (discard) is supported via ONCS, use UINT_MAX
	 * - Else discard is not supported (0)
	 */
	if (dmrsl) {
		/* Convert DMRSL (in LBAs) to bytes, capped at UINT_MAX sectors */
		__u64 dmrsl_sectors = ((__u64)dmrsl) << (*lba_shift - 9);
		if (dmrsl_sectors > UINT_MAX)
			dmrsl_sectors = UINT_MAX;
		discard->discard_max_bytes = dmrsl_sectors << 9;
	} else if (oncs & NVME_CTRL_ONCS_DSM) {
		/* DSM supported, no DMRSL limit */
		discard->discard_max_bytes = (__u64)UINT_MAX << 9;
	} else {
		/* Discard not supported */
		discard->discard_max_bytes = 0;
	}

	close(fd);

	return 0;
}

static int nvme_user_queue_flush_io(struct ublk_thread *t, struct ublk_queue *q,
				    const struct ublksrv_io_desc *iod, int tag)
{
	struct ublk_dev *dev = q->dev;
	struct nvme_user_tgt_data *data = dev->private_data;
	unsigned ublk_op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe[1];
	struct nvme_uring_cmd *cmd;

	ublk_io_alloc_sqes(t, sqe, 1);
	if (!sqe[0])
		return -ENOMEM;

	sqe[0]->opcode = IORING_OP_URING_CMD;
	sqe[0]->fd = ublk_get_registered_fd(q, 1);
	sqe[0]->cmd_op = NVME_URING_CMD_IO;
	sqe[0]->flags = IOSQE_FIXED_FILE;

	cmd = (struct nvme_uring_cmd *)&sqe[0]->cmd;
	memset(cmd, 0, sizeof(*cmd));
	cmd->nsid = data->nsid;
	cmd->opcode = nvme_cmd_flush;

	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, q->q_id, 1);

	return 1;
}

static int nvme_user_queue_write_zeroes_io(struct ublk_thread *t, struct ublk_queue *q,
					   const struct ublksrv_io_desc *iod, int tag)
{
	struct ublk_dev *dev = q->dev;
	struct nvme_user_tgt_data *data = dev->private_data;
	unsigned ublk_op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe[1];
	struct nvme_uring_cmd *cmd;
	__u64 slba;
	__u32 nlb;

	/* Convert ublk 512-byte sectors to NVMe LBAs */
	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = (iod->nr_sectors >> (data->lba_shift - 9)) - 1;

	ublk_io_alloc_sqes(t, sqe, 1);
	if (!sqe[0])
		return -ENOMEM;

	sqe[0]->opcode = IORING_OP_URING_CMD;
	sqe[0]->fd = ublk_get_registered_fd(q, 1);
	sqe[0]->cmd_op = NVME_URING_CMD_IO;
	sqe[0]->flags = IOSQE_FIXED_FILE;

	cmd = (struct nvme_uring_cmd *)&sqe[0]->cmd;
	memset(cmd, 0, sizeof(*cmd));
	cmd->nsid = data->nsid;
	cmd->opcode = nvme_cmd_write_zeroes;
	cmd->cdw10 = htole32(slba & 0xffffffff);
	cmd->cdw11 = htole32(slba >> 32);
	cmd->cdw12 = htole32(nlb & 0xffff);

	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, q->q_id, 1);

	return 1;
}

static int nvme_user_queue_discard_io(struct ublk_thread *t, struct ublk_queue *q,
				      const struct ublksrv_io_desc *iod, int tag)
{
	struct ublk_dev *dev = q->dev;
	struct nvme_user_tgt_data *data = dev->private_data;
	unsigned ublk_op = ublksrv_get_op(iod);
	struct io_uring_sqe *sqe[1];
	struct nvme_uring_cmd *cmd;
	struct nvme_dsm_range *range;
	struct ublk_io *io = ublk_get_io(q, tag);
	__u64 slba;
	__u32 nlb;

	/* Convert ublk 512-byte sectors to NVMe LBAs */
	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = iod->nr_sectors >> (data->lba_shift - 9);

	ublk_io_alloc_sqes(t, sqe, 1);
	if (!sqe[0])
		return -ENOMEM;

	/* Allocate DSM range (single segment) and store in io->private_data */
	range = (struct nvme_dsm_range *)malloc(sizeof(*range));
	if (!range)
		return -ENOMEM;

	range->cattr = 0;
	range->nlb = htole32(nlb);
	range->slba = htole64(slba);

	/* Store range pointer to free it in completion handler */
	io->private_data = range;

	sqe[0]->opcode = IORING_OP_URING_CMD;
	sqe[0]->fd = ublk_get_registered_fd(q, 1);
	sqe[0]->cmd_op = NVME_URING_CMD_IO;
	sqe[0]->flags = IOSQE_FIXED_FILE;

	cmd = (struct nvme_uring_cmd *)&sqe[0]->cmd;
	memset(cmd, 0, sizeof(*cmd));
	cmd->nsid = data->nsid;
	cmd->opcode = nvme_cmd_dsm;
	cmd->addr = (__u64)(uintptr_t)range;
	cmd->data_len = sizeof(*range);
	cmd->cdw10 = 0;  /* nr = 0 (1 range) */
	cmd->cdw11 = htole32(NVME_DSMGMT_AD);  /* attributes = deallocate */

	sqe[0]->user_data = build_user_data(tag, ublk_op, 0, q->q_id, 1);

	return 1;
}

static int nvme_user_queue_rw_io(struct ublk_thread *t, struct ublk_queue *q,
				 const struct ublksrv_io_desc *iod, int tag)
{
	struct ublk_dev *dev = q->dev;
	struct nvme_user_tgt_data *data = dev->private_data;
	unsigned ublk_op = ublksrv_get_op(iod);
	unsigned ublk_flags = ublksrv_get_flags(iod);
	unsigned zc = ublk_queue_use_zc(q);
	unsigned auto_zc = ublk_queue_use_auto_zc(q);
	struct io_uring_sqe *sqe[3];
	struct nvme_uring_cmd *cmd;
	__u64 slba;
	__u32 nlb;
	unsigned short buf_idx;

	/* Convert ublk 512-byte sectors to NVMe LBAs */
	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = (iod->nr_sectors >> (data->lba_shift - 9)) - 1;

	if (!zc || auto_zc) {
		/* Mode 1 (regular) or Mode 2 (auto_zc) */
		ublk_io_alloc_sqes(t, sqe, 1);
		if (!sqe[0])
			return -ENOMEM;

		sqe[0]->opcode = IORING_OP_URING_CMD;
		sqe[0]->fd = ublk_get_registered_fd(q, 1);
		sqe[0]->cmd_op = NVME_URING_CMD_IO;
		sqe[0]->flags = IOSQE_FIXED_FILE;

		if (auto_zc) {
			sqe[0]->uring_cmd_flags = IORING_URING_CMD_FIXED;
			sqe[0]->buf_index = ublk_io_buf_idx(t, q, tag);
		}

		cmd = (struct nvme_uring_cmd *)&sqe[0]->cmd;
		memset(cmd, 0, sizeof(*cmd));
		cmd->nsid = data->nsid;
		cmd->opcode = (ublk_op == UBLK_IO_OP_WRITE) ?
			      nvme_cmd_write : nvme_cmd_read;
		cmd->addr = auto_zc ? 0 : iod->addr;
		cmd->data_len = iod->nr_sectors << 9;
		cmd->cdw10 = slba & 0xffffffff;
		cmd->cdw11 = slba >> 32;
		cmd->cdw12 = nlb;
		/* Set FUA flag for writes if requested */
		if ((ublk_op == UBLK_IO_OP_WRITE) && (ublk_flags & UBLK_IO_F_FUA))
			cmd->cdw12 |= NVME_RW_FUA;

		sqe[0]->user_data = build_user_data(tag, ublk_op, 0, q->q_id, 1);
		return 1;
	}

	/* Mode 3: Manual zero-copy (3-SQE chain) */
	buf_idx = ublk_io_buf_idx(t, q, tag);
	ublk_io_alloc_sqes(t, sqe, 3);

	/* SQE 0: Register buffer */
	io_uring_prep_buf_register(sqe[0], q, tag, q->q_id, buf_idx);
	sqe[0]->flags |= IOSQE_CQE_SKIP_SUCCESS | IOSQE_IO_HARDLINK;
	sqe[0]->user_data = build_user_data(tag,
		ublk_cmd_op_nr(sqe[0]->cmd_op), 0, q->q_id, 1);

	/* SQE 1: NVMe I/O with fixed buffer */
	sqe[1]->opcode = IORING_OP_URING_CMD;
	sqe[1]->fd = ublk_get_registered_fd(q, 1);
	sqe[1]->cmd_op = NVME_URING_CMD_IO;
	sqe[1]->flags = IOSQE_FIXED_FILE | IOSQE_IO_HARDLINK;
	sqe[1]->uring_cmd_flags = IORING_URING_CMD_FIXED;
	sqe[1]->buf_index = buf_idx;

	cmd = (struct nvme_uring_cmd *)&sqe[1]->cmd;
	memset(cmd, 0, sizeof(*cmd));
	cmd->nsid = data->nsid;
	cmd->opcode = (ublk_op == UBLK_IO_OP_WRITE) ?
		      nvme_cmd_write : nvme_cmd_read;
	cmd->addr = 0;
	cmd->data_len = iod->nr_sectors << 9;
	cmd->cdw10 = slba & 0xffffffff;
	cmd->cdw11 = slba >> 32;
	cmd->cdw12 = nlb;
	/* Set FUA flag for writes if requested */
	if ((ublk_op == UBLK_IO_OP_WRITE) && (ublk_flags & UBLK_IO_F_FUA))
		cmd->cdw12 |= NVME_RW_FUA;

	sqe[1]->user_data = build_user_data(tag, ublk_op, 0, q->q_id, 1);

	/* SQE 2: Unregister buffer */
	io_uring_prep_buf_unregister(sqe[2], q, tag, q->q_id, buf_idx);
	sqe[2]->user_data = build_user_data(tag,
		ublk_cmd_op_nr(sqe[2]->cmd_op), 0, q->q_id, 1);

	return 2; /* Register is skipped, only I/O + unregister complete */
}

static int nvme_user_queue_tgt_io(struct ublk_thread *t, struct ublk_queue *q, int tag)
{
	const struct ublksrv_io_desc *iod = ublk_get_iod(q, tag);
	unsigned ublk_op = ublksrv_get_op(iod);
	int ret;

	switch (ublk_op) {
	case UBLK_IO_OP_FLUSH:
		ret = nvme_user_queue_flush_io(t, q, iod, tag);
		break;
	case UBLK_IO_OP_WRITE_ZEROES:
		ret = nvme_user_queue_write_zeroes_io(t, q, iod, tag);
		break;
	case UBLK_IO_OP_DISCARD:
		ret = nvme_user_queue_discard_io(t, q, iod, tag);
		break;
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = nvme_user_queue_rw_io(t, q, iod, tag);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	ublk_dbg(UBLK_DBG_IO, "%s: tag %d ublk io %x %llx %u\n", __func__, tag,
		 iod->op_flags, iod->start_sector, iod->nr_sectors << 9);
	return ret;
}

static int nvme_user_queue_io(struct ublk_thread *t, struct ublk_queue *q, int tag)
{
	int queued = nvme_user_queue_tgt_io(t, q, tag);

	ublk_queued_tgt_io(t, q, tag, queued);
	return 0;
}

static void nvme_user_io_done(struct ublk_thread *t, struct ublk_queue *q,
			      const struct io_uring_cqe *cqe)
{
	unsigned tag = user_data_to_tag(cqe->user_data);
	unsigned op = user_data_to_op(cqe->user_data);
	struct ublk_io *io = ublk_get_io(q, tag);
	const struct ublksrv_io_desc *iod = ublk_get_iod(q, tag);

	/* For NVMe uring_cmd: res=0 means success, but ublk needs bytes transferred */
	if (cqe->res < 0 || op != ublk_cmd_op_nr(UBLK_U_IO_UNREGISTER_IO_BUF)) {
		if (!io->result) {
			if (cqe->res == 0) {
				/* NVMe success - convert to bytes for READ/WRITE, keep 0 for others */
				if (op == UBLK_IO_OP_READ || op == UBLK_IO_OP_WRITE)
					io->result = iod->nr_sectors << 9;
				else
					io->result = 0;  /* FLUSH/WRITE_ZEROES/DISCARD return 0 on success */
			} else {
				/* Error code */
				io->result = cqe->res;
			}
		}
		if (cqe->res < 0)
			ublk_err("%s: io failed op %x user_data %lx res %d\n",
				 __func__, op, cqe->user_data, cqe->res);
	}

	/* Free DSM range buffer if this was a discard operation */
	if (op == UBLK_IO_OP_DISCARD && io->private_data) {
		free(io->private_data);
		io->private_data = NULL;
	}

	/* buffer register op is IOSQE_CQE_SKIP_SUCCESS */
	if (op == ublk_cmd_op_nr(UBLK_U_IO_REGISTER_IO_BUF))
		io->tgt_ios += 1;

	if (ublk_completed_tgt_io(t, q, tag))
		ublk_complete_io(t, q, tag, io->result);
}

static int nvme_user_tgt_init(const struct dev_ctx *ctx, struct ublk_dev *dev)
{
	struct nvme_user_tgt_data *data;
	struct stat st;
	int ret, fd;
	__u32 nsid, lba_shift, max_sectors_kb, chunk_sectors;
	__u64 dev_size;
	__u32 max_sectors;
	bool has_vwc;
	struct nvme_seg_limits seg;
	struct nvme_discard_limits discard;
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC | UBLK_PARAM_TYPE_DMA_ALIGN |
			 UBLK_PARAM_TYPE_SEGMENT | UBLK_PARAM_TYPE_DISCARD,
		.basic = {
			.attrs = 0,
			.io_opt_shift	= 12,
			.io_min_shift	= 9,
		},
	};

	if (ctx->auto_zc_fallback) {
		ublk_err("%s: not support auto_zc_fallback\n", __func__);
		return -EINVAL;
	}

	if (dev->tgt.nr_backing_files != 1) {
		ublk_err("%s: only supports one backing file\n", __func__);
		return -EINVAL;
	}

	/* Validate backing file is a character device */
	if (stat(dev->tgt.backing_file[0], &st) < 0) {
		ublk_err("%s: failed to stat %s\n", __func__,
			 dev->tgt.backing_file[0]);
		return -errno;
	}

	if (!S_ISCHR(st.st_mode)) {
		ublk_err("%s: %s is not a character device\n", __func__,
			 dev->tgt.backing_file[0]);
		return -EINVAL;
	}

	/* Query NVMe namespace information */
	ret = nvme_get_info(dev->tgt.backing_file[0], &nsid, &lba_shift, &dev_size,
			    &max_sectors_kb, &has_vwc, &seg, &chunk_sectors, &discard);
	if (ret) {
		ublk_err("%s: failed to get nvme info %d\n", __func__, ret);
		return ret;
	}

	/* Use the minimum of NVMe device limit and ublk buffer size */
	max_sectors = min(max_sectors_kb * 2, dev->dev_info.max_io_buf_bytes >> 9);
	p.basic.max_sectors = max_sectors;

	p.basic.logical_bs_shift = lba_shift;
	p.basic.physical_bs_shift = lba_shift;
	p.basic.dev_sectors = dev_size >> 9;
	p.basic.chunk_sectors = chunk_sectors;
	p.basic.virt_boundary_mask = seg.virt_boundary_mask;
	p.dma.alignment = (1 << lba_shift) - 1;

	/* Set segment limits based on NVMe device */
	p.seg.max_segment_size = seg.max_segment_size;
	p.seg.max_segments = seg.max_segments;
	/* seg_boundary_mask + 1 must be power of 2 and >= 4096 */
	p.seg.seg_boundary_mask = 4095;

	/*
	 * Set discard and write zeroes limits.
	 * discard_max_bytes comes from NVMe controller's DMRSL or ONCS.DSM.
	 * Discard doesn't transfer data through buffers, so not limited by max_io_buf_bytes.
	 */
	p.discard.discard_alignment = 0;
	p.discard.discard_granularity = 1 << lba_shift;
	p.discard.max_discard_sectors = discard.discard_max_bytes >> 9;
	p.discard.max_write_zeroes_sectors = max_sectors;
	p.discard.max_discard_segments = 1;  /* Single segment support */

	/* Set volatile write cache and FUA attributes based on NVMe device */
	if (has_vwc) {
		p.basic.attrs |= UBLK_ATTR_VOLATILE_CACHE;
		/* FUA is supported when device has volatile write cache */
		p.basic.attrs |= UBLK_ATTR_FUA;
	}

	dev->tgt.dev_size = dev_size;
	dev->tgt.params = p;

	data = malloc(sizeof(*data));
	if (!data)
		return -ENOMEM;
	data->nsid = nsid;
	data->lba_shift = lba_shift;
	dev->private_data = data;

	/* Open the NVMe char device */
	fd = open(dev->tgt.backing_file[0], O_RDWR);
	if (fd < 0) {
		free(data);
		ublk_err("%s: failed to open %s\n", __func__,
			 dev->tgt.backing_file[0]);
		return -errno;
	}
	dev->fds[1] = fd;
	dev->nr_fds++;

	return 0;
}

static void nvme_user_tgt_deinit(struct ublk_dev *dev)
{
	if (dev->private_data)
		free(dev->private_data);
	if (dev->nr_fds > 1) {
		fsync(dev->fds[1]);
		close(dev->fds[1]);
	}
}

const struct ublk_tgt_ops nvme_user_tgt_ops = {
	.name = "nvme_user",
	.init_tgt = nvme_user_tgt_init,
	.deinit_tgt = nvme_user_tgt_deinit,
	.queue_io = nvme_user_queue_io,
	.tgt_io_done = nvme_user_io_done,
};
