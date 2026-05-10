// SPDX-License-Identifier: GPL-2.0
#include "ublk.h"

#include <linux/xarray.h>

static DEFINE_XARRAY(ublk_zoned_report_descs);

static int ublk_zoned_insert_report_desc(const struct request *req,
		struct ublk_zoned_report_desc *desc)
{
	return xa_insert(&ublk_zoned_report_descs, (unsigned long)req,
			    desc, GFP_KERNEL);
}

static struct ublk_zoned_report_desc *ublk_zoned_erase_report_desc(
		const struct request *req)
{
	return xa_erase(&ublk_zoned_report_descs, (unsigned long)req);
}

static struct ublk_zoned_report_desc *ublk_zoned_get_report_desc(
		const struct request *req)
{
	return xa_load(&ublk_zoned_report_descs, (unsigned long)req);
}

static int ublk_get_nr_zones(const struct ublk_device *ub)
{
	const struct ublk_param_basic *p = &ub->params.basic;

	/* Zone size is a power of 2 */
	return p->dev_sectors >> ilog2(p->chunk_sectors);
}

int ublk_revalidate_disk_zones(struct ublk_device *ub)
{
	return blk_revalidate_disk_zones(ub->ub_disk);
}

int ublk_dev_param_zoned_validate(const struct ublk_device *ub)
{
	const struct ublk_param_zoned *p = &ub->params.zoned;
	int nr_zones;

	if (!ublk_dev_is_zoned(ub))
		return -EINVAL;

	if (!p->max_zone_append_sectors)
		return -EINVAL;

	nr_zones = ublk_get_nr_zones(ub);

	if (p->max_active_zones > nr_zones)
		return -EINVAL;

	if (p->max_open_zones > nr_zones)
		return -EINVAL;

	return 0;
}

void ublk_dev_param_zoned_apply(struct ublk_device *ub)
{
	ub->ub_disk->nr_zones = ublk_get_nr_zones(ub);
}

/* Based on virtblk_alloc_report_buffer */
static void *ublk_alloc_report_buffer(struct ublk_device *ublk,
				      unsigned int nr_zones, size_t *buflen)
{
	struct request_queue *q = ublk->ub_disk->queue;
	size_t bufsize;
	void *buf;

	nr_zones = min_t(unsigned int, nr_zones,
			 ublk->ub_disk->nr_zones);

	bufsize = nr_zones * sizeof(struct blk_zone);
	bufsize =
		min_t(size_t, bufsize, queue_max_hw_sectors(q) << SECTOR_SHIFT);

	while (bufsize >= sizeof(struct blk_zone)) {
		buf = kvmalloc(bufsize, GFP_KERNEL | __GFP_NORETRY);
		if (buf) {
			*buflen = bufsize;
			return buf;
		}
		bufsize >>= 1;
	}

	*buflen = 0;
	return NULL;
}

int ublk_report_zones(struct gendisk *disk, sector_t sector,
		      unsigned int nr_zones, struct blk_report_zones_args *args)
{
	struct ublk_device *ub = disk->private_data;
	unsigned int zone_size_sectors = disk->queue->limits.chunk_sectors;
	unsigned int first_zone = sector >> ilog2(zone_size_sectors);
	unsigned int done_zones = 0;
	unsigned int max_zones_per_request;
	int ret;
	struct blk_zone *buffer;
	size_t buffer_length;

	nr_zones = min_t(unsigned int, ub->ub_disk->nr_zones - first_zone,
			 nr_zones);

	buffer = ublk_alloc_report_buffer(ub, nr_zones, &buffer_length);
	if (!buffer)
		return -ENOMEM;

	max_zones_per_request = buffer_length / sizeof(struct blk_zone);

	while (done_zones < nr_zones) {
		unsigned int remaining_zones = nr_zones - done_zones;
		unsigned int zones_in_request =
			min_t(unsigned int, remaining_zones, max_zones_per_request);
		struct request *req;
		struct ublk_zoned_report_desc desc;
		blk_status_t status;

		memset(buffer, 0, buffer_length);

		req = blk_mq_alloc_request(disk->queue, REQ_OP_DRV_IN, 0);
		if (IS_ERR(req)) {
			ret = PTR_ERR(req);
			goto out;
		}

		desc.operation = UBLK_IO_OP_REPORT_ZONES;
		desc.sector = sector;
		desc.nr_zones = zones_in_request;
		ret = ublk_zoned_insert_report_desc(req, &desc);
		if (ret)
			goto free_req;

		ret = blk_rq_map_kern(req, buffer, buffer_length, GFP_KERNEL);
		if (ret)
			goto erase_desc;

		status = blk_execute_rq(req, 0);
		ret = blk_status_to_errno(status);
erase_desc:
		ublk_zoned_erase_report_desc(req);
free_req:
		blk_mq_free_request(req);
		if (ret)
			goto out;

		for (unsigned int i = 0; i < zones_in_request; i++) {
			struct blk_zone *zone = buffer + i;

			/* A zero length zone means no more zones in this response */
			if (!zone->len)
				break;

			ret = disk_report_zone(disk, zone, i, args);
			if (ret)
				goto out;

			done_zones++;
			sector += zone_size_sectors;

		}
	}

	ret = done_zones;

out:
	kvfree(buffer);
	return ret;
}

blk_status_t ublk_setup_iod_zoned(struct ublk_queue *ubq,
				  struct request *req)
{
	struct ublk_zoned_report_desc *desc;
	u32 ublk_op;

	switch (req_op(req)) {
	case REQ_OP_ZONE_OPEN:
		ublk_op = UBLK_IO_OP_ZONE_OPEN;
		break;
	case REQ_OP_ZONE_CLOSE:
		ublk_op = UBLK_IO_OP_ZONE_CLOSE;
		break;
	case REQ_OP_ZONE_FINISH:
		ublk_op = UBLK_IO_OP_ZONE_FINISH;
		break;
	case REQ_OP_ZONE_RESET:
		ublk_op = UBLK_IO_OP_ZONE_RESET;
		break;
	case REQ_OP_ZONE_APPEND:
		ublk_op = UBLK_IO_OP_ZONE_APPEND;
		break;
	case REQ_OP_ZONE_RESET_ALL:
		ublk_op = UBLK_IO_OP_ZONE_RESET_ALL;
		break;
	case REQ_OP_DRV_IN:
		desc = ublk_zoned_get_report_desc(req);
		if (!desc)
			return BLK_STS_IOERR;
		ublk_op = desc->operation;
		switch (ublk_op) {
		case UBLK_IO_OP_REPORT_ZONES:
			ublk_init_iod(ubq, req, ublk_op, desc->nr_zones,
				      desc->sector);
			return BLK_STS_OK;
		default:
			return BLK_STS_IOERR;
		}
	case REQ_OP_DRV_OUT:
		/* We do not support drv_out */
		return BLK_STS_NOTSUPP;
	default:
		return BLK_STS_IOERR;
	}

	ublk_init_iod(ubq, req, ublk_op, blk_rq_sectors(req), blk_rq_pos(req));
	return BLK_STS_OK;
}
