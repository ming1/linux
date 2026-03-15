// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal VFIO PCI + iommufd setup for ublk BPF selftests.
 *
 * Binds a PCI device to vfio-pci, opens iommufd, creates an IOAS,
 * and attaches the device. This provides the iommufd/ioas_id/vfio_dev_fd
 * needed by UBLK_F_DMA_ZC + UBLK_F_BPF.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/vfio.h>
#include <linux/iommufd.h>
#include "kublk.h"

struct vfio_pci_ctx {
	char pci_addr[32];
	int iommufd;
	int device_fd;
	__u32 ioas_id;
	__u32 dev_id;
};

static int unbind_pci_driver(const char *pci_addr)
{
	char path[256];
	int fd, retry;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/driver/unbind", pci_addr);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return 0; /* no driver bound */
	write(fd, pci_addr, strlen(pci_addr));
	close(fd);

	/* Wait for unbind */
	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/driver", pci_addr);
	for (retry = 0; retry < 50; retry++) {
		if (access(path, F_OK) != 0)
			return 0;
		usleep(100000);
	}
	return 0;
}

static int bind_vfio_pci(const char *pci_addr)
{
	char path[256];
	int fd;

	snprintf(path, sizeof(path),
		 "/sys/bus/pci/devices/%s/driver_override", pci_addr);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	if (write(fd, "vfio-pci", 8) < 0) {
		close(fd);
		return -1;
	}
	close(fd);

	fd = open("/sys/bus/pci/drivers_probe", O_WRONLY);
	if (fd < 0)
		return -1;
	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	usleep(200000);
	return 0;
}

static int open_vfio_cdev(const char *pci_addr)
{
	char sysfs_path[512], dev_path[512];
	struct dirent *entry;
	DIR *dir;
	int fd = -1;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/pci/devices/%s/vfio-dev", pci_addr);
	dir = opendir(sysfs_path);
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;
		snprintf(dev_path, sizeof(dev_path),
			 "/dev/vfio/devices/%s", entry->d_name);
		fd = open(dev_path, O_RDWR);
		break;
	}
	closedir(dir);
	return fd;
}

int vfio_pci_setup(struct vfio_pci_ctx *ctx, const char *pci_addr)
{
	struct vfio_device_bind_iommufd bind = { .argsz = sizeof(bind) };
	struct iommu_ioas_alloc ioas_alloc = { .size = sizeof(ioas_alloc) };
	struct vfio_device_attach_iommufd_pt attach = {
		.argsz = sizeof(attach)
	};

	strncpy(ctx->pci_addr, pci_addr, sizeof(ctx->pci_addr) - 1);
	ctx->iommufd = -1;
	ctx->device_fd = -1;

	/* Check if already bound to vfio-pci */
	{
		char path[256], link[256];
		ssize_t len;

		snprintf(path, sizeof(path),
			 "/sys/bus/pci/devices/%s/driver", pci_addr);
		len = readlink(path, link, sizeof(link) - 1);
		if (len > 0) {
			link[len] = '\0';
			if (!strstr(link, "vfio-pci")) {
				unbind_pci_driver(pci_addr);
				if (bind_vfio_pci(pci_addr) < 0)
					return -1;
			}
		} else {
			if (bind_vfio_pci(pci_addr) < 0)
				return -1;
		}
	}

	ctx->iommufd = open("/dev/iommu", O_RDWR);
	if (ctx->iommufd < 0)
		return -1;

	ctx->device_fd = open_vfio_cdev(pci_addr);
	if (ctx->device_fd < 0)
		goto err;

	bind.iommufd = ctx->iommufd;
	if (ioctl(ctx->device_fd, VFIO_DEVICE_BIND_IOMMUFD, &bind) < 0)
		goto err;
	ctx->dev_id = bind.out_devid;

	if (ioctl(ctx->iommufd, IOMMU_IOAS_ALLOC, &ioas_alloc) < 0)
		goto err;
	ctx->ioas_id = ioas_alloc.out_ioas_id;

	attach.pt_id = ctx->ioas_id;
	if (ioctl(ctx->device_fd, VFIO_DEVICE_ATTACH_IOMMUFD_PT, &attach) < 0)
		goto err;

	return 0;

err:
	if (ctx->device_fd >= 0)
		close(ctx->device_fd);
	if (ctx->iommufd >= 0)
		close(ctx->iommufd);
	ctx->device_fd = -1;
	ctx->iommufd = -1;
	return -1;
}

void vfio_pci_cleanup(struct vfio_pci_ctx *ctx)
{
	if (ctx->device_fd >= 0) {
		struct vfio_device_detach_iommufd_pt detach = {
			.argsz = sizeof(detach)
		};
		ioctl(ctx->device_fd, VFIO_DEVICE_DETACH_IOMMUFD_PT, &detach);
		close(ctx->device_fd);
	}
	if (ctx->iommufd >= 0) {
		struct iommu_destroy destroy = {
			.size = sizeof(destroy),
			.id = ctx->ioas_id,
		};
		ioctl(ctx->iommufd, IOMMU_DESTROY, &destroy);
		close(ctx->iommufd);
	}
}
