// SPDX-License-Identifier: GPL-2.0

/*
 * VFIO-based ublk NVMe/PCI Target
 *
 * This target accesses NVMe devices directly via VFIO, bypassing the kernel
 * NVMe driver. It provides an alternative I/O path for testing and performance
 * analysis.
 *
 * Usage:
 *   Standard mode (with IOMMU):
 *     sudo ./kublk add -t nvme_vfio -q 1 -d 1 280000:01:00.0
 *
 *   NoIOMMU mode (for VM testing, uses virtual addresses as IOVAs):
 *     sudo ./kublk add -t nvme_vfio --noiommu 1 -q 1 -d 128 0000:01:00.0
 * Prerequisites:
 *   Standard mode:
 *     - IOMMU enabled (intel_iommu=on or amd_iommu=on)
 *     - vfio-pci module loaded
 *
 *   NoIOMMU mode:
 *     - vfio-pci module loaded
 *     - echo Y > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
 *
 *   Both modes:
 *     - Device will be automatically bound to vfio-pci
 *
 * NoIOMMU Mode Details:
 *   Uses guest physical addresses from /proc/self/pagemap as IOVAs (matching
 *   SPDK's RTE_IOVA_PA mode in noiommu). This requires:
 *   - Real NVMe hardware with PCI passthrough, OR
 *   - Bare metal system with direct hardware access
 *
 *   IMPORTANT: vfio-noiommu does NOT work with emulated devices (e.g., QEMU
 *   NVMe emulation) because the emulated device cannot access guest memory
 *   when VFIO DMA mapping is unavailable. For VM testing with emulated devices,
 *   use regular VFIO with a virtual IOMMU device configured in QEMU.
 */

#include "kublk.h"
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <endian.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define ADMIN_Q_SIZE 64

/*
 * Memory barriers (aligned with SPDK barrier.h)
 */
#if defined(__x86_64__) || defined(__i386__)
#define ublk_wmb()	__asm__ __volatile__("sfence" ::: "memory")
#define ublk_rmb()	__asm__ __volatile__("lfence" ::: "memory")
#define ublk_mb()	__asm__ __volatile__("mfence" ::: "memory")
#elif defined(__aarch64__)
#define ublk_wmb()	__asm__ __volatile__("dsb st" ::: "memory")
#define ublk_rmb()	__asm__ __volatile__("dsb ld" ::: "memory")
#define ublk_mb()	__asm__ __volatile__("dsb sy" ::: "memory")
#else
#define ublk_wmb()	__sync_synchronize()
#define ublk_rmb()	__sync_synchronize()
#define ublk_mb()	__sync_synchronize()
#endif

#ifdef DEBUG
#define nvme_dbg  ublk_dbg
#else
#define nvme_dbg(...)
#endif

/* MMIO write with implicit wmb (like Linux writel) */
static inline void ublk_writel(__u32 val, volatile __u32 *addr)
{
	ublk_wmb();
	*addr = val;
}

/* MMIO read with implicit rmb (like Linux readl) */
static inline __u32 ublk_readl(volatile __u32 *addr)
{
	__u32 val = *addr;
	ublk_rmb();
	return val;
}

/* READ_ONCE - prevent compiler from caching or reordering reads */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

/* NVMe Register Offsets (BAR0) */
#define NVME_REG_CAP    0x0000  /* Controller Capabilities */
#define NVME_REG_VS     0x0008  /* Version */
#define NVME_REG_CC     0x0014  /* Controller Configuration */
#define NVME_REG_CSTS   0x001c  /* Controller Status */
#define NVME_REG_AQA    0x0024  /* Admin Queue Attributes */
#define NVME_REG_ASQ    0x0028  /* Admin Submission Queue Base */
#define NVME_REG_ACQ    0x0030  /* Admin Completion Queue Base */

/* Controller Configuration Register */
#define NVME_CC_ENABLE  (1 << 0)
#define NVME_CC_CSS_NVM (0 << 4)
#define NVME_CC_MPS_4K  (0 << 7)
#define NVME_CC_IOSQES  (6 << 16)  /* 2^6 = 64 bytes */
#define NVME_CC_IOCQES  (4 << 20)  /* 2^4 = 16 bytes */
#define NVME_CC_SHN_NORMAL (1 << 14)

/* Controller Status Register */
#define NVME_CSTS_RDY   (1 << 0)
#define NVME_CSTS_SHST_MASK (3 << 2)
#define NVME_CSTS_SHST_COMPLETE (2 << 2)

/* Admin Command Opcodes */
#define NVME_ADMIN_DELETE_SQ    0x00
#define NVME_ADMIN_CREATE_SQ    0x01
#define NVME_ADMIN_DELETE_CQ    0x04
#define NVME_ADMIN_CREATE_CQ    0x05
#define NVME_ADMIN_IDENTIFY     0x06

/* I/O Command Opcodes */
#define NVME_CMD_FLUSH          0x00
#define NVME_CMD_WRITE          0x01
#define NVME_CMD_READ           0x02

/* Command Flags */
#define NVME_RW_FUA             (1 << 14)

/* NVMe Command Structures */
struct nvme_common_command {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u32	cdw2[2];
	__u64	metadata;
	__u64	prp1;
	__u64	prp2;
	__u32	cdw10;
	__u32	cdw11;
	__u32	cdw12;
	__u32	cdw13;
	__u32	cdw14;
	__u32	cdw15;
};

struct nvme_rw_command {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u64	rsvd2;
	__u64	metadata;
	__u64	prp1;
	__u64	prp2;
	__u64	slba;
	__u16	length;
	__u16	control;
	__u32	dsmgmt;
	__u32	reftag;
	__u16	apptag;
	__u16	appmask;
};

struct nvme_create_cq {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[5];
	__u64	prp1;
	__u64	rsvd8;
	__u16	cqid;
	__u16	qsize;
	__u16	cq_flags;
	__u16	irq_vector;
	__u32	rsvd12[4];
};

struct nvme_create_sq {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[5];
	__u64	prp1;
	__u64	rsvd8;
	__u16	sqid;
	__u16	qsize;
	__u16	sq_flags;
	__u16	cqid;
	__u32	rsvd12[4];
};

struct nvme_delete_queue {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	rsvd1[9];
	__u16	qid;
	__u16	rsvd10;
	__u32	rsvd11[5];
};

struct nvme_identify {
	__u8	opcode;
	__u8	flags;
	__u16	cid;
	__u32	nsid;
	__u64	rsvd2[2];
	__u64	prp1;
	__u64	prp2;
	__u32	cns;
	__u32	rsvd11[5];
};

struct nvme_completion {
	__u32	result;
	__u32	rsvd;
	__u16	sq_head;
	__u16	sq_id;
	__u16	command_id;
	__u16	status;
};

/* Identify Namespace Structure (partial) */
struct nvme_lbaf {
	__le16	ms;
	__u8	ds;
	__u8	rp;
};

struct nvme_id_ns {
	__le64	nsze;
	__le64	ncap;
	__le64	nuse;
	__u8	nsfeat;
	__u8	nlbaf;
	__u8	flbas;
	__u8	mc;
	__u8	dpc;
	__u8	dps;
	__u8	nmic;
	__u8	rescap;
	__u8	fpi;
	__u8	dlfeat;
	__le16	nawun;
	__le16	nawupf;
	__le16	nacwu;
	__le16	nabsn;
	__le16	nabo;
	__le16	nabspf;
	__le16	noiob;
	__u8	nvmcap[16];
	__le16	npwg;
	__le16	npwa;
	__le16	npdg;
	__le16	npda;
	__le16	nows;
	__u8	rsvd74[18];
	__le32	anagrpid;
	__u8	rsvd96[3];
	__u8	nsattr;
	__le16	nvmsetid;
	__le16	endgid;
	__u8	nguid[16];
	__u8	eui64[8];
	struct nvme_lbaf lbaf[64];
};

/* Identify Controller Structure (partial) */
struct nvme_id_ctrl {
	__le16	vid;
	__le16	ssvid;
	char	sn[20];
	char	mn[40];
	char	fr[8];
	__u8	rab;
	__u8	ieee[3];
	__u8	cmic;
	__u8	mdts;
	__u8	rsvd78[178];
};

/*
 * DMA Mapping Tracking
 * - For I/O queues: one per tag, pre-allocated in io->private_data
 * - For queue buffers: stored in struct nvme_queue
 * - For temporary buffers (e.g., identify): local variable
 */
struct nvme_dma_mapping {
	__u64 vaddr;
	__u64 iova;
	size_t size;
};

/* Per-I/O private data for PRP list support */
struct nvme_io_priv {
	struct nvme_dma_mapping data_mapping;  /* I/O data buffer mapping */
	struct nvme_dma_mapping prp_mapping;   /* PRP list buffer mapping */
	__le64 *prp_list;                       /* PRP list buffer (virtual addr) */
};

/* Queue Structure */
struct nvme_queue {
	__u16 qid;
	__u16 qsize;

	/* Queue memory */
	void *sq_buffer;
	void *cq_buffer;
	__u64 sq_iova;
	__u64 cq_iova;

	/* DMA mappings for queue buffers */
	struct nvme_dma_mapping sq_mapping;
	struct nvme_dma_mapping cq_mapping;

	/* Queue state */
	__u16 sq_tail;
	__u16 last_sq_tail;	/* Last value written to SQ doorbell */
	__u16 cq_head;
	__u8 cq_phase;

	/* Doorbell registers */
	volatile __u32 *sq_doorbell;
	volatile __u32 *cq_doorbell;
};

/* Target Private Data */
struct nvme_vfio_tgt_data {
	char pci_addr[16];
	__u32 nsid;
	__u32 lba_shift;
	__u64 dev_size;

	/* VFIO handles */
	int container_fd;
	int group_fd;
	int device_fd;
	int iommu_group;
	int use_noiommu;

	/* NoIOMMU mode flag */
	int force_noiommu;	/* --noiommu flag: use virtual addresses as IOVAs */

	/* MMIO mapping */
	volatile void *bar0;
	size_t bar0_size;

	/* Queues */
	struct nvme_queue admin_queue;
	struct nvme_queue *io_queues;
	int nr_io_queues;

	/* Capabilities */
	unsigned int db_stride;
	unsigned int max_transfer_shift;

	/* DMA IOVA allocation */
	__u64 next_iova;
	pthread_spinlock_t iova_lock;	/* Protects next_iova allocation */

	/* dma_buf pool for pinned DMA memory */
	int dmabuf_fd;			/* fd from DMA_HEAP_IOCTL_ALLOC */
	void *dmabuf_base;		/* mmap'd base address */
	size_t dmabuf_size;		/* total allocated size */

	/* Region layout (offsets from dmabuf_base) */
	size_t queue_region_off;	/* end of queue region (= prp_region_off) */
	size_t prp_region_off;		/* offset to PRP list region */
	size_t io_buf_region_off;	/* offset to I/O buffer region */
	size_t identify_buf_off;	/* offset to identify buffer */

	/* Queue buffer allocation state (bump allocator) */
	size_t queue_alloc_off;

	/* Pagemap cache for noiommu mode */
	uint64_t *pagemap_cache;		/* Pre-read pagemap entries */
	__u64 pagemap_base_vaddr;		/* Base virtual address of cached region */
	size_t pagemap_nr_pages;		/* Number of pages in cache */

	/* Back-pointer to ublk device for I/O buffer info */
	struct ublk_dev *dev;
};

/* Helper: Read 32-bit register */
static inline __u32 nvme_readl(volatile void *bar, unsigned int offset)
{
	return *(volatile __u32 *)((char *)bar + offset);
}

/* Helper: Write 32-bit register */
static inline void nvme_writel(volatile void *bar, unsigned int offset, __u32 val)
{
	*(volatile __u32 *)((char *)bar + offset) = val;
}

/* Helper: Read 64-bit register */
static inline __u64 nvme_readq(volatile void *bar, unsigned int offset)
{
	return *(volatile __u64 *)((char *)bar + offset);
}

/* Helper: Write 64-bit register */
static inline void nvme_writeq(volatile void *bar, unsigned int offset, __u64 val)
{
	*(volatile __u64 *)((char *)bar + offset) = val;
}

/* Get IOMMU group for a PCI device */
static int get_iommu_group(const char *pci_addr, int *use_noiommu)
{
	char path[256];
	char link[256];
	char *group_name;
	ssize_t len;

	*use_noiommu = 0;

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/iommu_group", pci_addr);

	fprintf(stderr, "Checking for IOMMU group at: %s\n", path);
	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0) {
		/* No IOMMU group - use noiommu mode */
		*use_noiommu = 1;
		fprintf(stderr, "No IOMMU found, will use no-IOMMU mode (unsafe)\n");
		return 0;  /* noiommu uses group 0 typically */
	}
	link[len] = '\0';
	fprintf(stderr, "Found IOMMU group link: %s\n", link);

	group_name = strrchr(link, '/');
	if (!group_name) {
		fprintf(stderr, "Invalid iommu_group link: %s\n", link);
		return -1;
	}

	int group_num = atoi(group_name + 1);

	/* Check if this is a noiommu group by looking for "noiommu" in path */
	if (strstr(link, "noiommu")) {
		*use_noiommu = 1;
		fprintf(stderr, "Using no-IOMMU mode for group %d (unsafe)\n", group_num);
	}

	return group_num;
}

/*
 * Pre-read pagemap entries for the dmabuf region into a cache.
 * This avoids repeated open/read/close syscalls in nvme_virt_to_phys().
 */
static int nvme_read_pagemap(struct nvme_vfio_tgt_data *data)
{
	size_t nr_pages = data->dmabuf_size / PAGE_SIZE;
	__u64 base_vaddr = (__u64)data->dmabuf_base;
	off_t offset;
	ssize_t ret;
	int pagemap_fd;

	data->pagemap_cache = malloc(nr_pages * sizeof(uint64_t));
	if (!data->pagemap_cache) {
		fprintf(stderr, "Failed to allocate pagemap cache\n");
		return -ENOMEM;
	}

	pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
	if (pagemap_fd < 0) {
		fprintf(stderr, "Failed to open /proc/self/pagemap: %s\n",
			strerror(errno));
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
		return -errno;
	}

	offset = (base_vaddr / PAGE_SIZE) * sizeof(uint64_t);
	ret = pread(pagemap_fd, data->pagemap_cache,
		    nr_pages * sizeof(uint64_t), offset);
	close(pagemap_fd);

	if (ret != (ssize_t)(nr_pages * sizeof(uint64_t))) {
		fprintf(stderr, "pread pagemap failed: expected %zu, got %zd\n",
			nr_pages * sizeof(uint64_t), ret);
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
		return -EIO;
	}

	data->pagemap_base_vaddr = base_vaddr;
	data->pagemap_nr_pages = nr_pages;

	return 0;
}

/*
 * Query physical address from pre-read pagemap cache
 * Returns: physical address or 0 on error
 */
static __u64 nvme_virt_to_phys(struct nvme_vfio_tgt_data *data, __u64 vaddr)
{
	uint64_t entry;
	unsigned long pfn;
	size_t page_idx;

	if (!data->pagemap_cache) {
		fprintf(stderr, "pagemap cache not initialized\n");
		return 0;
	}

	/* Check if vaddr is within cached region */
	if (vaddr < data->pagemap_base_vaddr ||
	    vaddr >= data->pagemap_base_vaddr + data->pagemap_nr_pages * PAGE_SIZE) {
		fprintf(stderr, "vaddr 0x%llx outside cached region [0x%llx, 0x%llx)\n",
			vaddr, data->pagemap_base_vaddr,
			data->pagemap_base_vaddr + data->pagemap_nr_pages * PAGE_SIZE);
		return 0;
	}

	page_idx = (vaddr - data->pagemap_base_vaddr) / PAGE_SIZE;
	entry = data->pagemap_cache[page_idx];

	/* Check page present bit */
	if (!(entry & (1ULL << 63))) {
		fprintf(stderr, "Page not present for vaddr 0x%llx\n", vaddr);
		return 0;
	}

	/* Extract PFN (bits 0-54) */
	pfn = entry & 0x007fffffffffffffULL;

	__u64 paddr = (pfn * PAGE_SIZE) + (vaddr & (PAGE_SIZE - 1));
	nvme_dbg(UBLK_DBG_IO, "  PFN=0x%lx -> paddr=0x%llx\n", pfn, paddr);

	return paddr;
}

static inline bool nvme_use_iommu(struct nvme_vfio_tgt_data *data)
{
	return !data->use_noiommu && !data->force_noiommu;
}

/*
 * Get IOVA for buffer based on current mode
 * - NoIOMMU mode: use guest physical address (from /proc/self/pagemap)
 * - IOMMU mode: allocate from IOVA space
 */
static __u64 nvme_get_iova(struct nvme_vfio_tgt_data *data, void *vaddr, size_t size)
{
	__u64 iova;

	/* NoIOMMU mode: use physical address from /proc/self/pagemap */
	if (!nvme_use_iommu(data)) {
		__u64 paddr = nvme_virt_to_phys(data, (__u64)vaddr);
		nvme_dbg(UBLK_DBG_IO, "DEBUG: vaddr=0x%llx -> paddr=0x%llx (size=%zu)\n",
			(__u64)vaddr, paddr, size);
		return paddr;
	}

	/* Standard IOMMU mode: allocate sequential IOVA (with spinlock) */
	pthread_spin_lock(&data->iova_lock);
	iova = data->next_iova;
	data->next_iova += (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	pthread_spin_unlock(&data->iova_lock);
	return iova;
}

/*
 * Build PRP list with individual page addresses
 * - NoIOMMU mode: query guest physical address for each page
 * - IOMMU mode: increment IOVA sequentially from first page
 */
static int nvme_build_prp_list(struct nvme_vfio_tgt_data *data,
			       void *vaddr, size_t len, __u64 first_iova,
			       __le64 *prp_list, int max_entries)
{
	__u64 vaddr_page = (__u64)vaddr;
	__u64 iova;
	size_t offset = 0;
	size_t remaining = len;
	int prp_index = 0;

	/* Skip first page (already in PRP1) */
	offset = PAGE_SIZE - (vaddr_page & (PAGE_SIZE - 1));
	vaddr_page = ((__u64)vaddr + offset) & ~(PAGE_SIZE - 1);
	remaining = (len > offset) ? (len - offset) : 0;

	while (remaining > 0) {
		if (prp_index >= max_entries) {
			fprintf(stderr, "PRP list overflow\n");
			return -1;
		}

		/* Get IOVA for this page */
		if (!nvme_use_iommu(data)) {
			/* NoIOMMU mode: query physical address for each page */
			iova = nvme_virt_to_phys(data, vaddr_page);
			if (!iova) {
				fprintf(stderr, "Failed to get physical address for page at vaddr 0x%llx\n",
					vaddr_page);
				return -1;
			}
		} else {
			/* Standard IOMMU: increment from first IOVA */
			iova = first_iova + offset;
		}

		prp_list[prp_index++] = htole64(iova);

		vaddr_page += PAGE_SIZE;
		offset += PAGE_SIZE;
		remaining = (remaining > PAGE_SIZE) ? (remaining - PAGE_SIZE) : 0;
	}

	return prp_index;
}

/*
 * Perform VFIO DMA mapping if needed
 * - vfio-noiommu mode: skip mapping (no IOMMU hardware, ioctl not supported)
 * - Regular VFIO with IOMMU: perform mapping
 */
static int nvme_do_vfio_map(struct nvme_vfio_tgt_data *data,
			    void *vaddr, __u64 iova, size_t size)
{
	struct vfio_iommu_type1_dma_map dma_map = { .argsz = sizeof(dma_map) };

	/*
	 * Skip VFIO ioctl in any noiommu mode (doesn't support VFIO_IOMMU_MAP_DMA).
	 * In noiommu, devices use virtual addresses directly without IOMMU translation.
	 */
	if (!nvme_use_iommu(data))
		return 0;

	/* Perform VFIO DMA mapping for regular IOMMU mode */
	dma_map.vaddr = (__u64)vaddr;
	dma_map.size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	dma_map.iova = iova;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	if (ioctl(data->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map) < 0) {
		perror("VFIO_IOMMU_MAP_DMA");
		return -1;
	}

	return 0;
}

/* Unbind device from current driver */
static int unbind_driver(const char *pci_addr)
{
	char path[256];
	int fd, retry;

	/* Validate PCI address length */
	if (strlen(pci_addr) > 16) {
		fprintf(stderr, "Invalid PCI address length\n");
		return -1;
	}

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver/unbind", pci_addr);

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		/* May already be unbound */
		return 0;
	}

	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		perror("unbind device");
		close(fd);
		return -1;
	}

	close(fd);

	/*
	 * Wait for driver to fully unbind. The write() above initiates
	 * the unbind, but kernel cleanup (releasing namespaces, DMA mappings,
	 * etc.) happens asynchronously. Poll for the driver symlink to
	 * disappear before returning.
	 */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver", pci_addr);

	for (retry = 0; retry < 50; retry++) {
		char driver_link[256];
		ssize_t len;

		len = readlink(path, driver_link, sizeof(driver_link) - 1);
		if (len < 0) {
			/* Driver symlink gone - unbind complete */
			return 0;
		}

		/* Wait 100ms before next check (total max wait: 5 seconds) */
		usleep(100000);
	}

	fprintf(stderr, "Warning: driver unbind may not be complete\n");
	return 0;
}

/* Bind device to vfio-pci driver */
static int bind_vfio_pci(const char *pci_addr)
{
	char path[256], vendor[16], device[16];
	char vendor_device[32];
	int fd;

	/* Read vendor:device ID */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/vendor", pci_addr);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open vendor");
		return -1;
	}
	if (read(fd, vendor, sizeof(vendor)) < 0) {
		perror("read vendor");
		close(fd);
		return -1;
	}
	close(fd);
	vendor[strcspn(vendor, "\n")] = 0;  /* Remove newline */

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/device", pci_addr);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open device");
		return -1;
	}
	if (read(fd, device, sizeof(device)) < 0) {
		perror("read device");
		close(fd);
		return -1;
	}
	close(fd);
	device[strcspn(device, "\n")] = 0;  /* Remove newline */

	/* Remove 0x prefix and format as "vendor device" */
	snprintf(vendor_device, sizeof(vendor_device), "%s %s",
		vendor + 2, device + 2);

	/* Add device ID to vfio-pci */
	fd = open("/sys/bus/pci/drivers/vfio-pci/new_id", O_WRONLY);
	if (fd < 0) {
		perror("open new_id");
		return -1;
	}

	if (write(fd, vendor_device, strlen(vendor_device)) < 0) {
		/* May already be added */
		if (errno != EEXIST) {
			perror("write new_id");
			close(fd);
			return -1;
		}
	}
	close(fd);

	/* Explicitly bind the device */
	fd = open("/sys/bus/pci/drivers/vfio-pci/bind", O_WRONLY);
	if (fd < 0) {
		perror("open vfio-pci bind");
		return -1;
	}

	if (write(fd, pci_addr, strlen(pci_addr)) < 0) {
		if (errno != EEXIST) {
			perror("bind to vfio-pci");
			close(fd);
			return -1;
		}
	}
	close(fd);

	/* Wait for binding to complete */
	usleep(200000);  /* 200ms delay */

	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver", pci_addr);
	char driver_link[256];
	ssize_t len = readlink(path, driver_link, sizeof(driver_link) - 1);
	if (len > 0) {
		driver_link[len] = '\0';
		if (!strstr(driver_link, "vfio-pci")) {
			fprintf(stderr, "Device not bound to vfio-pci (bound to: %s)\n", driver_link);
			return -1;
		}
		printf("Device successfully bound to vfio-pci\n");
	} else {
		fprintf(stderr, "Warning: Could not verify vfio-pci binding\n");
	}

	return 0;
}

/* Setup device binding to vfio-pci */
static int setup_vfio_binding(const char *pci_addr)
{
	char path[256];
	char driver_link[256];
	ssize_t len;

	/* Validate PCI address length (format: DDDD:BB:DD.F) */
	if (strlen(pci_addr) > 16) {
		fprintf(stderr, "Invalid PCI address length\n");
		return -1;
	}

	/* Check current driver */
	snprintf(path, sizeof(path),
		"/sys/bus/pci/devices/%s/driver", pci_addr);

	len = readlink(path, driver_link, sizeof(driver_link) - 1);
	if (len > 0) {
		driver_link[len] = '\0';
		if (strstr(driver_link, "vfio-pci")) {
			/* Already bound to vfio-pci */
			return 0;
		}

		/* Unbind from current driver */
		printf("Unbinding %s from current driver\n", pci_addr);
		if (unbind_driver(pci_addr) < 0) {
			return -1;
		}
	}

	/* Bind to vfio-pci */
	printf("Binding %s to vfio-pci\n", pci_addr);
	return bind_vfio_pci(pci_addr);
}

/* Get I/O private data for a tag - stored in io->private_data */
static inline struct nvme_io_priv *nvme_get_io_priv(
	struct ublk_queue *q, int tag)
{
	struct ublk_io *io = ublk_get_io(q, tag);
	return (struct nvme_io_priv *)io->private_data;
}

/*
 * Hugepage-based DMA pool management
 *
 * Uses anonymous hugepages (MAP_HUGETLB) for DMA buffers. Hugepages are:
 * - Pinned and immune to page migration (unlike regular pages with mlock)
 * - Properly exposed in /proc/self/pagemap (unlike dma_buf)
 * - Automatically freed on munmap/process exit (unlike /dev/hugepages files)
 *
 * Pool layout:
 *   [Queue buffers (bump allocator)] [PRP lists] [I/O buffers] [Identify buf]
 */

#define HUGE_PAGE_SIZE (2 * 1024 * 1024)  /* 2MB hugepages */

/* Ensure enough hugepages are available, allocating more if needed */
static int nvme_ensure_hugepages(size_t needed_bytes)
{
	size_t needed_pages = (needed_bytes + HUGE_PAGE_SIZE - 1) / HUGE_PAGE_SIZE;
	unsigned long current_pages = 0, free_pages = 0;
	FILE *fp;
	char buf[64];

	/* Read current nr_hugepages */
	fp = fopen("/proc/sys/vm/nr_hugepages", "r");
	if (!fp)
		return -errno;
	if (fgets(buf, sizeof(buf), fp))
		current_pages = strtoul(buf, NULL, 10);
	fclose(fp);

	/* Read free hugepages */
	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "HugePages_Free: %lu", &free_pages) == 1)
				break;
		}
		fclose(fp);
	}

	/* If we have enough free pages, we're good */
	if (free_pages >= needed_pages)
		return 0;

	/* Try to allocate more hugepages */
	fp = fopen("/proc/sys/vm/nr_hugepages", "w");
	if (!fp)
		return -errno;

	fprintf(fp, "%lu\n", current_pages + needed_pages - free_pages);
	fclose(fp);

	/* Verify allocation succeeded */
	fp = fopen("/proc/meminfo", "r");
	if (fp) {
		free_pages = 0;
		while (fgets(buf, sizeof(buf), fp)) {
			if (sscanf(buf, "HugePages_Free: %lu", &free_pages) == 1)
				break;
		}
		fclose(fp);
	}

	if (free_pages < needed_pages) {
		fprintf(stderr, "Failed to allocate %zu hugepages (only %lu free)\n",
			needed_pages, free_pages);
		return -ENOMEM;
	}

	return 0;
}

static int nvme_dmabuf_pool_init(struct nvme_vfio_tgt_data *data)
{
	size_t queue_region, prp_region, io_buf_region, total_size;
	size_t admin_sq_size, admin_cq_size, io_sq_size, io_cq_size;
	int nr_queues = data->dev->dev_info.nr_hw_queues;
	int depth = data->dev->dev_info.queue_depth;
	size_t io_buf_size = data->dev->dev_info.max_io_buf_bytes;
	int ret;

	/*
	 * Calculate region sizes:
	 * - Queue region: admin queue + I/O queues (SQ + CQ each)
	 *   SQ entry = 64 bytes, CQ entry = 16 bytes, page-aligned
	 * - PRP region: nr_queues * depth * PAGE_SIZE
	 * - I/O buffer region: nr_queues * depth * io_buf_size
	 * - Identify buffer: PAGE_SIZE
	 */
	admin_sq_size = (ADMIN_Q_SIZE * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	admin_cq_size = (ADMIN_Q_SIZE * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	/* +1 for NVMe queue size to avoid full/empty ambiguity (see nvme_setup_io_queues) */
	io_sq_size = ((depth + 1) * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	io_cq_size = ((depth + 1) * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	queue_region = (admin_sq_size + admin_cq_size) +
		       nr_queues * (io_sq_size + io_cq_size);
	prp_region = nr_queues * depth * PAGE_SIZE;
	io_buf_region = nr_queues * depth * io_buf_size;

	data->queue_region_off = queue_region;
	data->prp_region_off = queue_region;
	data->io_buf_region_off = queue_region + prp_region;
	data->identify_buf_off = queue_region + prp_region + io_buf_region;

	total_size = data->identify_buf_off + PAGE_SIZE;

	/* Round up to hugepage size for MAP_HUGETLB */
	total_size = (total_size + HUGE_PAGE_SIZE - 1) & ~(HUGE_PAGE_SIZE - 1);

	/* Ensure enough hugepages are available */
	ret = nvme_ensure_hugepages(total_size);
	if (ret < 0)
		return ret;

	/*
	 * Allocate anonymous hugepages. Using MAP_HUGETLB avoids the
	 * /dev/hugepages filesystem which can leak hugepages on crash.
	 * Anonymous hugepages are automatically freed on munmap or exit.
	 *
	 * mlock() on regular pages only prevents swapping, not NUMA balancing
	 * migration - pages can still be moved, causing stale physical addresses
	 * for DMA. Hugepages don't have this issue: no swapping, no migration,
	 * no compaction. Physical addresses remain stable for DMA lifetime.
	 */
	data->dmabuf_base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
				 MAP_POPULATE, -1, 0);
	if (data->dmabuf_base == MAP_FAILED) {
		perror("Failed to mmap hugepages");
		return -errno;
	}

	data->dmabuf_fd = -1;  /* No fd for anonymous hugepages */
	data->dmabuf_size = total_size;

	/* Touch all pages to ensure they're faulted in */
	memset(data->dmabuf_base, 0, total_size);

	/* Initialize bump allocator for queue region */
	data->queue_alloc_off = 0;

	return 0;
}

static void nvme_dmabuf_pool_deinit(struct nvme_vfio_tgt_data *data)
{
	if (data->pagemap_cache) {
		free(data->pagemap_cache);
		data->pagemap_cache = NULL;
	}
	if (data->dmabuf_base && data->dmabuf_base != MAP_FAILED) {
		munmap(data->dmabuf_base, data->dmabuf_size);
		data->dmabuf_base = NULL;
	}
	if (data->dmabuf_fd >= 0) {
		close(data->dmabuf_fd);
		data->dmabuf_fd = -1;
	}
}

/* Allocate from queue region (bump allocator, page-aligned) */
static void *nvme_pool_alloc_queue_buf(struct nvme_vfio_tgt_data *data, size_t size)
{
	size_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	void *ptr;

	if (data->queue_alloc_off + aligned_size > data->queue_region_off) {
		fprintf(stderr, "Queue region exhausted\n");
		return NULL;
	}

	ptr = (char *)data->dmabuf_base + data->queue_alloc_off;
	data->queue_alloc_off += aligned_size;
	return ptr;
}

/* Get PRP list buffer for given queue/tag */
static void *nvme_pool_get_prp(struct nvme_vfio_tgt_data *data, int qid, int tag)
{
	int depth = data->dev->dev_info.queue_depth;
	size_t offset = data->prp_region_off + (qid * depth + tag) * PAGE_SIZE;

	return (char *)data->dmabuf_base + offset;
}

/* Get I/O buffer for given queue/tag */
static void *nvme_pool_get_io_buf(struct nvme_vfio_tgt_data *data, int qid, int tag)
{
	int depth = data->dev->dev_info.queue_depth;
	size_t io_buf_size = data->dev->dev_info.max_io_buf_bytes;
	size_t offset = data->io_buf_region_off + (qid * depth + tag) * io_buf_size;

	return (char *)data->dmabuf_base + offset;
}

/* Get identify buffer */
static void *nvme_pool_get_identify_buf(struct nvme_vfio_tgt_data *data)
{
	return (char *)data->dmabuf_base + data->identify_buf_off;
}

/*
 * Map buffer for DMA
 * - For I/O (tag >= 0 && q != NULL): uses pre-allocated mapping from io->private_data
 * - For admin/setup (mapping != NULL): uses provided mapping structure
 */
static __u64 nvme_map_dma(struct nvme_vfio_tgt_data *data,
			  void *vaddr, size_t size,
			  struct nvme_dma_mapping *mapping)
{
	__u64 iova;

	if (!mapping)
		return 0;

	/* Get IOVA based on current mode (helper handles all cases) */
	iova = nvme_get_iova(data, vaddr, size);
	if (!iova)
		return 0;

	/* Perform VFIO mapping if needed (helper handles all cases) */
	if (nvme_do_vfio_map(data, vaddr, iova, size) < 0)
		return 0;

	/* Store mapping info */
	mapping->vaddr = (__u64)vaddr;
	mapping->iova = iova;
	mapping->size = size;

	return iova;
}

/* Unmap DMA buffer - clears pre-allocated mapping */
static void nvme_unmap_dma(struct nvme_vfio_tgt_data *data,
			   struct nvme_dma_mapping *mapping)
{
	struct vfio_iommu_type1_dma_unmap dma_unmap = { .argsz = sizeof(dma_unmap) };

	if (!mapping || !mapping->iova)
		return;

	/* Skip ioctl in no-IOMMU mode */
	if (nvme_use_iommu(data)) {
		dma_unmap.iova = mapping->iova;
		dma_unmap.size = mapping->size;
		ioctl(data->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	}

	/* Clear mapping info (but don't free - it's part of io->private_data) */
	mapping->vaddr = 0;
	mapping->iova = 0;
	mapping->size = 0;
}

/*
 * Initialize NVMe queue pair (SQ + CQ)
 * Common helper for both admin and I/O queues.
 * Allocates from dma_buf pool for stable physical addresses.
 */
static int nvme_queue_init(struct nvme_vfio_tgt_data *data,
			   struct nvme_queue *q, __u16 qid, __u16 depth)
{
	volatile void *bar = data->bar0;
	size_t sq_buf_size, cq_buf_size;

	/* Calculate page-aligned buffer sizes */
	sq_buf_size = (depth * 64 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	cq_buf_size = (depth * 16 + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	/* Allocate SQ buffer from dma_buf pool */
	q->sq_buffer = nvme_pool_alloc_queue_buf(data, sq_buf_size);
	if (!q->sq_buffer) {
		fprintf(stderr, "Failed to allocate SQ buffer from pool\n");
		return -ENOMEM;
	}
	memset(q->sq_buffer, 0, sq_buf_size);

	/* Allocate CQ buffer from dma_buf pool */
	q->cq_buffer = nvme_pool_alloc_queue_buf(data, cq_buf_size);
	if (!q->cq_buffer) {
		fprintf(stderr, "Failed to allocate CQ buffer from pool\n");
		return -ENOMEM;
	}
	memset(q->cq_buffer, 0, cq_buf_size);

	/* Map for DMA (pool memory is already pinned by kernel) */
	q->sq_iova = nvme_map_dma(data, q->sq_buffer, sq_buf_size,
				  &q->sq_mapping);
	q->cq_iova = nvme_map_dma(data, q->cq_buffer, cq_buf_size,
				  &q->cq_mapping);

	if (!q->sq_iova || !q->cq_iova) {
		fprintf(stderr, "Failed to map queue %d for DMA\n", qid);
		nvme_unmap_dma(data, &q->sq_mapping);
		nvme_unmap_dma(data, &q->cq_mapping);
		return -ENOMEM;
	}

	/* Initialize queue state */
	q->qid = qid;
	q->qsize = depth;
	q->sq_tail = 0;
	q->last_sq_tail = 0;
	q->cq_head = 0;
	q->cq_phase = 1;

	/* Ensure CQ initialization is visible before device starts */
	ublk_wmb();

	/* Setup doorbell pointers */
	q->sq_doorbell = (volatile __u32 *)
		((char *)bar + 0x1000 + (2 * qid * data->db_stride));
	q->cq_doorbell = (volatile __u32 *)
		((char *)bar + 0x1000 + ((2 * qid + 1) * data->db_stride));

	return 0;
}

/*
 * Deinitialize NVMe queue pair (SQ + CQ)
 * Common helper for both admin and I/O queues.
 * Buffers are from dma_buf pool, freed when pool is destroyed.
 */
static void nvme_queue_deinit(struct nvme_vfio_tgt_data *data,
			      struct nvme_queue *q)
{
	if (!q)
		return;

	nvme_unmap_dma(data, &q->sq_mapping);
	nvme_unmap_dma(data, &q->cq_mapping);

	/* Pool buffers freed when pool is destroyed, just clear pointers */
	q->sq_buffer = NULL;
	q->cq_buffer = NULL;
	q->sq_iova = 0;
	q->cq_iova = 0;
}

/* Wait for admin command completion */
static int nvme_wait_admin_completion(struct nvme_vfio_tgt_data *data)
{
	struct nvme_queue *adminq = &data->admin_queue;
	struct nvme_completion *cq = adminq->cq_buffer;
	int timeout = 5000;  /* 5 seconds */

	while (timeout-- > 0) {
		struct nvme_completion *cqe = &cq[adminq->cq_head];
		__u8 phase = (cqe->status >> 0) & 1;

		if (phase == adminq->cq_phase) {
			__u16 status = (cqe->status >> 1);

			/* Advance head */
			adminq->cq_head = (adminq->cq_head + 1) % adminq->qsize;
			if (adminq->cq_head == 0)
				adminq->cq_phase = !adminq->cq_phase;

			/* Update doorbell */
			ublk_writel(adminq->cq_head, adminq->cq_doorbell);

			return (status == 0) ? 0 : -EIO;
		}

		usleep(1000);
	}

	fprintf(stderr, "Admin command timeout\n");
	return -ETIMEDOUT;
}

/* Submit admin command */
static int nvme_submit_admin_cmd(struct nvme_vfio_tgt_data *data,
				 void *cmd, size_t cmd_size)
{
	struct nvme_queue *adminq = &data->admin_queue;

	/* Copy command to SQ */
	memcpy((char *)adminq->sq_buffer + (adminq->sq_tail * 64),
	       cmd, cmd_size);

	/* Submit */
	adminq->sq_tail = (adminq->sq_tail + 1) % adminq->qsize;
	ublk_writel(adminq->sq_tail, adminq->sq_doorbell);

	/* Wait for completion */
	return nvme_wait_admin_completion(data);
}

/* Create admin queue */
static int nvme_create_admin_queue(struct nvme_vfio_tgt_data *data)
{
	struct nvme_queue *q = &data->admin_queue;
	volatile void *bar = data->bar0;
	int ret;

	/*
	 * With ADMIN_Q_SIZE=64, each buffer fits in a single 4KB page,
	 * guaranteeing physical contiguity even in noiommu mode.
	 */
	ret = nvme_queue_init(data, q, 0, ADMIN_Q_SIZE);
	if (ret < 0)
		return ret;

	fprintf(stderr, "Admin SQ: vaddr=%p iova=0x%llx\n", q->sq_buffer, q->sq_iova);
	fprintf(stderr, "Admin CQ: vaddr=%p iova=0x%llx\n", q->cq_buffer, q->cq_iova);

	/* Write queue addresses to controller */
	nvme_writel(bar, NVME_REG_AQA,
		    ((ADMIN_Q_SIZE - 1) << 16) | (ADMIN_Q_SIZE - 1));
	nvme_writeq(bar, NVME_REG_ASQ, q->sq_iova);
	nvme_writeq(bar, NVME_REG_ACQ, q->cq_iova);

	return 0;
}

/* Initialize NVMe controller */
static int nvme_init_controller(struct nvme_vfio_tgt_data *data)
{
	volatile void *bar = data->bar0;
	__u32 cc, csts;
	int timeout;

	/* Disable controller */
	cc = nvme_readl(bar, NVME_REG_CC);
	cc &= ~NVME_CC_ENABLE;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for ready = 0 */
	timeout = 5000;
	do {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if (!(csts & NVME_CSTS_RDY))
			break;
		usleep(1000);
	} while (timeout-- > 0);

	if (timeout <= 0) {
		fprintf(stderr, "Controller failed to disable\n");
		return -1;
	}

	/* Create admin queue */
	if (nvme_create_admin_queue(data) < 0) {
		return -1;
	}

	/* Configure and enable controller */
	cc = NVME_CC_ENABLE | NVME_CC_CSS_NVM | NVME_CC_MPS_4K |
	     NVME_CC_IOSQES | NVME_CC_IOCQES;
	nvme_writel(bar, NVME_REG_CC, cc);

	/* Wait for ready = 1 */
	timeout = 5000;
	do {
		csts = nvme_readl(bar, NVME_REG_CSTS);
		if (csts & NVME_CSTS_RDY)
			break;
		usleep(1000);
	} while (timeout-- > 0);

	if (timeout <= 0) {
		fprintf(stderr, "Controller failed to become ready\n");
		fprintf(stderr, "  Final CSTS=0x%08x CC=0x%08x\n",
			nvme_readl(bar, NVME_REG_CSTS),
			nvme_readl(bar, NVME_REG_CC));
		return -1;
	}

	printf("NVMe controller initialized successfully\n");
	return 0;
}

/* Identify namespace */
static int nvme_identify_namespace(struct nvme_vfio_tgt_data *data,
				   struct ublk_dev *dev)
{
	struct nvme_identify cmd = {};
	struct nvme_id_ns *ns;
	struct nvme_dma_mapping ns_mapping = {0};
	__u64 ns_iova;
	__u8 lba_format;
	int ret = -ENOMEM;

	/* Get identify buffer from dma_buf pool (already pinned) */
	ns = nvme_pool_get_identify_buf(data);
	if (!ns) {
		fprintf(stderr, "Failed to get identify buffer from pool\n");
		return -ENOMEM;
	}
	memset(ns, 0, PAGE_SIZE);

	/* Map for DMA */
	ns_iova = nvme_map_dma(data, ns, PAGE_SIZE, &ns_mapping);
	if (!ns_iova) {
		return -ENOMEM;
	}

	/* Send Identify Namespace command */
	cmd.opcode = NVME_ADMIN_IDENTIFY;
	cmd.nsid = 1;
	cmd.prp1 = ns_iova;
	cmd.cns = 0x00;  /* Namespace */

	ret = nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));
	if (ret < 0) {
		fprintf(stderr, "Identify namespace failed\n");
		goto fail_unmap;
	}

	/* Parse namespace info */
	data->nsid = 1;
	lba_format = ns->flbas & 0x0F;
	data->lba_shift = ns->lbaf[lba_format].ds;
	data->dev_size = le64toh(ns->nsze) << data->lba_shift;

	printf("Namespace 1: size=%llu bytes, LBA size=%u bytes\n",
	       (unsigned long long)data->dev_size, 1U << data->lba_shift);

	/* Populate ublk parameters */
	dev->tgt.dev_size = data->dev_size;
	dev->tgt.params.basic.logical_bs_shift = data->lba_shift;
	dev->tgt.params.basic.physical_bs_shift = data->lba_shift;
	dev->tgt.params.basic.dev_sectors = data->dev_size >> 9;
	dev->tgt.params.basic.max_sectors =
		(1U << data->max_transfer_shift) >> 9;
	/*
	 * PRP lists require 4KB-aligned segments (NVMe spec page size).
	 * Set virt_boundary_mask to 4095 so the block layer doesn't merge
	 * bios across 4KB boundaries. This matches the kernel NVMe driver.
	 */
	dev->tgt.params.basic.virt_boundary_mask = 4095;

	dev->tgt.params.seg.seg_boundary_mask = 4095;
	dev->tgt.params.seg.max_segment_size = 32 << 20;
	dev->tgt.params.seg.max_segments = 127;
	dev->tgt.params.types = UBLK_PARAM_TYPE_SEGMENT | UBLK_PARAM_TYPE_BASIC;

	nvme_unmap_dma(data, &ns_mapping);
	return 0;
fail_unmap:
	nvme_unmap_dma(data, &ns_mapping);
	return ret;
}

/* Create I/O queue pair */
static int nvme_create_io_queue(struct nvme_vfio_tgt_data *data,
				int qid, int qsize)
{
	struct nvme_create_cq create_cq = {};
	struct nvme_create_sq create_sq = {};
	struct nvme_queue *ioq = &data->io_queues[qid - 1];
	int ret;

	ret = nvme_queue_init(data, ioq, qid, qsize);
	if (ret < 0)
		return ret;

	/* Create completion queue */
	create_cq.opcode = NVME_ADMIN_CREATE_CQ;
	create_cq.prp1 = ioq->cq_iova;
	create_cq.cqid = qid;
	create_cq.qsize = qsize - 1;
	create_cq.cq_flags = 0x01;  /* Physically contiguous */
	create_cq.irq_vector = 0;

	ret = nvme_submit_admin_cmd(data, &create_cq, sizeof(create_cq));
	if (ret < 0) {
		fprintf(stderr, "Create I/O CQ %d failed\n", qid);
		goto err_deinit;
	}

	/* Create submission queue */
	create_sq.opcode = NVME_ADMIN_CREATE_SQ;
	create_sq.prp1 = ioq->sq_iova;
	create_sq.sqid = qid;
	create_sq.qsize = qsize - 1;
	create_sq.sq_flags = 0x01;  /* Physically contiguous */
	create_sq.cqid = qid;

	ret = nvme_submit_admin_cmd(data, &create_sq, sizeof(create_sq));
	if (ret < 0) {
		fprintf(stderr, "Create I/O SQ %d failed\n", qid);
		goto err_deinit;
	}

	printf("Created I/O queue %d (depth %d) sq_iova=0x%llx cq_iova=0x%llx\n",
	       qid, qsize, (unsigned long long)ioq->sq_iova,
	       (unsigned long long)ioq->cq_iova);
	return 0;

err_deinit:
	nvme_queue_deinit(data, ioq);
	return -1;
}

/* Setup I/O queues */
/*
 * Allocate DMA mapping structures and PRP list buffers for all I/Os in a queue.
 * Actual DMA mapping is done lazily on first use to avoid expensive
 * map/unmap on every I/O. Mappings are kept for the lifetime of the device.
 */
static int nvme_setup_ios(struct nvme_vfio_tgt_data *data,
			  struct ublk_dev *dev, struct ublk_queue *q)
{
	int qsize = dev->dev_info.queue_depth;
	int tag;

	for (tag = 0; tag < qsize; tag++) {
		struct ublk_io *io = ublk_get_io(q, tag);
		struct nvme_io_priv *priv;

		/* Allocate private data structure for this IO */
		priv = calloc(1, sizeof(struct nvme_io_priv));
		if (!priv) {
			perror("calloc nvme_io_priv");
			return -1;
		}

		/* Get PRP list buffer from dma_buf pool (already pinned) */
		priv->prp_list = nvme_pool_get_prp(data, q->q_id, tag);
		if (!priv->prp_list) {
			fprintf(stderr, "Failed to get PRP buffer for tag %d\n", tag);
			free(priv);
			return -1;
		}
		memset(priv->prp_list, 0, PAGE_SIZE);

		/* Map PRP list for DMA */
		priv->prp_mapping.iova = nvme_map_dma(data, priv->prp_list,
						      PAGE_SIZE, &priv->prp_mapping);
		if (!priv->prp_mapping.iova) {
			fprintf(stderr, "Failed to map PRP list for tag %d\n", tag);
			free(priv);
			return -1;
		}

		/*
		 * I/O buffers come from dma_buf pool (already pinned).
		 * Map for DMA on first use.
		 */

		/* Store in io->private_data - data will be mapped on first use */
		io->private_data = priv;
	}

	return 0;
}

static int nvme_setup_io_queues(struct nvme_vfio_tgt_data *data,
				struct ublk_dev *dev)
{
	int nr_queues = dev->dev_info.nr_hw_queues;
	/*
	 * NVMe queue needs one extra slot to distinguish full from empty.
	 * With circular queues, if qsize == queue_depth and all slots are
	 * used, sq_tail wraps back to equal sq_head, making the queue
	 * appear empty to the device.
	 */
	int qsize = dev->dev_info.queue_depth + 1;
	int i;

	data->io_queues = calloc(nr_queues, sizeof(struct nvme_queue));
	if (!data->io_queues) {
		perror("calloc io_queues");
		return -1;
	}
	data->nr_io_queues = nr_queues;

	for (i = 0; i < nr_queues; i++) {
		if (nvme_create_io_queue(data, i + 1, qsize) < 0) {
			return -1;
		}

		/* Pre-allocate and pre-map DMA buffers for this queue */
		if (nvme_setup_ios(data, dev, &dev->q[i]) < 0) {
			return -1;
		}
	}

	return 0;
}

/* Flush any pending SQ submissions by writing doorbell */
static inline void nvme_sq_flush(struct nvme_queue *nvmeq)
{
	if (nvmeq->sq_tail != nvmeq->last_sq_tail) {
		ublk_writel(nvmeq->sq_tail, nvmeq->sq_doorbell);
		nvmeq->last_sq_tail = nvmeq->sq_tail;
	}
}

/*
 * Submit command to SQ: advance tail and write doorbell if needed.
 *
 * Call this after filling in the command at nvmeq->sq_buffer[nvmeq->sq_tail].
 * This advances sq_tail and writes doorbell only when queue would wrap around
 * (batching). Use nvme_sq_flush() to force a doorbell write.
 */
static inline void nvme_sq_submit_cmd(struct nvme_queue *nvmeq)
{
	__u16 next_tail;

	/* Advance sq_tail */
	if (++nvmeq->sq_tail == nvmeq->qsize)
		nvmeq->sq_tail = 0;

	/* Batching: only write doorbell when queue is about to wrap */
	next_tail = nvmeq->sq_tail + 1;
	if (next_tail == nvmeq->qsize)
		next_tail = 0;
	if (next_tail != nvmeq->last_sq_tail)
		return;

	nvme_sq_flush(nvmeq);
}

/* Check if CQE is pending (matches kernel's nvme_cqe_pending) */
static inline bool nvme_cqe_pending(struct nvme_queue *nvmeq)
{
	struct nvme_completion *cqe = &((struct nvme_completion *)nvmeq->cq_buffer)[nvmeq->cq_head];

	return (le16toh(READ_ONCE(cqe->status)) & 1) == nvmeq->cq_phase;
}

/* Update CQ head and phase (matches kernel's nvme_update_cq_head) */
static inline void nvme_update_cq_head(struct nvme_queue *nvmeq)
{
	nvmeq->cq_head = (nvmeq->cq_head + 1) % nvmeq->qsize;
	if (nvmeq->cq_head == 0)
		nvmeq->cq_phase = !nvmeq->cq_phase;
}

/* Poll completion queue (matches kernel's nvme_poll_cq pattern) */
static void nvme_poll_cq(struct ublk_thread *t, struct ublk_queue *q,
			 struct nvme_queue *nvmeq)
{
	bool found = false;

	/* Flush pending SQ submissions before polling CQ */
	nvme_sq_flush(nvmeq);

	nvme_dbg(UBLK_DBG_IO, "%s: qid %d polling cq_head %u cq_phase %u io_inflight %u\n",
			__func__, q->q_id, nvmeq->cq_head, nvmeq->cq_phase,
			t->io_inflight);

	while (nvme_cqe_pending(nvmeq)) {
		struct nvme_completion *cqe = &((struct nvme_completion *)nvmeq->cq_buffer)[nvmeq->cq_head];
		__u16 status_field, status, cid;
		int tag, result;
		const struct ublksrv_io_desc *iod;

		found = true;

		/*
		 * Load-load control dependency between phase and the rest of
		 * the CQE requires a read memory barrier (see kernel's
		 * nvme_poll_cq which uses dma_rmb() here).
		 */
		ublk_rmb();

		/* Extract completion info */
		status_field = READ_ONCE(cqe->status);
		cid = READ_ONCE(cqe->command_id);
		status = status_field >> 1;
		tag = cid;

		nvme_dbg(UBLK_DBG_IO, "%s: cqe[%u] status=0x%x cid=%u\n",
				__func__, nvmeq->cq_head, status_field, cid);

		/* Get I/O descriptor */
		iod = ublk_get_iod(q, tag);

		/* Convert status to result */
		if (status == 0) {
			result = iod->nr_sectors << 9;
		} else {
			result = -EIO;
		}

		nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d status %u result %d\n",
				__func__, q->q_id, tag, status, result);

		/* Mark target I/O as completed (decrements io_inflight) */
		ublk_completed_tgt_io(t, q, tag);

		/* Complete I/O back to ublk driver */
		ublk_complete_io(t, q, tag, result);

		/* Advance CQ head */
		nvme_update_cq_head(nvmeq);
	}

	/* Update doorbell */
	if (found)
		ublk_writel(nvmeq->cq_head, nvmeq->cq_doorbell);
}

/* Queue read/write I/O */
static int nvme_queue_rw_io(struct ublk_thread *t, struct ublk_queue *q,
			    struct nvme_queue *nvmeq,
			    const struct ublksrv_io_desc *iod, int tag)
{
	struct nvme_vfio_tgt_data *data = q->dev->private_data;
	struct nvme_rw_command *cmd;
	struct nvme_io_priv *priv;
	__u64 slba, iova;
	__u32 nlb;
	size_t len, remaining;
	unsigned int op;

	/* Convert sectors to LBAs */
	slba = iod->start_sector >> (data->lba_shift - 9);
	nlb = (iod->nr_sectors >> (data->lba_shift - 9)) - 1;
	len = iod->nr_sectors << 9;

	/*
	 * Get or create DMA mapping for this I/O buffer.
	 * Map on first use and keep mapped for performance (avoids expensive
	 * map/unmap on every I/O). Buffers are only unmapped during cleanup.
	 */
	priv = nvme_get_io_priv(q, tag);
	iova = priv->data_mapping.iova;
	if (!iova) {
		size_t buf_size = q->dev->dev_info.max_io_buf_bytes;
		void *buf_addr = (void *)iod->addr;

		/* First use - map the buffer and keep it mapped */
		iova = nvme_map_dma(data, buf_addr, buf_size, &priv->data_mapping);
		if (!iova) {
			fprintf(stderr, "Failed to map I/O buffer tag %d\n", tag);
			munlock(buf_addr, buf_size);
			return -ENOMEM;
		}
	}

	/* Get SQ entry */
	cmd = (struct nvme_rw_command *)nvmeq->sq_buffer + nvmeq->sq_tail;

	/* Fill command - no memset, explicitly initialize all fields */
	op = ublksrv_get_op(iod);
	cmd->opcode = (op == UBLK_IO_OP_WRITE) ? NVME_CMD_WRITE : NVME_CMD_READ;
	cmd->flags = 0;
	cmd->cid = tag;
	cmd->nsid = data->nsid;
	cmd->rsvd2 = 0;
	cmd->metadata = 0;
	/* prp1/prp2 set below */
	cmd->slba = htole64(slba);
	cmd->length = htole16(nlb);
	cmd->control = (ublksrv_get_flags(iod) & UBLK_IO_F_FUA) ? htole16(NVME_RW_FUA) : 0;
	cmd->dsmgmt = 0;
	cmd->reftag = 0;
	cmd->apptag = 0;
	cmd->appmask = 0;

	/*
	 * Setup PRP entries:
	 * - PRP1: first page (can start at any offset)
	 * - PRP2: either second page directly, or pointer to PRP list
	 * - PRP list: array of page addresses for remaining pages
	 */
	cmd->prp1 = htole64(iova);
	remaining = len;

	/* Skip first page */
	__u64 first_page_len = PAGE_SIZE - (iova & (PAGE_SIZE - 1));
	if (first_page_len > remaining)
		first_page_len = remaining;
	remaining -= first_page_len;
	iova += first_page_len;

	if (remaining == 0) {
		/* Single page - PRP2 not needed */
		cmd->prp2 = 0;
	} else if (remaining <= PAGE_SIZE) {
		/* Two pages - PRP2 points directly to second page */
		if (!nvme_use_iommu(data)) {
			/* NoIOMMU: look up physical address of second page */
			__u64 vaddr_page2 = ((__u64)iod->addr + first_page_len) & ~(PAGE_SIZE - 1);
			__u64 paddr2 = nvme_virt_to_phys(data, vaddr_page2);
			if (!paddr2) {
				fprintf(stderr, "Failed to get paddr for 2nd page\n");
				return -EINVAL;
			}
			cmd->prp2 = htole64(paddr2);
		} else {
			/* IOMMU mode: addresses are contiguous */
			cmd->prp2 = htole64(iova);
		}
	} else {
		/* Multiple pages - PRP2 points to PRP list */
		cmd->prp2 = htole64(priv->prp_mapping.iova);

		/* Build PRP list for remaining pages using helper */
		if (nvme_build_prp_list(data, (void *)iod->addr, len,
					priv->data_mapping.iova,
					priv->prp_list,
					PAGE_SIZE / sizeof(__le64)) < 0) {
			return -EINVAL;
		}
	}

	/* Submit command: advance sq_tail and write doorbell if needed */
	nvme_sq_submit_cmd(nvmeq);

	nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d submitted slba=%llu nlb=%u sq_tail=%u\n",
			__func__, q->q_id, tag, (__u64)slba, nlb, nvmeq->sq_tail);

	return 0;
}

/* Queue flush I/O */
static int nvme_queue_flush_io(struct ublk_thread *t, struct ublk_queue *q,
			       struct nvme_queue *nvmeq,
			       const struct ublksrv_io_desc *iod, int tag)
{
	struct nvme_vfio_tgt_data *data = q->dev->private_data;
	struct nvme_common_command *cmd;

	/* Get SQ entry */
	cmd = (struct nvme_common_command *)nvmeq->sq_buffer + nvmeq->sq_tail;

	/* Fill command - no memset, explicitly initialize all fields */
	cmd->opcode = NVME_CMD_FLUSH;
	cmd->flags = 0;
	cmd->cid = tag;
	cmd->nsid = data->nsid;
	cmd->cdw2[0] = 0;
	cmd->cdw2[1] = 0;
	cmd->metadata = 0;
	cmd->prp1 = 0;
	cmd->prp2 = 0;
	cmd->cdw10 = 0;
	cmd->cdw11 = 0;
	cmd->cdw12 = 0;
	cmd->cdw13 = 0;
	cmd->cdw14 = 0;
	cmd->cdw15 = 0;

	/* Submit command: advance sq_tail and write doorbell if needed */
	nvme_sq_submit_cmd(nvmeq);

	nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d submitted sq_tail=%u\n",
			__func__, q->q_id, tag, nvmeq->sq_tail);

	return 0;
}

/* Queue I/O callback */
static int nvme_vfio_queue_io(struct ublk_thread *t, struct ublk_queue *q,
			      int tag)
{
	struct nvme_vfio_tgt_data *data = q->dev->private_data;
	const struct ublksrv_io_desc *iod = ublk_get_iod(q, tag);
	struct nvme_queue *nvmeq = &data->io_queues[q->q_id];
	unsigned int op = ublksrv_get_op(iod);
	int ret;

	nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d op %x sector %llx len %u sq_tail %u io_inflight %u\n",
			__func__, q->q_id, tag, op, iod->start_sector,
			iod->nr_sectors, nvmeq->sq_tail, t->io_inflight);

	switch (op) {
	case UBLK_IO_OP_READ:
	case UBLK_IO_OP_WRITE:
		ret = nvme_queue_rw_io(t, q, nvmeq, iod, tag);
		break;
	case UBLK_IO_OP_FLUSH:
		ret = nvme_queue_flush_io(t, q, nvmeq, iod, tag);
		break;
	default:
		ret = -EINVAL;
	}

	if (ret < 0) {
		nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d failed %d\n",
				__func__, q->q_id, tag, ret);
		ublk_complete_io(t, q, tag, ret);
		return 0;
	}

	/* Mark I/O in-flight */
	ublk_queued_tgt_io(t, q, tag, 1);

	nvme_dbg(UBLK_DBG_IO, "%s: qid %d tag %d queued, io_inflight %u\n",
			__func__, q->q_id, tag, t->io_inflight);

	return 0;
}

/* Poll queue callback - called by event loop to poll NVMe CQ */
static void nvme_vfio_poll_queue(struct ublk_thread *t, struct ublk_queue *q)
{
	struct nvme_vfio_tgt_data *data = q->dev->private_data;
	struct nvme_queue *nvmeq = &data->io_queues[q->q_id];

	nvme_poll_cq(t, q, nvmeq);
}

/* Delete I/O queue */
static int nvme_delete_io_queue(struct nvme_vfio_tgt_data *data, int qid)
{
	struct nvme_delete_queue cmd = {};

	/* Delete SQ */
	cmd.opcode = NVME_ADMIN_DELETE_SQ;
	cmd.qid = qid;
	nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));

	/* Delete CQ */
	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = NVME_ADMIN_DELETE_CQ;
	cmd.qid = qid;
	nvme_submit_admin_cmd(data, &cmd, sizeof(cmd));

	return 0;
}

/* Deinitialize target */
static void nvme_vfio_tgt_deinit(struct ublk_dev *dev)
{
	struct nvme_vfio_tgt_data *data = dev->private_data;
	volatile void *bar;
	__u32 cc, csts;
	int i;

	if (!data)
		return;

	bar = data->bar0;

	/* Delete I/O queues and free per-IO DMA mappings */
	for (i = 0; i < data->nr_io_queues; i++) {
		struct nvme_queue *ioq = &data->io_queues[i];
		struct ublk_queue *q = &dev->q[i];
		int tag;

		nvme_delete_io_queue(data, i + 1);

		/* Unmap and free per-IO DMA mappings and PRP lists */
		for (tag = 0; tag < dev->dev_info.queue_depth; tag++) {
			struct ublk_io *io = ublk_get_io(q, tag);
			if (io->private_data) {
				struct nvme_io_priv *priv =
					(struct nvme_io_priv *)io->private_data;
				/* Unmap the pre-mapped I/O buffer */
				if (priv->data_mapping.iova)
					nvme_unmap_dma(data, &priv->data_mapping);
				/* Unmap PRP list (buffer freed with pool) */
				if (priv->prp_mapping.iova)
					nvme_unmap_dma(data, &priv->prp_mapping);
				free(io->private_data);
				io->private_data = NULL;
			}
		}

		/* Cleanup queue buffers */
		nvme_queue_deinit(data, ioq);
	}
	free(data->io_queues);

	/* Shutdown controller */
	if (bar) {
		cc = nvme_readl(bar, NVME_REG_CC);
		cc |= NVME_CC_SHN_NORMAL;
		nvme_writel(bar, NVME_REG_CC, cc);

		/* Wait for shutdown complete */
		for (i = 0; i < 5000; i++) {
			csts = nvme_readl(bar, NVME_REG_CSTS);
			if ((csts & NVME_CSTS_SHST_MASK) == NVME_CSTS_SHST_COMPLETE)
				break;
			usleep(1000);
		}

		/* Disable controller */
		cc &= ~NVME_CC_ENABLE;
		nvme_writel(bar, NVME_REG_CC, cc);

		for (i = 0; i < 5000; i++) {
			csts = nvme_readl(bar, NVME_REG_CSTS);
			if (!(csts & NVME_CSTS_RDY))
				break;
			usleep(1000);
		}
	}

	/* Cleanup admin queue */
	nvme_queue_deinit(data, &data->admin_queue);

	/* Unmap BAR */
	if (data->bar0) {
		munmap((void *)data->bar0, data->bar0_size);
	}

	/* Close VFIO descriptors */
	if (data->device_fd >= 0)
		close(data->device_fd);
	if (data->group_fd >= 0)
		close(data->group_fd);
	if (data->container_fd >= 0)
		close(data->container_fd);

	/* Destroy spinlock */
	pthread_spin_destroy(&data->iova_lock);

	/* Free dma_buf pool */
	nvme_dmabuf_pool_deinit(data);

	printf("VFIO NVMe target cleaned up\n");

	free(data);
	dev->private_data = NULL;
}

/* Enable PCI Bus Mastering and disable INTx */
static int nvme_enable_pci_bus_master(int device_fd)
{
	struct vfio_region_info config_region = { .argsz = sizeof(config_region) };
	__u16 cmd_reg;

	/* Get PCI config space region info (index 7 = VFIO_PCI_CONFIG_REGION_INDEX) */
	config_region.index = 7;  /* VFIO_PCI_CONFIG_REGION_INDEX */
	if (ioctl(device_fd, VFIO_DEVICE_GET_REGION_INFO, &config_region) < 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO (config)");
		return -1;
	}

	/* Read PCI Command register (offset 0x04) */
	if (pread(device_fd, &cmd_reg, sizeof(cmd_reg),
		  config_region.offset + 0x04) != sizeof(cmd_reg)) {
		perror("pread PCI command register");
		return -1;
	}

	/* Enable Bus Master (bit 2) and disable INTx (bit 10) */
	cmd_reg |= 0x0404;

	/* Write back */
	if (pwrite(device_fd, &cmd_reg, sizeof(cmd_reg),
		   config_region.offset + 0x04) != sizeof(cmd_reg)) {
		perror("pwrite PCI command register");
		return -1;
	}

	/* Verify */
	if (pread(device_fd, &cmd_reg, sizeof(cmd_reg),
		  config_region.offset + 0x04) != sizeof(cmd_reg)) {
		perror("pread PCI command register (verify)");
		return -1;
	}

	if (!(cmd_reg & 0x04)) {
		fprintf(stderr, "ERROR: Failed to enable Bus Mastering\n");
		return -1;
	}

	return 0;
}

/*
 * Open VFIO group and attach to container
 *
 * Handles both regular IOMMU and no-IOMMU modes:
 * - Tries /dev/vfio/N first for regular IOMMU
 * - Falls back to /dev/vfio/noiommu-N for no-IOMMU mode
 *
 * Returns group_fd on success, -1 on failure
 */
static int nvme_open_vfio_group(int iommu_group, int container_fd,
				int *use_noiommu)
{
	struct vfio_group_status group_status = { .argsz = sizeof(group_status) };
	char group_path[256];
	int group_fd;

	/* Try regular VFIO group first */
	snprintf(group_path, sizeof(group_path), "/dev/vfio/%d", iommu_group);

	if (access(group_path, F_OK) != 0) {
		/* Try noiommu group path */
		snprintf(group_path, sizeof(group_path),
			 "/dev/vfio/noiommu-%d", iommu_group);
		fprintf(stderr, "Regular VFIO group not found, trying: %s\n",
			group_path);

		if (access(group_path, F_OK) != 0) {
			fprintf(stderr, "No VFIO or noiommu group found for group %d\n",
				iommu_group);
			return -1;
		}
		*use_noiommu = 1;
	}

	group_fd = open(group_path, O_RDWR);
	if (group_fd < 0) {
		perror("open vfio group");
		return -1;
	}

	/* Check group viability */
	if (ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status) < 0) {
		perror("VFIO_GROUP_GET_STATUS");
		goto err_close;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		fprintf(stderr, "VFIO group not viable\n");
		goto err_close;
	}

	/* Attach group to container */
	if (ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd) < 0) {
		perror("VFIO_GROUP_SET_CONTAINER");
		goto err_close;
	}

	/* Enable IOMMU */
	if (*use_noiommu) {
		if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) < 0) {
			perror("VFIO_SET_IOMMU (no-IOMMU)");
			goto err_close;
		}
	} else {
		if (ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0) {
			perror("VFIO_SET_IOMMU");
			goto err_close;
		}
	}

	return group_fd;

err_close:
	close(group_fd);
	return -1;
}

/* Initialize target */
static int nvme_vfio_tgt_init(const struct dev_ctx *ctx, struct ublk_dev *dev)
{
	struct nvme_vfio_tgt_data *data;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct vfio_region_info region_info = { .argsz = sizeof(region_info) };
	const char *pci_addr;
	__u64 cap;
	int version;

	/* nvme_vfio only supports page copy mode, not zero copy */
	if (dev->dev_info.flags & UBLK_F_AUTO_BUF_REG) {
		ublk_err("%s: auto zero copy (--auto_zc) not supported (page copy only)\n", __func__);
		return -EINVAL;
	}

	if (dev->dev_info.flags & UBLK_F_SUPPORT_ZERO_COPY) {
		ublk_err("%s: zero copy (-z) not supported (page copy only)\n", __func__);
		return -EINVAL;
	}

	fprintf(stderr, "nvme_vfio_tgt_init: starting initialization\n");

	/* Allocate private data */
	data = calloc(1, sizeof(*data));
	if (!data) {
		perror("calloc");
		return -1;
	}

	dev->private_data = data;
	data->force_noiommu = ctx->nvme_vfio.force_noiommu;
	data->container_fd = -1;
	data->group_fd = -1;
	data->device_fd = -1;
	data->next_iova = 0x100000000ULL;  /* Start at 4GB */
	data->dev = dev;
	pthread_spin_init(&data->iova_lock, PTHREAD_PROCESS_PRIVATE);
	/*
	 * With PRP list support (512 entries per 4KB page), we can support
	 * up to 512 pages = 2MB transfers. Set to 1MB for safety.
	 */
	data->max_transfer_shift = 20;      /* 1MB max transfer */

	/* Get PCI address from backing file */
	if (dev->tgt.nr_backing_files != 1) {
		fprintf(stderr, "Wrong PCI address specified\n");
		goto err;
	}

	pci_addr = dev->tgt.backing_file[0];
	if (strlen(pci_addr) == 0) {
		fprintf(stderr, "Empty PCI address\n");
		goto err;
	}
	if (strlen(pci_addr) >= sizeof(data->pci_addr)) {
		fprintf(stderr, "PCI address too long\n");
		goto err;
	}
	strcpy(data->pci_addr, pci_addr);

	printf("Initializing VFIO NVMe target for %s\n", pci_addr);

	/* Setup VFIO binding */
	if (setup_vfio_binding(pci_addr) < 0) {
		fprintf(stderr, "Failed to bind device to vfio-pci\n");
		goto err;
	}

	/* Get IOMMU group */
	data->iommu_group = get_iommu_group(pci_addr, &data->use_noiommu);
	if (data->iommu_group < 0) {
		fprintf(stderr, "Failed to get IOMMU group\n");
		goto err;
	}

	/* Open container */
	data->container_fd = open("/dev/vfio/vfio", O_RDWR);
	if (data->container_fd < 0) {
		perror("open /dev/vfio/vfio");
		goto err;
	}

	/* Check API version */
	version = ioctl(data->container_fd, VFIO_GET_API_VERSION);
	if (version != VFIO_API_VERSION) {
		fprintf(stderr, "VFIO API version mismatch\n");
		goto err;
	}

	/* Check IOMMU support */
	if (data->use_noiommu) {
		if (!ioctl(data->container_fd, VFIO_CHECK_EXTENSION, VFIO_NOIOMMU_IOMMU)) {
			fprintf(stderr, "VFIO no-IOMMU not supported\n");
			goto err;
		}
	} else {
		if (!ioctl(data->container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU)) {
			fprintf(stderr, "VFIO Type1 IOMMU not supported\n");
			goto err;
		}
	}

	/* Open VFIO group and attach to container */
	data->group_fd = nvme_open_vfio_group(data->iommu_group,
					      data->container_fd,
					      &data->use_noiommu);
	if (data->group_fd < 0)
		goto err;

	/* Get device */
	data->device_fd = ioctl(data->group_fd, VFIO_GROUP_GET_DEVICE_FD, pci_addr);
	if (data->device_fd < 0) {
		perror("VFIO_GROUP_GET_DEVICE_FD");
		goto err;
	}

	/* Get device info */
	if (ioctl(data->device_fd, VFIO_DEVICE_GET_INFO, &device_info) < 0) {
		perror("VFIO_DEVICE_GET_INFO");
		goto err;
	}

	/* Enable PCI Bus Mastering and disable INTx */
	if (nvme_enable_pci_bus_master(data->device_fd) < 0)
		goto err;

	/* Map BAR0 */
	region_info.index = 0;
	if (ioctl(data->device_fd, VFIO_DEVICE_GET_REGION_INFO, &region_info) < 0) {
		perror("VFIO_DEVICE_GET_REGION_INFO");
		goto err;
	}

	data->bar0_size = region_info.size;
	data->bar0 = mmap(NULL, region_info.size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, data->device_fd, region_info.offset);
	if (data->bar0 == MAP_FAILED) {
		perror("mmap BAR0");
		goto err;
	}

	/* Read capabilities */
	cap = nvme_readq(data->bar0, NVME_REG_CAP);
	data->db_stride = (1 << ((cap >> 32) & 0xF)) * 4;

	//printf("NVMe CAP: doorbell stride = %u bytes\n", data->db_stride);

	/* Initialize dma_buf pool for all DMA buffers */
	if (nvme_dmabuf_pool_init(data) < 0) {
		fprintf(stderr, "Failed to initialize dma_buf pool\n");
		goto err;
	}

	/* Pre-read pagemap for noiommu mode (avoids syscalls in I/O path) */
	if (!nvme_use_iommu(data)) {
		if (nvme_read_pagemap(data) < 0) {
			fprintf(stderr, "Failed to read pagemap\n");
			goto err;
		}
	}

	/* Initialize controller */
	if (nvme_init_controller(data) < 0)
		goto err;

	/* Identify namespace */
	if (nvme_identify_namespace(data, dev) < 0)
		goto err;

	/* Setup I/O queues */
	if (nvme_setup_io_queues(data, dev) < 0)
		goto err;

	printf("VFIO NVMe target initialized successfully\n");
	return 0;

err:
	nvme_vfio_tgt_deinit(dev);
	return -1;
}

/* I/O buffer allocation callback - returns buffer from dma_buf pool */
static void *nvme_vfio_alloc_io_buf(struct ublk_queue *q, int tag)
{
	struct nvme_vfio_tgt_data *data = q->dev->private_data;

	return nvme_pool_get_io_buf(data, q->q_id, tag);
}

/* I/O buffer free callback - no-op, pool freed at deinit */
static void nvme_vfio_free_io_buf(struct ublk_queue *q, int tag)
{
	/* Pool memory freed when pool is destroyed */
}

/* Command-line parsing for nvme_vfio target */
static void nvme_vfio_parse_cmd_line(struct dev_ctx *ctx, int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "noiommu",  0,  NULL,  0  },
		{ NULL,       0,  NULL,  0  }
	};
	int option_idx, opt;

	ctx->nvme_vfio.force_noiommu = 0;

	while ((opt = getopt_long(argc, argv, "",
				  longopts, &option_idx)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(longopts[option_idx].name, "noiommu")) {
				ctx->nvme_vfio.force_noiommu = 1;
				fprintf(stderr, "nvme_vfio: forcing noiommu mode (using virtual addresses as IOVAs)\n");
			}
			break;
		}
	}
}

static void nvme_vfio_usage(const struct ublk_tgt_ops *ops)
{
	printf("\tnvme_vfio: [--noiommu]\n");
	printf("\t  --noiommu: Force noiommu mode (use virtual addresses as IOVAs)\n");
	printf("\t             Suitable for VM environments without IOMMU\n");
}

/* Target operations structure */
const struct ublk_tgt_ops nvme_vfio_tgt_ops = {
	.name = "nvme_vfio",
	.init_tgt = nvme_vfio_tgt_init,
	.deinit_tgt = nvme_vfio_tgt_deinit,
	.queue_io = nvme_vfio_queue_io,
	.poll_queue = nvme_vfio_poll_queue,
	.alloc_io_buf = nvme_vfio_alloc_io_buf,
	.free_io_buf = nvme_vfio_free_io_buf,
	.parse_cmd_line = nvme_vfio_parse_cmd_line,
	.usage = nvme_vfio_usage,
};
