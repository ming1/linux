#include "kvm/virtio-pci.h"

#include "kvm/ioport.h"
#include "kvm/kvm.h"
#include "kvm/virtio-pci-dev.h"
#include "kvm/irq.h"
#include "kvm/virtio.h"
#include "kvm/ioeventfd.h"
#include "kvm/virtio-trans.h"

#include <linux/virtio_pci.h>
#include <linux/byteorder.h>
#include <string.h>

struct virtio_trans_ops *virtio_pci__get_trans_ops(void)
{
	static struct virtio_trans_ops virtio_pci_trans = (struct virtio_trans_ops) {
		.signal_vq	= virtio_pci__signal_vq,
		.signal_config	= virtio_pci__signal_config,
		.init		= virtio_pci__init,
	};
	return &virtio_pci_trans;
};

static void virtio_pci__ioevent_callback(struct kvm *kvm, void *param)
{
	struct virtio_pci_ioevent_param *ioeventfd = param;
	struct virtio_pci *vpci = ioeventfd->vtrans->virtio;

	ioeventfd->vtrans->virtio_ops->notify_vq(kvm, vpci->dev, ioeventfd->vq);
}

static int virtio_pci__init_ioeventfd(struct kvm *kvm, struct virtio_trans *vtrans, u32 vq)
{
	struct ioevent ioevent;
	struct virtio_pci *vpci = vtrans->virtio;

	vpci->ioeventfds[vq] = (struct virtio_pci_ioevent_param) {
		.vtrans		= vtrans,
		.vq		= vq,
	};

	ioevent = (struct ioevent) {
		.io_addr	= vpci->base_addr + VIRTIO_PCI_QUEUE_NOTIFY,
		.io_len		= sizeof(u16),
		.fn		= virtio_pci__ioevent_callback,
		.fn_ptr		= &vpci->ioeventfds[vq],
		.datamatch	= vq,
		.fn_kvm		= kvm,
		.fd		= eventfd(0, 0),
	};

	ioeventfd__add_event(&ioevent);

	if (vtrans->virtio_ops->notify_vq_eventfd)
		vtrans->virtio_ops->notify_vq_eventfd(kvm, vpci->dev, vq, ioevent.fd);

	return 0;
}

static inline bool virtio_pci__msix_enabled(struct virtio_pci *vpci)
{
	return vpci->pci_hdr.msix.ctrl & cpu_to_le16(PCI_MSIX_FLAGS_ENABLE);
}

static bool virtio_pci__specific_io_in(struct kvm *kvm, struct virtio_trans *vtrans, u16 port,
					void *data, int size, int offset)
{
	u32 config_offset;
	struct virtio_pci *vpci = vtrans->virtio;
	int type = virtio__get_dev_specific_field(offset - 20,
							virtio_pci__msix_enabled(vpci),
							&config_offset);
	if (type == VIRTIO_PCI_O_MSIX) {
		switch (offset) {
		case VIRTIO_MSI_CONFIG_VECTOR:
			ioport__write16(data, vpci->config_vector);
			break;
		case VIRTIO_MSI_QUEUE_VECTOR:
			ioport__write16(data, vpci->vq_vector[vpci->queue_selector]);
			break;
		};

		return true;
	} else if (type == VIRTIO_PCI_O_CONFIG) {
		u8 cfg;

		cfg = vtrans->virtio_ops->get_config(kvm, vpci->dev, config_offset);
		ioport__write8(data, cfg);
		return true;
	}

	return false;
}

static bool virtio_pci__io_in(struct ioport *ioport, struct kvm *kvm, u16 port, void *data, int size)
{
	unsigned long offset;
	bool ret = true;
	struct virtio_trans *vtrans;
	struct virtio_pci *vpci;
	u32 val;

	vtrans = ioport->priv;
	vpci = vtrans->virtio;
	offset = port - vpci->base_addr;

	switch (offset) {
	case VIRTIO_PCI_HOST_FEATURES:
		val = vtrans->virtio_ops->get_host_features(kvm, vpci->dev);
		ioport__write32(data, val);
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		val = vtrans->virtio_ops->get_pfn_vq(kvm, vpci->dev, vpci->queue_selector);
		ioport__write32(data, val);
		break;
	case VIRTIO_PCI_QUEUE_NUM:
		val = vtrans->virtio_ops->get_size_vq(kvm, vpci->dev, vpci->queue_selector);
		ioport__write16(data, val);
		break;
	case VIRTIO_PCI_STATUS:
		ioport__write8(data, vpci->status);
		break;
	case VIRTIO_PCI_ISR:
		ioport__write8(data, vpci->isr);
		kvm__irq_line(kvm, vpci->pci_hdr.irq_line, VIRTIO_IRQ_LOW);
		vpci->isr = VIRTIO_IRQ_LOW;
		break;
	default:
		ret = virtio_pci__specific_io_in(kvm, vtrans, port, data, size, offset);
		break;
	};

	return ret;
}

static bool virtio_pci__specific_io_out(struct kvm *kvm, struct virtio_trans *vtrans, u16 port,
					void *data, int size, int offset)
{
	struct virtio_pci *vpci = vtrans->virtio;
	u32 config_offset, gsi, vec;
	int type = virtio__get_dev_specific_field(offset - 20, virtio_pci__msix_enabled(vpci),
							&config_offset);
	if (type == VIRTIO_PCI_O_MSIX) {
		switch (offset) {
		case VIRTIO_MSI_CONFIG_VECTOR:
			vec = vpci->config_vector = ioport__read16(data);

			gsi = irq__add_msix_route(kvm, &vpci->msix_table[vec].msg);

			vpci->config_gsi = gsi;
			break;
		case VIRTIO_MSI_QUEUE_VECTOR:
			vec = vpci->vq_vector[vpci->queue_selector] = ioport__read16(data);

			gsi = irq__add_msix_route(kvm, &vpci->msix_table[vec].msg);
			vpci->gsis[vpci->queue_selector] = gsi;
			if (vtrans->virtio_ops->notify_vq_gsi)
				vtrans->virtio_ops->notify_vq_gsi(kvm, vpci->dev,
							vpci->queue_selector, gsi);
			break;
		};

		return true;
	} else if (type == VIRTIO_PCI_O_CONFIG) {
		vtrans->virtio_ops->set_config(kvm, vpci->dev, *(u8 *)data, config_offset);

		return true;
	}

	return false;
}

static bool virtio_pci__io_out(struct ioport *ioport, struct kvm *kvm, u16 port, void *data, int size)
{
	unsigned long offset;
	bool ret = true;
	struct virtio_trans *vtrans;
	struct virtio_pci *vpci;
	u32 val;

	vtrans = ioport->priv;
	vpci = vtrans->virtio;
	offset = port - vpci->base_addr;

	switch (offset) {
	case VIRTIO_PCI_GUEST_FEATURES:
		val = ioport__read32(data);
		vtrans->virtio_ops->set_guest_features(kvm, vpci->dev, val);
		break;
	case VIRTIO_PCI_QUEUE_PFN:
		val = ioport__read32(data);
		virtio_pci__init_ioeventfd(kvm, vtrans, vpci->queue_selector);
		vtrans->virtio_ops->init_vq(kvm, vpci->dev, vpci->queue_selector, val);
		break;
	case VIRTIO_PCI_QUEUE_SEL:
		vpci->queue_selector = ioport__read16(data);
		break;
	case VIRTIO_PCI_QUEUE_NOTIFY:
		val = ioport__read16(data);
		vtrans->virtio_ops->notify_vq(kvm, vpci->dev, val);
		break;
	case VIRTIO_PCI_STATUS:
		vpci->status = ioport__read8(data);
		break;
	default:
		ret = virtio_pci__specific_io_out(kvm, vtrans, port, data, size, offset);
		break;
	};

	return ret;
}

static struct ioport_operations virtio_pci__io_ops = {
	.io_in	= virtio_pci__io_in,
	.io_out	= virtio_pci__io_out,
};

static void callback_mmio_table(u64 addr, u8 *data, u32 len, u8 is_write, void *ptr)
{
	struct virtio_pci *vpci = ptr;
	void *table;
	u32 offset;

	if (addr > vpci->msix_io_block + PCI_IO_SIZE) {
		table	= &vpci->msix_pba;
		offset	= vpci->msix_io_block + PCI_IO_SIZE;
	} else {
		table	= &vpci->msix_table;
		offset	= vpci->msix_io_block;
	}

	if (is_write)
		memcpy(table + addr - offset, data, len);
	else
		memcpy(data, table + addr - offset, len);
}

int virtio_pci__signal_vq(struct kvm *kvm, struct virtio_trans *vtrans, u32 vq)
{
	struct virtio_pci *vpci = vtrans->virtio;
	int tbl = vpci->vq_vector[vq];

	if (virtio_pci__msix_enabled(vpci)) {
		if (vpci->pci_hdr.msix.ctrl & cpu_to_le16(PCI_MSIX_FLAGS_MASKALL) ||
		    vpci->msix_table[tbl].ctrl & cpu_to_le16(PCI_MSIX_ENTRY_CTRL_MASKBIT)) {

			vpci->msix_pba |= 1 << tbl;
			return 0;
		}

		kvm__irq_trigger(kvm, vpci->gsis[vq]);
	} else {
		vpci->isr = VIRTIO_IRQ_HIGH;
		kvm__irq_trigger(kvm, vpci->pci_hdr.irq_line);
	}
	return 0;
}

int virtio_pci__signal_config(struct kvm *kvm, struct virtio_trans *vtrans)
{
	struct virtio_pci *vpci = vtrans->virtio;
	int tbl = vpci->config_vector;

	if (virtio_pci__msix_enabled(vpci)) {
		if (vpci->pci_hdr.msix.ctrl & cpu_to_le16(PCI_MSIX_FLAGS_MASKALL) ||
		    vpci->msix_table[tbl].ctrl & cpu_to_le16(PCI_MSIX_ENTRY_CTRL_MASKBIT)) {

			vpci->msix_pba |= 1 << tbl;
			return 0;
		}

		kvm__irq_trigger(kvm, vpci->config_gsi);
	} else {
		vpci->isr = VIRTIO_PCI_ISR_CONFIG;
		kvm__irq_trigger(kvm, vpci->pci_hdr.irq_line);
	}

	return 0;
}

int virtio_pci__init(struct kvm *kvm, struct virtio_trans *vtrans, void *dev,
			int device_id, int subsys_id, int class)
{
	struct virtio_pci *vpci = vtrans->virtio;
	u8 pin, line, ndev;

	vpci->dev = dev;
	vpci->msix_io_block = pci_get_io_space_block(PCI_IO_SIZE * 2);

	vpci->base_addr = ioport__register(IOPORT_EMPTY, &virtio_pci__io_ops, IOPORT_SIZE, vtrans);
	kvm__register_mmio(kvm, vpci->msix_io_block, PCI_IO_SIZE, false, callback_mmio_table, vpci);

	vpci->pci_hdr = (struct pci_device_header) {
		.vendor_id		= cpu_to_le16(PCI_VENDOR_ID_REDHAT_QUMRANET),
		.device_id		= cpu_to_le16(device_id),
		.header_type		= PCI_HEADER_TYPE_NORMAL,
		.revision_id		= 0,
		.class[0]		= class & 0xff,
		.class[1]		= (class >> 8) & 0xff,
		.class[2]		= (class >> 16) & 0xff,
		.subsys_vendor_id	= cpu_to_le16(PCI_SUBSYSTEM_VENDOR_ID_REDHAT_QUMRANET),
		.subsys_id		= cpu_to_le16(subsys_id),
		.bar[0]			= cpu_to_le32(vpci->base_addr
							| PCI_BASE_ADDRESS_SPACE_IO),
		.bar[1]			= cpu_to_le32(vpci->msix_io_block
							| PCI_BASE_ADDRESS_SPACE_MEMORY),
		.status			= cpu_to_le16(PCI_STATUS_CAP_LIST),
		.capabilities		= (void *)&vpci->pci_hdr.msix - (void *)&vpci->pci_hdr,
		.bar_size[0]		= IOPORT_SIZE,
		.bar_size[1]		= PCI_IO_SIZE,
		.bar_size[3]		= PCI_IO_SIZE,
	};

	vpci->pci_hdr.msix.cap = PCI_CAP_ID_MSIX;
	vpci->pci_hdr.msix.next = 0;
	/*
	 * We at most have VIRTIO_PCI_MAX_VQ entries for virt queue,
	 * VIRTIO_PCI_MAX_CONFIG entries for config.
	 *
	 * To quote the PCI spec:
	 *
	 * System software reads this field to determine the
	 * MSI-X Table Size N, which is encoded as N-1.
	 * For example, a returned value of "00000000011"
	 * indicates a table size of 4.
	 */
	vpci->pci_hdr.msix.ctrl = cpu_to_le16(VIRTIO_PCI_MAX_VQ + VIRTIO_PCI_MAX_CONFIG - 1);

	/*
	 * Both table and PBA could be mapped on the same BAR, but for now
	 * we're not in short of BARs
	 */
	vpci->pci_hdr.msix.table_offset = cpu_to_le32(1); /* Use BAR 1 */
	vpci->pci_hdr.msix.pba_offset = cpu_to_le32(1 | PCI_IO_SIZE); /* Use BAR 3 */
	vpci->config_vector = 0;

	if (irq__register_device(subsys_id, &ndev, &pin, &line) < 0)
		return -1;

	vpci->pci_hdr.irq_pin	= pin;
	vpci->pci_hdr.irq_line	= line;
	pci__register(&vpci->pci_hdr, ndev);

	return 0;
}
