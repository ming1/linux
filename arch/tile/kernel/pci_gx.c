/*
 * Copyright 2011 Tilera Corporation. All Rights Reserved.
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation, version 2.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 *   NON INFRINGEMENT.  See the GNU General Public License for
 *   more details.
 */

#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/bootmem.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <asm/processor.h>
#include <asm/sections.h>
#include <asm/byteorder.h>

#include <gxio/iorpc_globals.h>
#include <gxio/kiorpc.h>
#include <gxio/trio.h>
#include <gxio/iorpc_trio.h>
#include <hv/drv_trio_intf.h>

#include <arch/sim.h>

/*
 * Initialization flow and process
 * -------------------------------
 *
 * This files containes the routines to search for PCI buses,
 * enumerate the buses, and configure any attached devices.
 *
 * There are two entry points here:
 * 1) tile_pci_init
 *    This sets up the pci_controller structs, and opens the
 *    FDs to the hypervisor.  This is called from setup_arch() early
 *    in the boot process.
 * 2) pcibios_init
 *    This probes the PCI bus(es) for any attached hardware.  It's
 *    called by subsys_initcall.  All of the real work is done by the
 *    generic Linux PCI layer.
 *
 */

static int __devinitdata pci_probe = 1;

/* Information on the PCIe RC ports configuration. */
static int __initdata pcie_rc[TILEGX_NUM_TRIO][TILEGX_TRIO_PCIES];

#ifndef GX_FPGA
/* Array of the PCIe ports configuration info obtained from the BIB. */
struct pcie_port_property pcie_ports[TILEGX_NUM_TRIO][TILEGX_TRIO_PCIES];
#endif

/* All drivers share the TRIO contexts defined here. */
gxio_trio_context_t trio_contexts[TILEGX_NUM_TRIO];

/* Pointer to an array of PCIe RC controllers. */
struct pci_controller *pci_controllers;
int num_rc_controllers;
static int num_ep_controllers;

static struct pci_ops tile_cfg_ops;

/* Mask of CPUs that should receive PCIe interrupts. */
static struct cpumask intr_cpus_map;

/*
 * We don't need to worry about the alignment of resources.
 */
resource_size_t pcibios_align_resource(void *data, const struct resource *res,
				resource_size_t size, resource_size_t align)
{
	return res->start;
}
EXPORT_SYMBOL(pcibios_align_resource);


/*
 * Pick a CPU to receive and handle the PCIe interrupts, based on the IRQ #.
 * For now, we simply send interrupts to non-dataplane CPUs.
 * We may implement methods to allow user to specify the target CPUs,
 * e.g. via boot arguments.
 */
static int tile_irq_cpu(int irq)
{
	unsigned int count;
	int i = 0;
	int cpu;

	count = cpumask_weight(&intr_cpus_map);
	if (unlikely(count == 0)) {
		pr_warning("intr_cpus_map empty, interrupts will be"
			   " delievered to dataplane tiles\n");
		return irq % (smp_height * smp_width);
	}

	count = irq % count;
	for_each_cpu(cpu, &intr_cpus_map) {
		if (i++ == count)
			break;
	}
	return cpu;
}

/*
 * Open a file descriptor to the TRIO shim.
 */
static int __devinit tile_pcie_open(int trio_index)
{
	gxio_trio_context_t *context = &trio_contexts[trio_index];
	int ret;

	/*
	 * This opens a file descriptor to the TRIO shim.
	 */
	ret = gxio_trio_init(context, trio_index);
	if (ret < 0)
		return ret;

	/*
	 * Allocate an ASID for the kernel.
	 */
	ret = gxio_trio_alloc_asids(context, 1, 0, 0);
	if (ret < 0) {
		pr_err("PCI: ASID alloc failure on TRIO %d, give up\n",
			trio_index);
		goto asid_alloc_failure;
	}

	context->asid = ret;

#ifdef USE_SHARED_PCIE_CONFIG_REGION
	/*
	 * Alloc a PIO region for config access, shared by all MACs per TRIO.
	 * This shouldn't fail since the kernel is supposed to the first
	 * client of the TRIO's PIO regions.
	 */
	ret = gxio_trio_alloc_pio_regions(context, 1, 0, 0);
	if (ret < 0) {
		pr_err("PCI: CFG PIO alloc failure on TRIO %d, give up\n",
			trio_index);
		goto pio_alloc_failure;
	}

	context->pio_cfg_index = ret;

	/*
	 * For PIO CFG, the bus_address_hi parameter is 0. The mac parameter
	 * is also 0 because it is specified in PIO_REGION_SETUP_CFG_ADDR.
	 */
	ret = gxio_trio_init_pio_region_aux(context, context->pio_cfg_index,
		0, 0, HV_TRIO_PIO_FLAG_CONFIG_SPACE);
	if (ret < 0) {
		pr_err("PCI: CFG PIO init failure on TRIO %d, give up\n",
			trio_index);
		goto pio_alloc_failure;
	}
#endif

	return ret;

asid_alloc_failure:
#ifdef USE_SHARED_PCIE_CONFIG_REGION
pio_alloc_failure:
#endif
	hv_dev_close(context->fd);

	return ret;
}

static void
tilegx_legacy_irq_ack(struct irq_data *d)
{
	__insn_mtspr(SPR_IPI_EVENT_RESET_K, 1UL << d->irq);
}

static void
tilegx_legacy_irq_mask(struct irq_data *d)
{
	__insn_mtspr(SPR_IPI_MASK_SET_K, 1UL << d->irq);
}

static void
tilegx_legacy_irq_unmask(struct irq_data *d)
{
	__insn_mtspr(SPR_IPI_MASK_RESET_K, 1UL << d->irq);
}

static struct irq_chip tilegx_legacy_irq_chip = {
	.name			= "tilegx_legacy_irq",
	.irq_ack		= tilegx_legacy_irq_ack,
	.irq_mask		= tilegx_legacy_irq_mask,
	.irq_unmask		= tilegx_legacy_irq_unmask,

	/* TBD: support set_affinity. */
};

/*
 * This is a wrapper function of the kernel level-trigger interrupt
 * handler handle_level_irq() for PCI legacy interrupts. The TRIO
 * is configured such that only INTx Assert interrupts are proxied
 * to Linux which just calls handle_level_irq() after clearing the
 * MAC INTx Assert status bit associated with this interrupt.
 */
static void
trio_handle_level_irq(unsigned int irq, struct irq_desc *desc)
{
	struct pci_controller *controller = irq_desc_get_handler_data(desc);
	gxio_trio_context_t *trio_context = controller->trio;
	uint64_t intx = (uint64_t)irq_desc_get_chip_data(desc);
	int mac = controller->mac;
	unsigned int reg_offset;
	uint64_t level_mask;

	handle_level_irq(irq, desc);

	/*
	 * Clear the INTx Level status, otherwise future interrupts are
	 * not sent.
	 */
	reg_offset = (TRIO_PCIE_INTFC_MAC_INT_STS <<
		TRIO_CFG_REGION_ADDR__REG_SHIFT) |
		(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_INTERFACE <<
		TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
		(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

	level_mask = TRIO_PCIE_INTFC_MAC_INT_STS__INT_LEVEL_MASK << intx;

	__gxio_mmio_write(trio_context->mmio_base_mac + reg_offset, level_mask);
}

/*
 * Create kernel irqs and set up the handlers for the legacy interrupts.
 * Also some minimum initialization for the MSI support.
 */
static int __devinit tile_init_irqs(struct pci_controller *controller)
{
	int i;
	int j;
	int irq;
	int result;

	cpumask_copy(&intr_cpus_map, cpu_online_mask);


	for (i = 0; i < 4; i++) {
		gxio_trio_context_t *context = controller->trio;
		int cpu;

		/* Ask the kernel to allocate an IRQ. */
		irq = create_irq();
		if (irq < 0) {
			pr_err("PCI: no free irq vectors, failed for %d\n", i);

			goto free_irqs;
		}
		controller->irq_intx_table[i] = irq;

		/* Distribute the 4 IRQs to different tiles. */
		cpu = tile_irq_cpu(irq);

		/* Configure the TRIO intr binding for this IRQ. */
		result = gxio_trio_config_legacy_intr(context, cpu_x(cpu),
						      cpu_y(cpu), KERNEL_PL,
						      irq, controller->mac, i);
		if (result < 0) {
			pr_err("PCI: MAC intx config failed for %d\n", i);

			goto free_irqs;
		}

		/*
		 * Register the IRQ handler with the kernel.
		 */
		irq_set_chip_and_handler(irq, &tilegx_legacy_irq_chip,
					trio_handle_level_irq);
		irq_set_chip_data(irq, (void *)(uint64_t)i);
		irq_set_handler_data(irq, controller);
	}

	return 0;

free_irqs:
	for (j = 0; j < i; j++)
		destroy_irq(controller->irq_intx_table[j]);

	return -1;
}

/*
 * First initialization entry point, called from setup_arch().
 *
 * Find valid controllers and fill in pci_controller structs for each
 * of them.
 *
 * Returns the number of controllers discovered.
 */
int __devinit tile_pci_init(void)
{
	int num_trio_shims = 0;
	int ctl_index = 0;
	int i, j;

	if (!pci_probe) {
		pr_info("PCI: disabled by boot argument\n");
		return 0;
	}

	pr_info("PCI: Searching for controllers...\n");

	/*
	 * We loop over all the TRIO shims.
	 */
	for (i = 0; i < TILEGX_NUM_TRIO; i++) {
		int ret;

		ret = tile_pcie_open(i);
		if (ret < 0)
			continue;

		num_trio_shims++;
	}

        if (num_trio_shims == 0 || sim_is_simulator())
		return 0;

	/*
	 * Now determine which PCIe ports are configured to operate in RC mode.
	 * We look at the Board Information Block first and then see if there
	 * are any overriding configuration in the kernel boot arguments.
	 */
#ifndef GX_FPGA
	for (i = 0; i < TILEGX_NUM_TRIO; i++) {
		gxio_trio_context_t *context = &trio_contexts[i];
		int ret;

		if (context->fd < 0)
			continue;

		ret = hv_dev_pread(context->fd, 0,
			(HV_VirtAddr)&pcie_ports[i][0],
			sizeof(struct pcie_port_property) * TILEGX_TRIO_PCIES,
			GXIO_TRIO_OP_GET_PORT_PROPERTY);
		if (ret < 0) {
			pr_err("PCI: PCIE_GET_PORT_PROPERTY failure, error %d,"
				" on TRIO %d\n", ret, i);
			continue;
		}

		for (j = 0; j < TILEGX_TRIO_PCIES; j++) {
			if (pcie_ports[i][j].allow_rc) {
				pcie_rc[i][j] = 1;
				num_rc_controllers++;
			}
			else if (pcie_ports[i][j].allow_ep) {
				num_ep_controllers++;
			}
		}
	}
#else
	/*
	 * For now, just assume that there is a single RC port on trio/0.
	 */
	num_rc_controllers = 1;
	pcie_rc[0][2] = 1;
#endif

	/*
	 * Return if no PCIe ports are configured to operate in RC mode.
	 */
        if (num_rc_controllers == 0)
		return 0;

	pci_controllers = alloc_bootmem(sizeof(struct pci_controller) *
					num_rc_controllers);
        if (pci_controllers == NULL)
          return -ENOMEM;

	/*
	 * Set the TRIO pointer and MAC index for each PCIe RC port.
	 */
	for (i = 0; i < TILEGX_NUM_TRIO; i++) {
		for (j = 0; j < TILEGX_TRIO_PCIES; j++) {
			if (pcie_rc[i][j]) {
				pci_controllers[ctl_index].trio =
					&trio_contexts[i];
				pci_controllers[ctl_index].mac = j;
				pci_controllers[ctl_index].trio_index = i;
				ctl_index++;
				if (ctl_index == num_rc_controllers)
					goto out;
			}
		}
	}

out:
	/*
	 * Configure each PCIe RC port.
	 */
	for (i = 0; i < num_rc_controllers; i++) {
		/*
		 * Configure the PCIe MAC to run in RC mode.
		 */

		struct pci_controller *controller = &pci_controllers[i];

		controller->index = i;
		controller->last_busno = 0xff;
		controller->ops = &tile_cfg_ops;

	}

	return num_rc_controllers;
}

/*
 * (pin - 1) converts from the PCI standard's [1:4] convention to
 * a normal [0:3] range.
 */
static int tile_map_irq(const struct pci_dev *dev, u8 device, u8 pin)
{
	struct pci_controller *controller =
		(struct pci_controller *)dev->sysdata;
	return controller->irq_intx_table[pin - 1];
}


static void __devinit fixup_read_and_payload_sizes(struct pci_controller *
						controller)
{
	gxio_trio_context_t *trio_context = controller->trio;
	TRIO_PCIE_RC_DEVICE_CONTROL_t dev_control;
	TRIO_PCIE_RC_DEVICE_CAP_t rc_dev_cap;
	unsigned int smallest_max_payload;
	struct pci_dev *dev = NULL;
	unsigned int reg_offset;
	u16 new_values;
	int mac;
	int err;

	mac = controller->mac;

	/*
	 * Set our max read request size to be 4KB.
	 */
	reg_offset =
		(TRIO_PCIE_RC_DEVICE_CONTROL <<
			TRIO_CFG_REGION_ADDR__REG_SHIFT) |
		(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_STANDARD <<
			TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
		(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

	dev_control.word = __gxio_mmio_read32(trio_context->mmio_base_mac +
						reg_offset);
	dev_control.max_read_req_sz = 5;
	__gxio_mmio_write32(trio_context->mmio_base_mac + reg_offset,
						dev_control.word);

	/*
	 * Set the max payload size supported by this Gx PCIe MAC.
	 * Though Gx PCIe supports Max Payload Size of up to 1024 bytes,
	 * experiments have shown that setting MPS to 256 yields the
	 * best performance.
	 */
	reg_offset =
		(TRIO_PCIE_RC_DEVICE_CAP <<
			TRIO_CFG_REGION_ADDR__REG_SHIFT) |
		(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_STANDARD <<
			TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
		(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

	rc_dev_cap.word = __gxio_mmio_read32(trio_context->mmio_base_mac +
						reg_offset);
	rc_dev_cap.mps_sup = 1;
	__gxio_mmio_write32(trio_context->mmio_base_mac + reg_offset,
						rc_dev_cap.word);

	smallest_max_payload = rc_dev_cap.mps_sup;

	/* Scan for the smallest maximum payload size. */
	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		int pcie_caps_offset;
		u32 devcap;
		int max_payload;

		/* Skip device that is not in this PCIe domain. */
		if ((struct pci_controller *)dev->sysdata != controller)
			continue;

		pcie_caps_offset = pci_find_capability(dev, PCI_CAP_ID_EXP);
		if (pcie_caps_offset == 0)
			continue;

		pci_read_config_dword(dev, pcie_caps_offset + PCI_EXP_DEVCAP,
				      &devcap);
		max_payload = devcap & PCI_EXP_DEVCAP_PAYLOAD;
		if (max_payload < smallest_max_payload)
			smallest_max_payload = max_payload;
	}

	/* Now, set the max_payload_size for all devices to that value. */
	new_values = smallest_max_payload << 5;
	while ((dev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, dev)) != NULL) {
		int pcie_caps_offset;
		u16 devctl;

		/* Skip device that is not in this PCIe domain. */
		if ((struct pci_controller *)dev->sysdata != controller)
			continue;

		pcie_caps_offset = pci_find_capability(dev, PCI_CAP_ID_EXP);
		if (pcie_caps_offset == 0)
			continue;

		pci_read_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL,
				     &devctl);
		devctl &= ~PCI_EXP_DEVCTL_PAYLOAD;
		devctl |= new_values;
		pci_write_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL,
				      devctl);
	}

	/*
	 * Set the mac_config register in trio based on the MPS/MRS of the link.
	 */
        err = gxio_trio_set_mps_mrs(trio_context,
                        smallest_max_payload,
                        dev_control.max_read_req_sz,
                        mac);
        if (err < 0) {
		pr_err("PCI: PCIE_CONFIGURE_MAC_MPS_MRS failure, "
			"MAC %d on TRIO %d\n",
			mac, controller->trio_index);
	}
}


/*
 * Second PCI initialization entry point, called by subsys_initcall.
 *
 * The controllers have been set up by the time we get here, by a call to
 * tile_pci_init.
 */
int __devinit pcibios_init(void)
{
	resource_size_t offset;
	int i;

        if (num_rc_controllers == 0 && num_ep_controllers == 0)
		return 0;

	pr_info("PCI: Probing PCI hardware\n");

	/*
	 * We loop over all the TRIO shims and set up the MMIO mappings.
	 * This step can't be done in tile_pci_init because the MM subsystem
	 * hasn't been initialized then.
	 */
	for (i = 0; i < TILEGX_NUM_TRIO; i++) {
		gxio_trio_context_t *context = &trio_contexts[i];

		if (context->fd < 0)
			continue;

		/*
		 * Map in the MMIO space for the MAC.
                 */
		offset = 0;
		context->mmio_base_mac =
			iorpc_ioremap(context->fd, offset,
				      HV_TRIO_CONFIG_IOREMAP_SIZE);
		if (context->mmio_base_mac == NULL) {
			pr_err("PCI: MAC map failure on TRIO %d\n", i);

			hv_dev_close(context->fd);
			context->fd = -1;
			continue;
		}
	}

	/*
	 * Delay a bit in case devices aren't ready.  Some devices are
	 * known to require at least 20ms here, but we use a more
	 * conservative value.
	 */
	mdelay(250);

	/* Scan all of the recorded PCI controllers.  */
	for (i = 0; i < num_rc_controllers; i++) {
		struct pci_controller *controller = &pci_controllers[i];
		gxio_trio_context_t *trio_context = controller->trio;
		TRIO_PCIE_INTFC_PORT_CONFIG_t port_config;
		TRIO_PCIE_INTFC_PORT_STATUS_t port_status;
		TRIO_PCIE_INTFC_TX_FIFO_CTL_t tx_fifo_ctl;
		struct pci_bus *bus;
		unsigned int reg_offset;
		unsigned int class_code_revision;
		int mac;
#ifndef USE_SHARED_PCIE_CONFIG_REGION
		int ret;
#endif

		if (trio_context->fd < 0)
			continue;

		mac = controller->mac;

		/*
		 * Check the port strap state which will override the BIB
		 * setting.
		 */

		reg_offset =
			(TRIO_PCIE_INTFC_PORT_CONFIG <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
			(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_INTERFACE <<
				TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
			(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

		port_config.word =
			__gxio_mmio_read(trio_context->mmio_base_mac +
					 reg_offset);

		if ((port_config.strap_state !=
			TRIO_PCIE_INTFC_PORT_CONFIG__STRAP_STATE_VAL_AUTO_CONFIG_RC) &&
			(port_config.strap_state !=
			TRIO_PCIE_INTFC_PORT_CONFIG__STRAP_STATE_VAL_AUTO_CONFIG_RC_G1)) {
			/*
			 * If this is really intended to be an EP port,
			 * record it so that the endpoint driver will know about it.
			 */
			if (port_config.strap_state ==
			TRIO_PCIE_INTFC_PORT_CONFIG__STRAP_STATE_VAL_AUTO_CONFIG_ENDPOINT ||
			port_config.strap_state ==
			TRIO_PCIE_INTFC_PORT_CONFIG__STRAP_STATE_VAL_AUTO_CONFIG_ENDPOINT_G1)
				pcie_ports[controller->trio_index][mac].allow_ep = 1;

			continue;
		}

		ret = gxio_trio_force_link_up(trio_context, mac);
		if (ret < 0)
			pr_err("PCI: PCIE_FORCE_LINK_UP failure, "
				"MAC %d on TRIO %d\n",
				mac, controller->trio_index);

		pr_info("PCI: Found PCI controller #%d on TRIO %d MAC %d\n", i,
			controller->trio_index, controller->mac);

		/*
		 * Wait a bit here because some EP devices take longer to come up.
		 */
		mdelay(1000);

		/*
		 * Check for PCIe link-up status.
		 */

		reg_offset =
			(TRIO_PCIE_INTFC_PORT_STATUS <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
			(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_INTERFACE <<
				TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
			(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

		port_status.word =
			__gxio_mmio_read(trio_context->mmio_base_mac +
					 reg_offset);
		if (!port_status.dl_up) {
			pr_err("PCI: link is down, MAC %d on TRIO %d\n",
				mac, controller->trio_index);
			continue;
		}

		/*
		 * Ensure that the link can come out of L1 power down state.
		 * Strictly speaking, this is needed only in the case of
		 * heavy RC-initiated DMAs.
		 */
		reg_offset =
			(TRIO_PCIE_INTFC_TX_FIFO_CTL <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
			(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_INTERFACE <<
				TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
			(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);
		tx_fifo_ctl.word =
			__gxio_mmio_read(trio_context->mmio_base_mac +
					 reg_offset);
		tx_fifo_ctl.min_p_credits = 0;
		__gxio_mmio_write(trio_context->mmio_base_mac + reg_offset,
				  tx_fifo_ctl.word);

		/*
		 * Change the device ID so that Linux bus crawl doesn't confuse
		 * the internal bridge with any Tilera endpoints.
		 */

		reg_offset =
			(TRIO_PCIE_RC_DEVICE_ID_VEN_ID <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
			(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_STANDARD <<
				TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
			(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

		__gxio_mmio_write32(trio_context->mmio_base_mac + reg_offset,
				    (TILERA_GX36_RC_DEV_ID <<
				    TRIO_PCIE_RC_DEVICE_ID_VEN_ID__DEV_ID_SHIFT) |
				    TILERA_VENDOR_ID);

		/*
		 * Set the internal P2P bridge class code.
		 */

		reg_offset =
			(TRIO_PCIE_RC_REVISION_ID <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
			(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_STANDARD <<
				TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
			(mac << TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

		class_code_revision =
			__gxio_mmio_read32(trio_context->mmio_base_mac +
					   reg_offset);
		class_code_revision = (class_code_revision & 0xff ) |
					(PCI_CLASS_BRIDGE_PCI << 16);

		__gxio_mmio_write32(trio_context->mmio_base_mac +
				    reg_offset, class_code_revision);

#ifdef USE_SHARED_PCIE_CONFIG_REGION

		/*
		 * Map in the MMIO space for the PIO region.
                 */
		offset = HV_TRIO_PIO_OFFSET(trio_context->pio_cfg_index) |
			(((unsigned long long)mac) <<
			TRIO_TILE_PIO_REGION_SETUP_CFG_ADDR__MAC_SHIFT);

#else

		/*
		 * Alloc a PIO region for PCI config access per MAC.
		 */
		ret = gxio_trio_alloc_pio_regions(trio_context, 1, 0, 0);
		if (ret < 0) {
			pr_err("PCI: PCI CFG PIO alloc failure for mac %d "
				"on TRIO %d, give up\n",
				mac, controller->trio_index);

			/* TBD: cleanup ... */

			continue;
		}

		trio_context->pio_cfg_index[mac] = ret;

		/*
		 * For PIO CFG, the bus_address_hi parameter is 0.
		 */
		ret = gxio_trio_init_pio_region_aux(trio_context,
			trio_context->pio_cfg_index[mac],
			mac, 0, HV_TRIO_PIO_FLAG_CONFIG_SPACE);
		if (ret < 0) {
			pr_err("PCI: PCI CFG PIO init failure for mac %d "
				"on TRIO %d, give up\n",
				mac, controller->trio_index);

			/* TBD: cleanup ... */

			continue;
		}

		offset = HV_TRIO_PIO_OFFSET(trio_context->pio_cfg_index[mac]) |
			(((unsigned long long)mac) <<
			TRIO_TILE_PIO_REGION_SETUP_CFG_ADDR__MAC_SHIFT);

#endif

		trio_context->mmio_base_pio_cfg[mac] =
			iorpc_ioremap(trio_context->fd, offset,
			(1 << TRIO_TILE_PIO_REGION_SETUP_CFG_ADDR__MAC_SHIFT));
		if (trio_context->mmio_base_pio_cfg[mac] == NULL) {
			pr_err("PCI: PIO map failure for mac %d on TRIO %d\n",
				mac, controller->trio_index);

			/* TBD: cleanup ... */

			continue;
		}

		/*
		 * Initialize the PCIe interrupts.
                 */
		if (tile_init_irqs(controller)) {
			pr_err("PCI: IRQs init failure for mac %d on TRIO %d\n",
				mac, controller->trio_index);

			continue;
		}

		/*
		 * This comes from the generic Linux PCI driver.
		 *
		 * It reads the PCI tree for this bus into the Linux
		 * data structures.
		 *
		 * This is inlined in linux/pci.h and calls into
		 * pci_scan_bus_parented() in probe.c.
		 */
		bus = pci_scan_bus(0, controller->ops, controller);
		controller->root_bus = bus;
		controller->last_busno = bus->subordinate;

	}

	/* Do machine dependent PCI interrupt routing */
	pci_fixup_irqs(pci_common_swizzle, tile_map_irq);

	/*
	 * This comes from the generic Linux PCI driver.
	 *
	 * It allocates all of the resources (I/O memory, etc)
	 * associated with the devices read in above.
	 */

	pci_assign_unassigned_resources();

	/* Record the I/O resources in the PCI controller structure. */
	for (i = 0; i < num_rc_controllers; i++) {
		struct pci_controller *controller = &pci_controllers[i];
		gxio_trio_context_t *trio_context = controller->trio;
		struct pci_bus *root_bus = pci_controllers[i].root_bus;
		struct pci_bus *next_bus;
		uint32_t bus_address_hi;
		struct pci_dev *dev;
		int ret;
		int j;

		/*
		 * Skip controllers that are not properly initialized or
		 * have down links.
		 */
		if (root_bus == NULL)
			continue;

		/* Configure the max_payload_size values for this domain. */
		fixup_read_and_payload_sizes(controller);

		list_for_each_entry(dev, &root_bus->devices, bus_list) {
			/* Find the PCI host controller, ie. the 1st bridge. */
			if ((dev->class >> 8) == PCI_CLASS_BRIDGE_PCI &&
				(PCI_SLOT(dev->devfn) == 0)) {
				next_bus = dev->subordinate;
				pci_controllers[i].mem_resources[0] =
					*next_bus->resource[0];
				pci_controllers[i].mem_resources[1] =
					 *next_bus->resource[1];
				pci_controllers[i].mem_resources[2] =
					 *next_bus->resource[2];

				break;
			}
		}

		if (pci_controllers[i].mem_resources[1].flags & IORESOURCE_MEM)
			bus_address_hi =
				pci_controllers[i].mem_resources[1].start >> 32;
		else if (pci_controllers[i].mem_resources[2].flags & IORESOURCE_PREFETCH)
			bus_address_hi =
				pci_controllers[i].mem_resources[2].start >> 32;
		else {
			/* This is unlikely. */
			pr_err("PCI: no memory resources on TRIO %d mac %d\n",
				controller->trio_index, controller->mac);
			continue;
		}

		/*
		 * We always assign 32-bit PCI bus BAR ranges.
                 */
		BUG_ON(bus_address_hi != 0);

		/*
		 * Alloc a PIO region for PCI memory access for each RC port.
		 */
		ret = gxio_trio_alloc_pio_regions(trio_context, 1, 0, 0);
		if (ret < 0) {
			pr_err("PCI: MEM PIO alloc failure on TRIO %d mac %d, "
				"give up\n", controller->trio_index,
				controller->mac);

			/* TBD: cleanup ... */

			continue;
		}

		controller->pio_mem_index = ret;

		/*
		 * For PIO MEM, the bus_address_hi parameter is hard-coded 0
		 * because we always assign 32-bit PCI bus BAR ranges.
                 */
		ret = gxio_trio_init_pio_region_aux(trio_context,
						    controller->pio_mem_index,
						    controller->mac,
						    bus_address_hi,
						    0);
		if (ret < 0) {
			pr_err("PCI: MEM PIO init failure on TRIO %d mac %d, "
				"give up\n", controller->trio_index,
				controller->mac);

			/* TBD: cleanup ... */

			continue;
		}

		/*
		 * Configure a Mem-Map region for each memory controller so
		 * that Linux can map all of its PA space to the PCI bus.
		 * Use the IOMMU to handle hash-for-home memory.
                 */
		for_each_online_node(j) {
			unsigned long start_pfn = node_start_pfn[j];
			unsigned long end_pfn = node_end_pfn[j];
			unsigned long nr_pages = end_pfn - start_pfn;

			ret = gxio_trio_alloc_memory_maps(trio_context, 1, 0,
							  0);
			if (ret < 0) {
				pr_err("PCI: Mem-Map alloc failure on TRIO %d "
					"mac %d for MC %d, give up\n",
					controller->trio_index,
					controller->mac, j);

				/* TBD: cleanup ... */

				goto alloc_mem_map_failed;
			}

			controller->mem_maps[j] = ret;

			/*
			 * Initialize the Mem-Map and the I/O MMU so that all
			 * the physical memory can be accessed by the endpoint
			 * devices. The base bus address is set to the base CPA
			 * of this memory controller, so is the base VA. The
			 * I/O MMU table essentially translates the CPA to
			 * the real PA.
                         */
			ret = gxio_trio_init_memory_map_mmu_aux(trio_context,
				controller->mem_maps[j],
				start_pfn << PAGE_SHIFT,
				nr_pages << PAGE_SHIFT,
				trio_context->asid,
				controller->mac,
				start_pfn << PAGE_SHIFT,
				j,
				GXIO_TRIO_ORDER_MODE_UNORDERED);
			if (ret < 0) {
				pr_err("PCI: Mem-Map init failure on TRIO %d "
					"mac %d for MC %d, give up\n",
					controller->trio_index,
					controller->mac, j);

				/* TBD: cleanup ... */

				goto alloc_mem_map_failed;
			}

			continue;

alloc_mem_map_failed:
			break;
		}

	}

	return 0;
}
subsys_initcall(pcibios_init);

/*
 * No bus fixups needed.
 */
void __devinit pcibios_fixup_bus(struct pci_bus *bus)
{
	/* Nothing needs to be done. */
}

/*
 * This can be called from the generic PCI layer, but doesn't need to
 * do anything.
 */
char __devinit *pcibios_setup(char *str)
{
	if (!strcmp(str, "off")) {
		pci_probe = 0;
		return NULL;
	}
	return str;
}

/*
 * This is called from the generic Linux layer.
 */
void __devinit pcibios_update_irq(struct pci_dev *dev, int irq)
{
	pci_write_config_byte(dev, PCI_INTERRUPT_LINE, irq);
}

/*
 * Enable memory and/or address decoding, as appropriate, for the
 * device described by the 'dev' struct.
 *
 * This is called from the generic PCI layer, and can be called
 * for bridges or endpoints.
 */
int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	u16 cmd, old_cmd;
	u8 header_type;
	int i;
	struct resource *r;

	pci_read_config_byte(dev, PCI_HEADER_TYPE, &header_type);

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	old_cmd = cmd;
	if ((header_type & 0x7F) == PCI_HEADER_TYPE_BRIDGE) {
		/*
		 * For bridges, we enable both memory and I/O decoding
		 * in call cases.
		 */
		cmd |= PCI_COMMAND_IO;
		cmd |= PCI_COMMAND_MEMORY;
	} else {
		/*
		 * For endpoints, we enable memory and/or I/O decoding
		 * only if they have a memory resource of that type.
		 */
		for (i = 0; i < 6; i++) {
			r = &dev->resource[i];
			if (r->flags & IORESOURCE_UNSET) {
				pr_err("PCI: Device %s not available "
				       "because of resource collisions\n",
				       pci_name(dev));
				return -EINVAL;
			}
			if (r->flags & IORESOURCE_IO)
				cmd |= PCI_COMMAND_IO;
			if (r->flags & IORESOURCE_MEM)
				cmd |= PCI_COMMAND_MEMORY;
		}
	}

	/*
	 * We only write the command if it changed.
	 */
	if (cmd != old_cmd)
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	return 0;
}

/* Map a PCI MMIO bus address into VA space. */
void __iomem *ioremap(resource_size_t phys_addr, unsigned long size)
{
	struct pci_controller *controller = NULL;
	resource_size_t bar_start;
	resource_size_t bar_end;
	resource_size_t offset;
	resource_size_t start;
	resource_size_t end;
	int trio_fd;
	int i, j;

	start = phys_addr;
	end = phys_addr + size - 1;

	/*
	 * In the following, each PCI controller's mem_resources[1]
	 * represents its (non-prefetchable) PCI memory resource and
	 * mem_resources[2] refers to its prefetchable PCI memory resource.
	 * By searching phys_addr in each controller's mem_resources[], we can
	 * determine the controller that should accept the PCI memory access.
	 */

	for (i = 0; i < num_rc_controllers; i++) {
		/*
		 * Skip controllers that are not properly initialized or
		 * have down links.
		 */
		if (pci_controllers[i].root_bus == NULL)
			continue;

		for (j = 1; j < 3; j++) {
			bar_start =
				pci_controllers[i].mem_resources[j].start;
			bar_end =
				pci_controllers[i].mem_resources[j].end;

			if ((start >= bar_start) && (end <= bar_end)) {

				controller = &pci_controllers[i];

				goto got_it;
			}
		}
	}

	if (controller == NULL)
		return NULL;

got_it:
	trio_fd = controller->trio->fd;

	offset = HV_TRIO_PIO_OFFSET(controller->pio_mem_index) + phys_addr;

	/*
	 * We need to keep the PCI bus address's in-page offset in the VA.
	 */
        return iorpc_ioremap(trio_fd, offset, size) +
					(phys_addr & (PAGE_SIZE - 1));
}
EXPORT_SYMBOL(ioremap);

void pci_iounmap(struct pci_dev *dev, void __iomem *addr)
{
	iounmap(addr);
}
EXPORT_SYMBOL(pci_iounmap);

/****************************************************************
 *
 * Tile PCI config space read/write routines
 *
 ****************************************************************/

/*
 * These are the normal read and write ops
 * These are expanded with macros from  pci_bus_read_config_byte() etc.
 *
 * devfn is the combined PCI device & function.
 *
 * offset is in bytes, from the start of config space for the
 * specified bus & device.
 */

static int __devinit tile_cfg_read(struct pci_bus *bus,
				   unsigned int devfn,
				   int offset,
				   int size,
				   u32 *val)
{
	struct pci_controller *controller = bus->sysdata;
	gxio_trio_context_t *trio_context = controller->trio;
	int busnum = bus->number & 0xff;
	int device = (devfn >> 3) & 0x1f;
	int function = devfn & 0x7;
	int config_type = 1;
	TRIO_TILE_PIO_REGION_SETUP_CFG_ADDR_t cfg_addr;
	void *mmio_addr;

	/*
	 * Map all accesses to the local device (bus == 0) into the
	 * MMIO space of the MAC. Accesses to the downstream devices
	 * go to the PIO space.
	 */
	if (busnum == 0) {
		if (device == 0) {
			/*
			 * This is the internal downstream P2P bridge,
			 * access directly.
			 */
			unsigned int reg_offset;

			reg_offset = ((offset & 0xFFF) <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
				(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_PROTECTED
				<< TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
				(controller->mac <<
					TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

			mmio_addr = trio_context->mmio_base_mac + reg_offset;

			goto valid_device;

		} else {
			/*
			 * We fake an empty device for (device > 0),
			 * since there is only one device on bus 0.
                         */
			goto invalid_device;
		}
	}

	/*
	 * Accesses to the directly attached device (bus == 1) have to be
	 * sent as type-0 configs.
	 */

	if (busnum == 1) {
		/*
		 * There is only one device off of our built-in P2P bridge.
                 */
		if (device != 0)
			goto invalid_device;

		config_type = 0;
	}

	cfg_addr.word = 0;
	cfg_addr.reg_addr = (offset & 0xFFF);
	cfg_addr.fn = function;
	cfg_addr.dev = device;
	cfg_addr.bus = busnum;
	cfg_addr.type = config_type;

	/*
	 * Note that we don't set the mac field in cfg_addr because the
	 * mapping is per port.
	 */

	mmio_addr = trio_context->mmio_base_pio_cfg[controller->mac] +
			cfg_addr.word;

valid_device:

	switch (size) {
	case 4:
		*val = __gxio_mmio_read32(mmio_addr);
		break;

	case 2:
		*val = __gxio_mmio_read16(mmio_addr);
		break;

	case 1:
		*val = __gxio_mmio_read8(mmio_addr);
		break;

	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}

	return 0;

invalid_device:

	switch (size) {
	case 4:
		*val = 0xFFFFFFFF;
		break;

	case 2:
		*val = 0xFFFF;
		break;

	case 1:
		*val = 0xFF;
		break;

	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}

	return 0;
}


/*
 * See tile_cfg_read() for relevent comments.
 * Note that "val" is the value to write, not a pointer to that value.
 */
static int __devinit tile_cfg_write(struct pci_bus *bus,
				    unsigned int devfn,
				    int offset,
				    int size,
				    u32 val)
{
	struct pci_controller *controller = bus->sysdata;
	gxio_trio_context_t *trio_context = controller->trio;
	int busnum = bus->number & 0xff;
	int device = (devfn >> 3) & 0x1f;
	int function = devfn & 0x7;
	int config_type = 1;
	TRIO_TILE_PIO_REGION_SETUP_CFG_ADDR_t cfg_addr;
	void *mmio_addr;
	u32 val_32 = (u32)val;
	u16 val_16 = (u16)val;
	u8 val_8 = (u8)val;

	/*
	 * Map all accesses to the local device (bus == 0) into the
	 * MMIO space of the MAC. Accesses to the downstream devices
	 * go to the PIO space.
	 */
	if (busnum == 0) {
		if (device == 0) {
			/*
			 * This is the internal downstream P2P bridge,
			 * access directly.
			 */
			unsigned int reg_offset;

			reg_offset = ((offset & 0xFFF) <<
				TRIO_CFG_REGION_ADDR__REG_SHIFT) |
				(TRIO_CFG_REGION_ADDR__INTFC_VAL_MAC_PROTECTED
				<< TRIO_CFG_REGION_ADDR__INTFC_SHIFT ) |
				(controller->mac <<
					TRIO_CFG_REGION_ADDR__MAC_SEL_SHIFT);

			mmio_addr = trio_context->mmio_base_mac + reg_offset;

			goto valid_device;

		} else {
			/*
			 * We fake an empty device for (device > 0),
			 * since there is only one device on bus 0.
                         */
			goto invalid_device;
		}
	}

	/*
	 * Accesses to the directly attached device (bus == 1) have to be
	 * sent as type-0 configs.
	 */

	if (busnum == 1) {
		/*
		 * There is only one device off of our built-in P2P bridge.
                 */
		if (device != 0)
			goto invalid_device;

		config_type = 0;
	}

	cfg_addr.word = 0;
	cfg_addr.reg_addr = (offset & 0xFFF);
	cfg_addr.fn = function;
	cfg_addr.dev = device;
	cfg_addr.bus = busnum;
	cfg_addr.type = config_type;

	/*
	 * Note that we don't set the mac field in cfg_addr because the
	 * mapping is per port.
	 */

	mmio_addr = trio_context->mmio_base_pio_cfg[controller->mac] +
			cfg_addr.word;

valid_device:

	switch (size) {
	case 4:
		__gxio_mmio_write32(mmio_addr, val_32);
		break;

	case 2:
		__gxio_mmio_write16(mmio_addr, val_16);
		break;

	case 1:
		__gxio_mmio_write8(mmio_addr, val_8);
		break;

	default:
		return PCIBIOS_FUNC_NOT_SUPPORTED;
	}

invalid_device:

	return 0;
}


static struct pci_ops tile_cfg_ops = {
	.read =         tile_cfg_read,
	.write =        tile_cfg_write,
};


inline u8 _tile_readb(unsigned long addr)
{
	return __gxio_mmio_read8((void *)addr);
}
EXPORT_SYMBOL(_tile_readb);

inline u16 _tile_readw(unsigned long addr)
{
	return __gxio_mmio_read16((void *)addr);
}
EXPORT_SYMBOL(_tile_readw);

inline u32 _tile_readl(unsigned long addr)
{
	return __gxio_mmio_read32((void *)addr);
}
EXPORT_SYMBOL(_tile_readl);

inline u64 _tile_readq(unsigned long addr)
{
	return __gxio_mmio_read64((void *)addr);
}
EXPORT_SYMBOL(_tile_readq);

inline void _tile_writeb(u8 val, unsigned long addr)
{
	__gxio_mmio_write8((void *)addr, val);
}
EXPORT_SYMBOL(_tile_writeb);

inline void _tile_writew(u16 val, unsigned long addr)
{
	__gxio_mmio_write16((void *)addr, val);
}
EXPORT_SYMBOL(_tile_writew);

inline void _tile_writel(u32 val, unsigned long addr)
{
	__gxio_mmio_write32((void *)addr, val);
}
EXPORT_SYMBOL(_tile_writel);

inline void _tile_writeq(u64 val, unsigned long addr)
{
	__gxio_mmio_write64((void *)addr, val);
}
EXPORT_SYMBOL(_tile_writeq);

/*
 * MSI support starts here.
 */
static unsigned int
tilegx_msi_startup(struct irq_data *d)
{
	if (d->msi_desc)
		unmask_msi_irq(d);

	return 0;
}

static void
tilegx_msi_ack(struct irq_data *d)
{
	__insn_mtspr(SPR_IPI_EVENT_RESET_K, 1UL << d->irq);
}

static void
tilegx_msi_mask(struct irq_data *d)
{
	mask_msi_irq(d);
	__insn_mtspr(SPR_IPI_MASK_SET_K, 1UL << d->irq);
}

static void
tilegx_msi_unmask(struct irq_data *d)
{
	__insn_mtspr(SPR_IPI_MASK_RESET_K, 1UL << d->irq);
	unmask_msi_irq(d);
}

static struct irq_chip tilegx_msi_chip = {
	.name			= "tilegx_msi",
	.irq_startup		= tilegx_msi_startup,
	.irq_ack		= tilegx_msi_ack,
	.irq_mask		= tilegx_msi_mask,
	.irq_unmask		= tilegx_msi_unmask,

	/* TBD: support set_affinity. */
};

int arch_setup_msi_irq(struct pci_dev *pdev, struct msi_desc *desc)
{
	struct pci_controller *controller;
	gxio_trio_context_t *trio_context;
	struct msi_msg msg;
	int default_irq;
	uint64_t mem_map_base;
	uint64_t mem_map_limit;
	u64 msi_addr;
	int mem_map;
	int cpu;
	int irq;
	int ret;

	irq = create_irq();
	if (irq < 0)
		return irq;

	/*
	 * Since we use a 64-bit Mem-Map to accept the MSI write, we fail
	 * devices that are not capable of generating a 64-bit message address.
	 * These devices will fall back to using the legacy interrupts.
	 * Most PCIe endpoint devices do support 64-bit message addressing.
	 */
	if (desc->msi_attrib.is_64 == 0) {
		dev_printk(KERN_INFO, &pdev->dev,
			"64-bit MSI message address not supported, "
			"falling back to legacy interrupts.\n");

		ret = -ENOMEM;
		goto is_64_failure;
	}

	default_irq = desc->msi_attrib.default_irq;
	controller = irq_get_handler_data(default_irq);

	BUG_ON(!controller);

	trio_context = controller->trio;

	/*
	 * Allocate the Mem-Map that will accept the MSI write and
	 * trigger the TILE-side interrupts.
	 */
	mem_map = gxio_trio_alloc_memory_maps(trio_context, 1, 0, 0);
	if (mem_map < 0) {
		dev_printk(KERN_INFO, &pdev->dev,
			"%s Mem-Map alloc failure. "
			"Failed to initialize MSI interrupts. "
			"Falling back to legacy interrupts.\n",
			desc->msi_attrib.is_msix ? "MSI-X" : "MSI");

		ret = -ENOMEM;
		goto msi_mem_map_alloc_failure;
	}

	/* We try to distribute different IRQs to different tiles. */
	cpu = tile_irq_cpu(irq);

	/*
	 * Now call up to the HV to configure the Mem-Map interrupt and
	 * set up the IPI binding.
	 */
	mem_map_base = MEM_MAP_INTR_REGIONS_BASE +
		mem_map * MEM_MAP_INTR_REGION_SIZE;
	mem_map_limit = mem_map_base + MEM_MAP_INTR_REGION_SIZE - 1;

	ret = gxio_trio_config_msi_intr(trio_context, cpu_x(cpu), cpu_y(cpu),
					KERNEL_PL, irq, controller->mac,
					mem_map, mem_map_base, mem_map_limit,
					trio_context->asid);
	if (ret < 0) {
		dev_printk(KERN_INFO, &pdev->dev, "HV MSI config failed.\n");

		goto hv_msi_config_failure;
	}

	irq_set_msi_desc(irq, desc);

	msi_addr = mem_map_base + TRIO_MAP_MEM_REG_INT3 - TRIO_MAP_MEM_REG_INT0;

	msg.address_hi = msi_addr >> 32;
	msg.address_lo = msi_addr & 0xffffffff;

	msg.data = mem_map;

	write_msi_msg(irq, &msg);
	irq_set_chip_and_handler(irq, &tilegx_msi_chip, handle_level_irq);
	irq_set_handler_data(irq, controller);

	return 0;

hv_msi_config_failure:
	/* Free mem-map */
msi_mem_map_alloc_failure:
is_64_failure:
	destroy_irq(irq);
	return ret;
}

void arch_teardown_msi_irq(unsigned int irq)
{
	destroy_irq(irq);
}
