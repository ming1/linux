/*
 * OF helpers for SH intc
 *
 * Copyright (C) 2012  Nobuhiro Iwamatsu <nobuhiro.iwamatsu.yj@renesas.com>
 * Copyright (C) 2012  Renesas Solutions Corp.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/sh_intc.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>

static int __init of_sh_intc_get_reg_addrs(struct device_node *np,
				unsigned long *set_reg, unsigned long *clr_reg,
				unsigned long *reg_width,
				unsigned long *field_width)
{
	struct resource res;
	int err;

	if (set_reg) {
		err = of_address_to_resource(np, 0, &res);
		if (err)
			return err;
		*set_reg = res.start;
	}

	if (resource_size(&res) && reg_width)
		*reg_width = resource_size(&res) * 8; /* byte */

	if (clr_reg) {
		err = of_address_to_resource(np, 1, &res);
		/* It is ok for this to be missing */
		if (err != -EINVAL) {
			if (err)
				return err;
			*clr_reg = res.start;
		}
	}

	if (field_width) {
		u32 width;
		err = of_property_read_u32(np, "field-width", &width);
		if (err)
			return err;
		*field_width = width;
	}

	return 0;
}

static int of_sh_intc_parse_vector(struct device_node *np, uint32_t *vect)
{
	return of_property_read_u32(np, "vector", vect);
}

static int of_sh_intc_parse_group(struct device_node *np,
				struct intc_group *grp)
{
	const __be32 *list, *list_end;
	int size, ret = 0, count = 0;
	phandle phandle;

	/* Retrieve the phandle list property */
	list = of_get_property(np, "group", &size);
	if (!list)
		return -ENOENT;

	list_end = list + size / sizeof(*list);

	grp->enum_id = np->phandle;
	/* Loop over the phandles until all the requested entry is found */
	while (list < list_end) {
		/* If phandle is 0, then it is an empty entry with
		   no arguments. */
		phandle = be32_to_cpup(list);
		if (phandle)
			grp->enum_ids[count] = phandle;
		list++;
		count++;
	}

	pr_debug("%d:[", grp->enum_id);
	for (size = 0 ; size < count ; size++)
		pr_debug(" %d ", grp->enum_ids[size]);

	pr_debug("]\n");

	return ret;
}

static int of_sh_intc_parse_vectortbl(struct device_node *np,
				struct intc_vect **vect, int *tbl_size)
{
	const __be32 *list, *list_end;
	int size, ret = 0, count = 0;
	struct device_node *node = NULL;
	phandle phandle;

	/* Retrieve the phandle list property */
	list = of_get_property(np, "vector_table", &size);
	if (!list)
		return -ENOENT;

	*tbl_size = size / sizeof(*list);

	pr_debug("vector table size: %d\n", *tbl_size);

	*vect = kzalloc(sizeof(struct intc_vect) * *tbl_size,
					GFP_KERNEL);
	if (!*vect)
		return -ENOMEM;

	list_end = list + *tbl_size;

	/* Loop over the phandles until all the requested entry is found */
	while (list < list_end) {
		/* If phandle is 0, then it is an empty entry with
		   no arguments. */
		phandle = be32_to_cpup(list);
		if (phandle) {
			uint32_t vector_id;

			(*vect)[count].enum_id = phandle;
			node = of_find_node_by_phandle(phandle);

			ret = of_sh_intc_parse_vector(node, &vector_id);
			if (ret)
				return ret;

			(*vect)[count].vect = vector_id;
			pr_debug("id %d : vector 0x%x\n",
				(*vect)[count].enum_id, (*vect)[count].vect);
		} else {
			ret = -EINVAL;
			goto error;
		}
		list++;
		count++;
	}
	return ret;

error:
	kfree(*vect);

	return ret;
}

static int of_sh_intc_parse_reginfo(struct device_node *np,
				struct intc_mask_reg *mask,
				struct intc_prio_reg *prio,
				struct intc_sense_reg *sense)
{
	const __be32 *list, *list_end;
	int size, id, ret = 0, count = 0;
	phandle phandle;

	/* Retrieve the phandle list property */
	list = of_get_property(np, "reginfo", &size);
	if (!list)
		return -ENOENT;

	list_end = list + size / sizeof(*list);

	/* Loop over the phandles until all the requested entry is found */
	while (list < list_end) {
		/* If phandle is 0, then it is an empty entry with
		   no arguments. */
		phandle = be32_to_cpup(list);
		if (phandle)
			id = phandle;
		else
			id = 0;

		if (mask)
			mask->enum_ids[count] = id;
		if (prio)
			prio->enum_ids[count] = id;
		if (sense)
			sense->enum_ids[count] = id;

		pr_debug("reg: [%d] %d\n", count, id);
		list++;
		count++;
	}

	return ret;
}

static struct device_node *
__init of_sh_intc_check_base_node(struct device_node *np,
		const char *node_name, int *tbl_size)
{
	struct device_node *node;

	node = of_find_node_by_name(np, node_name);
	if (!node) {
		pr_err("%s table not found\n", node_name);
		return NULL;
	}

	pr_debug("%s\n", node->full_name);

	*tbl_size = of_get_child_count(node);

	pr_debug("Size of %s: %d\n", node_name, *tbl_size);

	return node;
}

static int __init of_sh_intc_get_mask_ack(struct device_node *np,
				struct intc_mask_reg **masks, int *tbl_size,
				const char *base_name, const char *reg_name)
{
	struct device_node *intc_node, *reg_node;
	int i, ret;
	char node_name[13]; /* intc_mask + 999 */

	intc_node = of_sh_intc_check_base_node(np, base_name, tbl_size);
	if (!intc_node)
		return -ENOENT;

	*masks = kzalloc(sizeof(struct intc_mask_reg) * *tbl_size, GFP_KERNEL);
	if (!*masks)
		return -ENOMEM;

	for (i = 0 ; i < *tbl_size; i++) {
		memset(node_name, 0, sizeof(node_name));
		snprintf(node_name, sizeof(node_name), "%s%d", reg_name, i);

		pr_debug("intc node[%d]: name: %s\n", i, node_name);

		reg_node = of_find_node_by_name(intc_node, node_name);
		if (!reg_node) {
			pr_warn("%s not found\n", node_name);
			ret = -EINVAL;
			goto error;
		}

		ret = of_sh_intc_get_reg_addrs(reg_node, &(*masks)[i].set_reg,
					       &(*masks)[i].clr_reg,
					       &(*masks)[i].reg_width, NULL);
		if (ret)
			goto error;

#ifdef CONFIG_INTC_BALANCING
		of_property_read_u32(reg_node, "dist_reg",
						&(*masks)[i].dist_reg);
#endif
#ifdef CONFIG_SMP
		of_property_read_u32(reg_node, "smp",
						(u32 *)&(*masks)[i].smp);
#endif

		pr_debug("set reg: 0x%lx clr reg: 0x%lx reg_width: %ld\n",
				(*masks)[i].set_reg, (*masks)[i].clr_reg,
				(*masks)[i].reg_width);

		ret = of_sh_intc_parse_reginfo(reg_node, &(*masks)[i], NULL,
						NULL);
		if (ret)
			goto error;
	}

	return ret;

error:
	kfree(*masks);
	return ret;
}

static int __init of_sh_intc_get_vector(struct device_node *np,
				struct intc_vect **vectors, int *tbl_size)
{
	struct device_node *intc_node;

	/* Get INTCA vector register info */
	intc_node = of_find_node_by_name(np, "intc_vectors");
	if (!intc_node) {
		pr_err("Get INTC vector table not found\n");
		return -ENOENT;
	}

	return of_sh_intc_parse_vectortbl(intc_node, vectors, tbl_size);
}

static int __init of_sh_intc_get_prio(struct device_node *np,
				struct intc_prio_reg **prios, int *tbl_size)
{
	struct device_node *intc_node, *reg_node;
	int i, ret;
	char node_name[13]; /* intc_prio + 999 */

	intc_node = of_sh_intc_check_base_node(np, "intc_prio_registers",
					tbl_size);
	if (!intc_node)
		return -ENOENT;

	*prios = kzalloc(sizeof(struct intc_prio_reg) * *tbl_size, GFP_KERNEL);
	if (!*prios)
		return -ENOMEM;

	/* Get INTC priority register info */
	for (i = 0 ; i < *tbl_size; i++) {
		memset(node_name, 0, sizeof(node_name));
		snprintf(node_name, sizeof(node_name), "intc_prio%d", i);

		pr_debug("INTC node name: %s\n", node_name);

		reg_node = of_find_node_by_name(intc_node, node_name);

		if (!intc_node) {
			pr_err("INTC prio register not found\n");
			ret = -EINVAL;
			goto error;
		}

		ret = of_sh_intc_get_reg_addrs(reg_node, &(*prios)[i].set_reg,
				&(*prios)[i].clr_reg, &(*prios)[i].reg_width,
				&(*prios)[i].field_width);
		if (ret)
			goto error;

		pr_debug("\tset reg: 0x%lx clr reg: 0x%lx\n",
				(*prios)[i].set_reg, (*prios)[i].clr_reg);
		pr_debug("\treg_width: %ld field_width: %ld\n",
				(*prios)[i].reg_width, (*prios)[i].field_width);

		ret = of_sh_intc_parse_reginfo(reg_node, NULL, &(*prios)[i],
						NULL);
		if (ret)
			goto error;
	}

	return ret;

error:
	kfree(*prios);
	return ret;
}

static int __init of_sh_intc_get_sense(struct device_node *np,
				struct intc_sense_reg **senses, int *tbl_size)
{
	struct device_node *intc_node, *reg_node;
	int i, ret;
	char node_name[14]; /* intc_sense + 999 */

	intc_node = of_sh_intc_check_base_node(np, "intc_sense_registers",
					tbl_size);
	if (!intc_node)
		return -ENOENT;

	*senses = kzalloc(sizeof(struct intc_sense_reg) * *tbl_size,
					GFP_KERNEL);
	if (!*senses)
		return -ENOMEM;

	/* Get INTC priority register info */
	for (i = 0 ; i < *tbl_size; i++) {
		memset(node_name, 0, sizeof(node_name));
		snprintf(node_name, sizeof(node_name), "intc_sense%d", i);

		pr_debug("INTC node name: %s\n", node_name);

		reg_node = of_find_node_by_name(intc_node, node_name);

		if (!intc_node) {
			pr_err("INTC senses register not found\n");
			ret = -EINVAL;
			goto error;
		}

		ret = of_sh_intc_get_reg_addrs(reg_node, &(*senses)[i].reg,
					NULL, &(*senses)[i].reg_width,
					&(*senses)[i].field_width);
		if (ret)
			goto error;

		pr_debug("\tset reg: 0x%lx\n", (*senses)[i].reg);
		pr_debug("\treg_width: %ld field_width: %ld\n",
					(*senses)[i].reg_width,
					(*senses)[i].field_width);

		ret = of_sh_intc_parse_reginfo(reg_node, NULL, NULL,
						&(*senses)[i]);
		if (ret)
			goto error;
	}

	return ret;

error:
	kfree(*senses);
	return ret;
}

static int __init of_sh_intc_get_ack(struct device_node *np,
				struct intc_mask_reg **masks, int *tbl_size)
{
	return of_sh_intc_get_mask_ack(np, masks, tbl_size,
					"intc_ack_registers", "intc_ack");
}

static int __init of_sh_intc_get_mask(struct device_node *np,
				struct intc_mask_reg **masks, int *tbl_size)
{
	return of_sh_intc_get_mask_ack(np, masks, tbl_size,
					"intc_mask_registers", "intc_mask");
}

static int __init of_sh_intc_get_group(struct device_node *np,
				struct intc_group **groups, int *tbl_size)
{
	struct device_node *node;
	int i, ret, size;
	const __be32 *list;
	struct device_node *grp_node;
	char node_name[15]; /* intc_group@999 */

	node = of_sh_intc_check_base_node(np, "intc_groups", tbl_size);
	if (!node || !*tbl_size)
		return -ENOENT;

	*groups = kzalloc(sizeof(struct intc_group) * *tbl_size, GFP_KERNEL);
	if (!*groups)
		return -ENOMEM;

	/* Get INTCA node info */
	for (i = 0 ; i < *tbl_size; i++) {
		memset(node_name, 0, sizeof(node_name));
		snprintf(node_name, sizeof(node_name), "intc_group%d", i);

		pr_debug("intc group[%d]: name: %s\n", i, node_name);

		grp_node = of_find_node_by_name(np, node_name);
		if (!grp_node) {
			pr_warn("%s not found\n", node_name);
			ret = -EINVAL;
			goto error;
		}

		list = of_get_property(np, node_name, &size);
		ret = of_sh_intc_parse_group(grp_node, &(*groups)[i]);
		if (ret) {
			pr_err("intc group not found\n");
			goto error;
		}
	}

	return ret;

error:
	kfree(*groups);
	return ret;
}

int __init of_sh_intc_get_intevtsa_vect(struct device_node *np,
				unsigned short *vect)
{
	int size;
	const __be32 *list;
	struct device_node *node;
	phandle phandle;

	node = of_find_node_by_name(np, "intc_intevtsa");
	if (!node)
		return -ENOENT;

	/* Retrieve the phandle list property */
	list = of_get_property(node, "vector", &size);
	if (!list)
		return -ENOENT;

	phandle = be32_to_cpup(list);
	if (phandle) {
		uint32_t tmp;
		struct device_node *vect_node =
				of_find_node_by_phandle(phandle);

		if (!of_sh_intc_parse_vector(vect_node, &tmp))
			*vect = tmp;
		else
			return -ENOENT;
	} else {
		pr_debug("intc_intevtsa data not found\n");
		return -ENOENT;
	}
	return 0;
}

static int of_sh_intc_get_force_flags(struct device_node *np,
				const char *node_name)
{
	int size;
	const __be32 *list = of_get_property(np, node_name, &size);
	if (list)
		return be32_to_cpup(list);

	return 0;
}

void __init of_sh_intc_get_force_enable(struct device_node *np,
				struct intc_desc *d)
{
	d->force_enable = of_sh_intc_get_force_flags(np, "force_enable");
}

void __init of_sh_intc_get_force_disable(struct device_node *np,
				struct intc_desc *d)
{
	d->force_disable = of_sh_intc_get_force_flags(np, "force_disable");
}

void __init of_sh_intc_get_skip_syscore_suspend(struct device_node *np,
				struct intc_desc *d)
{
	if (of_find_property(np, "skip_syscore_suspend", NULL))
		d->skip_syscore_suspend = true;
	else
		d->skip_syscore_suspend = false;
}

int __init of_sh_intc_get_intc(struct device_node *np, struct intc_desc *d)
{
	int ret = of_sh_intc_get_vector(np, &d->hw.vectors, &d->hw.nr_vectors);
	if (ret)
		return ret;

	ret = of_sh_intc_get_group(np, &d->hw.groups, &d->hw.nr_groups);
	/* INTC may not need groups. */
	if (ret && ret != -ENOENT)
		return ret;

	ret = of_sh_intc_get_mask(np, &d->hw.mask_regs, &d->hw.nr_mask_regs);
	if (ret)
		return ret;

	ret = of_sh_intc_get_prio(np, &d->hw.prio_regs, &d->hw.nr_prio_regs);
	if (ret)
		return ret;

	ret = of_sh_intc_get_sense(np, &d->hw.sense_regs, &d->hw.nr_sense_regs);
	/* INTC may not need Sense register. */
	if (ret && ret != -ENOENT)
		return ret;

	ret = of_sh_intc_get_ack(np, &d->hw.ack_regs, &d->hw.nr_ack_regs);
	/* INTC may not need Ack register. */
	if (ret && ret != -ENOENT)
		return ret;

	d->of_node = np;

	return 0;
}
