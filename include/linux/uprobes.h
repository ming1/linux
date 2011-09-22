#ifndef _LINUX_UPROBES_H
#define _LINUX_UPROBES_H
/*
 * Userspace Probes (UProbes)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2008-2011
 * Authors:
 *	Srikar Dronamraju
 *	Jim Keniston
 */

#include <linux/rbtree.h>

struct uprobe {
	struct rb_node		rb_node;	/* node in the rb tree */
	atomic_t		ref;
	struct inode		*inode;		/* Also hold a ref to inode */
	loff_t			offset;
};

#endif	/* _LINUX_UPROBES_H */
