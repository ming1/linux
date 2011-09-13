/*
 * Syscall support for the Hexagon architecture
 *
 * Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef _ASM_HEXAGON_SYSCALL_H
#define _ASM_HEXAGON_SYSCALL_H

typedef long (*syscall_fn)(unsigned long, unsigned long,
	unsigned long, unsigned long,
	unsigned long, unsigned long);

asmlinkage int sys_execve(char __user *ufilename, char __user * __user *argv,
			  char __user * __user *envp);
asmlinkage int sys_clone(unsigned long clone_flags, unsigned long newsp,
			 unsigned long parent_tidp, unsigned long child_tidp);

#define sys_execve	sys_execve
#define sys_clone	sys_clone

#include <asm-generic/syscalls.h>

extern void *sys_call_table[];

#endif
