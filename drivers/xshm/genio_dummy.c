/*
 * Copyright (C) ST-Ericsson AB 2010
 * Author:	Sjur Brendeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

/* This is a dummy implementation of GENIO */

#include <linux/c2c_genio.h>
int genio_subscribe(int bit, void (*bit_set_cb)(void *data), void *data)
{
	return 0;
}

int genio_unsubscribe(int bit)
{
	return 0;
}

int genio_set_bit(int bit)
{
	return 0;
}

int genio_init(void)
{
	return 0;
}

void genio_exit(void)
{
}

int genio_reset(void)
{
	return 0;
}

int genio_subscribe_caif_ready(void (*caif_ready_cb) (bool ready))
{
	return 0;
}

int genio_set_shm_addr(u32 addr, void (*ipc_ready_cb) (void))
{
	return 0;
}

int genio_bit_alloc(u32 setter_mask, u32 getter_mask)
{
	return 0;
}

void genio_register_errhandler(void (*errhandler)(int errno))
{
}

int genio_power_req(int state)
{
	return 0;
}
