/*
 * Copyright (C) ST-Ericsson AB 2012
 * Author:	Sjur Brændeland / sjur.brandeland@stericsson.com
 * License terms: GNU General Public License (GPL) version 2
 */

/* This is a dummy implementation of GENIO */

#include <linux/module.h>
#include <linux/c2c_genio.h>

int genio_subscribe(int bit, void (*bit_set_cb)(void *data), void *data)
{
	return 0;
}
EXPORT_SYMBOL(genio_subscribe);

int genio_unsubscribe(int bit)
{
	return 0;
}
EXPORT_SYMBOL(genio_unsubscribe);

int genio_set_bit(int bit)
{
	return 0;
}
EXPORT_SYMBOL(genio_set_bit);

int genio_reset(void)
{
	return 0;
}
EXPORT_SYMBOL(genio_reset);

int genio_subscribe_caif_ready(void (*caif_ready_cb) (bool ready))
{
	return 0;
}
EXPORT_SYMBOL(genio_subscribe_caif_ready);

int genio_set_shm_addr(u32 addr, void (*ipc_ready_cb) (void))
{
	return 0;
}
EXPORT_SYMBOL(genio_set_shm_addr);

int genio_bit_alloc(u32 setter_mask, u32 getter_mask)
{
	return 0;
}
EXPORT_SYMBOL(genio_bit_alloc);

void genio_register_errhandler(void (*errhandler)(int errno))
{
}
EXPORT_SYMBOL(genio_register_errhandler);

int genio_power_req(int state)
{
	return 0;
}
EXPORT_SYMBOL(genio_power_req);

static int __init genio_init(void)
{
	return 0;
}

static void __exit genio_exit(void)
{
}
module_init(genio_init);
module_exit(genio_exit);

MODULE_LICENSE("GPL");
