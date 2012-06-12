/*
 * Glue Code for SSE2 assembler versions of Serpent Cipher
 *
 * Copyright (C) 2012 Johannes Goetzfried
 *     <Johannes.Goetzfried@informatik.stud.uni-erlangen.de>
 *
 * Copyright (C) 2011 Jussi Kivilinna <jussi.kivilinna@mbnet.fi>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 * USA
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/algapi.h>
#include <crypto/serpent.h>
#include <crypto/cryptd.h>
#include <crypto/ctr.h>
#include <crypto/lrw.h>
#include <crypto/xts.h>
#include <asm/i387.h>
#include <asm/xcr.h>
#include <asm/xsave.h>
#include <asm/serpent.h>

static struct crypto_alg serpent_algs[10] = { {
	.cra_name		= "__ecb-serpent-sse2",
	.cra_driver_name	= "__driver-ecb-serpent-sse2",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[0].cra_list),
	.cra_u = {
		.blkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.setkey		= serpent_setkey,
			.encrypt	= serpent_ecb_encrypt,
			.decrypt	= serpent_ecb_decrypt,
		},
	},
}, {
	.cra_name		= "__cbc-serpent-sse2",
	.cra_driver_name	= "__driver-cbc-serpent-sse2",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[1].cra_list),
	.cra_u = {
		.blkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.setkey		= serpent_setkey,
			.encrypt	= serpent_cbc_encrypt,
			.decrypt	= serpent_cbc_decrypt,
		},
	},
}, {
	.cra_name		= "__ctr-serpent-sse2",
	.cra_driver_name	= "__driver-ctr-serpent-sse2",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[2].cra_list),
	.cra_u = {
		.blkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_setkey,
			.encrypt	= serpent_ctr_crypt,
			.decrypt	= serpent_ctr_crypt,
		},
	},
}, {
	.cra_name		= "__lrw-serpent-sse2",
	.cra_driver_name	= "__driver-lrw-serpent-sse2",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct serpent_lrw_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[3].cra_list),
	.cra_exit		= serpent_lrw_exit_tfm,
	.cra_u = {
		.blkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE +
					  SERPENT_BLOCK_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE +
					  SERPENT_BLOCK_SIZE,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_lrw_setkey,
			.encrypt	= serpent_lrw_encrypt,
			.decrypt	= serpent_lrw_decrypt,
		},
	},
}, {
	.cra_name		= "__xts-serpent-sse2",
	.cra_driver_name	= "__driver-xts-serpent-sse2",
	.cra_priority		= 0,
	.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct serpent_xts_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_blkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[4].cra_list),
	.cra_u = {
		.blkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE * 2,
			.max_keysize	= SERPENT_MAX_KEY_SIZE * 2,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_xts_setkey,
			.encrypt	= serpent_xts_encrypt,
			.decrypt	= serpent_xts_decrypt,
		},
	},
}, {
	.cra_name		= "ecb(serpent)",
	.cra_driver_name	= "ecb-serpent-sse2",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[5].cra_list),
	.cra_init		= serpent_ablk_init,
	.cra_exit		= serpent_ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.setkey		= serpent_ablk_set_key,
			.encrypt	= serpent_ablk_encrypt,
			.decrypt	= serpent_ablk_decrypt,
		},
	},
}, {
	.cra_name		= "cbc(serpent)",
	.cra_driver_name	= "cbc-serpent-sse2",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[6].cra_list),
	.cra_init		= serpent_ablk_init,
	.cra_exit		= serpent_ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_ablk_set_key,
			.encrypt	= __serpent_ablk_encrypt,
			.decrypt	= serpent_ablk_decrypt,
		},
	},
}, {
	.cra_name		= "ctr(serpent)",
	.cra_driver_name	= "ctr-serpent-sse2",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= 1,
	.cra_ctxsize		= sizeof(struct async_serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[7].cra_list),
	.cra_init		= serpent_ablk_init,
	.cra_exit		= serpent_ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_ablk_set_key,
			.encrypt	= serpent_ablk_encrypt,
			.decrypt	= serpent_ablk_encrypt,
			.geniv		= "chainiv",
		},
	},
}, {
	.cra_name		= "lrw(serpent)",
	.cra_driver_name	= "lrw-serpent-sse2",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[8].cra_list),
	.cra_init		= serpent_ablk_init,
	.cra_exit		= serpent_ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE +
					  SERPENT_BLOCK_SIZE,
			.max_keysize	= SERPENT_MAX_KEY_SIZE +
					  SERPENT_BLOCK_SIZE,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_ablk_set_key,
			.encrypt	= serpent_ablk_encrypt,
			.decrypt	= serpent_ablk_decrypt,
		},
	},
}, {
	.cra_name		= "xts(serpent)",
	.cra_driver_name	= "xts-serpent-sse2",
	.cra_priority		= 400,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= SERPENT_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct async_serpent_ctx),
	.cra_alignmask		= 0,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(serpent_algs[9].cra_list),
	.cra_init		= serpent_ablk_init,
	.cra_exit		= serpent_ablk_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= SERPENT_MIN_KEY_SIZE * 2,
			.max_keysize	= SERPENT_MAX_KEY_SIZE * 2,
			.ivsize		= SERPENT_BLOCK_SIZE,
			.setkey		= serpent_ablk_set_key,
			.encrypt	= serpent_ablk_encrypt,
			.decrypt	= serpent_ablk_decrypt,
		},
	},
} };

static int __init serpent_sse2_init(void)
{
	if (!cpu_has_xmm2) {
		printk(KERN_INFO "SSE2 instructions are not detected.\n");
		return -ENODEV;
	}

	return crypto_register_algs(serpent_algs, ARRAY_SIZE(serpent_algs));
}

static void __exit serpent_sse2_exit(void)
{
	crypto_unregister_algs(serpent_algs, ARRAY_SIZE(serpent_algs));
}

module_init(serpent_sse2_init);
module_exit(serpent_sse2_exit);

MODULE_DESCRIPTION("Serpent Cipher Algorithm, SSE2 optimized");
MODULE_LICENSE("GPL");
MODULE_ALIAS("serpent");
