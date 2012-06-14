#ifndef ASM_X86_SERPENT_H
#define ASM_X86_SERPENT_H

#include <linux/crypto.h>
#include <crypto/serpent.h>
#include <crypto/cryptd.h>
#include <crypto/lrw.h>


struct async_serpent_ctx {
	struct cryptd_ablkcipher *cryptd_tfm;
};

struct serpent_xts_ctx {
	struct serpent_ctx tweak_ctx;
	struct serpent_ctx crypt_ctx;
};

struct serpent_lrw_ctx {
	struct lrw_table_ctx lrw_table;
	struct serpent_ctx serpent_ctx;
};

/* These functions are shared between the different implementations */
int serpent_ecb_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);
int serpent_ecb_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);

int serpent_cbc_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);
int serpent_cbc_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);

int serpent_ctr_crypt(struct blkcipher_desc *desc, struct scatterlist *dst,
		      struct scatterlist *src, unsigned int nbytes);

int serpent_lrw_setkey(struct crypto_tfm *tfm, const u8 *key,
		       unsigned int keylen);
int serpent_lrw_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);
int serpent_lrw_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);
void serpent_lrw_exit_tfm(struct crypto_tfm *tfm);

int serpent_xts_setkey(struct crypto_tfm *tfm, const u8 *key,
		       unsigned int keylen);
int serpent_xts_encrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);
int serpent_xts_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes);

int serpent_ablk_set_key(struct crypto_ablkcipher *tfm, const u8 *key,
			 unsigned int key_len);
int __serpent_ablk_encrypt(struct ablkcipher_request *req);
int serpent_ablk_encrypt(struct ablkcipher_request *req);
int serpent_ablk_decrypt(struct ablkcipher_request *req);
void serpent_ablk_exit(struct crypto_tfm *tfm);
int serpent_ablk_init(struct crypto_tfm *tfm);


#ifdef CONFIG_X86_32

#define SERPENT_PARALLEL_BLOCKS 4

asmlinkage void __serpent_enc_blk_4way(struct serpent_ctx *ctx, u8 *dst,
				       const u8 *src, bool xor);
asmlinkage void serpent_dec_blk_4way(struct serpent_ctx *ctx, u8 *dst,
				     const u8 *src);

static inline void serpent_enc_blk_xway(struct serpent_ctx *ctx, u8 *dst,
					const u8 *src)
{
	__serpent_enc_blk_4way(ctx, dst, src, false);
}

static inline void serpent_enc_blk_xway_xor(struct serpent_ctx *ctx, u8 *dst,
					    const u8 *src)
{
	__serpent_enc_blk_4way(ctx, dst, src, true);
}

static inline void serpent_dec_blk_xway(struct serpent_ctx *ctx, u8 *dst,
					const u8 *src)
{
	serpent_dec_blk_4way(ctx, dst, src);
}

#else

#define SERPENT_PARALLEL_BLOCKS 8

asmlinkage void __serpent_enc_blk_8way(struct serpent_ctx *ctx, u8 *dst,
				       const u8 *src, bool xor);
asmlinkage void serpent_dec_blk_8way(struct serpent_ctx *ctx, u8 *dst,
				     const u8 *src);

static inline void serpent_enc_blk_xway(struct serpent_ctx *ctx, u8 *dst,
				   const u8 *src)
{
	__serpent_enc_blk_8way(ctx, dst, src, false);
}

static inline void serpent_enc_blk_xway_xor(struct serpent_ctx *ctx, u8 *dst,
				       const u8 *src)
{
	__serpent_enc_blk_8way(ctx, dst, src, true);
}

static inline void serpent_dec_blk_xway(struct serpent_ctx *ctx, u8 *dst,
				   const u8 *src)
{
	serpent_dec_blk_8way(ctx, dst, src);
}

#endif

#endif
