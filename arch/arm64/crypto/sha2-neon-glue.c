/*
 * sha2-neon-glue.c - SHA-224/SHA-256 using ARMv8 Neon
 *
 * Copyright (C) 2016 Linaro Ltd <daniel.thompson@linaro.org>
 * Copyright (C) 2016 Linaro Ltd <victor.chong@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <asm/neon.h>
#include <asm/unaligned.h>
#include <crypto/internal/hash.h>
#include <crypto/sha.h>
#include <crypto/sha256_base.h>
#include <linux/cpufeature.h>
#include <linux/crypto.h>
#include <linux/module.h>

#define ASM_EXPORT(sym, val) \
	asm(".globl " #sym "; .set " #sym ", %0" :: "I"(val));

MODULE_DESCRIPTION("SHA-224/SHA-256 secure hash using ARMv8 Neon");
MODULE_AUTHOR("Daniel Thompson <daniel.thompson@linaro.org>");
MODULE_AUTHOR("Victor Chong <victor.chong@linaro.org>");
MODULE_LICENSE("GPL v2");

struct sha256_neon_state {
	struct sha256_state	sst;
	u32			finalize;
};

//which regs to read out sst, srcn blocks? read procedure call std
asmlinkage void sha2_neon_transform(struct sha256_neon_state *sst, u8 const *src,
				  int blocks);

static int sha256_neon_update(struct shash_desc *desc, const u8 *data,
			    unsigned int len)
{
	struct sha256_neon_state *sctx = shash_desc_ctx(desc);

	sctx->finalize = 0;
	kernel_neon_begin_partial(28);
	sha256_base_do_update(desc, data, len,
			      (sha256_block_fn *)sha2_neon_transform);
	kernel_neon_end();

	return 0;
}

static int sha256_neon_finup(struct shash_desc *desc, const u8 *data,
			   unsigned int len, u8 *out)
{
	struct sha256_neon_state *sctx = shash_desc_ctx(desc);
	bool finalize = !sctx->sst.count && !(len % SHA256_BLOCK_SIZE);

	sctx->finalize = finalize;

	kernel_neon_begin_partial(28);
	if (len)
		sha256_base_do_update(desc, data, len,
			(sha256_block_fn *)sha2_neon_transform);
	sha256_base_do_finalize(desc,
			(sha256_block_fn *)sha2_neon_transform);
	kernel_neon_end();

	return sha256_base_finish(desc, out);
}

static int sha256_neon_final(struct shash_desc *desc, u8 *out)
{
	return sha256_neon_finup(desc, NULL, 0, out);
}

static struct shash_alg algs[] = { {
	.init			= sha224_base_init,
	.update			= sha256_neon_update,
	.final			= sha256_neon_final,
	.finup			= sha256_neon_finup,
	.descsize		= sizeof(struct sha256_neon_state),
	.digestsize		= SHA224_DIGEST_SIZE,
	.base			= {
		.cra_name		= "sha224",
		.cra_driver_name	= "sha224-neon",
		.cra_priority		= 300, //FIXME: Change this to 100
		.cra_flags		= CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize		= SHA256_BLOCK_SIZE,
		.cra_module		= THIS_MODULE,
	}
}, {
	.init			= sha256_base_init,
	.update			= sha256_neon_update,
	.final			= sha256_neon_final,
	.finup			= sha256_neon_finup,
	.descsize		= sizeof(struct sha256_neon_state),
	.digestsize		= SHA256_DIGEST_SIZE,
	.base			= {
		.cra_name		= "sha256",
		.cra_driver_name	= "sha256-neon",
		.cra_priority		= 300, //FIXME: Change this to 100
		.cra_flags		= CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize		= SHA256_BLOCK_SIZE,
		.cra_module		= THIS_MODULE,
	}
} };

static int __init sha2_neon_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha2_neon_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_cpu_feature_match(SHA2, sha2_neon_mod_init);
module_exit(sha2_neon_mod_fini);
