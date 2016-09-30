/*
 * AArch64 port of the OpenSSL SHA256 implementation for ARM NEON
 *
 * Copyright (c) 2016 Linaro Ltd. <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <crypto/internal/hash.h>
#include <linux/cryptohash.h>
#include <linux/types.h>
#include <linux/string.h>
#include <crypto/sha.h>
#include <crypto/sha256_base.h>
#include <asm/neon.h>

MODULE_DESCRIPTION("SHA-224/SHA-256 secure hash using ARMv8 NEON");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");

asmlinkage void sha256_block_data_order_neon(u32 *digest, const void *data,
					     unsigned int num_blks);

static int sha256_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);

	if ((sctx->count % SHA256_BLOCK_SIZE) + len < SHA256_BLOCK_SIZE)
		return crypto_sha256_update(desc, data, len);

	kernel_neon_begin_partial(12);
	sha256_base_do_update(desc, data, len,
			(sha256_block_fn *)sha256_block_data_order_neon);
	kernel_neon_end();

	return 0;
}

static int sha256_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	kernel_neon_begin_partial(12);
	if (len)
		sha256_base_do_update(desc, data, len,
			(sha256_block_fn *)sha256_block_data_order_neon);
	sha256_base_do_finalize(desc,
			(sha256_block_fn *)sha256_block_data_order_neon);
	kernel_neon_end();

	return sha256_base_finish(desc, out);
}

static int sha256_final(struct shash_desc *desc, u8 *out)
{
	return sha256_finup(desc, NULL, 0, out);
}

static struct shash_alg algs[] = { {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_base_init,
	.update			= sha256_update,
	.final			= sha256_final,
	.finup			= sha256_finup,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha256",
	.base.cra_driver_name	= "sha256-neon",
	.base.cra_priority	= 150,
	.base.cra_flags		= CRYPTO_ALG_TYPE_SHASH,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA224_DIGEST_SIZE,
	.init			= sha224_base_init,
	.update			= sha256_update,
	.final			= sha256_final,
	.finup			= sha256_finup,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha224",
	.base.cra_driver_name	= "sha224-neon",
	.base.cra_priority	= 150,
	.base.cra_flags		= CRYPTO_ALG_TYPE_SHASH,
	.base.cra_blocksize	= SHA224_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
} };

static int __init sha256_neon_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha256_neon_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(sha256_neon_mod_init);
module_exit(sha256_neon_mod_fini);
