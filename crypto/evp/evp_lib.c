/* crypto/evp/evp_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "evp_locl.h"

int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	int ret;

	if (c->cipher->set_asn1_parameters != NULL)
		ret=c->cipher->set_asn1_parameters(c,type);
	else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1)
		{
		if (EVP_CIPHER_CTX_mode(c) == EVP_CIPH_WRAP_MODE)
			{
			ASN1_TYPE_set(type, V_ASN1_NULL, NULL);
			ret = 1;
			}
		else
			ret=EVP_CIPHER_set_asn1_iv(c, type);
		}
	else
		ret=-1;
	return(ret);
	}

int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	int ret;

	if (c->cipher->get_asn1_parameters != NULL)
		ret=c->cipher->get_asn1_parameters(c,type);
	else if (c->cipher->flags & EVP_CIPH_FLAG_DEFAULT_ASN1)
		{
		if (EVP_CIPHER_CTX_mode(c) == EVP_CIPH_WRAP_MODE)
			return 1;
		ret=EVP_CIPHER_get_asn1_iv(c, type);
		}
	else
		ret=-1;
	return(ret);
	}

int EVP_CIPHER_get_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	int i=0;
	unsigned int l;

	if (type != NULL) 
		{
		l=EVP_CIPHER_CTX_iv_length(c);
		OPENSSL_assert(l <= sizeof(c->iv));
		i=ASN1_TYPE_get_octetstring(type,c->oiv,l);
		if (i != (int)l)
			return(-1);
		else if (i > 0)
			memcpy(c->iv,c->oiv,l);
		}
	return(i);
	}

int EVP_CIPHER_set_asn1_iv(EVP_CIPHER_CTX *c, ASN1_TYPE *type)
	{
	int i=0;
	unsigned int j;

	if (type != NULL)
		{
		j=EVP_CIPHER_CTX_iv_length(c);
		OPENSSL_assert(j <= sizeof(c->iv));
		i=ASN1_TYPE_set_octetstring(type,c->oiv,j);
		}
	return(i);
	}

/* Convert the various cipher NIDs and dummies to a proper OID NID */
int EVP_CIPHER_type(const EVP_CIPHER *ctx)
{
	int nid;
	ASN1_OBJECT *otmp;
	nid = EVP_CIPHER_nid(ctx);

	switch(nid) {

		case NID_rc2_cbc:
		case NID_rc2_64_cbc:
		case NID_rc2_40_cbc:

		return NID_rc2_cbc;

		case NID_rc4:
		case NID_rc4_40:

		return NID_rc4;

		case NID_aes_128_cfb128:
		case NID_aes_128_cfb8:
		case NID_aes_128_cfb1:

		return NID_aes_128_cfb128;

		case NID_aes_192_cfb128:
		case NID_aes_192_cfb8:
		case NID_aes_192_cfb1:

		return NID_aes_192_cfb128;

		case NID_aes_256_cfb128:
		case NID_aes_256_cfb8:
		case NID_aes_256_cfb1:

		return NID_aes_256_cfb128;

		case NID_des_cfb64:
		case NID_des_cfb8:
		case NID_des_cfb1:

		return NID_des_cfb64;

		case NID_des_ede3_cfb64:
		case NID_des_ede3_cfb8:
		case NID_des_ede3_cfb1:

		return NID_des_cfb64;

		default:
		/* Check it has an OID and it is valid */
		otmp = OBJ_nid2obj(nid);
		if(!otmp || !otmp->data) nid = NID_undef;
		ASN1_OBJECT_free(otmp);
		return nid;
	}
}

int EVP_CIPHER_block_size(const EVP_CIPHER *e)
	{
	return e->block_size;
	}

int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->cipher->block_size;
	}

struct evp_md_ctx_internal_st
	{
	/* For asynch operations */
	int (*cb)(unsigned char *md, unsigned int size,
		void *userdata, int status);
	void *cb_data;
	/* Internal cache */
	int (*internal_cb)(unsigned char *md, unsigned int size,
		EVP_MD_CTX *ctx, int status);
	};

typedef struct evp_asynch_ctx_st EVP_ASYNCH_CTX;
typedef int (*internal_asynch_cb_t)(unsigned char *out, int outl,
	EVP_ASYNCH_CTX *ctx, int status);
typedef int (*asynch_cb_t)(unsigned char *out, int outl, void *ctx, int status);

/* Asynch requires to have a per-call context.  To avoid memory fragmentation,
 * we use a big pool that gets allocated once. */
struct evp_asynch_ctx_st
	{
	EVP_CIPHER_CTX *ctx;
	internal_asynch_cb_t internal_cb;
	asynch_cb_t user_cb;	/* Cache of ctx->internal->cb */
	void *user_cb_data;	/* Cache of ctx->internal->cb_data */
	EVP_ASYNCH_CTX *next_free;
	};
static EVP_ASYNCH_CTX *asynch_ctx_pool = NULL;
static EVP_ASYNCH_CTX *asynch_ctx_next_free = NULL;
static int asynch_ctx_break;
static int asynch_ctx_items;
static EVP_ASYNCH_CTX *alloc_asynch_ctx()
	{
	EVP_ASYNCH_CTX *ret = NULL;
	CRYPTO_w_lock(CRYPTO_LOCK_ASYNCH);
	if (asynch_ctx_pool == NULL)
		{
		asynch_ctx_items = 1024;
		asynch_ctx_break = 0;
		asynch_ctx_next_free = NULL;
		asynch_ctx_pool =
			(EVP_ASYNCH_CTX *)OPENSSL_malloc(sizeof(EVP_ASYNCH_CTX) * asynch_ctx_items);
		if (asynch_ctx_pool == NULL)
			{
			CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
			return NULL;
			}
		}
	if (asynch_ctx_next_free)
		{
		ret = asynch_ctx_next_free;
		asynch_ctx_next_free = asynch_ctx_next_free->next_free;
		}
	else if (asynch_ctx_break < asynch_ctx_items)
		ret = &asynch_ctx_pool[asynch_ctx_break++];
	else
		ret = NULL;
	CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
	return ret;
	}
static void free_asynch_ctx(EVP_ASYNCH_CTX *item)
	{
	CRYPTO_w_lock(CRYPTO_LOCK_ASYNCH);
	item->next_free = asynch_ctx_next_free;
	asynch_ctx_next_free = item;
	CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
	}

static int _evp_Cipher_post(unsigned char *out, int outl,
	EVP_ASYNCH_CTX *actx, int status)
	{
	int ret = actx->user_cb(out, outl, actx->user_cb_data, status);
	if (status >= 0)
		free_asynch_ctx(actx);
	return ret;
	}
int EVP_Cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl)
	{
	if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH)
		{
		EVP_ASYNCH_CTX *actx = NULL;
		int ret = 0;

		if (!(ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH))
			return 0;

		actx = alloc_asynch_ctx();
		if (actx == NULL)
			return 0;
		actx->ctx = ctx;
		actx->user_cb = ctx->internal->cb;
		actx->user_cb_data = ctx->internal->cb_data;
		actx->internal_cb = _evp_Cipher_post;
		ret = ctx->cipher->do_cipher.asynch(ctx,out,in,inl,actx);
		if (!ret)
			free_asynch_ctx(actx);
		return ret;
		}
	else
		return ctx->cipher->do_cipher.synch(ctx,out,in,inl);
	}

const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->cipher;
	}

unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher)
	{
	return cipher->flags;
	}

unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->cipher->flags;
	}

void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->app_data;
	}

void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data)
	{
	ctx->app_data = data;
	}

int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher)
	{
	return cipher->iv_len;
	}

int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->cipher->iv_len;
	}

int EVP_CIPHER_key_length(const EVP_CIPHER *cipher)
	{
	return cipher->key_len;
	}

int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->key_len;
	}

int EVP_CIPHER_nid(const EVP_CIPHER *cipher)
	{
	return cipher->nid;
	}

int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx)
	{
	return ctx->cipher->nid;
	}

int EVP_MD_block_size(const EVP_MD *md) 
	{
	return md->block_size;
	}

int EVP_MD_type(const EVP_MD *md)
	{
	return md->type;
	}

int EVP_MD_pkey_type(const EVP_MD *md)
	{
	return md->pkey_type;
	}

int EVP_MD_size(const EVP_MD *md)
	{
	if (!md)
		{
		EVPerr(EVP_F_EVP_MD_SIZE, EVP_R_MESSAGE_DIGEST_IS_NULL);
		return -1;
		}
	return md->md_size;
	}

unsigned long EVP_MD_flags(const EVP_MD *md)
	{
	return md->flags;
	}

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)
	{
	if (!ctx)
		return NULL;
	return ctx->digest;
	}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
	{
	ctx->flags |= flags;
	}

void EVP_MD_CTX_clear_flags(EVP_MD_CTX *ctx, int flags)
	{
	ctx->flags &= ~flags;
	}

int EVP_MD_CTX_test_flags(const EVP_MD_CTX *ctx, int flags)
	{
	return (ctx->flags & flags);
	}

void EVP_CIPHER_CTX_set_flags(EVP_CIPHER_CTX *ctx, int flags)
	{
	ctx->flags |= flags;
	}

void EVP_CIPHER_CTX_clear_flags(EVP_CIPHER_CTX *ctx, int flags)
	{
	ctx->flags &= ~flags;
	}

int EVP_CIPHER_CTX_test_flags(const EVP_CIPHER_CTX *ctx, int flags)
	{
	return (ctx->flags & flags);
	}
