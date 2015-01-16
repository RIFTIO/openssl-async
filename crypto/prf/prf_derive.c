/* crypto/prf/prf_derive*/
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
#include <time.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/prf.h>
#include "../../ssl/ssl_locl.h"
#ifdef OPENSSL_FIPS
#include <openssl/fips.h>
#endif

static int tls1_PRF(EVP_MD **md,int md_count,
		     const void *seed1, int seed1_len,
		     const void *seed2, int seed2_len,
		     const void *seed3, int seed3_len,
		     const void *seed4, int seed4_len,
		     const void *seed5, int seed5_len,
		     const unsigned char *sec, int slen,
		     unsigned char *out1,
		     unsigned char *out2, size_t *olen);

int PRF_derive(PRF *prf, unsigned char *out, size_t *olen)
	{
		//unsigned char tmp2[EVP_MAX_KEY_LENGTH];
		unsigned char tmp2[*olen];
		int ret=-1;
		if( prf->version >= TLS1_VERSION )
		    ret = tls1_PRF( prf->md, prf->md_count,
			 prf->seed1, prf->seed1_len,
		         prf->seed2, prf->seed2_len,
		         prf->seed3, prf->seed3_len,
		         prf->seed4, prf->seed4_len,
		         prf->seed5, prf->seed5_len,
		         prf->sec, prf->sec_len,
		         out,
		         tmp2, olen);
		/* else
			//Handle for SSL3 */
		return ret;
	}


/* seed1 through seed5 are virtually concatenated */
static int tls1_P_hash(const EVP_MD *md, const unsigned char *sec,
			int sec_len,
			const void *seed1, int seed1_len,
			const void *seed2, int seed2_len,
			const void *seed3, int seed3_len,
			const void *seed4, int seed4_len,
			const void *seed5, int seed5_len,
			unsigned char *out, size_t olen)
	{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx, ctx_tmp;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;

	chunk=EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	EVP_MD_CTX_set_flags(&ctx_tmp, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
	if (!mac_key)
		goto err;
	if (!EVP_DigestSignInit(&ctx,NULL,md, NULL, mac_key))
		goto err;
	if (!EVP_DigestSignInit(&ctx_tmp,NULL,md, NULL, mac_key))
		goto err;
	if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
		goto err;
	if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
		goto err;
	if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
		goto err;
	if (seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
		goto err;
	if (seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
		goto err;
	if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
		goto err;

	for (;;)
		{
		/* Reinit mac contexts */
		if (!EVP_DigestSignInit(&ctx,NULL,md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignInit(&ctx_tmp,NULL,md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx,A1,A1_len))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx_tmp,A1,A1_len))
			goto err;
		if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
			goto err;
		if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
			goto err;
		if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
			goto err;
		if (seed4 && !EVP_DigestSignUpdate(&ctx,seed4,seed4_len))
			goto err;
		if (seed5 && !EVP_DigestSignUpdate(&ctx,seed5,seed5_len))
			goto err;

		if (olen > chunk)
			{
			if (!EVP_DigestSignFinal(&ctx,out,&j))
				goto err;
			out+=j;
			olen-=j;
			/* calc the next A1 value */
			if (!EVP_DigestSignFinal(&ctx_tmp,A1,&A1_len))
				goto err;
			 }
		else    /* last one */
			{
			if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
				goto err;
			memcpy(out,A1,olen);
			break;
			}
		}
	ret = 1;
err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	OPENSSL_cleanse(A1,sizeof(A1));
	return ret;
	}

/* seed1 through seed5 are virtually concatenated */
int tls1_PRF(EVP_MD **prf_md, int md_count,
		     const void *seed1, int seed1_len,
		     const void *seed2, int seed2_len,
		     const void *seed3, int seed3_len,
		     const void *seed4, int seed4_len,
		     const void *seed5, int seed5_len,
		     const unsigned char *sec, int slen,
		     unsigned char *out1,
		     unsigned char *out2, size_t *olen)
	{ 
	int len,i,idx;
	const unsigned char *S1;
	EVP_MD *md;
	int ret = 0;

	len=slen/md_count;
	if (md_count == 1)
		slen = 0;
	S1=sec;
	memset(out1,0,*olen);
	for (idx=0;idx < md_count;idx++) 
		{
		md = (EVP_MD *) *prf_md;
		if (!tls1_P_hash(md ,S1,len+(slen&1),
				seed1,seed1_len,seed2,seed2_len,seed3,seed3_len,seed4,seed4_len,seed5,seed5_len,
				out2,*olen))
			goto err;
		S1+=len;
		for (i=0; i < *olen; i++)
			{
			out1[i]^=out2[i];
			}
		prf_md++;
		}
	ret = 1;
err:
	return ret;
	}

