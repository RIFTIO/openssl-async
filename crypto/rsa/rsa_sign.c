/* crypto/rsa/rsa_sign.c */
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
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include "rsa_locl.h"
#include <openssl/pool.h>

/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH	36

typedef struct rsa_asynch_ctx_st RSA_ASYNCH_CTX;
struct rsa_asynch_ctx_st
	{
	/* For asynch operations */
	int (*sign_user_cb)(unsigned char *md, size_t size,
		void *userdata, int status);
	int (*verify_user_cb)(void *userdata, int status);
	void *cb_userdata;
	/* internal cache for sign */
	int type;
	unsigned int *siglen_s;
	int j;
	unsigned char *tmps;
	/* internal cache for verify */
	int dtype;
	const unsigned char *m;
	unsigned int m_len;
	unsigned char *rm;
	size_t *prm_len;
	size_t siglen_v;
	};
IMPLEMENT_TYPED_LOCKED_POOL(RSA_ASYNCH_CTX, 1024, CRYPTO_LOCK_ASYNCH)

int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
	     unsigned char *sigret, unsigned int *siglen, RSA *rsa)
	{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j,ret=1;
	unsigned char *p, *tmps = NULL;
	const unsigned char *s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
			&& !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW))
		{
		RSAerr(RSA_F_RSA_SIGN, RSA_R_NON_FIPS_RSA_METHOD);
		return 0;
		}
#endif
	if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_sign)
		{
		return rsa->meth->rsa_sign(type, m, m_len,
			sigret, siglen, rsa);
		}
	/* Special case: SSL signature, just check the length */
	if(type == NID_md5_sha1) {
		if(m_len != SSL_SIG_LENGTH) {
			RSAerr(RSA_F_RSA_SIGN,RSA_R_INVALID_MESSAGE_LENGTH);
			return(0);
		}
		i = SSL_SIG_LENGTH;
		s = m;
	} else {
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
			{
			RSAerr(RSA_F_RSA_SIGN,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return(0);
			}
		if (sig.algor->algorithm->length == 0)
			{
			RSAerr(RSA_F_RSA_SIGN,RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
			return(0);
			}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;

		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m; /* TMP UGLY CAST */
		sig.digest->length=m_len;

		i=i2d_X509_SIG(&sig,NULL);
	}
	j=RSA_size(rsa);
	if (i > (j-RSA_PKCS1_PADDING_SIZE))
		{
		RSAerr(RSA_F_RSA_SIGN,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
		return(0);
		}
	if(type != NID_md5_sha1) {
		tmps=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (tmps == NULL)
			{
			RSAerr(RSA_F_RSA_SIGN,ERR_R_MALLOC_FAILURE);
			return(0);
			}
		p=tmps;
		i2d_X509_SIG(&sig,&p);
		s=tmps;
	}
	i=RSA_private_encrypt(i,s,sigret,rsa,RSA_PKCS1_PADDING);
	if (i <= 0)
		ret=0;
	else
		*siglen=i;

	if(type != NID_md5_sha1) {
		OPENSSL_cleanse(tmps,(unsigned int)j+1);
		OPENSSL_free(tmps);
	}
	return(ret);
	}

static int RSA_sign_asynch_post(unsigned char *res, size_t reslen,
	RSA_ASYNCH_CTX *cb_data, int status);
int RSA_sign_asynch(int type, const unsigned char *m, unsigned int m_len,
	unsigned char *sigret, unsigned int *siglen, RSA *rsa,
	int (*cb)(unsigned char *res, size_t reslen, void *cb_data, int status),
	void *cb_data)
	{
	X509_SIG sig;
	ASN1_TYPE parameter;
	int i,j,ret=1;
	unsigned char *p, *tmps = NULL;
	const unsigned char *s = NULL;
	X509_ALGOR algor;
	ASN1_OCTET_STRING digest;
	RSA_ASYNCH_CTX *actx = NULL;

	if((rsa->meth->flags & RSA_FLAG_ASYNCH) == 0)
	{
		RSAerr(RSA_F_RSA_SIGN_ASYNCH, RSA_R_NO_ASYNCH_SUPPORT);
		return 0;
	}

#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
			&& !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW))
		{
		RSAerr(RSA_F_RSA_SIGN_ASYNCH, RSA_R_NON_FIPS_RSA_METHOD);
		return 0;
		}
#endif
	if(rsa->meth->rsa_sign_asynch)
		{
		return rsa->meth->rsa_sign_asynch(type, m, m_len,
			sigret, siglen, rsa, cb, cb_data);
		}
	/* Special case: SSL signature, just check the length */
	if(type == NID_md5_sha1) {
		if(m_len != SSL_SIG_LENGTH) {
			RSAerr(RSA_F_RSA_SIGN_ASYNCH,RSA_R_INVALID_MESSAGE_LENGTH);
			return(0);
		}
		i = SSL_SIG_LENGTH;
		s = m;
	} else {
		sig.algor= &algor;
		sig.algor->algorithm=OBJ_nid2obj(type);
		if (sig.algor->algorithm == NULL)
			{
			RSAerr(RSA_F_RSA_SIGN_ASYNCH,RSA_R_UNKNOWN_ALGORITHM_TYPE);
			return(0);
			}
		if (sig.algor->algorithm->length == 0)
			{
			RSAerr(RSA_F_RSA_SIGN_ASYNCH,RSA_R_THE_ASN1_OBJECT_IDENTIFIER_IS_NOT_KNOWN_FOR_THIS_MD);
			return(0);
			}
		parameter.type=V_ASN1_NULL;
		parameter.value.ptr=NULL;
		sig.algor->parameter= &parameter;

		sig.digest= &digest;
		sig.digest->data=(unsigned char *)m; /* TMP UGLY CAST */
		sig.digest->length=m_len;

		i=i2d_X509_SIG(&sig,NULL);
	}
	j=RSA_size(rsa);
	if (i > (j-RSA_PKCS1_PADDING_SIZE))
		{
		RSAerr(RSA_F_RSA_SIGN_ASYNCH,RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
		return(0);
		}
	if(type != NID_md5_sha1) {
		tmps=(unsigned char *)OPENSSL_malloc((unsigned int)j+1);
		if (tmps == NULL)
			{
			RSAerr(RSA_F_RSA_SIGN_ASYNCH,ERR_R_MALLOC_FAILURE);
			return(0);
			}
		p=tmps;
		i2d_X509_SIG(&sig,&p);
		s=tmps;
	}
	actx = alloc_RSA_ASYNCH_CTX();
	if (actx == NULL)
		{
		if(type != NID_md5_sha1) {
			OPENSSL_cleanse(tmps,(unsigned int)j+1);
			OPENSSL_free(tmps);
		}
		RSAerr(RSA_F_RSA_SIGN_ASYNCH,ERR_R_RETRY);
		return -1;
		}
	actx->type = type;
	actx->j = j;
	actx->tmps = tmps;
	actx->siglen_s = siglen;
	actx->sign_user_cb = cb;
	actx->cb_userdata = cb_data;

	i=RSA_private_encrypt_asynch(i,s,sigret,rsa,RSA_PKCS1_PADDING,
		(int (*)(unsigned char *res, size_t reslen,
			void *cb_data, int status))RSA_sign_asynch_post,actx);
	if (i <= 0)
		{
		ret=0;
		if(type != NID_md5_sha1) {
			OPENSSL_cleanse(tmps,(unsigned int)j+1);
			OPENSSL_free(tmps);
		}
		free_RSA_ASYNCH_CTX(actx);
		}
	return(ret);
	}

static int RSA_sign_asynch_post(unsigned char *res, size_t reslen,
	RSA_ASYNCH_CTX *actx, int status)
	{
	if(status)
		*(actx->siglen_s) = reslen;
	if(actx->type != NID_md5_sha1)
		{
		OPENSSL_cleanse(actx->tmps,(unsigned int)actx->j+1);
		OPENSSL_free(actx->tmps);
		}
	status = actx->sign_user_cb(res, reslen, actx->cb_userdata, status);
	free_RSA_ASYNCH_CTX(actx);
	return status;
	}

int int_rsa_verify(int dtype, const unsigned char *m,
			  unsigned int m_len,
			  unsigned char *rm, size_t *prm_len,
			  const unsigned char *sigbuf, size_t siglen,
			  RSA *rsa)
	{
	int i,ret=0,sigtype;
	unsigned char *s;
	X509_SIG *sig=NULL;

#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
			&& !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW))
		{
		RSAerr(RSA_F_INT_RSA_VERIFY, RSA_R_NON_FIPS_RSA_METHOD);
		return 0;
		}
#endif

	if (siglen != (unsigned int)RSA_size(rsa))
		{
		RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_WRONG_SIGNATURE_LENGTH);
		return(0);
		}

	if((dtype == NID_md5_sha1) && rm)
		{
		i = RSA_public_decrypt((int)siglen,
					sigbuf,rm,rsa,RSA_PKCS1_PADDING);
		if (i <= 0)
			return 0;
		*prm_len = i;
		return 1;
		}

	s=(unsigned char *)OPENSSL_malloc((unsigned int)siglen);
	if (s == NULL)
		{
		RSAerr(RSA_F_INT_RSA_VERIFY,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if((dtype == NID_md5_sha1) && (m_len != SSL_SIG_LENGTH) ) {
			RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_INVALID_MESSAGE_LENGTH);
			goto err;
	}
	i=RSA_public_decrypt((int)siglen,sigbuf,s,rsa,RSA_PKCS1_PADDING);

	if (i <= 0) goto err;
	/* Oddball MDC2 case: signature can be OCTET STRING.
	 * check for correct tag and length octets.
	 */
	if (dtype == NID_mdc2 && i == 18 && s[0] == 0x04 && s[1] == 0x10)
		{
		if (rm)
			{
			memcpy(rm, s + 2, 16);
			*prm_len = 16;
			ret = 1;
			}
		else if(memcmp(m, s + 2, 16))
			RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
		else
			ret = 1;
		}

	/* Special case: SSL signature */
	if(dtype == NID_md5_sha1) {
		if((i != SSL_SIG_LENGTH) || memcmp(s, m, SSL_SIG_LENGTH))
				RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
		else ret = 1;
	} else {
		const unsigned char *p=s;
		sig=d2i_X509_SIG(NULL,&p,(long)i);

		if (sig == NULL) goto err;

		/* Excess data can be used to create forgeries */
		if(p != s+i)
			{
			RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
			goto err;
			}

		/* Parameters to the signature algorithm can also be used to
		   create forgeries */
		if(sig->algor->parameter
		   && ASN1_TYPE_get(sig->algor->parameter) != V_ASN1_NULL)
			{
			RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
			goto err;
			}

		sigtype=OBJ_obj2nid(sig->algor->algorithm);


	#ifdef RSA_DEBUG
		/* put a backward compatibility flag in EAY */
		fprintf(stderr,"in(%s) expect(%s)\n",OBJ_nid2ln(sigtype),
			OBJ_nid2ln(dtype));
	#endif
		if (sigtype != dtype)
			{
			if (((dtype == NID_md5) &&
				(sigtype == NID_md5WithRSAEncryption)) ||
				((dtype == NID_md2) &&
				(sigtype == NID_md2WithRSAEncryption)))
				{
				/* ok, we will let it through */
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
				fprintf(stderr,"signature has problems, re-make with post SSLeay045\n");
#endif
				}
			else
				{
				RSAerr(RSA_F_INT_RSA_VERIFY,
						RSA_R_ALGORITHM_MISMATCH);
				goto err;
				}
			}
		if (rm)
			{
			const EVP_MD *md;
			md = EVP_get_digestbynid(dtype);
			if (md && (EVP_MD_size(md) != sig->digest->length))
				RSAerr(RSA_F_INT_RSA_VERIFY,
						RSA_R_INVALID_DIGEST_LENGTH);
			else
				{
				memcpy(rm, sig->digest->data,
							sig->digest->length);
				*prm_len = sig->digest->length;
				ret = 1;
				}
			}
		else if (((unsigned int)sig->digest->length != m_len) ||
			(memcmp(m,sig->digest->data,m_len) != 0))
			{
			RSAerr(RSA_F_INT_RSA_VERIFY,RSA_R_BAD_SIGNATURE);
			}
		else
			ret=1;
	}
err:
	if (sig != NULL) X509_SIG_free(sig);
	if (s != NULL)
		{
		OPENSSL_cleanse(s,(unsigned int)siglen);
		OPENSSL_free(s);
		}
	return(ret);
	}

int RSA_verify(int dtype, const unsigned char *m, unsigned int m_len,
		const unsigned char *sigbuf, unsigned int siglen,
		RSA *rsa)
	{

	if((rsa->flags & RSA_FLAG_SIGN_VER) && rsa->meth->rsa_verify)
		{
		return rsa->meth->rsa_verify(dtype, m, m_len,
			sigbuf, siglen, rsa);
		}

	return int_rsa_verify(dtype, m, m_len, NULL, NULL, sigbuf, siglen, rsa);
	}

static int int_rsa_verify_post1(unsigned char *res, size_t reslen,
	RSA_ASYNCH_CTX *actx, int status);
static int int_rsa_verify_post2(unsigned char *res, size_t reslen,
	RSA_ASYNCH_CTX *actx, int status);
static int int_rsa_verify_pre(int dtype, const unsigned char *m,
	unsigned int m_len,
	unsigned char *rm, size_t *prm_len,
	const unsigned char *sigbuf, size_t siglen,
	RSA *rsa,
	int (*cb)(void *cb_data, int status),
	void *cb_data)
	{
	int i=0;
	unsigned char *s = NULL;
	RSA_ASYNCH_CTX *actx;

#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !(rsa->meth->flags & RSA_FLAG_FIPS_METHOD)
			&& !(rsa->flags & RSA_FLAG_NON_FIPS_ALLOW))
		{
		RSAerr(RSA_F_INT_RSA_VERIFY_PRE, RSA_R_NON_FIPS_RSA_METHOD);
		return 0;
		}
#endif

	if (siglen != (unsigned int)RSA_size(rsa))
		{
		RSAerr(RSA_F_INT_RSA_VERIFY_PRE,RSA_R_WRONG_SIGNATURE_LENGTH);
		return(0);
		}

	actx = alloc_RSA_ASYNCH_CTX();
	if (actx == NULL)
		{
		if (s != NULL)
			{
			OPENSSL_cleanse(s,(unsigned int)siglen);
			OPENSSL_free(s);
			}
		RSAerr(RSA_F_INT_RSA_VERIFY_PRE,ERR_R_RETRY);
		return -1;
		}
	actx->dtype = dtype;
	actx->m = m;
	actx->m_len = m_len;
	actx->rm = rm;
	actx->prm_len = prm_len;
	actx->siglen_v = siglen;
	actx->verify_user_cb = cb;
	actx->cb_userdata = cb_data;

	if((dtype == NID_md5_sha1) && rm)
		{
		i = RSA_public_decrypt_asynch((int)siglen,
			sigbuf,rm,rsa,RSA_PKCS1_PADDING,
			(int(*)(unsigned char *, size_t, void *, int))int_rsa_verify_post1, actx);
		goto end;
		}

	s=(unsigned char *)OPENSSL_malloc((unsigned int)siglen);
	if (s == NULL)
		{
		RSAerr(RSA_F_INT_RSA_VERIFY_PRE,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if((dtype == NID_md5_sha1) && (m_len != SSL_SIG_LENGTH) ) {
			RSAerr(RSA_F_INT_RSA_VERIFY_PRE,RSA_R_INVALID_MESSAGE_LENGTH);
			goto err;
	}
	i=RSA_public_decrypt_asynch((int)siglen,
		sigbuf,s,rsa,RSA_PKCS1_PADDING,
		(int(*)(unsigned char *, size_t, void *, int))int_rsa_verify_post2, actx);
end:
	if (i)
		return(1);
err:
	if (s != NULL)
		{
		OPENSSL_cleanse(s,(unsigned int)siglen);
		OPENSSL_free(s);
		}
	free_RSA_ASYNCH_CTX(actx);
	return(0);
	}

static int int_rsa_verify_post1(unsigned char *res, size_t i,
	RSA_ASYNCH_CTX *actx, int status)
	{
	if (status < 0)
		status = 0;
	else
		{
		*actx->prm_len = i;
		status = 1;
		}
	status = actx->verify_user_cb(actx->cb_userdata, status);
	free_RSA_ASYNCH_CTX(actx);
	return status;
	}

static int int_rsa_verify_post2(unsigned char *res, size_t i,
	RSA_ASYNCH_CTX *actx, int status)
	{
	int ret=0,sigtype;
	unsigned char *s = res;
	X509_SIG *sig=NULL;
	int dtype = actx->dtype;
	const unsigned char *m = actx->m;
	unsigned int m_len = actx->m_len;
	unsigned char *rm = actx->rm;
	size_t *prm_len = actx->prm_len;
	size_t siglen = actx->siglen_v;

	if (status < 0) goto err;

	/* Oddball MDC2 case: signature can be OCTET STRING.
	 * check for correct tag and length octets.
	 */
	if (dtype == NID_mdc2 && i == 18 && s[0] == 0x04 && s[1] == 0x10)
		{
		if (rm)
			{
			memcpy(rm, s + 2, 16);
			*prm_len = 16;
			ret = 1;
			}
		else if(memcmp(m, s + 2, 16))
			RSAerr(RSA_F_INT_RSA_VERIFY_POST2,RSA_R_BAD_SIGNATURE);
		else
			ret = 1;
		}

	/* Special case: SSL signature */
	if(dtype == NID_md5_sha1) {
		if((i != SSL_SIG_LENGTH) || memcmp(s, m, SSL_SIG_LENGTH))
				RSAerr(RSA_F_INT_RSA_VERIFY_POST2,RSA_R_BAD_SIGNATURE);
		else ret = 1;
	} else {
		const unsigned char *p=s;
		sig=d2i_X509_SIG(NULL,&p,(long)i);

		if (sig == NULL) goto err;

		/* Excess data can be used to create forgeries */
		if(p != s+i)
			{
			RSAerr(RSA_F_INT_RSA_VERIFY_POST2,RSA_R_BAD_SIGNATURE);
			goto err;
			}

		/* Parameters to the signature algorithm can also be used to
		   create forgeries */
		if(sig->algor->parameter
		   && ASN1_TYPE_get(sig->algor->parameter) != V_ASN1_NULL)
			{
			RSAerr(RSA_F_INT_RSA_VERIFY_POST2,RSA_R_BAD_SIGNATURE);
			goto err;
			}

		sigtype=OBJ_obj2nid(sig->algor->algorithm);


	#ifdef RSA_DEBUG
		/* put a backward compatibility flag in EAY */
		fprintf(stderr,"in(%s) expect(%s)\n",OBJ_nid2ln(sigtype),
			OBJ_nid2ln(dtype));
	#endif
		if (sigtype != dtype)
			{
			if (((dtype == NID_md5) &&
				(sigtype == NID_md5WithRSAEncryption)) ||
				((dtype == NID_md2) &&
				(sigtype == NID_md2WithRSAEncryption)))
				{
				/* ok, we will let it through */
#if !defined(OPENSSL_NO_STDIO) && !defined(OPENSSL_SYS_WIN16)
				fprintf(stderr,"signature has problems, re-make with post SSLeay045\n");
#endif
				}
			else
				{
				RSAerr(RSA_F_INT_RSA_VERIFY_POST2,
						RSA_R_ALGORITHM_MISMATCH);
				goto err;
				}
			}
		if (rm)
			{
			const EVP_MD *md;
			md = EVP_get_digestbynid(dtype);
			if (md && (EVP_MD_size(md) != sig->digest->length))
				RSAerr(RSA_F_INT_RSA_VERIFY_POST2,
						RSA_R_INVALID_DIGEST_LENGTH);
			else
				{
				memcpy(rm, sig->digest->data,
							sig->digest->length);
				*prm_len = sig->digest->length;
				ret = 1;
				}
			}
		else if (((unsigned int)sig->digest->length != m_len) ||
			(memcmp(m,sig->digest->data,m_len) != 0))
			{
			RSAerr(RSA_F_INT_RSA_VERIFY_POST2,RSA_R_BAD_SIGNATURE);
			}
		else
			ret=1;
	}
err:
	if (sig != NULL) X509_SIG_free(sig);
	if (s != NULL)
		{
		OPENSSL_cleanse(s,(unsigned int)siglen);
		OPENSSL_free(s);
		}
	ret = actx->verify_user_cb(actx->cb_userdata, ret);
	free_RSA_ASYNCH_CTX(actx);
	return ret;
	}

int RSA_verify_asynch(int dtype, const unsigned char *m, unsigned int m_len,
	const unsigned char *sigbuf, unsigned int siglen,
	RSA *rsa,
	int (*cb)(void *cb_data, int status),
	void *cb_data)
	{
	if((rsa->flags & RSA_FLAG_ASYNCH) == 0)
		return 0;

	if(rsa->meth->rsa_verify_asynch)
		{
		return rsa->meth->rsa_verify_asynch(dtype, m, m_len,
			sigbuf, siglen, rsa, cb, cb_data);
		}
	return int_rsa_verify_pre(dtype, m, m_len, NULL, NULL,
		sigbuf, siglen, rsa, cb, cb_data);
	}
