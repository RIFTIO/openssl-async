/* crypto/evp/p_verify.c */
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
#include <openssl/x509.h>

struct evp_md_ctx_internal_st {
    /* For asynch operations */
    void (*cb) (void);
    void *cb_data;
    /* Internal cache */
    int (*internal_cb) (unsigned char *md, size_t size,
                        EVP_MD_CTX *ctx, int status);
};

static int _evp_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                            unsigned int siglen, EVP_PKEY *pkey)
{
    unsigned char m[EVP_MAX_MD_SIZE];
    unsigned int m_len;
    int i = 0, ok = 0, ret = -1, v;
    EVP_MD_CTX tmp_ctx;
    EVP_PKEY_CTX *pkctx = NULL;

    if (NULL == m)
        goto err;
    EVP_MD_CTX_init(&tmp_ctx);
    if (!EVP_MD_CTX_copy_ex(&tmp_ctx, ctx))
        goto err;
    if (!EVP_DigestFinal_ex(&tmp_ctx, m, &m_len))
        goto err;
    EVP_MD_CTX_cleanup(&tmp_ctx);

    if (ctx->digest->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE) {
        pkctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkctx)
            goto err;
        if (EVP_PKEY_verify_init(pkctx) <= 0)
            goto err;
        if (EVP_PKEY_CTX_set_signature_md(pkctx, ctx->digest) <= 0)
            goto err;
        ret = EVP_PKEY_verify(pkctx, sigbuf, siglen, m, m_len);
 err:
        EVP_PKEY_CTX_free(pkctx);
        return ret;
    }

    for (i = 0; i < 4; i++) {
        v = ctx->digest->required_pkey_type[i];
        if (v == 0)
            break;
        if (pkey->type == v) {
            ok = 1;
            break;
        }
    }
    if (!ok) {
        EVPerr(EVP_F__EVP_VERIFYFINAL, EVP_R_WRONG_PUBLIC_KEY_TYPE);
        return (ret);
    }

    if (ctx->digest->verify.synch == NULL) {
        EVPerr(EVP_F__EVP_VERIFYFINAL, EVP_R_NO_VERIFY_FUNCTION_CONFIGURED);
        return (ret);
    }

    ret =
        (ctx->digest->
         verify.synch(ctx->digest->type, m, m_len, sigbuf, siglen,
                      pkey->pkey.ptr));
    return (ret);
}

int _evp_VerifyFinal_asynch_post(void *cb_data, int status)
{
    EVP_PKEY_CTX *pkctx;
    EVP_PKEY_asynch_verify_cb *pkcb;
    EVP_MD_CTX *md_ctx;
    unsigned char *digest_buffer;
    int ret = 0;
    if (cb_data) {
        pkctx = (EVP_PKEY_CTX *)cb_data;
        if (pkctx) {
            md_ctx = (EVP_MD_CTX *)EVP_PKEY_CTX_get_asynch_cb_data(pkctx);
            pkcb = (EVP_PKEY_asynch_verify_cb *)
                EVP_PKEY_CTX_get_asynch_cb(pkctx);
            if (pkcb && md_ctx && md_ctx->internal) {
                pkcb(md_ctx->internal->cb_data, status);
                ret = 1;
            }
            if (md_ctx) {
                EVP_MD_CTX_cleanup(md_ctx);
                OPENSSL_free(md_ctx);
            }
            digest_buffer = EVP_PKEY_CTX_get_digest_buffer(pkctx);
            if (digest_buffer)
                OPENSSL_free(digest_buffer);
            EVP_PKEY_CTX_free(pkctx);
        }
    }
    return ret;
}

static int _evp_VerifyFinal_asynch(EVP_MD_CTX *ctx,
                                   const unsigned char *sigbuf,
                                   unsigned int siglen, EVP_PKEY *pkey)
{
    unsigned char *m = OPENSSL_malloc(EVP_MAX_MD_SIZE);
    unsigned int m_len;
    int i = 0, ok = 0, ret = -1, v;
    EVP_MD_CTX *tmp_ctx = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    /* FIXME: add asynch digest processing as a next step */
    tmp_ctx = OPENSSL_malloc(sizeof(EVP_MD_CTX));
    if (NULL == tmp_ctx || NULL == m)
        goto err;
    EVP_MD_CTX_init(tmp_ctx);
    if (!EVP_MD_CTX_copy_ex(tmp_ctx, ctx))
        goto err;
    if (!EVP_DigestFinal_ex(tmp_ctx, m, &m_len))
        goto err;
    if (ctx->digest->flags & EVP_MD_FLAG_PKEY_METHOD_SIGNATURE) {
        pkctx = EVP_PKEY_CTX_new(pkey, NULL);
        if (!pkctx)
            goto err;
        if (!EVP_PKEY_CTX_set_asynch_cb(pkctx, tmp_ctx->internal->cb)
            || !EVP_PKEY_CTX_set_asynch_cb_data(pkctx, tmp_ctx)
            || !EVP_PKEY_CTX_set_digest_buffer(pkctx, m)
            || !EVP_PKEY_CTX_set_digest_buffer_length(pkctx, m_len))
            goto err;
        if (EVP_PKEY_verify_init(pkctx) <= 0)
            goto err;
        if (EVP_PKEY_CTX_set_signature_md(pkctx, tmp_ctx->digest) <= 0)
            goto err;
        ret =
            EVP_PKEY_verify_asynch(pkctx, sigbuf, siglen, m, m_len,
                                   _evp_VerifyFinal_asynch_post, pkctx);
        if (ret <= 0)
            goto err;
        return ret;
 err:
        if (m)
            OPENSSL_free(m);
        if (tmp_ctx) {
            EVP_MD_CTX_cleanup(tmp_ctx);
            OPENSSL_free(tmp_ctx);
        }
        EVP_PKEY_CTX_free(pkctx);
        return ret;
    }

    for (i = 0; i < 4; i++) {
        v = tmp_ctx->digest->required_pkey_type[i];
        if (v == 0)
            break;
        if (pkey->type == v) {
            ok = 1;
            break;
        }
    }
    if (!ok) {
        EVPerr(EVP_F__EVP_VERIFYFINAL_ASYNCH, EVP_R_WRONG_PUBLIC_KEY_TYPE);
        if (m)
            OPENSSL_free(m);
        if (tmp_ctx) {
            EVP_MD_CTX_cleanup(tmp_ctx);
            OPENSSL_free(tmp_ctx);
        }
        return ret;
    }

    if (tmp_ctx->digest->verify.asynch == NULL) {
        if (tmp_ctx->digest->verify.synch != NULL) {
            EVP_PKEY_asynch_verify_cb *asynch_cb =
                (EVP_PKEY_asynch_verify_cb *) tmp_ctx->internal->cb;
            ret =
                (ctx->digest->
                 verify.synch(ctx->digest->type, m, m_len, sigbuf, siglen,
                              pkey->pkey.ptr));
            asynch_cb(tmp_ctx, ret);
            return ret;
        } else {
            EVPerr(EVP_F__EVP_VERIFYFINAL_ASYNCH,
                   EVP_R_NO_SIGN_FUNCTION_CONFIGURED);
            if (m)
                OPENSSL_free(m);
            if (tmp_ctx) {
                EVP_MD_CTX_cleanup(tmp_ctx);
                OPENSSL_free(tmp_ctx);
            }
            return ret;
        }
    }
    return (tmp_ctx->digest->verify.asynch(tmp_ctx->digest->type, m, m_len,
                                           sigbuf, siglen, pkey->pkey.ptr,
                                           (EVP_PKEY_asynch_verify_cb *)
                                           tmp_ctx->internal->cb, tmp_ctx));
}

int EVP_VerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sigbuf,
                    unsigned int siglen, EVP_PKEY *pkey)
{
    if ((ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
        && ctx->internal->cb) {
        return _evp_VerifyFinal_asynch(ctx, sigbuf, siglen, pkey);
    }
    return _evp_VerifyFinal(ctx, sigbuf, siglen, pkey);
}
