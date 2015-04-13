/* crypto/evp/digest.c */
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
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/pool.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

typedef struct evp_asynch_ctx_st EVP_ASYNCH_CTX;
typedef int (*asynch_cb_t) (unsigned char *md, unsigned int size,
                            void *ctx, int status);
typedef int (*internal_asynch_cb_t) (unsigned char *md, unsigned int size,
                                     EVP_ASYNCH_CTX * actx, int status);

struct evp_md_ctx_internal_st {
    /* For asynch operations */
    void (*cb) (void);
    void *cb_data;
    /* Internal cache */
    int (*internal_cb) (unsigned char *md, unsigned int size,
                        EVP_MD_CTX *ctx, int status);
};

/*
 * Asynch requires to have a per-call context.  To avoid memory
 * fragmentation, we use a big pool that gets allocated once.
 */
struct evp_asynch_ctx_st {
    EVP_MD_CTX *ctx;
    internal_asynch_cb_t internal_cb;
    asynch_cb_t user_cb;        /* Cache of ctx->internal->cb */
    void *user_cb_data;         /* Cache of ctx->internal->cb_data */
};
static POOL *asynch_ctx_pool = NULL;
static EVP_ASYNCH_CTX *alloc_asynch_ctx()
{
    EVP_ASYNCH_CTX *ret = NULL;
    CRYPTO_w_lock(CRYPTO_LOCK_ASYNCH);
    if (asynch_ctx_pool == NULL) {
        asynch_ctx_pool = POOL_init(sizeof(EVP_ASYNCH_CTX), 1024);
        if (!asynch_ctx_pool) {
            CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
            EVPerr(EVP_F_ALLOC_ASYNCH_CTX, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    }
    ret = (EVP_ASYNCH_CTX *) POOL_alloc_item(asynch_ctx_pool);
    if (!ret) {
        CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
        EVPerr(EVP_F_ALLOC_ASYNCH_CTX, ERR_R_RETRY);
        return ret;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
    return ret;
}

static void free_asynch_ctx(EVP_ASYNCH_CTX * item)
{
    CRYPTO_w_lock(CRYPTO_LOCK_ASYNCH);
    POOL_free_item(asynch_ctx_pool, item);
    CRYPTO_w_unlock(CRYPTO_LOCK_ASYNCH);
}

void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
{
    ctx->digest = NULL;
    ctx->engine = NULL;

    ctx->flags = 0;
    ctx->md_data = NULL;
    ctx->pctx = NULL;
    ctx->update.synch = NULL;
    ctx->internal = NULL;
}

static int evp_MD_CTX_expand(EVP_MD_CTX *ctx)
{
    ctx->internal = OPENSSL_malloc(sizeof(struct evp_md_ctx_internal_st));
    if (!ctx->internal)
        return 0;
    memset(ctx->internal, 0, sizeof(struct evp_md_ctx_internal_st));
    EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_EXPANDED);
    return 1;
}

void EVP_MD_CTX_init_ex(EVP_MD_CTX *ctx)
{
    EVP_MD_CTX_init(ctx);
    evp_MD_CTX_expand(ctx);
}

EVP_MD_CTX *EVP_MD_CTX_create(void)
{
    EVP_MD_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    if (ctx)
        EVP_MD_CTX_init(ctx);

    return ctx;
}

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)
{
    EVP_MD_CTX_init(ctx);
    return EVP_DigestInit_ex(ctx, type, NULL);
}

static int _evp_digest_cb(unsigned char *md, unsigned int size,
                          EVP_ASYNCH_CTX * actx, int status)
{
    /*
     * Everything of value is handled by the internal callback, this function
     * only acts as a conduit.
     */
    return actx->internal_cb(md, size, actx, status);
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    int call_asynch_cb_at_end = 0;
    EVP_MD_CTX_clear_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unecessary.
     */
    if (ctx->engine && ctx->digest && (!type ||
                                       (type
                                        && (type->type ==
                                            ctx->digest->type))))
        goto skip_to_init;
    if (type) {
        /*
         * Ensure an ENGINE left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_MD could be used).
         */
        if (ctx->engine)
            ENGINE_finish(ctx->engine);
        if (impl) {
            if (!ENGINE_init(impl)) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else
            /* Ask if an ENGINE is reserved for this job */
            impl = ENGINE_get_digest_engine(type->type);
        if (impl) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_MD *d = NULL;
            if ((ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
                && !(ctx->flags & EVP_MD_CTX_FLAG_DISABLE_ASYNCH_MD_ONLY)
                && ctx->internal->cb) {
                d = ENGINE_get_digest_asynch(impl, type->type);
            }

            if (!d) {
                d = ENGINE_get_digest(impl, type->type);
            }

            if (!d) {
                /* Same comment from evp_enc.c */
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_INITIALIZATION_ERROR);
                ENGINE_finish(impl);
                return 0;
            }
            /* We'll use the ENGINE's private digest definition */
            type = d;
            /*
             * Store the ENGINE functional reference so we know 'type' came
             * from an ENGINE and we need to release it when done.
             */
            ctx->engine = impl;
        } else {
            ctx->engine = NULL;
        }

        if (type->flags & EVP_MD_FLAG_ASYNCH) {
# ifdef OPENSSL_FIPS
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_NO_ASYNCH_SUPPORT_IN_FIPS);
            ERR_add_error_data(1, EVP_MD_name(type));
            return 0;
# else
            if (!(ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
                || ctx->internal->cb == NULL) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_NO_CALLBACK_SET);
                return 0;
            }
# endif
        }
    } else {
        if (!ctx->digest) {
            EVPerr(EVP_F_EVP_DIGESTINIT_EX, EVP_R_NO_DIGEST_SET);
            return 0;
        }
        type = ctx->digest;
    }
#endif
    if (ctx->digest != type) {
        if (ctx->digest && ctx->digest->ctx_size)
            OPENSSL_free(ctx->md_data);
        ctx->digest = type;
        if (!(ctx->flags & EVP_MD_CTX_FLAG_NO_INIT) && type->ctx_size) {
            if (ctx->digest->flags & EVP_MD_FLAG_ASYNCH)
                ctx->update.asynch = type->update.asynch;
            else
                ctx->update.synch = type->update.synch;
            ctx->md_data = OPENSSL_malloc(type->ctx_size);
            if (ctx->md_data == NULL) {
                EVPerr(EVP_F_EVP_DIGESTINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memset(ctx->md_data, 0, type->ctx_size);
        }
    }
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
    if (ctx->pctx) {
        int r;
        r = EVP_PKEY_CTX_ctrl(ctx->pctx, -1, EVP_PKEY_OP_TYPE_SIG,
                              EVP_PKEY_CTRL_DIGESTINIT, 0, ctx);
        if (r <= 0 && (r != -2))
            return 0;
    }
    {
        int rc;
        if (ctx->flags & EVP_MD_CTX_FLAG_NO_INIT)
            rc = 1;
        else {
#ifdef OPENSSL_FIPS
            if (FIPS_mode()) {
                if (FIPS_digestinit(ctx, type))
                    return 1;
                OPENSSL_free(ctx->md_data);
                ctx->md_data = NULL;
                return 0;
            }
#endif
            if (ctx->digest->flags & EVP_MD_FLAG_ASYNCH) {
                ctx->internal->internal_cb = NULL;
                rc = ctx->digest->init.asynch(ctx,
                                              (asynch_cb_t) _evp_digest_cb);
                if (!rc)
                    return rc;
                call_asynch_cb_at_end = 1;
            } else {
                rc = ctx->digest->init.synch(ctx);
                if (!rc)
                    return rc;
                if ((ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
                    && !(ctx->flags & EVP_MD_CTX_FLAG_DISABLE_ASYNCH_MD_ONLY)
                    && ctx->internal->cb) {
                    call_asynch_cb_at_end = 1;
                }
            }
        }

        if (call_asynch_cb_at_end) {
            asynch_cb_t asynch_cb = (asynch_cb_t) ctx->internal->cb;
            asynch_cb(NULL, 0, ctx->internal->cb_data, rc);
        }
        return rc;
    }
}

static int _evp_DigestUpdate_post(unsigned char *md, unsigned int size,
                                  EVP_ASYNCH_CTX * actx, int status)
{
    if (status >= 0)
        free_asynch_ctx(actx);
    else
        status = actx->user_cb(NULL, 0, actx->user_cb_data, status);
    return status;
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
#ifdef OPENSSL_FIPS
    return FIPS_digestupdate(ctx, data, count);
#else
    if (ctx->digest && ctx->digest->flags & EVP_MD_FLAG_ASYNCH) {
        EVP_ASYNCH_CTX *actx = NULL;
        int ret = 0;
        actx = alloc_asynch_ctx();
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = (asynch_cb_t) ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->internal_cb = _evp_DigestUpdate_post;
        ret = ctx->update.asynch(ctx, data, count, actx);
        if (!ret)
            free_asynch_ctx(actx);
        return ret;
    }
    if ((ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
        && !(ctx->flags & EVP_MD_CTX_FLAG_DISABLE_ASYNCH_MD_ONLY)
        && ctx->internal->cb) {
        int ret = 0;
        ret = ctx->update.synch(ctx, data, count);
        asynch_cb_t asynch_cb = (asynch_cb_t) ctx->internal->cb;
        asynch_cb(NULL, 0, ctx->internal->cb_data, ret);
        return ret;

    }
    return ctx->update.synch(ctx, data, count);
#endif
}

static int _evp_DigestFinal_post(unsigned char *md, unsigned int size,
                                 EVP_ASYNCH_CTX * actx, int status)
{
    EVP_MD_CTX *ctx = actx->ctx;
    int ret;
    if (status < 0) {
        ret = actx->user_cb(md, size, actx->user_cb_data, status);
    } else {
        if (ctx->digest->cleanup) {
            ctx->digest->cleanup(ctx);
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
        }
        memset(ctx->md_data, 0, ctx->digest->ctx_size);
        ret = actx->user_cb(md, size, actx->user_cb_data, status);
        free_asynch_ctx(actx);
    }
    return ret;
}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    int ret;
    ret = EVP_DigestFinal_ex(ctx, md, size);
    EVP_MD_CTX_cleanup(ctx);
    return ret;
}

/* The caller can assume that this removes any secret data from the context */
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
#ifdef OPENSSL_FIPS
    return FIPS_digestfinal(ctx, md, size);
#else
    int ret = 0;

    OPENSSL_assert(ctx->digest->md_size <= EVP_MAX_MD_SIZE);
    if (ctx->digest->flags & EVP_MD_FLAG_ASYNCH) {
        EVP_ASYNCH_CTX *actx = NULL;
        actx = alloc_asynch_ctx();
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = (asynch_cb_t) ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->internal_cb = _evp_DigestFinal_post;
        ret = ctx->digest->final.asynch(ctx, md, actx);
        if (!ret)
            free_asynch_ctx(actx);
        return ret;
    }
    if ((ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)
        && !(ctx->flags & EVP_MD_CTX_FLAG_DISABLE_ASYNCH_MD_ONLY)
        && ctx->internal->cb) {
        unsigned int tmpsize = 0;
        asynch_cb_t asynch_cb = (asynch_cb_t) ctx->internal->cb;
        void *asynch_cb_data = ctx->internal->cb_data;
        ret = ctx->digest->final.synch(ctx, md);
        if (size != NULL)
            *size = ctx->digest->md_size;
        tmpsize = ctx->digest->md_size;

        if (ctx->digest->cleanup) {
            ctx->digest->cleanup(ctx);
            EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
        }
        memset(ctx->md_data, 0, ctx->digest->ctx_size);
        asynch_cb(md, tmpsize, asynch_cb_data, ret);
        return ret;

    }
    ret = ctx->digest->final.synch(ctx, md);
    if (size != NULL)
        *size = ctx->digest->md_size;
    if (ctx->digest->cleanup) {
        ctx->digest->cleanup(ctx);
        EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
    }
    memset(ctx->md_data, 0, ctx->digest->ctx_size);
    return ret;
#endif
}

int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    EVP_MD_CTX_init(out);
    return EVP_MD_CTX_copy_ex(out, in);
}

int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
    unsigned char *tmp_buf;
    if ((in == NULL) || (in->digest == NULL)) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a digest context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    if (out->digest == in->digest) {
        tmp_buf = out->md_data;
        EVP_MD_CTX_set_flags(out, EVP_MD_CTX_FLAG_REUSE);
    } else
        tmp_buf = NULL;
    EVP_MD_CTX_cleanup(out);
    out->digest = in->digest;
    out->engine = in->engine;

    out->flags = in->flags;
    out->update.synch = in->update.synch;

    if (in->md_data && out->digest->ctx_size) {
        if (tmp_buf)
            out->md_data = tmp_buf;
        else {
            out->md_data = OPENSSL_malloc(out->digest->ctx_size);
            if (!out->md_data) {
                EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        memcpy(out->md_data, in->md_data, out->digest->ctx_size);
    }

    out->update.synch = in->update.synch;

    if (in->pctx) {
        out->pctx = EVP_PKEY_CTX_dup(in->pctx);
        if (!out->pctx) {
            EVP_MD_CTX_cleanup(out);
            return 0;
        }
    }

    if (out->flags & EVP_MD_CTX_FLAG_EXPANDED) {
        if (!evp_MD_CTX_expand(out)) {
            EVPerr(EVP_F_EVP_MD_CTX_COPY_EX, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        out->internal->cb = in->internal->cb;
        out->internal->cb_data = in->internal->cb_data;
    }

    if (out->digest->copy)
        return out->digest->copy(out, in);

    return 1;
}

int EVP_Digest(const void *data, size_t count,
               unsigned char *md, unsigned int *size, const EVP_MD *type,
               ENGINE *impl)
{
    EVP_MD_CTX ctx;
    int ret;

    EVP_MD_CTX_init(&ctx);
    EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_ONESHOT);
    ret = EVP_DigestInit_ex(&ctx, type, impl)
        && EVP_DigestUpdate(&ctx, data, count)
        && EVP_DigestFinal_ex(&ctx, md, size);
    EVP_MD_CTX_cleanup(&ctx);

    return ret;
}

static int EVP_check_ctx(EVP_MD_CTX *ctx)
{
    if (!ctx->digest) {
        EVPerr(EVP_F_EVP_CHECK_CTX, EVP_R_NO_DIGEST_SET);
        return 0;
    }
    if (!(ctx->flags & EVP_MD_CTX_FLAG_EXPANDED)) {
        EVPerr(EVP_F_EVP_CHECK_CTX, EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
        return 0;
    }
    return 1;
}

int EVP_MD_CTX_ctrl_ex(EVP_MD_CTX *ctx, int type, int arg, void *ptr,
                       void (*fn_ptr) (void))
{
    int ret;

    /*
     * Intercept any pre-init EVP level commands before trying to hand them
     * on to algorithm specific ctrl() handlers.
     */
    switch (type) {
    case EVP_MD_CTRL_SETUP_ASYNCH_CALLBACK:
        if (ctx->digest) {
            EVPerr(EVP_F_EVP_MD_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_SET_AFTER_DIGESTINIT);
            return 0;
        }
        if (!(ctx->flags & EVP_MD_CTX_FLAG_EXPANDED))
            if (!evp_MD_CTX_expand(ctx)) {
                EVPerr(EVP_F_EVP_MD_CTX_CTRL_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        ctx->internal->cb = (void (*)(void))fn_ptr;
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_MD_CTRL_UPDATE_ASYNCH_CALLBACK:
        if (!EVP_check_ctx(ctx))
            return 0;
        ctx->internal->cb = (void (*)(void))fn_ptr;
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_MD_CTRL_UPDATE_ASYNCH_CALLBACK_DATA:
        if (!EVP_check_ctx(ctx))
            return 0;
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_MD_CTRL_GET_ASYNCH_CALLBACK_FN:
        if (!EVP_check_ctx(ctx))
            return 0;
        *(void (**)(void))ptr = ctx->internal->cb;
        return 1;
    case EVP_MD_CTRL_GET_ASYNCH_CALLBACK_DATA:
        if (!EVP_check_ctx(ctx))
            return 0;
        *(void **)ptr = ctx->internal->cb_data;
        return 1;
    default:
        break;
    }

    if (!ctx->digest) {
        EVPerr(EVP_F_EVP_MD_CTX_CTRL_EX, EVP_R_NO_DIGEST_SET);
        return 0;
    }

    if (!ctx->digest->md_ctrl) {
        EVPerr(EVP_F_EVP_MD_CTX_CTRL_EX, EVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->digest->md_ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        EVPerr(EVP_F_EVP_MD_CTX_CTRL_EX,
               EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)
{
    if (ctx) {
        EVP_MD_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

/* This call frees resources associated with the context */
int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
{
#ifndef OPENSSL_FIPS
    /*
     * Don't assume ctx->md_data was cleaned in EVP_Digest_Final, because
     * sometimes only copies of the context are ever finalised.
     */
    if (ctx->digest && ctx->digest->cleanup
        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))
        ctx->digest->cleanup(ctx);
    if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
        OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
        OPENSSL_free(ctx->md_data);
    }
#endif
    if (ctx->pctx)
        EVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
    if (ctx->engine)
        /*
         * The EVP_MD we used belongs to an ENGINE, release the functional
         * reference we held for this reason.
         */
        ENGINE_finish(ctx->engine);
#endif
#ifdef OPENSSL_FIPS
    FIPS_md_ctx_cleanup(ctx);
#endif
    if (ctx->flags & EVP_MD_CTX_FLAG_EXPANDED) {
        OPENSSL_free(ctx->internal);
        ctx->internal = NULL;
    }
    EVP_MD_CTX_init(ctx);

    return 1;
}
