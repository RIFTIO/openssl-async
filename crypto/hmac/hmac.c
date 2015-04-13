/* crypto/hmac/hmac.c */
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
#include <stdlib.h>
#include <string.h>
#include "cryptlib.h"
#include <openssl/hmac.h>

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

struct hmac_ctx_asynch_st {
    void (*cb) (unsigned char *md, size_t len, void *userdata, int status);
    void *cb_data;
    enum {
        /* The following states are used for init */
        hmac_init,
        hmac_initkey_final,
        hmac_initkey_pad,
        hmac_reset,
        hmac_reset_final,
        hmac_init_final,
        /* The following state is used for update and final */
        hmac_data,
        hmac_final,
        hmac_final2,
        hmac_final3,
        hmac_final4
    } next_state;               /* State for our internal asynch callback */

    /* cache */
    int ctx_i_done;
    int ctx_o_done;
    const EVP_MD *md;
    ENGINE *impl;
};

static int HMAC_CTX_ASYNCH_copy(struct hmac_ctx_asynch_st **dest,
                                struct hmac_ctx_asynch_st *src)
{
    if (dest == NULL) {
        EVPerr(EVP_F_HMAC_CTX_ASYNCH_COPY, EVP_R_MALLOC_FAILURE);
        return 0;
    }
    if (src == NULL) {
        *dest = NULL;
        return 1;
    }
    *dest = OPENSSL_malloc(sizeof(struct hmac_ctx_asynch_st));
    if (*dest == NULL) {
        EVPerr(EVP_F_HMAC_CTX_ASYNCH_COPY, EVP_R_MALLOC_FAILURE);
        return 0;
    }
    memset((*dest), '\0', sizeof(struct hmac_ctx_asynch_st));
    (*dest)->cb = src->cb;
    (*dest)->cb_data = src->cb_data;
    (*dest)->next_state = src->next_state;
    (*dest)->ctx_i_done = src->ctx_i_done;
    (*dest)->ctx_o_done = src->ctx_o_done;
    (*dest)->md = src->md;
    (*dest)->impl = src->impl;
    return 1;
}

int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len,
                 const EVP_MD *md, ENGINE *impl)
{
    int i, j, reset = 0;
    unsigned char pad[HMAC_MAX_MD_CBLOCK];

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        /* If we have an ENGINE need to allow non FIPS */
        if ((impl || ctx->i_ctx.engine)
            && !(ctx->i_ctx.flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW)) {
            EVPerr(EVP_F_HMAC_INIT_EX, EVP_R_DISABLED_FOR_FIPS);
            return 0;
        }
        /*
         * Other algorithm blocking will be done in FIPS_cmac_init, via
         * FIPS_hmac_init_ex().
         */
        if (!impl && !ctx->i_ctx.engine)
            return FIPS_hmac_init_ex(ctx, key, len, md, NULL);
    }
#endif

    if (md != NULL) {
        reset = 1;
        ctx->md = md;
    } else
        md = ctx->md;

    if (key != NULL) {
        reset = 1;
        j = EVP_MD_block_size(md);
        OPENSSL_assert(j <= (int)sizeof(ctx->key));
        if (j < len) {
            if (!EVP_DigestInit_ex(&ctx->md_ctx, md, impl))
                goto err;
            if (!EVP_DigestUpdate(&ctx->md_ctx, key, len))
                goto err;
            if (!EVP_DigestFinal_ex(&(ctx->md_ctx), ctx->key,
                                    &ctx->key_length))
                goto err;
        } else {
            OPENSSL_assert(len >= 0 && len <= (int)sizeof(ctx->key));
            memcpy(ctx->key, key, len);
            ctx->key_length = len;
        }
        if (ctx->key_length != HMAC_MAX_MD_CBLOCK)
            memset(&ctx->key[ctx->key_length], 0,
                   HMAC_MAX_MD_CBLOCK - ctx->key_length);
    }

    if (reset) {
        for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
            pad[i] = 0x36 ^ ctx->key[i];
        if (!EVP_DigestInit_ex(&ctx->i_ctx, md, impl))
            goto err;
        if (!EVP_DigestUpdate(&ctx->i_ctx, pad, EVP_MD_block_size(md)))
            goto err;

        for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
            pad[i] = 0x5c ^ ctx->key[i];
        if (!EVP_DigestInit_ex(&ctx->o_ctx, md, impl))
            goto err;
        if (!EVP_DigestUpdate(&ctx->o_ctx, pad, EVP_MD_block_size(md)))
            goto err;
    }
    if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->i_ctx))
        goto err;
    return 1;
 err:
    return 0;
}

static void _hmac_cb(unsigned char *md, unsigned int size,
                     void *userdata, int status);

/*
 * FIXME: We have a possible race condition, if i_ctx and o_ctx are done
 * EXACTLY at the same time and we run on two different cores, we might have
 * a case when they won't look ready at the same time
 */
static void _hmac_cb_i(unsigned char *md, unsigned int size,
                       void *userdata, int status)
{
    HMAC_CTX *ctx = (HMAC_CTX *)userdata;
    ctx->ctx_asynch->ctx_i_done = 1;
    _hmac_cb(md, size, userdata, status);
}

static void _hmac_cb_o(unsigned char *md, unsigned int size,
                       void *userdata, int status)
{
    HMAC_CTX *ctx = (HMAC_CTX *)userdata;
    ctx->ctx_asynch->ctx_o_done = 1;
    _hmac_cb(md, size, userdata, status);
}

static void _hmac_cb(unsigned char *md, unsigned int size,
                     void *userdata, int status)
{
    HMAC_CTX *ctx = (HMAC_CTX *)userdata;
    unsigned char pad[HMAC_MAX_MD_CBLOCK];
    unsigned int i;

    OPENSSL_assert(ctx->ctx_asynch != NULL);

    if (!status)                /* Callback because of error, break out */
        goto err;

    switch (ctx->ctx_asynch->next_state) {
    case hmac_init:            /* Never called with this */
        goto err;
    case hmac_initkey_final:
        /* Continue where it left off */
        ctx->ctx_asynch->next_state = hmac_initkey_pad;
        if (!EVP_DigestFinal_ex(&(ctx->md_ctx), ctx->key, &ctx->key_length))
            goto err;
        break;
    case hmac_initkey_pad:
        ctx->ctx_asynch->next_state = hmac_reset;
        if (ctx->key_length != HMAC_MAX_MD_CBLOCK)
            memset(&ctx->key[ctx->key_length], 0,
                   HMAC_MAX_MD_CBLOCK - ctx->key_length);
        /* Fall through */

        /*
         * We use the fact that we have two separate contexts to fiddle with
         * to run them in parallell.
         */
    case hmac_reset:
        ctx->ctx_asynch->next_state = hmac_reset_final;
        if (!EVP_MD_CTX_ctrl_ex(&ctx->i_ctx,
                                EVP_MD_CTRL_SETUP_ASYNCH_CALLBACK,
                                0, ctx, (void (*)(void))_hmac_cb_i)
            || !EVP_DigestInit_ex(&ctx->i_ctx,
                                  ctx->ctx_asynch->md, ctx->ctx_asynch->impl))
            goto err;
        if (!EVP_MD_CTX_ctrl_ex(&ctx->o_ctx,
                                EVP_MD_CTRL_SETUP_ASYNCH_CALLBACK,
                                0, ctx, (void (*)(void))_hmac_cb_o)
            || !EVP_DigestInit_ex(&ctx->o_ctx,
                                  ctx->ctx_asynch->md, ctx->ctx_asynch->impl))
            goto err;
        break;
    case hmac_reset_final:
        if (ctx->ctx_asynch->ctx_i_done && ctx->ctx_asynch->ctx_o_done) {
            ctx->ctx_asynch->ctx_i_done = 0;
            ctx->ctx_asynch->ctx_o_done = 0;
            ctx->ctx_asynch->next_state = hmac_init_final;
            for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
                pad[i] = 0x36 ^ ctx->key[i];
            if (!EVP_DigestUpdate(&ctx->i_ctx,
                                  pad,
                                  EVP_MD_block_size(ctx->ctx_asynch->md)))
                goto err;

            for (i = 0; i < HMAC_MAX_MD_CBLOCK; i++)
                pad[i] = 0x5c ^ ctx->key[i];
            if (!EVP_DigestUpdate(&ctx->o_ctx,
                                  pad,
                                  EVP_MD_block_size(ctx->ctx_asynch->md)))
                goto err;
        }
        break;
    case hmac_init_final:
        if (ctx->ctx_asynch->ctx_i_done) {
            if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->i_ctx))
                goto err;
        }
        if (!(ctx->ctx_asynch->ctx_i_done && ctx->ctx_asynch->ctx_o_done))
            break;

        /*
         * FALLTHROUGH, because the rule is that at the end of init, we call
         * the user callback with NULL arguments
         */
        ctx->ctx_asynch->next_state = hmac_data;
    case hmac_data:
        ctx->ctx_asynch->cb(NULL, 0, ctx->ctx_asynch->cb_data, 1);
        break;
    case hmac_final:
        ctx->ctx_asynch->next_state = hmac_final2;
        if (!EVP_DigestFinal_ex(&ctx->md_ctx, NULL, 0))
            goto err;
        break;
    case hmac_final2:
        ctx->ctx_asynch->next_state = hmac_final3;
        if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->o_ctx))
            goto err;
        if (!EVP_DigestUpdate(&ctx->md_ctx, md, size))
            goto err;
        break;
    case hmac_final3:
        ctx->ctx_asynch->next_state = hmac_final4;
        if (!EVP_DigestFinal_ex(&ctx->md_ctx, NULL, 0))
            goto err;
        break;
    case hmac_final4:
        ctx->ctx_asynch->cb(md, size, ctx->ctx_asynch->cb_data, 1);
        break;
    }
    return;
 err:
    ctx->ctx_asynch->cb(NULL, 0, ctx->ctx_asynch->cb_data, 0);
}

int HMAC_Init_asynch(HMAC_CTX *ctx, const void *key, int len,
                     const EVP_MD *md, ENGINE *impl,
                     void (*callback_fn) (unsigned char *md, size_t len,
                                          void *userdata, int status),
                     void *callback_data)
{
    int j, reset = 0;

#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
        /* If we have an ENGINE need to allow non FIPS */
        if ((impl || ctx->i_ctx.engine)
            && !(ctx->i_ctx.flags & EVP_CIPH_FLAG_NON_FIPS_ALLOW)) {
            EVPerr(EVP_F_HMAC_INIT_ASYNCH, EVP_R_DISABLED_FOR_FIPS);
            return 0;
        }
        /*
         * Other algorithm blocking will be done in FIPS_cmac_init, via
         * FIPS_hmac_init_ex().
         */
        if (!impl && !ctx->i_ctx.engine)
            return FIPS_hmac_init_ex(ctx, key, len, md, NULL);
    }
#endif

    if (md != NULL) {
        reset = 1;
        ctx->md = md;
    } else
        md = ctx->md;

    if (!ctx->ctx_asynch) {
        ctx->ctx_asynch = OPENSSL_malloc(sizeof(struct hmac_ctx_asynch_st));
        memset(ctx->ctx_asynch, '\0', sizeof(struct hmac_ctx_asynch_st));
    }

    ctx->ctx_asynch->cb = callback_fn;
    ctx->ctx_asynch->cb_data = callback_data;
    ctx->ctx_asynch->next_state = hmac_init;
    ctx->ctx_asynch->md = md;
    ctx->ctx_asynch->impl = impl;

    if (ctx->ctx_asynch->cb == NULL) {
        EVPerr(EVP_F_HMAC_INIT_ASYNCH, EVP_R_NO_CALLBACK_SET);
        return 0;
    }

    if (key != NULL) {
        j = EVP_MD_block_size(md);
        OPENSSL_assert(j <= (int)sizeof(ctx->key));
        if (j < len) {
            ctx->ctx_asynch->next_state = hmac_initkey_final;
            if (!EVP_MD_CTX_ctrl_ex(&ctx->i_ctx,
                                    EVP_MD_CTRL_SETUP_ASYNCH_CALLBACK,
                                    0, ctx, (void (*)(void))_hmac_cb)
                || !EVP_DigestInit_ex(&ctx->md_ctx, md, impl))
                goto err;
            if (!EVP_DigestUpdate(&ctx->md_ctx, key, len))
                goto err;
            return 1;
        } else {
            OPENSSL_assert(len >= 0 && len <= (int)sizeof(ctx->key));
            memcpy(ctx->key, key, len);
            ctx->key_length = len;
        }
        ctx->ctx_asynch->next_state = hmac_initkey_pad;
        _hmac_cb(NULL, 0, ctx, 1);
    } else if (reset) {
        ctx->ctx_asynch->next_state = hmac_reset;
        _hmac_cb(NULL, 0, ctx, 1);
    }
    return 1;
 err:
    _hmac_cb(NULL, 0, ctx, 0);
    return 0;
}

int HMAC_Init(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md)
{
    if (key && md)
        HMAC_CTX_init(ctx);
    return HMAC_Init_ex(ctx, key, len, md, NULL);
}

static int _hmac_Update_synch(HMAC_CTX *ctx, const unsigned char *data,
                              size_t len)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !ctx->i_ctx.engine)
        return FIPS_hmac_update(ctx, data, len);
#endif
    return EVP_DigestUpdate(&ctx->md_ctx, data, len);
}

static int _hmac_Update_asynch(HMAC_CTX *ctx, const unsigned char *data,
                               size_t len)
{
    if (ctx->ctx_asynch && ctx->ctx_asynch->next_state != hmac_data) {
        EVPerr(EVP_F__HMAC_UPDATE_ASYNCH, EVP_R_INITIALIZING);
        return 0;
    }
    return EVP_DigestUpdate(&ctx->md_ctx, data, len);
}

int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len)
{
    if (ctx->ctx_asynch)
        return _hmac_Update_asynch(ctx, data, len);
    return _hmac_Update_synch(ctx, data, len);
}

static int _hmac_Final_synch(HMAC_CTX *ctx, unsigned char *md,
                             unsigned int *len)
{
    unsigned int i;
    unsigned char buf[EVP_MAX_MD_SIZE];
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !ctx->i_ctx.engine)
        return FIPS_hmac_final(ctx, md, len);
#endif

    if (!EVP_DigestFinal_ex(&ctx->md_ctx, buf, &i))
        goto err;
    if (!EVP_MD_CTX_copy_ex(&ctx->md_ctx, &ctx->o_ctx))
        goto err;
    if (!EVP_DigestUpdate(&ctx->md_ctx, buf, i))
        goto err;
    if (!EVP_DigestFinal_ex(&ctx->md_ctx, md, len))
        goto err;
    return 1;
 err:
    return 0;
}

static int _hmac_Final_asynch(HMAC_CTX *ctx)
{
    ctx->ctx_asynch->next_state = hmac_final;
    _hmac_cb(NULL, 0, ctx, 1);
    return 1;
}

int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    if (ctx->ctx_asynch)
        return _hmac_Final_asynch(ctx);
    return _hmac_Final_synch(ctx, md, len);
}

void HMAC_CTX_init(HMAC_CTX *ctx)
{
    EVP_MD_CTX_init(&ctx->i_ctx);
    EVP_MD_CTX_init(&ctx->o_ctx);
    EVP_MD_CTX_init(&ctx->md_ctx);
    ctx->ctx_asynch = NULL;
}

int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx)
{
    HMAC_CTX_init(dctx);
    if (!EVP_MD_CTX_copy(&dctx->i_ctx, &sctx->i_ctx))
        goto err;
    if (!EVP_MD_CTX_copy(&dctx->o_ctx, &sctx->o_ctx))
        goto err;
    if (!EVP_MD_CTX_copy(&dctx->md_ctx, &sctx->md_ctx))
        goto err;
    memcpy(dctx->key, sctx->key, HMAC_MAX_MD_CBLOCK);
    dctx->key_length = sctx->key_length;
    dctx->md = sctx->md;
    if (!HMAC_CTX_ASYNCH_copy(&dctx->ctx_asynch, sctx->ctx_asynch))
        goto err;
    return 1;
 err:
    return 0;
}

void HMAC_CTX_cleanup(HMAC_CTX *ctx)
{
#ifdef OPENSSL_FIPS
    if (FIPS_mode() && !ctx->i_ctx.engine) {
        FIPS_hmac_ctx_cleanup(ctx);
        return;
    }
#endif
    EVP_MD_CTX_cleanup(&ctx->i_ctx);
    EVP_MD_CTX_cleanup(&ctx->o_ctx);
    EVP_MD_CTX_cleanup(&ctx->md_ctx);
    if (ctx->ctx_asynch)
        OPENSSL_free(ctx->ctx_asynch);
    memset(ctx, 0, sizeof *ctx);
}

unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *d, size_t n, unsigned char *md,
                    unsigned int *md_len)
{
    HMAC_CTX c;
    static unsigned char m[EVP_MAX_MD_SIZE];

    if (md == NULL)
        md = m;
    HMAC_CTX_init(&c);
    if (!HMAC_Init(&c, key, key_len, evp_md))
        goto err;
    if (!HMAC_Update(&c, d, n))
        goto err;
    if (!HMAC_Final(&c, md, md_len))
        goto err;
    HMAC_CTX_cleanup(&c);
    return md;
 err:
    return NULL;
}

void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags)
{
    EVP_MD_CTX_set_flags(&ctx->i_ctx, flags);
    EVP_MD_CTX_set_flags(&ctx->o_ctx, flags);
    EVP_MD_CTX_set_flags(&ctx->md_ctx, flags);
}
