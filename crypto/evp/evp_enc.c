/* crypto/evp/evp_enc.c */
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
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pool.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif
#include "evp_locl.h"

#ifdef OPENSSL_FIPS
# define M_do_cipher(ctx, out, in, inl) FIPS_cipher(ctx, out, in, inl)
# define M_do_cipher_asynch(ctx, out, in, inl, cb_data) cb->internal->cb(out, FIPS_cipher(ctx, out, in, inl), cb_data)
#else
# define M_do_cipher(ctx, out, in, inl) ctx->cipher->do_cipher.synch(ctx, out, in, inl)
# define M_do_cipher_asynch(ctx, out, in, inl, cb_data) ctx->cipher->do_cipher.asynch(ctx, out, in, inl, cb_data)
#endif

typedef struct evp_asynch_ctx_st EVP_ASYNCH_CTX;
typedef int (*internal_asynch_cb_t) (unsigned char *out, unsigned int outl,
                                     EVP_ASYNCH_CTX * ctx, int status);
typedef int (*asynch_cb_t) (unsigned char *out, int outl, void *ctx,
                            int status);

const char EVP_version[] = "EVP" OPENSSL_VERSION_PTEXT;

/*
 * Asynch requires to have a per-call context.  To avoid memory
 * fragmentation, we use a big pool that gets allocated once.
 */
struct evp_asynch_ctx_st {
    EVP_CIPHER_CTX *ctx;
    internal_asynch_cb_t internal_cb;
    asynch_cb_t user_cb;        /* Cache of ctx->internal->cb */
    void *user_cb_data;         /* Cache of ctx->internal->cb_data */
    unsigned char *out;
    unsigned int outl;
    char *in;
    int inl;
    int final;                  /* Used to flag that we're running a Final */
    /* Specific for encryption */
    int enc_buffered;
    /* Specific for decryption */
    int dec_buffered;
    unsigned char final_out[EVP_MAX_BLOCK_LENGTH]; /* possible final block */
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

void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx)
{
    ctx->cipher = NULL;
    ctx->engine = NULL;
    ctx->encrypt = 0;
    ctx->buf_len = 0;

    memset(ctx->oiv, 0, EVP_MAX_IV_LENGTH);
    memset(ctx->iv, 0, EVP_MAX_IV_LENGTH);
    memset(ctx->buf, 0, EVP_MAX_BLOCK_LENGTH);
    ctx->num = 0;

    ctx->app_data = NULL;
    ctx->key_len = 0;
    ctx->flags = 0;
    ctx->cipher_data = NULL;
    ctx->final_used = 0;
    ctx->block_mask = 0;
    memset(ctx->final, 0, EVP_MAX_BLOCK_LENGTH);
}

static int evp_CIPHER_CTX_expand(EVP_CIPHER_CTX *ctx)
{
    ctx->internal = OPENSSL_malloc(sizeof(struct evp_cipher_ctx_internal_st));
    if (!ctx->internal)
        return 0;
    memset(ctx->internal, 0, sizeof(struct evp_cipher_ctx_internal_st));
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_CTX_FLAG_EXPANDED);
    return 1;
}

void EVP_CIPHER_CTX_init_ex(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_init(ctx);
    evp_CIPHER_CTX_expand(ctx);
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    EVP_CIPHER_CTX *ctx = OPENSSL_malloc(sizeof *ctx);
    if (ctx)
        EVP_CIPHER_CTX_init(ctx);
    return ctx;
}

int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                   const unsigned char *key, const unsigned char *iv, int enc)
{
    if (cipher)
        EVP_CIPHER_CTX_init(ctx);
    return EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
}

static int _evp_cipher_cb(unsigned char *out, int outl,
                          EVP_ASYNCH_CTX * actx, int status)
{
    /*
     * Everything of value is handled by the internal callback, this function
     * only acts as a conduit.
     */
    return actx->internal_cb(out, outl, actx, status);
}

int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                      ENGINE *impl, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    int call_asynch_cb_at_end = 0;
    if (enc == -1)
        enc = ctx->encrypt;
    else {
        if (enc)
            enc = 1;
        ctx->encrypt = enc;
    }
#ifndef OPENSSL_NO_ENGINE
    /*
     * Whether it's nice or not, "Inits" can be used on "Final"'d contexts so
     * this context may already have an ENGINE! Try to avoid releasing the
     * previous handle, re-querying for an ENGINE, and having a
     * reinitialisation, when it may all be unecessary.
     */
    if (ctx->engine && ctx->cipher && (!cipher ||
                                       (cipher
                                        && (cipher->nid ==
                                            ctx->cipher->nid))))
        goto skip_to_init;
#endif
    if (cipher) {
        /*
         * Ensure a context left lying around from last time is cleared (the
         * previous check attempted to avoid this if the same ENGINE and
         * EVP_CIPHER could be used).
         */
        if (ctx->cipher) {
            unsigned long flags = ctx->flags;
            int (*cb) (unsigned char *out, int outl,
                       void *userdata, int status) =
                flags & EVP_CIPH_CTX_FLAG_EXPANDED ? ctx->internal->cb : NULL;
            void *cb_data =
                flags & EVP_CIPH_CTX_FLAG_EXPANDED ?
                ctx->internal->cb_data : NULL;
            EVP_CIPHER_CTX_cleanup(ctx);
            /* Restore encrypt and flags */
            ctx->encrypt = enc;
            ctx->flags = flags;
            if (flags & EVP_CIPH_CTX_FLAG_EXPANDED) {
                ctx->internal->cb = cb;
                ctx->internal->cb_data = cb_data;
            }
        }
#ifndef OPENSSL_NO_ENGINE
        if (impl) {
            if (!ENGINE_init(impl)) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        } else
            /* Ask if an ENGINE is reserved for this job */
            impl = ENGINE_get_cipher_engine(cipher->nid);
        if (impl) {
            /* There's an ENGINE for this job ... (apparently) */
            const EVP_CIPHER *c = NULL;

            if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                && ctx->internal->cb)
                c = ENGINE_get_cipher_asynch(impl, cipher->nid);

            if (!c)
                c = ENGINE_get_cipher(impl, cipher->nid);

            if (!c) {
                /*
                 * One positive side-effect of US's export * control history,
                 * is that we should at least * be able to avoid using US
                 * mispellings of * "initialisation"?
                 */
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
            /*
             * We'll use the ENGINE's private cipher definition
             */
            cipher = c;
            /*
             * Store the ENGINE functional reference so we know * 'cipher'
             * came from an ENGINE and we need to release * it when done.
             */
            ctx->engine = impl;
        } else {
            ctx->engine = NULL;
        }
#endif

#ifdef OPENSSL_FIPS
        if (FIPS_mode())
            return FIPS_cipherinit(ctx, cipher, key, iv, enc);
#endif
        ctx->cipher = cipher;
        if (ctx->cipher->ctx_size) {
            ctx->cipher_data = OPENSSL_malloc(ctx->cipher->ctx_size);
            if (!ctx->cipher_data) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memset(ctx->cipher_data, 0, ctx->cipher->ctx_size);
        } else {
            ctx->cipher_data = NULL;
        }
        ctx->key_len = cipher->key_len;
        if (ctx->cipher->flags & EVP_CIPH_CTRL_INIT) {
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_INIT, 0, NULL)) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_INITIALIZATION_ERROR);
                return 0;
            }
        }

        if (cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
#ifdef OPENSSL_FIPS
            EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_ASYNCH_SUPPORT_IN_FIPS);
            ERR_add_error_data(1, EVP_CIPHER_name(cipher));
            return 0;
#else
            if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                || ctx->internal->cb == NULL) {
                EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_CALLBACK_SET);
                return 0;
            }
#endif
        }
    } else if (!ctx->cipher) {
        EVPerr(EVP_F_EVP_CIPHERINIT_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
 skip_to_init:
#endif
#ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_cipherinit(ctx, cipher, key, iv, enc);
#endif
    /* we assume block size is a power of 2 in *cryptUpdate */
    OPENSSL_assert(ctx->cipher->block_size == 1
                   || ctx->cipher->block_size == 8
                   || ctx->cipher->block_size == 16);

    if (!(EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_CUSTOM_IV)) {
        switch (EVP_CIPHER_CTX_mode(ctx)) {

        case EVP_CIPH_STREAM_CIPHER:
        case EVP_CIPH_ECB_MODE:
            break;

        case EVP_CIPH_CFB_MODE:
        case EVP_CIPH_OFB_MODE:

            ctx->num = 0;
            /* fall-through */

        case EVP_CIPH_CBC_MODE:

            OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) <=
                           (int)sizeof(ctx->iv));
            if (iv)
                memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        case EVP_CIPH_CTR_MODE:
            ctx->num = 0;
            /* Don't reuse IV for CTR mode */
            if (iv)
                memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
            break;

        default:
            return 0;
        }
    }

    if (key || (ctx->cipher->flags & EVP_CIPH_ALWAYS_CALL_INIT)) {
        if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
            if (!ctx->cipher->init.asynch(ctx, key, iv, enc,
                                          (asynch_cb_t) _evp_cipher_cb)) {
                return 0;
            }
            call_asynch_cb_at_end = 1;
        } else {
            if (!ctx->cipher->init.synch(ctx, key, iv, enc)) {
                return 0;
            }
            if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                && ctx->internal->cb) {
                call_asynch_cb_at_end = 1;
            }
        }
    }
    ctx->buf_len = 0;
    ctx->final_used = 0;
    ctx->block_mask = ctx->cipher->block_size - 1;
    if (call_asynch_cb_at_end)
        ctx->internal->cb(NULL, 0, ctx->internal->cb_data, 1);
    return 1;
}

int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                     const unsigned char *in, int inl)
{
    if (ctx->encrypt)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);
    else
        return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal_ex(ctx, out, outl);
    else
        return EVP_DecryptFinal_ex(ctx, out, outl);
}

int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->encrypt)
        return EVP_EncryptFinal(ctx, out, outl);
    else
        return EVP_DecryptFinal(ctx, out, outl);
}

int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 1);
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 1);
}

int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                    const unsigned char *key, const unsigned char *iv)
{
    return EVP_CipherInit(ctx, cipher, key, iv, 0);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv)
{
    return EVP_CipherInit_ex(ctx, cipher, impl, key, iv, 0);
}

static int _evp_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl)
{
    int i, j, bl;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher(ctx, out, in, inl);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (M_do_cipher(ctx, out, in, inl)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    bl = ctx->cipher->block_size;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (i + inl < bl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            *outl = 0;
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            if (!M_do_cipher(ctx, out, ctx->buf, bl))
                return 0;
            inl -= j;
            in += j;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;
    if (inl > 0) {
        if (!M_do_cipher(ctx, out, in, inl))
            return 0;
        *outl += inl;
    }

    if (i != 0)
        memcpy(ctx->buf, &(in[inl]), i);
    ctx->buf_len = i;
    return 1;
}

static int _evp_EncryptDecrypt_post(unsigned char *out, unsigned int outl,
                                    EVP_ASYNCH_CTX * actx, int status)
{
    int used_bytes;
    if (status > 0) {
        actx->outl += outl;
    }

    used_bytes = actx->outl + actx->enc_buffered + actx->dec_buffered;
    /*
     * Only call the callback specified by the application when the status is
     * -1 or 0 or when the whole update has been encrypted.
     */
    if (status <= 0 || used_bytes > actx->inl || used_bytes == actx->inl) {
        int ret = actx->user_cb(actx->out, actx->outl,
                                actx->user_cb_data, status);
        if (status >= 0)
            free_asynch_ctx(actx);
        return ret;
    }
    return status;              /* */
}

static int _evp_EncryptUpdate_asynch(EVP_ASYNCH_CTX * actx,
                                     unsigned char *out, int *outl,
                                     const unsigned char *in, int inl)
{
    int i, j, bl;
    EVP_CIPHER_CTX *ctx;
    int end_call_cb = 1;

    if (actx == NULL)
        return 0;

    ctx = actx->ctx;
    actx->internal_cb = _evp_EncryptDecrypt_post;

    if (actx->ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher_asynch(actx->ctx, out, in, inl, actx);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        if (inl == 0)
            _evp_cipher_cb(out, *outl, actx, 1);
        return inl == 0;
    }

    if (ctx->buf_len == 0 && (inl & (ctx->block_mask)) == 0) {
        if (M_do_cipher_asynch(actx->ctx, out, in, inl, actx)) {
            *outl = inl;
            return 1;
        } else {
            *outl = 0;
            return 0;
        }
    }
    i = ctx->buf_len;
    bl = ctx->cipher->block_size;
    OPENSSL_assert(bl <= (int)sizeof(ctx->buf));
    if (i != 0) {
        if (i + inl < bl) {
            memcpy(&(ctx->buf[i]), in, inl);
            ctx->buf_len += inl;
            actx->enc_buffered += inl;
            _evp_cipher_cb(out, *outl, actx, 1);
            return 1;
        } else {
            j = bl - i;
            memcpy(&(ctx->buf[i]), in, j);
            actx->enc_buffered -= i;
            inl -= j;
            in += j;
            end_call_cb = 0;
            if (!M_do_cipher_asynch(ctx, out, ctx->buf, bl, actx))
                return 0;
            out += bl;
            *outl = bl;
        }
    } else
        *outl = 0;
    i = inl & (bl - 1);
    inl -= i;

    if (i != 0) {
        actx->enc_buffered += i;
        memcpy(ctx->buf, &(in[inl]), i);
    }
    ctx->buf_len = i;

    if (inl > 0) {
        end_call_cb = 0;
        if (!M_do_cipher_asynch(ctx, out, in, inl, actx))
            return 0;
        *outl += inl;
    }

    if (end_call_cb) {
        _evp_cipher_cb(out, *outl, actx, 1);
    }
    return 1;
}

/*
 * In asynch mode, *out is used as an output buffer, so it needs to be kept
 * alive by the user until the final callback is called.  *outl is used BEST
 * EFFORT to indicate how much space the output will eventually take up (this
 * is not the case for custome ciphers).
 */
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
        EVP_ASYNCH_CTX *actx = alloc_asynch_ctx();
        int ret = 0;
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->final = 0;
        actx->inl = inl;
        actx->out = out;
        actx->outl = 0;         /* It gets updated by
                                 * _evp_EncryptDecrypt_post */
        actx->enc_buffered = 0;
        actx->dec_buffered = 0;
        ret = _evp_EncryptUpdate_asynch(actx, out, outl, in, inl);
        if (!ret)
            free_asynch_ctx(actx);
        return ret;
    } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
               && ctx->internal->cb) {
        int ret = 0;
        ret = _evp_EncryptUpdate(ctx, out, outl, in, inl);
        if (ret > 0)
            ctx->internal->cb(out, *outl, ctx->internal->cb_data, ret);
        return ret;
    }
    return _evp_EncryptUpdate(ctx, out, outl, in, inl);
}

int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_EncryptFinal_ex(ctx, out, outl);
    return ret;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int n, ret;
    unsigned int i, b, bl;
    EVP_ASYNCH_CTX *actx = NULL;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
        actx = alloc_asynch_ctx();
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->inl = 0;
        actx->out = out;
        actx->outl = 0;
        actx->final = 1;
        actx->enc_buffered = 0;
        actx->dec_buffered = 0;
        actx->internal_cb = _evp_EncryptDecrypt_post;
    }

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
            ret = M_do_cipher_asynch(ctx, out, NULL, 0, ctx);
            if (ret < 0)
                free_asynch_ctx(actx);
        } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                   && ctx->internal->cb) {
            ret = M_do_cipher(ctx, out, NULL, 0);
            if (ret > 0)
                ctx->internal->cb(out, 0, ctx->internal->cb_data, ret);
        } else {
            ret = M_do_cipher(ctx, out, NULL, 0);
        }
        if (ret < 0)
            return 0;
        else
            *outl = ret;
        return 1;
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof ctx->buf);
    if (b == 1) {
        *outl = 0;
        if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
            actx->internal_cb(out, *outl, actx, 1);
        } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                   && ctx->internal->cb) {
            ctx->internal->cb(out, *outl, ctx->internal->cb_data, 1);
        }
        return 1;
    }
    bl = ctx->buf_len;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (bl) {
            EVPerr(EVP_F_EVP_ENCRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH)
                free_asynch_ctx(actx);
            return 0;
        }
        *outl = 0;
        if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
            actx->internal_cb(out, *outl, actx, 1);
        } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
                   && ctx->internal->cb) {
            ctx->internal->cb(out, *outl, ctx->internal->cb_data, 1);
        }
        return 1;
    }

    n = b - bl;
    for (i = bl; i < b; i++)
        ctx->buf[i] = n;
    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
        ret = M_do_cipher_asynch(ctx, out, ctx->buf, b, actx);
        if (ret <= 0)
            free_asynch_ctx(actx);
    } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
               && ctx->internal->cb) {
        ret = M_do_cipher(ctx, out, ctx->buf, b);
        if (ret > 0)
            ctx->internal->cb(out, b, ctx->internal->cb_data, ret);
    } else {
        ret = M_do_cipher(ctx, out, ctx->buf, b);
    }

    if (ret)
        *outl = b;

    return ret;
}

static int _evp_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              int *outl, const unsigned char *in, int inl)
{
    int fix_len;
    unsigned int b;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        fix_len = M_do_cipher(ctx, out, in, inl);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING)
        return EVP_EncryptUpdate(ctx, out, outl, in, inl);

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof ctx->final);

    if (ctx->final_used) {
        memcpy(out, ctx->final, b);
        out += b;
        fix_len = 1;
    } else
        fix_len = 0;

    if (!EVP_EncryptUpdate(ctx, out, outl, in, inl))
        return 0;

    /*
     * if we have 'decrypted' a multiple of block size, make sure we have a
     * copy of this last block
     */
    if (b > 1 && !ctx->buf_len) {
        *outl -= b;
        ctx->final_used = 1;
        memcpy(ctx->final, &out[*outl], b);
    } else
        ctx->final_used = 0;

    if (fix_len)
        *outl += b;

    return 1;
}

static int _evp_DecryptUpdate_asynch(EVP_ASYNCH_CTX * actx,
                                     unsigned char *out, int *outl,
                                     const unsigned char *in, int inl)
{
    int fix_len;
    unsigned int b;
    EVP_CIPHER_CTX *ctx;

    if (actx == NULL)
        return 0;
    ctx = actx->ctx;
    actx->internal_cb = _evp_EncryptDecrypt_post;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        fix_len = M_do_cipher_asynch(ctx, out, in, inl, actx);
        if (fix_len < 0) {
            *outl = 0;
            return 0;
        } else
            *outl = fix_len;
        return 1;
    }

    if (inl <= 0) {
        *outl = 0;
        if (inl == 0)
            actx->internal_cb(out, *outl, actx, 1);
        return inl == 0;
    }

    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        return _evp_EncryptUpdate_asynch(actx, out, outl, in, inl);
    }

    b = ctx->cipher->block_size;
    OPENSSL_assert(b <= sizeof ctx->final);

    if (ctx->final_used) {
        int dummy;
        if (!_evp_EncryptUpdate_asynch(actx, out, &dummy, ctx->final, b))
            return 0;
        out += dummy;
        *outl += dummy;
    }

    /*
     * if we're about to 'decrypt' a multiple of block size, make sure we
     * have a copy of this last input block, and don't 'decrypt' it.
     */
    if (b > 1 && inl > 0 && ((ctx->buf_len + inl) & (ctx->block_mask)) == 0) {
        ctx->final_used = 1;
        inl -= b;
        actx->dec_buffered += b;
        memcpy(ctx->final, &in[inl], b);
    } else
        ctx->final_used = 0;

    return _evp_EncryptUpdate_asynch(actx, out, outl, in, inl);
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
        EVP_ASYNCH_CTX *actx = alloc_asynch_ctx();
        int ret = 0;
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->inl = inl;
        actx->out = out;
        actx->outl = 0;
        actx->final = 0;
        actx->enc_buffered = 0;
        actx->dec_buffered = 0;
        ret = _evp_DecryptUpdate_asynch(actx, out, outl, in, inl);
        if (!ret)
            free_asynch_ctx(actx);
        return ret;
    }
    return _evp_DecryptUpdate(ctx, out, outl, in, inl);
}

int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int ret;
    ret = EVP_DecryptFinal_ex(ctx, out, outl);
    return ret;
}

int _evp_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    int i, n;
    unsigned int b;
    *outl = 0;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher(ctx, out, NULL, 0);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = ctx->cipher->block_size;
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_EX,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_EX,
                   EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            return (0);
        }
        OPENSSL_assert(b <= sizeof ctx->final);

        /*
         * The following assumes that the ciphertext has been authenticated.
         * Otherwise it provides a padding oracle.
         */
        n = ctx->final[b - 1];
        if (n == 0 || n > (int)b) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
            return (0);
        }
        for (i = 0; i < n; i++) {
            if (ctx->final[--b] != n) {
                EVPerr(EVP_F__EVP_DECRYPTFINAL_EX, EVP_R_BAD_DECRYPT);
                return (0);
            }
        }
        n = ctx->cipher->block_size - n;
        for (i = 0; i < n; i++)
            out[i] = ctx->final[i];
        *outl = n;
    } else
        *outl = 0;
    return (1);
}

static int _evp_DecryptFinal_post(unsigned char *out, unsigned int outl,
                                  EVP_ASYNCH_CTX * actx, int status);
int _evp_DecryptFinal_ex_asynch(EVP_ASYNCH_CTX * actx, unsigned char *out,
                                int *outl)
{
    int i;
    unsigned int b;
    EVP_CIPHER_CTX *ctx = NULL;
    *outl = 0;

    if (actx == NULL)
        return 0;
    ctx = actx->ctx;
    actx->internal_cb = _evp_EncryptDecrypt_post;

    if (ctx->cipher->flags & EVP_CIPH_FLAG_CUSTOM_CIPHER) {
        i = M_do_cipher_asynch(ctx, out, NULL, 0, actx);
        if (i < 0)
            return 0;
        else
            *outl = i;
        return 1;
    }

    b = (unsigned int)(ctx->cipher->block_size);
    if (ctx->flags & EVP_CIPH_NO_PADDING) {
        if (ctx->buf_len) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_EX_ASYNCH,
                   EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
            return 0;
        }
        *outl = 0;
        _evp_cipher_cb(out, *outl, actx, 1);
        return 1;
    }
    if (b > 1) {
        if (ctx->buf_len || !ctx->final_used) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_EX_ASYNCH,
                   EVP_R_WRONG_FINAL_BLOCK_LENGTH);
            return (0);
        }
        OPENSSL_assert(b <= sizeof ctx->final);
        actx->internal_cb = _evp_DecryptFinal_post;
        actx->out = out;
        actx->outl = *outl;
        *outl += b;             /* It's a lie, the message is shorter. The
                                 * callback will have the right amount,
                                 * though. */
        return M_do_cipher_asynch(ctx, actx->final_out, ctx->final, b, actx);
    } else
        *outl = 0;
    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH)
        _evp_cipher_cb(out, *outl, actx, 1);
    return (1);
}

static int _evp_DecryptFinal_post(unsigned char *out, unsigned int outl,
                                  EVP_ASYNCH_CTX * actx, int status)
{
    if (status > 0) {
        int b = actx->ctx->cipher->block_size;
        int n = out[b - 1];
        if (n == 0 || n > (int)b) {
            EVPerr(EVP_F__EVP_DECRYPTFINAL_POST, EVP_R_BAD_DECRYPT);
            status = 0;
        } else {
            int i;
            for (i = 0; i < n; i++) {
                if (out[--b] != n) {
                    EVPerr(EVP_F__EVP_DECRYPTFINAL_POST, EVP_R_BAD_DECRYPT);
                    status = 0;
                    break;
                }
            }
            if (status > 0) {
                n = actx->ctx->cipher->block_size - n;
                for (i = 0; i < n; i++)
                    actx->out[i] = out[i];
                outl = n;
            }
            out = actx->out;
        }
    }
    return _evp_EncryptDecrypt_post(out, outl, actx, status);
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx->cipher->flags & EVP_CIPH_FLAG_ASYNCH) {
        EVP_ASYNCH_CTX *actx = alloc_asynch_ctx();
        int ret = 0;
        if (actx == NULL) {
            return 0;
        }
        actx->ctx = ctx;
        actx->user_cb = ctx->internal->cb;
        actx->user_cb_data = ctx->internal->cb_data;
        actx->inl = 0;
        actx->out = out;
        actx->outl = 0;
        actx->final = 1;
        actx->enc_buffered = 0;
        ret = _evp_DecryptFinal_ex_asynch(actx, out, outl);
        if (!ret)
            free_asynch_ctx(actx);
        return ret;
    } else if ((ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)
               && ctx->internal->cb) {
        int ret = 0;
        ret = _evp_DecryptFinal_ex(ctx, out, outl);
        if (ret > 0)
            ctx->internal->cb(out, *outl, ctx->internal->cb_data, ret);
        return ret;
    }
    return _evp_DecryptFinal_ex(ctx, out, outl);
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}

int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *c)
{
#ifndef OPENSSL_FIPS
    if (c->cipher != NULL) {
        if (c->cipher->cleanup && !c->cipher->cleanup(c))
            return 0;
        /* Cleanse cipher context data */
        if (c->cipher_data)
            OPENSSL_cleanse(c->cipher_data, c->cipher->ctx_size);
    }
    if (c->cipher_data)
        OPENSSL_free(c->cipher_data);
#endif
#ifndef OPENSSL_NO_ENGINE
    if (c->engine)
        /*
         * The EVP_CIPHER we used belongs to an ENGINE, release the
         * functional reference we held for this reason.
         */
        ENGINE_finish(c->engine);
#endif
#ifdef OPENSSL_FIPS
    FIPS_cipher_ctx_cleanup(c);
#endif
    if (c->flags & EVP_CIPH_CTX_FLAG_EXPANDED) {
        OPENSSL_free(c->internal);
        c->internal = NULL;
    }
    EVP_CIPHER_CTX_init(c);
    return 1;
}

int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *c, int keylen)
{
    if (c->cipher->flags & EVP_CIPH_CUSTOM_KEY_LENGTH)
        return EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_KEY_LENGTH, keylen, NULL);
    if (c->key_len == keylen)
        return 1;
    if ((keylen > 0) && (c->cipher->flags & EVP_CIPH_VARIABLE_LENGTH)) {
        c->key_len = keylen;
        return 1;
    }
    EVPerr(EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH, EVP_R_INVALID_KEY_LENGTH);
    return 0;
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad)
{
    if (pad)
        ctx->flags &= ~EVP_CIPH_NO_PADDING;
    else
        ctx->flags |= EVP_CIPH_NO_PADDING;
    return 1;
}

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return EVP_CIPHER_CTX_ctrl_ex(ctx, type, arg, ptr, NULL);
}

int EVP_CIPHER_CTX_ctrl_ex(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr,
                           void (*fn_ptr) (void))
{
    int ret;

    /*
     * Intercept any pre-init EVP level commands before trying to hand them
     * on to algorithm specific ctrl() handlers.
     */
    switch (type) {
    case EVP_CTRL_SETUP_ASYNCH_CALLBACK:
        if (ctx->cipher) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_SET_AFTER_CIPHERINIT);
            return 0;
        }
        if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED))
            if (!evp_CIPHER_CTX_expand(ctx)) {
                EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX, ERR_R_MALLOC_FAILURE);
                return 0;
            }
        ctx->internal->cb = (int (*)(unsigned char *data, int datalen,
                                     void *userdata, int status))fn_ptr;
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_CTRL_UPDATE_ASYNCH_CALLBACK:
        if (!ctx->cipher) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        ctx->internal->cb = (int (*)(unsigned char *data, int datalen,
                                     void *userdata, int status))fn_ptr;
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_CTRL_UPDATE_ASYNCH_CALLBACK_DATA:
        if (!ctx->cipher) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        ctx->internal->cb_data = ptr;
        return 1;
    case EVP_CTRL_GET_ASYNCH_CALLBACK_FN:
        if (!ctx->cipher) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        *(int (**)(unsigned char *data, int datalen,
                   void *userdata, int status))ptr = ctx->internal->cb;
        return 1;
    case EVP_CTRL_GET_ASYNCH_CALLBACK_DATA:
        if (!ctx->cipher) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        if (!(ctx->flags & EVP_CIPH_CTX_FLAG_EXPANDED)) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
                   EVP_R_ASYNCH_CALLBACK_NOT_SETUP);
            return 0;
        }
        *(void **)ptr = ctx->internal->cb_data;
        return 1;
    default:
        break;
    }

    if (!ctx->cipher) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX, EVP_R_NO_CIPHER_SET);
        return 0;
    }

    if (!ctx->cipher->ctrl) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX, EVP_R_CTRL_NOT_IMPLEMENTED);
        return 0;
    }

    ret = ctx->cipher->ctrl(ctx, type, arg, ptr);
    if (ret == -1) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_CTRL_EX,
               EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED);
        return 0;
    }
    return ret;
}

int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key)
{
    if (ctx->cipher->flags & EVP_CIPH_RAND_KEY)
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key);
    if (RAND_bytes(key, ctx->key_len) <= 0)
        return 0;
    return 1;
}

int EVP_CIPHER_CTX_copy(EVP_CIPHER_CTX *out, const EVP_CIPHER_CTX *in)
{
    if ((in == NULL) || (in->cipher == NULL)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, EVP_R_INPUT_NOT_INITIALIZED);
        return 0;
    }
#ifndef OPENSSL_NO_ENGINE
    /* Make sure it's safe to copy a cipher context using an ENGINE */
    if (in->engine && !ENGINE_init(in->engine)) {
        EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_ENGINE_LIB);
        return 0;
    }
#endif

    EVP_CIPHER_CTX_cleanup(out);
    out->cipher = in->cipher;
    out->engine = in->engine;
    out->encrypt = in->encrypt;
    out->buf_len = in->buf_len;

    memcpy(out->oiv, in->oiv, EVP_MAX_IV_LENGTH);
    memcpy(out->iv, in->iv, EVP_MAX_IV_LENGTH);
    memcpy(out->buf, in->buf, EVP_MAX_BLOCK_LENGTH);
    out->num = in->num;

    out->app_data = in->app_data;
    out->key_len = in->key_len;
    out->flags = in->flags;
    out->cipher_data = in->cipher_data;
    out->final_used = in->final_used;
    out->block_mask = in->block_mask;
    memcpy(out->final, in->final, EVP_MAX_BLOCK_LENGTH);

    if (out->flags & EVP_CIPH_CTX_FLAG_EXPANDED) {
        if (!evp_CIPHER_CTX_expand(out)) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        out->internal->cb = in->internal->cb;
        out->internal->cb_data = in->internal->cb_data;
    }

    if (in->cipher_data && in->cipher->ctx_size) {
        out->cipher_data = OPENSSL_malloc(in->cipher->ctx_size);
        if (!out->cipher_data) {
            EVPerr(EVP_F_EVP_CIPHER_CTX_COPY, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(out->cipher_data, in->cipher_data, in->cipher->ctx_size);
    }

    if (in->cipher->flags & EVP_CIPH_CUSTOM_COPY)
        return in->cipher->ctrl((EVP_CIPHER_CTX *)in, EVP_CTRL_COPY, 0, out);
    return 1;
}
