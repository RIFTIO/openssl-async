/* engines/e_dasync.c */
/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>

#define DASYNC_LIB_NAME "DASYNC"
#include "e_dasync_err.c"

/* Engine Id and Name */
static const char *engine_dasync_id = "dasync";
static const char *engine_dasync_name = "Dummy Async engine support";


/* Engine Lifetime functions */
static int dasync_destroy(ENGINE *e);
static int dasync_init(ENGINE *e);
static int dasync_finish(ENGINE *e);
void ENGINE_load_dasync(void);


/* Set up digests. Just SHA1 for now */
static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

static void dummy_pause_job(void);

/* SHA1 */
static int dasync_sha1_init(EVP_MD_CTX *ctx);
static int dasync_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count);
static int dasync_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static EVP_MD *_hidden_sha1_md = NULL;
static const EVP_MD *dasync_sha1(void)
{
    if (_hidden_sha1_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL
            || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH)
            || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK)
            || !EVP_MD_meth_set_app_datasize(md,
                                             sizeof(EVP_MD *) + sizeof(SHA_CTX))
            || !EVP_MD_meth_set_flags(md, EVP_MD_FLAG_DIGALGID_ABSENT)
            || !EVP_MD_meth_set_init(md, dasync_sha1_init)
            || !EVP_MD_meth_set_update(md, dasync_sha1_update)
            || !EVP_MD_meth_set_final(md, dasync_sha1_final)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        _hidden_sha1_md = md;
    }
    return _hidden_sha1_md;
}
static void destroy_digests(void)
{
    EVP_MD_meth_free(_hidden_sha1_md);
    _hidden_sha1_md = NULL;
}
static int dasync_digest_nids(const int **nids)
{
    static int digest_nids[2] = { 0, 0 };
    static int pos = 0;
    static int init = 0;

    if (!init) {
        const EVP_MD *md;
        if ((md = dasync_sha1()) != NULL)
            digest_nids[pos++] = EVP_MD_type(md);
        digest_nids[pos] = 0;
        init = 1;
    }
    *nids = digest_nids;
    return pos;
}

/* RSA */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding);
static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa,
                              BN_CTX *ctx);

static int dasync_rsa_init(RSA *rsa);
static int dasync_rsa_finish(RSA *rsa);

static RSA_METHOD dasync_rsa_method = {
    "Dummy Async RSA method",
    dasync_pub_enc,             /* pub_enc */
    dasync_pub_dec,             /* pub_dec */
    dasync_rsa_priv_enc,        /* priv_enc */
    dasync_rsa_priv_dec,        /* priv_dec */
    dasync_rsa_mod_exp,         /* rsa_mod_exp */
    BN_mod_exp_mont,            /* bn_mod_exp */
    dasync_rsa_init,            /* init */
    dasync_rsa_finish,          /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    0,                          /* rsa_sign */
    0,                          /* rsa_verify */
    NULL                        /* rsa_keygen */
};


/* AES */

static int dasync_aes128_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                  void *ptr);

static int dasync_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                  const unsigned char *iv, int enc);

static int dasync_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                    const unsigned char *in, size_t inl);

static int dasync_aes128_cbc_cleanup(EVP_CIPHER_CTX *ctx);

struct aes_128_cbc_pipeline_ctx {
    void *inner_cipher_data;
    unsigned char dummy[256];
    unsigned int numpipes;
    unsigned char **inbufs;
    unsigned char **outbufs;
    size_t *lens;
};

static const EVP_CIPHER dasync_aes_128_cbc = { \
    NID_aes_128_cbc,
    16, /* block size */
    16, /* key len */
    16, /* iv len */
    EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_PIPELINE,
    dasync_aes128_init_key,
    dasync_aes128_cbc_cipher,
    dasync_aes128_cbc_cleanup,
    sizeof(struct aes_128_cbc_pipeline_ctx),
    NULL,NULL,
    dasync_aes128_cbc_ctrl,
    NULL
};

static int dasync_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                   const int **nids, int nid);

#  ifdef NID_aes_128_cbc_hmac_sha256
static int dasync_cipher_nids[] = {
    NID_aes_128_cbc,
    0
};
#  else
static int dasync_cipher_nids[] = { 0 };
#endif

static int bind_dasync(ENGINE *e)
{
    /* Ensure the dasync error handling is set up */
    ERR_load_DASYNC_strings();

    if (!ENGINE_set_id(e, engine_dasync_id)
        || !ENGINE_set_name(e, engine_dasync_name)
        || !ENGINE_set_RSA(e, &dasync_rsa_method)
        || !ENGINE_set_digests(e, dasync_digests)
        || !ENGINE_set_ciphers(e, dasync_ciphers)
        || !ENGINE_set_destroy_function(e, dasync_destroy)
        || !ENGINE_set_init_function(e, dasync_init)
        || !ENGINE_set_finish_function(e, dasync_finish)) {
        DASYNCerr(DASYNC_F_BIND_DASYNC, DASYNC_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_dasync_id) != 0))
        return 0;
    if (!bind_dasync(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
# endif

static ENGINE *engine_dasync(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_dasync(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void ENGINE_load_dasync(void)
{
    ENGINE *toadd = engine_dasync();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}

static int dasync_init(ENGINE *e)
{
    return 1;
}


static int dasync_finish(ENGINE *e)
{
    return 1;
}


static int dasync_destroy(ENGINE *e)
{
    destroy_digests();
    ERR_unload_DASYNC_strings();
    return 1;
}

static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        return dasync_digest_nids(nids);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_sha1:
        *digest = dasync_sha1();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}

static int dasync_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                   const int **nids, int nid)
{
    int ok = 1;
    if (!cipher) {
        /* We are returning a list of supported nids */
        *nids = dasync_cipher_nids;
        return (sizeof(dasync_cipher_nids) -
                1) / sizeof(dasync_cipher_nids[0]);
    }
    /* We are being asked for a specific cipher */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = &dasync_aes_128_cbc;
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}

static void dummy_pause_job(void) {
    ASYNC_JOB *job;

    if ((job = ASYNC_get_current_job()) == NULL)
        return;

    /*
     * In the Dummy async engine we are cheating. We signal that the job
     * is complete by waking it before the call to ASYNC_pause_job(). A real
     * async engine would only wake when the job was actually complete
     */
    ASYNC_wake(job);

    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

    ASYNC_clear_wake(job);
}


/*
 * SHA1 implementation. At the moment we just defer to the standard
 * implementation
 */
#undef data
#define data(ctx) ((SHA_CTX *)EVP_MD_CTX_md_data(ctx))
static int dasync_sha1_init(EVP_MD_CTX *ctx)
{
    dummy_pause_job();

    return SHA1_Init(data(ctx));
}

static int dasync_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             size_t count)
{
    dummy_pause_job();

    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int dasync_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    dummy_pause_job();

    return SHA1_Final(md, data(ctx));
}

/*
 * RSA implementation
 */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_pub_enc(flen, from, to, rsa, padding);
}

static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_pub_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_priv_enc(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_priv_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    /* Ignore errors - we carry on anyway */
    dummy_pause_job();
    return RSA_PKCS1_OpenSSL()->rsa_mod_exp(r0, I, rsa, ctx);
}

static int dasync_rsa_init(RSA *rsa)
{
    return RSA_PKCS1_OpenSSL()->init(rsa);
}
static int dasync_rsa_finish(RSA *rsa)
{
    return RSA_PKCS1_OpenSSL()->finish(rsa);
}

/*
 * AES128 Implementation
 */

static int dasync_aes128_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                  void *ptr)
{
    struct aes_128_cbc_pipeline_ctx *pipe_ctx =
        (struct aes_128_cbc_pipeline_ctx *)ctx->cipher_data;

    if (pipe_ctx == NULL)
        return 0;

    switch (type) {
        case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
            pipe_ctx->numpipes = arg;
            pipe_ctx->outbufs = (unsigned char **)ptr;
            break;

        case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
            pipe_ctx->numpipes = arg;
            pipe_ctx->inbufs = (unsigned char **)ptr;
            break;

        case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
            pipe_ctx->numpipes = arg;
            pipe_ctx->lens = (size_t *)ptr;
            break;

        default:
            return 0;
    }

    return 1;
}

static int dasync_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ret;
    struct aes_128_cbc_pipeline_ctx *pipe_ctx =
        (struct aes_128_cbc_pipeline_ctx *)ctx->cipher_data;

    if (pipe_ctx->inner_cipher_data == NULL
            && EVP_aes_128_cbc()->ctx_size != 0) {
        pipe_ctx->inner_cipher_data =
            OPENSSL_zalloc(EVP_aes_128_cbc()->ctx_size);
        if (pipe_ctx->inner_cipher_data == NULL) {
            DASYNCerr(DASYNC_F_DASYNC_AES128_INIT_KEY,
                        ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    pipe_ctx->numpipes = 0;

    ctx->cipher_data = pipe_ctx->inner_cipher_data;
    ret = EVP_aes_128_cbc()->init(ctx, key, iv, enc);
    ctx->cipher_data = pipe_ctx;

    return ret;
}

static int dasync_aes128_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    int ret = 1;
    unsigned int i, pipes;
    struct aes_128_cbc_pipeline_ctx *pipe_ctx =
        (struct aes_128_cbc_pipeline_ctx *)ctx->cipher_data;

    pipes = pipe_ctx->numpipes;
    ctx->cipher_data = pipe_ctx->inner_cipher_data;
    if (pipes == 0) {
        ret = EVP_aes_128_cbc()->do_cipher(ctx, out, in, inl);
    } else {
        for (i = 0; i < pipes; i++) {
            ret = ret && EVP_aes_128_cbc()->do_cipher(ctx, pipe_ctx->outbufs[i],
                                                      pipe_ctx->inbufs[i],
                                                      pipe_ctx->lens[i]);
        }
        pipe_ctx->numpipes = 0;
    }
    ctx->cipher_data = pipe_ctx;
    return ret;
}

static int dasync_aes128_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct aes_128_cbc_pipeline_ctx *pipe_ctx =
        (struct aes_128_cbc_pipeline_ctx *)ctx->cipher_data;

    OPENSSL_clear_free(pipe_ctx->inner_cipher_data,
                         EVP_aes_128_cbc()->ctx_size);

    return 1;
}
