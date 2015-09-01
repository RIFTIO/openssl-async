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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>

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

static int dasync_digest_nids[] = { NID_sha1, 0 };

static void dummy_pause_job(void);

/* SHA1 */
static int digest_sha1_init(EVP_MD_CTX *ctx);
static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             unsigned long count);
static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md);

static const EVP_MD digest_sha1 = {
    NID_sha1,
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE | EVP_MD_FLAG_DIGALGID_ABSENT,
    digest_sha1_init,
    digest_sha1_update,
    digest_sha1_final,
    NULL,
    NULL,
    EVP_PKEY_NULL_method,
    SHA_CBLOCK,
    sizeof(EVP_MD *) + sizeof(SHA_CTX),
};

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

/* AES128 HMAC SHA256 */
static int dasync_aes_cbc_hmac_sha256_init_key(EVP_CIPHER_CTX *ctx,
        const unsigned char *inkey, const unsigned char *iv, int enc);
static int dasync_aes_cbc_hmac_sha256_cipher(EVP_CIPHER_CTX *ctx,
        unsigned char *out, const unsigned char *in, size_t len);
static int dasync_aes_cbc_hmac_sha256_ctrl(EVP_CIPHER_CTX *ctx, int type,
        int arg, void *ptr);

# if !defined(EVP_CIPH_FLAG_DEFAULT_ASN1)
#  define EVP_CIPH_FLAG_DEFAULT_ASN1 0
# endif

# if !defined(EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK)
#  define EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK 0
# endif

/* TODO: As defined in e_aes_cbc_hmac_sha256.c */
typedef struct {
    AES_KEY ks;
    SHA256_CTX head, tail, md;
    size_t payload_length;      /* AAD length in decrypt case */
    union {
        unsigned int tls_ver;
        unsigned char tls_aad[16]; /* 13 used */
    } aux;
} EVP_AES_HMAC_SHA256;


static EVP_CIPHER dasync_aes_128_cbc_hmac_sha256_cipher = {
#  ifdef NID_aes_128_cbc_hmac_sha256
    NID_aes_128_cbc_hmac_sha256,
#  else
    NID_undef,
#  endif
    16, 16, 16,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1 |
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK,
    dasync_aes_cbc_hmac_sha256_init_key,
    dasync_aes_cbc_hmac_sha256_cipher,
    NULL,
    sizeof(EVP_AES_HMAC_SHA256),
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv,
    dasync_aes_cbc_hmac_sha256_ctrl,
    NULL
};

static int dasync_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                                   const int **nids, int nid);

#  ifdef NID_aes_128_cbc_hmac_sha256
static int dasync_cipher_nids[] = { NID_aes_128_cbc_hmac_sha256, 0 };
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
# else
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
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_dasync();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
# endif


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
    ERR_unload_DASYNC_strings();
    return 1;
}

static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid)
{
    int ok = 1;
    if (!digest) {
        /* We are returning a list of supported nids */
        *nids = dasync_digest_nids;
        return (sizeof(dasync_digest_nids) -
                1) / sizeof(dasync_digest_nids[0]);
    }
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_sha1:
        *digest = &digest_sha1;
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
# ifdef NID_aes_128_cbc_hmac_sha256
    case NID_aes_128_cbc_hmac_sha256:
        *cipher = &dasync_aes_128_cbc_hmac_sha256_cipher;
        break;
# endif
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
#define data(ctx) ((SHA_CTX *)(ctx)->md_data)
static int digest_sha1_init(EVP_MD_CTX *ctx)
{
    dummy_pause_job();

    return SHA1_Init(data(ctx));
}

static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             unsigned long count)
{
    dummy_pause_job();

    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    dummy_pause_job();

    return SHA1_Final(md, data(ctx));
}

/*
 * RSA implementation
 */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    dummy_pause_job();
    return RSA_PKCS1_SSLeay()->rsa_pub_enc(flen, from, to, rsa, padding);
}

static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    dummy_pause_job();
    return RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    dummy_pause_job();
    return RSA_PKCS1_SSLeay()->rsa_priv_enc(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
    return RSA_PKCS1_SSLeay()->rsa_priv_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    dummy_pause_job();
    return RSA_PKCS1_SSLeay()->rsa_mod_exp(r0, I, rsa, ctx);
}

static int dasync_rsa_init(RSA *rsa)
{
    return RSA_PKCS1_SSLeay()->init(rsa);
}
static int dasync_rsa_finish(RSA *rsa)
{
    return RSA_PKCS1_SSLeay()->finish(rsa);
}


static int dasync_aes_cbc_hmac_sha256_init_key(EVP_CIPHER_CTX *ctx,
                                               const unsigned char *inkey,
                                               const unsigned char *iv, int enc)
{
    return EVP_aes_128_cbc_hmac_sha256()->init(ctx, inkey, iv, enc);
}

static int dasync_aes_cbc_hmac_sha256_cipher(EVP_CIPHER_CTX *ctx,
                                             unsigned char *out,
                                             const unsigned char *in,
                                             size_t len)
{
    return EVP_aes_128_cbc_hmac_sha256()->do_cipher(ctx, out, in, len);
}

static int dasync_aes_cbc_hmac_sha256_ctrl(EVP_CIPHER_CTX *ctx, int type,
                                           int arg, void *ptr)
{
    int ret, num_records = 0, packlen = 0;
    EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *mb_param = NULL, tmp_param;
    unsigned char *tmpbuf = NULL;

    /* For the purposes of this dummy engine we are going to demonstrate
     * receiving multiple records in one go. This gives us the opportunity
     * to submit multiple encryptions to our engine all at the same time.
     *
     * The number of records we are dealing with is in num_records.
     *
     * In this example code we are going to send back the first encrypted
     * record; then pause; and then finish the remaining records. In a
     * real engine the records could all be sent for encryption simultaneously
     * and come back in any order.
     *
     * Note: An engine using this multiblock capability is responsible for
     * adding the record headers for each of the encrypted records.
     */
    if (type == EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT) {
        packlen = EVP_CIPHER_CTX_ctrl(ctx,
                            EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE,
                            SSL3_RT_MAX_PLAIN_LENGTH, NULL);
        mb_param = (EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM *)ptr;
        num_records = mb_param->interleave;
        packlen *= num_records;

        tmpbuf = OPENSSL_malloc(packlen);
        if (tmpbuf == NULL)
            return 0;
        memcpy(&tmp_param, mb_param, sizeof(EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM));
        tmp_param.out = tmpbuf;
        ret = EVP_aes_128_cbc_hmac_sha256()->ctrl(ctx, type, arg, &tmp_param);

        if (ret > 0) {
            unsigned int length;
            unsigned char *p;

            p = tmpbuf;

            /* Parse the record header for the first record */
            /* Skip over content-type and version */
            p += 3;
            /* Get the Record payload length */
            length = ((int)p[0]) << 8 | ((int)p[1]);
            /* Add the record header length */
            length += SSL3_RT_HEADER_LENGTH;
            /* Copy the first record */
            memcpy(mb_param->out, tmpbuf, length);

            /* Pause */
            dummy_pause_job();

            /* Copy the remaining records */
            memcpy(mb_param->out + length, tmpbuf + length, ret - length);
        }
        OPENSSL_free(tmpbuf);
    } else {
        ret = EVP_aes_128_cbc_hmac_sha256()->ctrl(ctx, type, arg, ptr);
    }

    return ret;
}
