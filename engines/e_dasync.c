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
#include <openssl/aes.h>
#include <openssl/modes.h>

# define DASYNC_AES_BLOCK_SIZE      16
# define DASYNC_AES_IV_LEN          16
# define DASYNC_AES_KEY_SIZE_256    32
# define DASYNC_AES_KEY_SIZE_128    16

typedef unsigned char u8;
typedef unsigned long long u64;

struct ccm128_context {
    union {
        u64 u[2];
        u8 c[16];
    } nonce, cmac;
    u64 blocks;
    block128_f block;
    void *key;
};

typedef struct {
    union {
        double align;
        AES_KEY ks;
    } ks;                       /* AES key schedule to use */
    int key_set;                /* Set if key initialised */
    int iv_set;                 /* Set if an iv is set */
    int tag_set;                /* Set if tag is valid */
    int len_set;                /* Set if message length set */
    int L, M;                   /* L and M parameters from RFC3610 */
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_AES_CCM_CTX;

typedef struct {
    AES_KEY ks;
    SHA_CTX head, tail, md;
    size_t payload_length;      /* AAD length in decrypt case */
    union {
        unsigned int tls_ver;
        unsigned char tls_aad[16]; /* 13 used */
    } aux;
} EVP_AES_HMAC_SHA1;

extern unsigned long long fibre_switch_acc;
extern unsigned int fibre_switch_num;
extern unsigned long long fibre_switch_start;
extern unsigned int fibre_switch_out;
extern unsigned long long fibre_switch_avg;


#define DASYNC_LIB_NAME "DASYNC"
#include "e_dasync_err.c"

/* Engine Id and Name */
static const char *engine_dasync_id = "dasync";
static const char *engine_dasync_name = "Dummy Async engine support";

static __inline__ unsigned long long rdtsc(void)
{
    unsigned long a, d;

    asm volatile ("rdtsc":"=a" (a), "=d"(d));
    return (((unsigned long long)a) | (((unsigned long long)d) << 32));
}


/* Engine Lifetime functions */
static int dasync_destroy(ENGINE *e);
static int dasync_init(ENGINE *e);
static int dasync_finish(ENGINE *e);
void ENGINE_load_dasync(void);


static int dasync_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid);

static int dasync_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc);

static int dasync_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);

static int dasync_cipher_cleanup(EVP_CIPHER_CTX *ctx);

static int dasync_aes_cbc_hmac_sha1_init(EVP_CIPHER_CTX *ctx,
                                    const unsigned char *inkey,
                                    const unsigned char *iv, int enc);

static int dasync_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t len);

static int dasync_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr);

static int dasync_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx);


/* Dasync Symmetric cipher function register */
int dasync_cipher_nids[] = {
    NID_aes_128_cbc,
    NID_aes_256_cbc,
    NID_aes_128_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha1
};

/* dasync cipher AES128 function structure declaration */
static const EVP_CIPHER dasync_aes_128_cbc = {
    NID_aes_128_cbc,            /* nid */
    DASYNC_AES_BLOCK_SIZE,             /* block_size */
    DASYNC_AES_KEY_SIZE_128,           /* key_size in Bytes */
    DASYNC_AES_IV_LEN,                 /* iv_len in Bytes */
    EVP_CIPH_FLAG_DEFAULT_ASN1 |
    EVP_CIPH_CBC_MODE |
    EVP_CIPH_CUSTOM_IV,         /* flags */
    dasync_cipher_init,
    dasync_do_cipher,
    dasync_cipher_cleanup,
    sizeof(EVP_AES_CCM_CTX),    /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* dasync cipher AES256 function structure declaration */
static const EVP_CIPHER dasync_aes_256_cbc = {
    NID_aes_256_cbc,            /* nid */
    DASYNC_AES_BLOCK_SIZE,             /* block_size */
    DASYNC_AES_KEY_SIZE_256,           /* key_size in Bytes */
    DASYNC_AES_IV_LEN,                 /* iv_len in Bytes */
    EVP_CIPH_FLAG_DEFAULT_ASN1 |
    EVP_CIPH_CBC_MODE |
    EVP_CIPH_CUSTOM_IV,         /* flags */
    dasync_cipher_init,
    dasync_do_cipher,
    dasync_cipher_cleanup,
    sizeof(EVP_AES_CCM_CTX),    /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Dasync cipher AES128-SHA1 function structure declaration */
static const EVP_CIPHER dasync_aes_128_cbc_hmac_sha1 = {
    NID_aes_128_cbc_hmac_sha1,  /* nid */
    DASYNC_AES_BLOCK_SIZE,             /* block_size */
    DASYNC_AES_KEY_SIZE_128,           /* key_size in Bytes */
    DASYNC_AES_IV_LEN,                 /* iv_len in Bytes */
    EVP_CIPH_FLAG_DEFAULT_ASN1 |
    EVP_CIPH_CBC_MODE |
    EVP_CIPH_CUSTOM_IV |        /* flags */
    EVP_CIPH_FLAG_AEAD_CIPHER,
    dasync_aes_cbc_hmac_sha1_init,
    dasync_aes_cbc_hmac_sha1_cipher,
    dasync_aes_cbc_hmac_sha1_cleanup,
    sizeof(EVP_AES_HMAC_SHA1),  /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv,
    dasync_aes_cbc_hmac_sha1_ctrl,
    NULL
};

/* Dasync cipher AES256-SHA1 function structure declaration */
static const EVP_CIPHER dasync_aes_256_cbc_hmac_sha1 = {
    NID_aes_256_cbc_hmac_sha1,  /* nid */
    DASYNC_AES_BLOCK_SIZE,             /* block_size */
    DASYNC_AES_KEY_SIZE_256,           /* key_size in Bytes */
    DASYNC_AES_IV_LEN,                 /* iv_len in Bytes */
    EVP_CIPH_FLAG_DEFAULT_ASN1 |
    EVP_CIPH_CBC_MODE |
    EVP_CIPH_CUSTOM_IV |        /* flags */
    EVP_CIPH_FLAG_AEAD_CIPHER,
    dasync_aes_cbc_hmac_sha1_init,
    dasync_aes_cbc_hmac_sha1_cipher,
    dasync_aes_cbc_hmac_sha1_cleanup,
    sizeof(EVP_AES_HMAC_SHA1),  /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1 ? NULL : EVP_CIPHER_get_asn1_iv,
    dasync_aes_cbc_hmac_sha1_ctrl,
    NULL
};



/* Set up digests. Just SHA1 for now */
static int dasync_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid);

static int dasync_digest_nids[] = { NID_sha1, 0 };


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
static int dasync_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                        unsigned char *sigret, unsigned int *siglen,
                        const RSA *rsa);
static int dasync_rsa_verify(int dtype, const unsigned char *m,
                          unsigned int m_len, const unsigned char *sigbuf,
                          unsigned int siglen, const RSA *rsa);

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
    dasync_rsa_sign,            /* rsa_sign */
    dasync_rsa_verify,          /* rsa_verify */
    NULL                        /* rsa_keygen */
};


static int bind_dasync(ENGINE *e)
{
    /* Ensure the dasync error handling is set up */
    ERR_load_DASYNC_strings();

    if (!ENGINE_set_id(e, engine_dasync_id)
        || !ENGINE_set_name(e, engine_dasync_name)
        || !ENGINE_set_RSA(e, &dasync_rsa_method)
        || !ENGINE_set_ciphers(e, dasync_ciphers)
        || !ENGINE_set_digests(e, dasync_digests)
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

static int dasync_software_cipher(EVP_CIPHER **cipher, int nid)
{
    switch (nid) {
        case NID_aes_128_cbc:
            *cipher = EVP_aes_128_cbc();
            break;
        case NID_aes_256_cbc:
            *cipher = EVP_aes_256_cbc();
            break;
        case NID_aes_128_cbc_hmac_sha1:
            *cipher = EVP_aes_128_cbc_hmac_sha1();
            break;
        case NID_aes_256_cbc_hmac_sha1:
            *cipher = EVP_aes_256_cbc_hmac_sha1();
            break;
        default:
            *cipher = NULL;
            return 0;
        }
    return 1;
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
    /* We are being asked for a specific digest */
    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = &dasync_aes_128_cbc;
        break;
    case NID_aes_256_cbc:
        *cipher = &dasync_aes_256_cbc;
        break;
    case NID_aes_128_cbc_hmac_sha1:
        *cipher = &dasync_aes_128_cbc_hmac_sha1;
        break;
    case NID_aes_256_cbc_hmac_sha1:
        *cipher = &dasync_aes_256_cbc_hmac_sha1;
        break;
    default:
        ok = 0;
        *cipher = NULL;
        break;
    }
    return ok;
}


static int dasync_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    if (dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx)))
        return cipher->init(ctx, key, iv, enc);

    return 0;
}


static int dasync_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx));
    /* Ignore errors - we carry on anyway */

    ASYNC_pause_job();

#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    if (cipher)
        return cipher->do_cipher(ctx, out, in, inl);

    return 0;
}

static int dasync_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER *cipher;
    
    if (!ctx)
       return 0;

    if (dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx)))
        if (cipher && cipher->cleanup)
            return cipher->cleanup(ctx);

    return 1;
}

static int dasync_aes_cbc_hmac_sha1_init(EVP_CIPHER_CTX *ctx,
                                    const unsigned char *inkey,
                                    const unsigned char *iv, int enc)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    if (dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx)))
        return cipher->init(ctx, inkey, iv, enc);

    return 0;
}

static int dasync_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t len)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx));
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    if (cipher)
        return cipher->do_cipher(ctx, out, in, len);

    return 0;
}

static int dasync_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                                    void *ptr)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    if (dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx)))
        return cipher->ctrl(ctx, type, arg, ptr);

    return 0;
}

static int dasync_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER *cipher;

    if (!ctx)
       return 0;

    if (dasync_software_cipher(&cipher, EVP_CIPHER_CTX_nid(ctx)))
        if (cipher && cipher->cleanup)
            return cipher->cleanup(ctx);

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

/*
 * SHA1 implementation. At the moment we just defer to the standard
 * implementation
 */
#undef data
#define data(ctx) ((SHA_CTX *)(ctx)->md_data)
static int digest_sha1_init(EVP_MD_CTX *ctx)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

    return SHA1_Init(data(ctx));
}

static int digest_sha1_update(EVP_MD_CTX *ctx, const void *data,
                             unsigned long count)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

    return SHA1_Update(data(ctx), data, (size_t)count);
}

static int digest_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();

    return SHA1_Final(md, data(ctx));
}

/*
 * RSA implementation
 */

static int dasync_pub_enc(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_pub_enc(flen, from, to, rsa, padding);
}

static int dasync_pub_dec(int flen, const unsigned char *from,
                    unsigned char *to, RSA *rsa, int padding) {
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_enc(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_priv_enc(flen, from, to, rsa, padding);
}

static int dasync_rsa_priv_dec(int flen, const unsigned char *from,
                      unsigned char *to, RSA *rsa, int padding)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_priv_dec(flen, from, to, rsa, padding);
}

static int dasync_rsa_sign(int type, const unsigned char *m,
    unsigned int m_len, unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_sign(type, m, m_len, sigret, siglen, rsa);
}

static int dasync_rsa_verify(int dtype, const unsigned char *m,
    unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
#ifdef QAT_CPU_CYCLES_COUNT
        unsigned long long fibre_switch_current = rdtsc() - fibre_switch_start;
        ++fibre_switch_num;
        fibre_switch_acc += fibre_switch_current;
#endif
    return RSA_PKCS1_SSLeay()->rsa_verify(dtype, m, m_len, sigbuf, siglen, rsa);
}

static int dasync_rsa_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
    /* Ignore errors - we carry on anyway */
    ASYNC_pause_job();
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
