/* crypto/prf/prf_pmeth.c */
/*
 * Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/prf.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pool.h>
#ifndef OPENSSL_NO_CMS
# include <openssl/cms.h>
#endif
#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif
#include "evp_locl.h"

static int pkey_prf_derive_init(EVP_PKEY_CTX *ctx)
{
    PRF *prf_ctx;
    prf_ctx = OPENSSL_malloc(sizeof(PRF));
    if (!prf_ctx) {
        EVPerr(EVP_F_PKEY_PRF_DERIVE_INIT, EVP_R_MALLOC_FAILURE);
        return 0;
    }
    prf_ctx->seed1 = NULL;
    prf_ctx->seed1_len = 0;
    prf_ctx->seed2 = NULL;
    prf_ctx->seed2_len = 0;
    prf_ctx->seed3 = NULL;
    prf_ctx->seed3_len = 0;
    prf_ctx->seed4 = NULL;
    prf_ctx->seed4_len = 0;
    prf_ctx->seed5 = NULL;
    prf_ctx->seed5_len = 0;
    prf_ctx->sec = NULL;
    prf_ctx->sec_len = 0;
    prf_ctx->sec = NULL;
    prf_ctx->version = 0;
    prf_ctx->md = NULL;
    prf_ctx->md_count = 0;

    ctx->data = prf_ctx;
    return 1;
}

static void pkey_prf_cleanup(EVP_PKEY_CTX *ctx)
{
    PRF *prf_ctx = ctx->data;
    if (prf_ctx) {
        OPENSSL_free(prf_ctx);
        prf_ctx = NULL;
        // HANDLE: NOT sure whether we will be allocating memory, if so
        // cleanup here
    }
}

static int pkey_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    PRF *prf_ctx = ctx->data;
    if (!prf_ctx) {
        EVPerr(EVP_F_PKEY_PRF_CTRL, EVP_R_INPUT_NOT_INITIALIZED);
        return -1;
    }
    switch (type) {
    case EVP_PKEY_CTRL_SET_PRF_SEED1:
        prf_ctx->seed1 = p2;
        prf_ctx->seed1_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_SEED2:
        prf_ctx->seed2 = p2;
        prf_ctx->seed2_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_SEED3:
        prf_ctx->seed3 = p2;
        prf_ctx->seed3_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_SEED4:
        prf_ctx->seed4 = p2;
        prf_ctx->seed4_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_SEED5:
        prf_ctx->seed5 = p2;
        prf_ctx->seed5_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_SECRET:
        prf_ctx->sec = p2;
        prf_ctx->sec_len = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_DIGEST:
        prf_ctx->md = (EVP_MD **)p2;
        prf_ctx->md_count = p1;
        break;
    case EVP_PKEY_CTRL_SET_PRF_VERSION:
        prf_ctx->version = p1;
        break;
    default:
        return -1;
    }
    return 1;
}

static int pkey_prf_derive_synch(EVP_PKEY_CTX *ctx, unsigned char *key,
                                 size_t *olen)
{
    PRF *prf_ctx = ctx->data;
    int ret = -1;
    if (!prf_ctx) {
        EVPerr(EVP_F_PKEY_PRF_DERIVE_SYNCH, EVP_R_INPUT_NOT_INITIALIZED);
        return ret;
    }
    ret = PRF_derive(prf_ctx, key, olen);
    return ret;
}

const EVP_PKEY_METHOD prf_pkey_meth = {
    EVP_PKEY_PRF,
    0,
    0,
    0,
    pkey_prf_cleanup,

    0, 0,

    0,
    0,

    0,
    {0, 0},

    0,
    {0, 0},

    0,
    {0, 0},

    0, {0, 0}, 0, {0, 0},

    0,
    {0, 0},

    0,
    {0, 0},

    pkey_prf_derive_init,
    {pkey_prf_derive_synch, 0},

    pkey_prf_ctrl,
    0
};
