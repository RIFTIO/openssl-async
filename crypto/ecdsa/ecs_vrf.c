/* crypto/ecdsa/ecdsa_vrf.c */
/*
 * Written by Nils Larsch for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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

#include "ecs_locl.h"

// This header contains the definition of  EC_KEY
#include "../ec/ec_lcl.h"

#include <string.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif


struct ecdsa_verify_async_args {
    int type;
    const unsigned char *dgst;
    unsigned int dgst_len;
    const unsigned char *sigbuf;
    unsigned int sig_len;
    EC_KEY *eckey;
};

static int ecdsa_verify_async_internal(void *vargs)
{
    struct ecdsa_verify_async_args *args;
    args = (struct ecdsa_verify_async_args *)vargs;
    if (!args)
        return 0;
    return ECDSA_verify(args->type, args->dgst, args->dgst_len,
                    args->sigbuf, args->sig_len, args->eckey);
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len,
                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    ECDSA_DATA *ecdsa = ecdsa_check(eckey);
    if (ecdsa == NULL)
        return 0;
    return ecdsa->meth->ecdsa_do_verify(dgst, dgst_len, sig, eckey);
}

/*-
 * returns
 *      1: correct signature
 *      0: incorrect signature
 *     -1: error
 */
int ECDSA_verify(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen))
        goto err;
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
 err:
    if (derlen > 0) {
        OPENSSL_cleanse(der, derlen);
        OPENSSL_free(der);
    }
    ECDSA_SIG_free(s);
    return (ret);
}

int ECDSA_verify_async(int type, const unsigned char *dgst, int dgst_len,
                 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    int ret;
    struct ecdsa_verify_async_args args;
    ASYNC_JOB *tmp_job = EC_KEY_get_job(eckey);

    args.type = type;
    args.dgst = dgst;
    args.dgst_len = dgst_len;
    args.sigbuf = sigbuf;
    args.sig_len = sig_len;
    args.eckey = eckey;

    if(!ASYNC_in_job()) {
        switch(ASYNC_start_job(&tmp_job, &ret, ecdsa_verify_async_internal, &args,
            sizeof(struct ecdsa_verify_async_args))) {
        case ASYNC_ERR:
            //SSLerr(SSL_F_SSL_READ, SSL_R_FAILED_TO_INIT_ASYNC);
            return -1;
        case ASYNC_PAUSE:
            return -1;
        case ASYNC_FINISH:
            EC_KEY_set_job(eckey, NULL);
            return ret;
        default:
            //SSLerr(SSL_F_SSL_READ, ERR_R_INTERNAL_ERROR);
            /* Shouldn't happen */
            return -1;
        }
    }
    return ECDSA_verify(type, dgst, dgst_len, sigbuf, sig_len, eckey);
}
