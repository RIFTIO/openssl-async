/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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

/*****************************************************************************
 * @file qat_ecdsa.c
 *
 * This file provides support for ECDSA
 *
 *****************************************************************************/

#include "ecs_locl.h"
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_ec.h"
#include "cpa_cy_ecdsa.h"
#include "e_qat.h"
#include "qat_asym_common.h"
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif
#include "e_qat_err.h"
#include "qat_utils.h"
#include "qat_ecdsa.h"

#ifdef OPENSSL_ENABLE_QAT_ECDSA_SYNCH
# ifdef OPENSSL_DISABLE_QAT_ECDSA_SYNCH
#  undef OPENSSL_DISABLE_QAT_ECDSA_SYNCH
# endif
#endif

#ifdef OPENSSL_ENABLE_QAT_ECDSA_ASYNCH
# ifdef OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
#  undef OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
# endif
#endif

#ifndef OPENSSL_QAT_ASYNCH
# define OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
#endif

static ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dlen,
                                    const BIGNUM *, const BIGNUM *,
                                    EC_KEY *eckey, unsigned char *sig,
                                    unsigned int *siglen,
                                    int (*cb) (unsigned char *res,
                                               size_t reslen, void *cb_data,
                                               int status), void *cb_data);
static int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                               const ECDSA_SIG *sig, EC_KEY *eckey,
                               int (*cb) (void *cb_data, int status),
                               void *cb_data);

static ECDSA_SIG *qat_ecdsa_do_sign_sync(const unsigned char *dgst,
                                         int dgst_len, const BIGNUM *in_kinv,
                                         const BIGNUM *in_r, EC_KEY *eckey);

#ifdef OPENSSL_QAT_ASYNCH
static ECDSA_SIG *qat_ecdsa_do_sign_asynch(const unsigned char *dgst,
                                           int dgst_len,
                                           const BIGNUM *in_kinv,
                                           const BIGNUM *in_r, EC_KEY *eckey,
                                           unsigned char *sig,
                                           unsigned int *siglen,
                                           int (*cb) (unsigned char *res,
                                                      size_t reslen,
                                                      void *cb_data,
                                                      int status),
                                           void *cb_data);
#endif

static int qat_ecdsa_do_verify_sync(const unsigned char *dgst, int dgst_len,
                                    const ECDSA_SIG *sig, EC_KEY *eckey);

#ifdef OPENSSL_QAT_ASYNCH
static int qat_ecdsa_do_verify_asynch(const unsigned char *dgst, int dgst_len,
                                      const ECDSA_SIG *sig, EC_KEY *eckey,
                                      int (*cb) (void *cb_data, int status),
                                      void *cb_data);
#endif

static ECDSA_METHOD qat_ecdsa_method = {
    "QAT ECDSA method",
    qat_ecdsa_do_sign_sync,
    NULL,
    qat_ecdsa_do_verify_sync,
#ifdef OPENSSL_QAT_ASYNCH
    qat_ecdsa_do_sign_asynch,
    qat_ecdsa_do_verify_asynch,
#endif
    0,                          /* flags */
    NULL                        /* app_data */
};

ECDSA_METHOD *get_ECDSA_methods(void)
{
#ifdef OPENSSL_DISABLE_QAT_ECDSA_SYNCH
# ifndef OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
    const ECDSA_METHOD *def_ecdsa_meth = ECDSA_get_default_method();

    qat_ecdsa_method.ecdsa_do_sign = def_ecdsa_meth->ecdsa_do_sign;
    qat_ecdsa_method.ecdsa_sign_setup = def_ecdsa_meth->ecdsa_sign_setup;
    qat_ecdsa_method.ecdsa_do_verify = def_ecdsa_meth->ecdsa_do_verify;
# endif
#endif

#ifdef OPENSSL_QAT_ASYNCH
# ifndef OPENSSL_DISABLE_QAT_ECDSA_SYNCH
#  ifdef OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
    qat_ecdsa_method.ecdsa_do_sign_asynch = NULL;
    qat_ecdsa_method.ecdsa_do_verify_asynch = NULL;
#  endif
# endif
#endif

#ifdef OPENSSL_DISABLE_QAT_ECDSA_SYNCH
# ifdef OPENSSL_DISABLE_QAT_ECDSA_ASYNCH
    return NULL;
# endif
#endif
    return &qat_ecdsa_method;
}

typedef struct ecdsa_sign_op_data {
    BN_CTX *ctx;
    unsigned char *sig;
    unsigned int *siglen;
    CpaCyEcdsaSignRSOpData *sign_op_data;
    int (*cb_func) (unsigned char *res, size_t reslen, void *cb_data,
                    int status);
    void *cb_data;
} ecdsa_sign_op_data_t;

typedef struct ecdsa_verify_op_data {
    BN_CTX *ctx;
    CpaCyEcdsaVerifyOpData *verify_op_data;
    int (*cb_func) (void *cb_data, int status);
    void *cb_data;
} ecdsa_verify_op_data_t;

/* Callback to indicate QAT sync completion of ECDSA Sign */
void qat_ecdsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                             void *pOpData, CpaBoolean bEcdsaSignStatus,
                             CpaFlatBuffer * pResultR,
                             CpaFlatBuffer * pResultS)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_FALSE);
}

#ifdef OPENSSL_QAT_ASYNCH
/* Callback to indicate QAT async completion of ECDSA Sign */
void qat_ecdsaAsyncSignCallbackFn(void *pCallbackTag, CpaStatus status,
                                  void *pOpData, CpaBoolean bEcdsaSignStatus,
                                  CpaFlatBuffer * pResultR,
                                  CpaFlatBuffer * pResultS)
{
    ECDSA_SIG *ret = NULL;
    ecdsa_sign_op_data_t *sign_async_data =
        (ecdsa_sign_op_data_t *) (pCallbackTag);
    int cb_status = status == CPA_STATUS_SUCCESS ? 1 : 0;

    if (!sign_async_data) {
        WARN("[%s] --- pCallbackTag NULL!\n", __func__);
        goto err;
    }

    ret = ECDSA_SIG_new();
    if (!ret) {
        WARN("[%s] --- ECDSA_SIG_new() failed!\n", __func__);
        goto err;
    }

    /* Convert the flatbuffer results back to a BN */
    BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, ret->r);
    BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, ret->s);

    *sign_async_data->siglen = i2d_ECDSA_SIG(ret, &sign_async_data->sig);

    /* Invoke the user registered callback */
    sign_async_data->cb_func(sign_async_data->sig, *sign_async_data->siglen,
                             sign_async_data->cb_data, cb_status);

 err:
    if (pResultR) {
        if (pResultR->pData) {
            qaeCryptoMemFree(pResultR->pData);
        }
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        if (pResultS->pData) {
            qaeCryptoMemFree(pResultS->pData);
        }
        OPENSSL_free(pResultS);
    }

    if (ret)
        ECDSA_SIG_free(ret);

    if (sign_async_data) {
        if (sign_async_data->sign_op_data) {
            if (sign_async_data->sign_op_data->k.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->k.pData);
            if (sign_async_data->sign_op_data->n.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->n.pData);
            if (sign_async_data->sign_op_data->m.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->m.pData);
            if (sign_async_data->sign_op_data->d.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->d.pData);
            if (sign_async_data->sign_op_data->xg.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->xg.pData);
            if (sign_async_data->sign_op_data->yg.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->yg.pData);
            if (sign_async_data->sign_op_data->a.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->a.pData);
            if (sign_async_data->sign_op_data->b.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->b.pData);
            if (sign_async_data->sign_op_data->q.pData)
                qaeCryptoMemFree(sign_async_data->sign_op_data->q.pData);
            OPENSSL_free(sign_async_data->sign_op_data);
        }

        if (sign_async_data->ctx)
            BN_CTX_end(sign_async_data->ctx);
        if (sign_async_data->ctx)
            BN_CTX_free(sign_async_data->ctx);
        OPENSSL_free(sign_async_data);
    }
}
#endif

/* Callback to indicate QAT sync completion of ECDSA Verify */
void qat_ecdsaVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                               void *pOpData, CpaBoolean bEcdsaVerifyStatus)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bEcdsaVerifyStatus);
}

#ifdef OPENSSL_QAT_ASYNCH
/* Callback to indicate QAT async completion of ECDSA Verify */
void qat_ecdsaAsyncVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData,
                                    CpaBoolean bEcdsaVerifyStatus)
{
    ecdsa_verify_op_data_t *verify_async_data =
        (ecdsa_verify_op_data_t *) (pCallbackTag);
    int cb_status = bEcdsaVerifyStatus == CPA_TRUE ? 1 : 0;

    if (!verify_async_data) {
        WARN("[%s] --- pCallbackTag NULL!\n", __func__);
        goto err;
    }

    /* Invoke the user registered callback */
    verify_async_data->cb_func(verify_async_data->cb_data, cb_status);

 err:
    if (verify_async_data) {
        if (verify_async_data->verify_op_data) {
            if (verify_async_data->verify_op_data->r.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->r.pData);
            if (verify_async_data->verify_op_data->s.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->s.pData);
            if (verify_async_data->verify_op_data->n.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->n.pData);
            if (verify_async_data->verify_op_data->m.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->m.pData);
            if (verify_async_data->verify_op_data->xg.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->xg.pData);
            if (verify_async_data->verify_op_data->yg.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->yg.pData);
            if (verify_async_data->verify_op_data->a.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->a.pData);
            if (verify_async_data->verify_op_data->b.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->b.pData);
            if (verify_async_data->verify_op_data->q.pData)
                qaeCryptoMemFree(verify_async_data->verify_op_data->q.pData);
            OPENSSL_free(verify_async_data->verify_op_data);
        }

        if (verify_async_data->ctx)
            BN_CTX_end(verify_async_data->ctx);
        if (verify_async_data->ctx)
            BN_CTX_free(verify_async_data->ctx);
        OPENSSL_free(verify_async_data);
    }
}
#endif

static ECDSA_SIG *qat_ecdsa_do_sign(const unsigned char *dgst, int dgst_len,
                                    const BIGNUM *in_kinv, const BIGNUM *in_r,
                                    EC_KEY *eckey, unsigned char *sig,
                                    unsigned int *siglen,
                                    int (*cb) (unsigned char *res,
                                               size_t reslen, void *cb_data,
                                               int status), void *cb_data)
{
    int ok = 0, i, rc = 1;
    BIGNUM *m = NULL, *order = NULL;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group;
    ECDSA_SIG *ret = NULL;
    ECDSA_DATA *ecdsa;
    const BIGNUM *priv_key;
    BIGNUM *p = NULL, *a = NULL, *b = NULL, *k = NULL, *r = NULL;
    BIGNUM *xg = NULL, *yg = NULL;
    const EC_POINT *pub_key = NULL;

    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    CpaInstanceHandle instanceHandle;
    CpaCyEcdsaSignRSOpData *opData = NULL;
    CpaBoolean bEcdsaSignStatus;
    CpaStatus status;
    size_t buflen;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    const EC_POINT *ec_point = NULL;
#ifdef OPENSSL_QAT_ASYNCH
    ecdsa_sign_op_data_t *ecdsa_op_done = NULL;
#endif

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    ecdsa = ecdsa_check(eckey);
    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_key = EC_KEY_get0_public_key(eckey);

    if (group == NULL || priv_key == NULL || ecdsa == NULL || pub_key == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if ((ec_point = EC_GROUP_get0_generator(group)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        return ret;
    }

    opData = (CpaCyEcdsaSignRSOpData *)
        OPENSSL_malloc(sizeof(CpaCyEcdsaSignRSOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyEcdsaSignRSOpData));

    ret = ECDSA_SIG_new();
    if (!ret) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((p = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((a = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((b = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((xg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((yg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((m = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((k = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((r = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((order = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->d), (BIGNUM *)priv_key)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EC_GROUP_get_order(group, order, ctx)) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_EC_LIB);
        goto err;
    }
    i = BN_num_bits(order);

    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_BN_LIB);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->m), (BIGNUM *)m)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    do
        if (!BN_rand_range(k, order)) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    while (BN_is_zero(k)) ;

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field) {
        if ((!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GFp(group, ec_point,
                                                  xg, yg, ctx))) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    } else {
        if ((!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GF2m(group, ec_point,
                                                   xg, yg, ctx))) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_BINARY;
    }

    if ((qat_BN_to_FB(&(opData->xg), xg) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yg) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1)) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */
    if (opData->a.pData == NULL && opData->a.dataLenInBytes == 0) {
        opData->a.pData = qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        opData->a.dataLenInBytes = 1;
        if (opData->a.pData) {
            opData->a.pData[0] = 0;
        }
    }

    if ((qat_BN_to_FB(&(opData->b), b) != 1) ||
        (qat_BN_to_FB(&(opData->q), p) != 1)) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (in_kinv == NULL || in_r == NULL) {
        if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)k)) != 1) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if ((qat_BN_to_FB(&(opData->n), (BIGNUM *)order)) != 1) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }

    } else {
        if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)in_kinv)) != 1) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if ((qat_BN_to_FB(&(opData->n), (BIGNUM *)in_r)) != 1) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }

    }

    buflen = EC_GROUP_get_degree(group);
    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultR) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultR->pData) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;
    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultS) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultS->pData) {
        QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    if (!cb) {                  /* Sync Mode */
        /* perform ECDSA sign */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyEcdsaSignRS(instanceHandle,
                                      qat_ecdsaSignCallbackFn,
                                      &op_done,
                                      opData,
                                      &bEcdsaSignStatus, pResultR, pResultS);

            if (status == CPA_STATUS_RETRY) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
            }
        }
        while (status == CPA_STATUS_RETRY &&
               ((qatPerformOpRetries < iMsgRetry) ||
                (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

        if (status != CPA_STATUS_SUCCESS) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        rc = waitForOpToComplete(&op_done);
        cleanupOpDone(&op_done);
        if (rc)
            goto err;

        /* Convert the flatbuffer results back to a BN */
        BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, ret->r);
        BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, ret->s);

        ok = 1;
    }
#ifdef OPENSSL_QAT_ASYNCH
    else {                      /* Async Mode */

        ecdsa_op_done = (ecdsa_sign_op_data_t *)
            OPENSSL_malloc(sizeof(ecdsa_sign_op_data_t));
        if (ecdsa_op_done == NULL) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        ecdsa_op_done->ctx = ctx;
        ecdsa_op_done->sig = sig;
        ecdsa_op_done->siglen = siglen;
        ecdsa_op_done->sign_op_data = opData;
        ecdsa_op_done->cb_func = cb;
        ecdsa_op_done->cb_data = cb_data;

        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(ecdsa_op_done);
            goto err;
        }

        status = cpaCyEcdsaSignRS(instanceHandle,
                                  qat_ecdsaAsyncSignCallbackFn,
                                  ecdsa_op_done,
                                  opData,
                                  &bEcdsaSignStatus, pResultR, pResultS);

        if (status != CPA_STATUS_SUCCESS) {
            WARN("[%s] --- Async cpaCyEcdsaSignRS, status=%d.\n", __func__,
                 status);
            if (status == CPA_STATUS_RETRY) {
                QATerr(QAT_F_QAT_ECDSA_DO_SIGN, ERR_R_RETRY);
            }
            OPENSSL_free(ecdsa_op_done);
            goto err;
        }
        return ret;
    }
#endif

 err:
    if (!ok) {
        ECDSA_SIG_free(ret);
        ret = NULL;
    }

    if (pResultR) {
        if (pResultR->pData) {
            qaeCryptoMemFree(pResultR->pData);
        }
        OPENSSL_free(pResultR);
    }
    if (pResultS) {
        if (pResultS->pData) {
            qaeCryptoMemFree(pResultS->pData);
        }
        OPENSSL_free(pResultS);
    }

    if (opData) {
        if (opData->k.pData)
            qaeCryptoMemFree(opData->k.pData);
        if (opData->n.pData)
            qaeCryptoMemFree(opData->n.pData);
        if (opData->m.pData)
            qaeCryptoMemFree(opData->m.pData);
        if (opData->d.pData)
            qaeCryptoMemFree(opData->d.pData);
        if (opData->xg.pData)
            qaeCryptoMemFree(opData->xg.pData);
        if (opData->yg.pData)
            qaeCryptoMemFree(opData->yg.pData);
        if (opData->a.pData)
            qaeCryptoMemFree(opData->a.pData);
        if (opData->b.pData)
            qaeCryptoMemFree(opData->b.pData);
        if (opData->q.pData)
            qaeCryptoMemFree(opData->q.pData);
        OPENSSL_free(opData);
    }

    if (ctx)
        BN_CTX_end(ctx);
    if (ctx)
        BN_CTX_free(ctx);
    return ret;
}

static ECDSA_SIG *qat_ecdsa_do_sign_sync(const unsigned char *dgst,
                                         int dgst_len, const BIGNUM *in_kinv,
                                         const BIGNUM *in_r, EC_KEY *eckey)
{
    return qat_ecdsa_do_sign(dgst, dgst_len, in_kinv, in_r, eckey, NULL, NULL,
                             NULL, NULL);

}

#ifdef OPENSSL_QAT_ASYNCH
static ECDSA_SIG *qat_ecdsa_do_sign_asynch(const unsigned char *dgst,
                                           int dgst_len,
                                           const BIGNUM *in_kinv,
                                           const BIGNUM *in_r, EC_KEY *eckey,
                                           unsigned char *sig,
                                           unsigned int *siglen,
                                           int (*cb) (unsigned char *res,
                                                      size_t reslen,
                                                      void *cb_data,
                                                      int status),
                                           void *cb_data)
{
    if (!cb) {
        DEBUG("[%s] --- Invalid Parameter\n", __func__);
        return 0;
    }

    return qat_ecdsa_do_sign(dgst, dgst_len, in_kinv, in_r, eckey, sig,
                             siglen, cb, cb_data);
}
#endif

static int qat_ecdsa_do_verify(const unsigned char *dgst, int dgst_len,
                               const ECDSA_SIG *sig, EC_KEY *eckey,
                               int (*cb) (void *cb_data, int status),
                               void *cb_data)
{
    int ret = -1, i, rc = 1;
    BN_CTX *ctx = NULL;
    BIGNUM *order = NULL, *m = NULL;
    const EC_GROUP *group;
    const EC_POINT *pub_key;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *xg = NULL, *yg = NULL, *xp = NULL, *yp = NULL;
    const EC_POINT *ec_point;

    CpaInstanceHandle instanceHandle;
    CpaCyEcdsaVerifyOpData *opData = NULL;
    CpaBoolean bEcdsaVerifyStatus;
    CpaStatus status;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
#ifdef OPENSSL_QAT_ASYNCH
    ecdsa_verify_op_data_t *ecdsa_op_done = NULL;
#endif

    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    /* check input values */
    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL ||
        (pub_key = EC_KEY_get0_public_key(eckey)) == NULL || sig == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    if ((ec_point = EC_GROUP_get0_generator(group)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        return ret;
    }

    opData = (CpaCyEcdsaVerifyOpData *)
        OPENSSL_malloc(sizeof(CpaCyEcdsaVerifyOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyEcdsaVerifyOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((p = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((a = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((b = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((xg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((yg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((xp = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((yp = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((m = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((order = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
        BN_ucmp(sig->r, order) >= 0 || BN_is_zero(sig->s) ||
        BN_is_negative(sig->s) || BN_ucmp(sig->s, order) >= 0) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        ret = 0;                /* signature is invalid */
        goto err;
    }
    /* digest -> m */
    i = BN_num_bits(order);
    /*
     * Need to truncate digest if it is too long: first truncate whole bytes.
     */
    if (8 * dgst_len > i)
        dgst_len = (i + 7) / 8;

    if (!BN_bin2bn(dgst, dgst_len, m)) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }
    /* If still too long truncate remaining bits with a shift */
    if ((8 * dgst_len > i) && !BN_rshift(m, m, 8 - (i & 0x7))) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->m), (BIGNUM *)m)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
        == NID_X9_62_prime_field) {
        if ((!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GFp(group, ec_point,
                                                  xg, yg, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GFp(group, pub_key,
                                                  xp, yp, ctx))) {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    } else {
        if ((!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GF2m(group, ec_point,
                                                   xg, yg, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GF2m(group, pub_key,
                                                   xp, yp, ctx))) {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_BINARY;
    }

    if ((qat_BN_to_FB(&(opData->xg), xg) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yg) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1)) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * This is a special handling required for curves with 'a' co-efficient
     * of 0. The translation to a flatbuffer results in a zero sized field
     * but the Quickassist API expects a flatbuffer of size 1 with a value
     * of zero. As a special case we will create that manually.
     */

    if (opData->a.pData == NULL && opData->a.dataLenInBytes == 0) {
        opData->a.pData = qaeCryptoMemAlloc(1, __FILE__, __LINE__);
        opData->a.dataLenInBytes = 1;
        if (opData->a.pData) {
            opData->a.pData[0] = 0;
        }
    }

    if ((qat_BN_to_FB(&(opData->b), b) != 1) ||
        (qat_BN_to_FB(&(opData->q), p) != 1)) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->n), (BIGNUM *)order)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->r), (BIGNUM *)sig->r)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->s), (BIGNUM *)sig->s)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->xp), (BIGNUM *)xp)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->yp), (BIGNUM *)yp)) != 1) {
        QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!cb) {                  /* Sync Mode */
        /* perform ECDSA verify */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyEcdsaVerify(instanceHandle,
                                      qat_ecdsaVerifyCallbackFn,
                                      &op_done, opData, &bEcdsaVerifyStatus);

            if (status == CPA_STATUS_RETRY) {
                usleep(ulPollInterval +
                       (qatPerformOpRetries %
                        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
            }
        }
        while (status == CPA_STATUS_RETRY &&
               ((qatPerformOpRetries < iMsgRetry) ||
                (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

        if (status != CPA_STATUS_SUCCESS) {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        rc = waitForOpToComplete(&op_done);

        if (op_done.verifyResult == CPA_TRUE)
            ret = 1;

        cleanupOpDone(&op_done);
        if (rc) {
            ret = -1;
            goto err;
        }
    }
#ifdef OPENSSL_QAT_ASYNCH
    else {                      /* Async mode */

        ecdsa_op_done = (ecdsa_verify_op_data_t *)
            OPENSSL_malloc(sizeof(ecdsa_verify_op_data_t));
        if (ecdsa_op_done == NULL) {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        ecdsa_op_done->ctx = ctx;
        ecdsa_op_done->verify_op_data = opData;
        ecdsa_op_done->cb_func = cb;
        ecdsa_op_done->cb_data = cb_data;

        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(ecdsa_op_done);
            goto err;
        }

        status = cpaCyEcdsaVerify(instanceHandle,
                                  qat_ecdsaAsyncVerifyCallbackFn,
                                  ecdsa_op_done, opData, &bEcdsaVerifyStatus);

        if (status != CPA_STATUS_SUCCESS) {
            WARN("[%s] --- Async cpaCyEcdsaVerify, status=%d.\n", __func__,
                 status);
            if (status == CPA_STATUS_RETRY) {
                QATerr(QAT_F_QAT_ECDSA_DO_VERIFY, ERR_R_RETRY);
            }
            OPENSSL_free(ecdsa_op_done);
            ret = 0;
            goto err;
        }
        ret = 1;
        return ret;
    }
#endif

 err:
    if (opData) {
        if (opData->r.pData)
            qaeCryptoMemFree(opData->r.pData);
        if (opData->s.pData)
            qaeCryptoMemFree(opData->s.pData);
        if (opData->n.pData)
            qaeCryptoMemFree(opData->n.pData);
        if (opData->m.pData)
            qaeCryptoMemFree(opData->m.pData);
        if (opData->xg.pData)
            qaeCryptoMemFree(opData->xg.pData);
        if (opData->yg.pData)
            qaeCryptoMemFree(opData->yg.pData);
        if (opData->a.pData)
            qaeCryptoMemFree(opData->a.pData);
        if (opData->b.pData)
            qaeCryptoMemFree(opData->b.pData);
        if (opData->q.pData)
            qaeCryptoMemFree(opData->q.pData);
        OPENSSL_free(opData);
    }

    if (ctx)
        BN_CTX_end(ctx);
    if (ctx)
        BN_CTX_free(ctx);
    return ret;
}

static int qat_ecdsa_do_verify_sync(const unsigned char *dgst, int dgst_len,
                                    const ECDSA_SIG *sig, EC_KEY *eckey)
{
    return qat_ecdsa_do_verify(dgst, dgst_len, sig, eckey, NULL, NULL);
}

#ifdef OPENSSL_QAT_ASYNCH
static int qat_ecdsa_do_verify_asynch(const unsigned char *dgst, int dgst_len,
                                      const ECDSA_SIG *sig, EC_KEY *eckey,
                                      int (*cb) (void *cb_data, int status),
                                      void *cb_data)
{
    if (!cb) {
        DEBUG("[%s] --- Invalid Parameter\n", __func__);
        return 0;
    }

    return qat_ecdsa_do_verify(dgst, dgst_len, sig, eckey, cb, cb_data);
}
#endif
