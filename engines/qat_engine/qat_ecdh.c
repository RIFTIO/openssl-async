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
 * @file qat_ecdh.c
 *
 * This file provides support for ECDH
 *
 *****************************************************************************/

#include <string.h>
#include <limits.h>
#include <unistd.h>
#include "qat_ecdh.h"
#include <openssl/ecdh.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <ech_locl.h>
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_ecdh.h"
#include "cpa_cy_ec.h"
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

#ifdef OPENSSL_ENABLE_QAT_ECDH_SYNCH
# ifdef OPENSSL_DISABLE_QAT_ECDH_SYNCH
#  undef OPENSSL_DISABLE_QAT_ECDH_SYNCH
# endif
#endif

/* Qat engine ECDH methods declaration */
static int qat_ecdh_compute_key(void *outX, size_t lenX, void *outY,
                                size_t lenY, const EC_POINT *pub_key,
                                EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                            size_t inlen,
                                                            void *out,
                                                            size_t *outlen),
                                int (*cb) (unsigned char *res, size_t reslen,
                                           void *cb_data, int status),
                                void *cb_data);

static int qat_ecdh_compute_key_sync(void *out, size_t outlen,
                                     const EC_POINT *pub_key, EC_KEY *ecdh,
                                     void *(*KDF) (const void *in,
                                                   size_t inlen, void *out,
                                                   size_t *outlen));

#ifdef OPENSSL_QAT_ASYNCH
static int qat_ecdh_generate_key_sync(EC_KEY *ecdh);
#endif

static ECDH_METHOD qat_ecdh_method = {
    "QAT ECDH method",          /* name */
    qat_ecdh_compute_key_sync,  /* compute_key sync */
    0,                          /* flags */
    NULL                        /* app_data */
#ifdef OPENSSL_QAT_ASYNCH
        , qat_ecdh_generate_key_sync /* generate_key sync */
#endif
};

ECDH_METHOD *get_ECDH_methods(void)
{

#ifdef OPENSSL_DISABLE_QAT_ECDH_SYNCH
    const ECDH_METHOD *def_ecdh_meth = ECDH_get_default_method();

    qat_ecdh_method.compute_key = def_ecdh_meth->compute_key;
    qat_ecdh_method.generate_key = def_ecdh_meth->generate_key;
#endif

    return &qat_ecdh_method;
}

/* Callback to indicate QAT completion of ECDH point multiply */
void qat_ecdhCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                        CpaBoolean multiplyStatus, CpaFlatBuffer * pXk,
                        CpaFlatBuffer * pYk)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_FALSE);
}

static int qat_ecdh_compute_key(void *outX, size_t outlenX, void *outY,
                                size_t outlenY, const EC_POINT *pub_key,
                                EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                            size_t inlen,
                                                            void *out,
                                                            size_t *outlen),
                                int (*cb) (unsigned char *res, size_t reslen,
                                           void *cb_data, int status),
                                void *cb_data)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    BIGNUM *xg = NULL, *yg = NULL;
    const BIGNUM *priv_key;
    const EC_GROUP *group;
    int ret = -1, rc = 1;
    size_t buflen;

    CpaInstanceHandle instanceHandle;
    CpaCyEcdhPointMultiplyOpData *opData = NULL;
    CpaBoolean bEcdhStatus;
    CpaFlatBuffer *pResultX = NULL;
    CpaFlatBuffer *pResultY = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    struct op_done op_done;

    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    opData = (CpaCyEcdhPointMultiplyOpData *)
        OPENSSL_malloc(sizeof(CpaCyEcdhPointMultiplyOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    opData->k.pData = NULL;
    opData->xg.pData = NULL;
    opData->yg.pData = NULL;
    opData->a.pData = NULL;
    opData->b.pData = NULL;
    opData->q.pData = NULL;

    /* To instruct the Quickassist API not to use co-factor */
    opData->h.pData = NULL;
    opData->h.dataLenInBytes = 0;

    /* Populate the parameters required for ECDH point multiply */
    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);
    if ((p = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((a = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((b = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((xg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((yg = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (ecdh == NULL || (priv_key = EC_KEY_get0_private_key(ecdh)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if ((group = EC_KEY_get0_group(ecdh)) == NULL) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    buflen = (EC_GROUP_get_degree(group) + 7) / 8;
    pResultX = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultX) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultX->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultX->pData) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultX->dataLenInBytes = (Cpa32U) buflen;
    pResultY = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultY) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultY->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultY->pData) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultY->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->k), (BIGNUM *)priv_key)) != 1) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx)) {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, xg, yg, ctx)) {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_PRIME;
    } else {
        if ((!EC_GROUP_get_curve_GF2m(group, p, a, b, ctx)) ||
            (!EC_POINT_get_affine_coordinates_GF2m(group, pub_key,
                                                   xg, yg, ctx))) {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        opData->fieldType = CPA_CY_EC_FIELD_TYPE_BINARY;
    }
    if ((qat_BN_to_FB(&(opData->xg), xg) != 1) ||
        (qat_BN_to_FB(&(opData->yg), yg) != 1) ||
        (qat_BN_to_FB(&(opData->a), a) != 1)) {
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
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
        QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    opData->pointVerify = CPA_FALSE;

    if (!cb) {                  /* Sync Mode */
        initOpDone(&op_done);

        /* Invoke the crypto engine API for ECDH */
        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyEcdhPointMultiply(instanceHandle,
                                            qat_ecdhCallbackFn,
                                            &op_done,
                                            opData,
                                            &bEcdhStatus, pResultX, pResultY);

            if (status == CPA_STATUS_RETRY) {
                //usleep(ulPollInterval +
                //       (qatPerformOpRetries %
                //        QAT_RETRY_BACKOFF_MODULO_DIVISOR));
                qatPerformOpRetries++;
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_RETRY);
                ASYNC_pause_job();
                if(!getEnableExternalPolling())
                    poll_instances();
            }
        }
        while (status == CPA_STATUS_RETRY );
        //while (status == CPA_STATUS_RETRY &&
        //       ((qatPerformOpRetries < iMsgRetry) ||
        //        (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

        if (status != CPA_STATUS_SUCCESS) {
            QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        //rc = waitForOpToComplete(&op_done);
        do {
            ASYNC_pause_job();
            if(!getEnableExternalPolling())
                poll_instances();
        }
        while (!op_done.flag);

        cleanupOpDone(&op_done);
        //if (rc)
        //    goto err;

        /* Invoke the key derivative function */
        if (KDF != NULL) {
            if (KDF(pResultX->pData, pResultX->dataLenInBytes,
                    outX, &outlenX) == NULL) {
                QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, QAT_R_ECDH_KDF_FAILED);
                goto err;
            }
            ret = outlenX;
        } else {
            /* no KDF, just copy as much as we can */
            if (outlenX > pResultX->dataLenInBytes)
                outlenX = pResultX->dataLenInBytes;
            memcpy(outX, pResultX->pData, outlenX);
            ret = outlenX;

            if (outY != NULL) {
                if (outlenY != pResultY->dataLenInBytes) {
                    QATerr(QAT_F_QAT_ECDH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                memcpy(outY, pResultY->pData, pResultY->dataLenInBytes);
            }
        }
    }
 err:
    if (pResultX) {
        if (pResultX->pData) {
            qaeCryptoMemFree(pResultX->pData);
        }
        OPENSSL_free(pResultX);
    }
    if (pResultY) {
        if (pResultY->pData) {
            qaeCryptoMemFree(pResultY->pData);
        }
        OPENSSL_free(pResultY);
    }
    if (opData->k.pData)
        qaeCryptoMemFree(opData->k.pData);
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
    if (opData)
        OPENSSL_free(opData);
    if (ctx)
        BN_CTX_end(ctx);
    if (ctx)
        BN_CTX_free(ctx);
    return (ret);
}

static int qat_ecdh_compute_key_sync(void *out,
                                     size_t outlen,
                                     const EC_POINT *pub_key,
                                     EC_KEY *ecdh,
                                     void *(*KDF) (const void *in,
                                                   size_t inlen, void *out,
                                                   size_t *outlen))
{
    return qat_ecdh_compute_key(out, outlen, NULL, 0, pub_key, ecdh, KDF,
                                NULL, NULL);
}


#ifdef OPENSSL_QAT_ASYNCH
static int qat_ecdh_generate_key_sync(EC_KEY *ecdh)
{
    int ok = 0;
    int alloc_priv = 0, alloc_pub = 0;
    int field_size = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL, *x_bn = NULL, *y_bn =
        NULL, *tx_bn = NULL, *ty_bn = NULL;
    EC_POINT *pub_key = NULL;
    const EC_POINT *gen;
    const EC_GROUP *group;
    unsigned char *temp_buf = NULL;

# ifdef OPENSSL_FIPS
    if (FIPS_mode())
        return FIPS_ec_key_generate_key(ecdh);
# endif

    if (!ecdh || !(group = EC_KEY_get0_group(ecdh))) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (((order = BN_new()) == NULL) || ((ctx = BN_CTX_new()) == NULL)) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if ((priv_key = (BIGNUM *)EC_KEY_get0_private_key(ecdh)) == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        alloc_priv = 1;
    }

    if (!EC_GROUP_get_order(group, order, ctx)) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    do
        if (!BN_rand_range(priv_key, order)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    while (BN_is_zero(priv_key)) ;

    if (alloc_priv) {
        if (!EC_KEY_set_private_key(ecdh, priv_key)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if ((pub_key = (EC_POINT *)EC_KEY_get0_public_key(ecdh)) == NULL) {
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, QAT_R_MEM_ALLOC_FAILED);
            goto err;
        }
        alloc_pub = 1;
    }

    field_size = EC_GROUP_get_degree(group);
    if (field_size <= 0) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, QAT_R_FIELD_SIZE_ERROR);
        goto err;
    }
    temp_buf = OPENSSL_malloc(2 * ((field_size + 7) / 8));
    if (temp_buf == NULL) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, QAT_R_MEM_ALLOC_FAILED);
        goto err;
    }
    gen = EC_GROUP_get0_generator(group);

    if (!qat_ecdh_compute_key(temp_buf,
                              (field_size + 7) / 8,
                              temp_buf + ((field_size + 7) / 8),
                              (field_size + 7) / 8,
                              gen, ecdh, NULL, NULL, NULL)) {
        /*
         * No QATerr is raised here because errors are already handled in
         * qat_ecdh_compute_key()
         */
        goto err;
    }

    if (((x_bn = BN_new()) == NULL) ||
        ((y_bn = BN_new()) == NULL) ||
        ((tx_bn = BN_new()) == NULL) || ((ty_bn = BN_new()) == NULL)) {
        QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, QAT_R_MEM_ALLOC_FAILED);
        goto err;
    }

    x_bn = BN_bin2bn(temp_buf, (field_size + 7) / 8, NULL);
    y_bn =
        BN_bin2bn((temp_buf + ((field_size + 7) / 8)), (field_size + 7) / 8,
                  NULL);
    if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
        NID_X9_62_prime_field) {
        if (!EC_POINT_set_affine_coordinates_GFp
            (group, pub_key, x_bn, y_bn, ctx)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                   QAT_R_ECDH_SET_AFFINE_COORD_FAILED);
            goto err;
        }
        if (!EC_POINT_get_affine_coordinates_GFp
            (group, pub_key, tx_bn, ty_bn, ctx)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                   QAT_R_ECDH_GET_AFFINE_COORD_FAILED);
            goto err;
        }

        /*
         * Check if retrieved coordinates match originals: if not values are
         * out of range.
         */
        if (BN_cmp(x_bn, tx_bn) || BN_cmp(y_bn, ty_bn)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!EC_KEY_set_public_key(ecdh, pub_key)) {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) ==
            NID_X9_62_characteristic_two_field) {
            if (!EC_POINT_set_affine_coordinates_GF2m
                (group, pub_key, x_bn, y_bn, ctx)) {
                QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                       QAT_R_ECDH_SET_AFFINE_COORD_FAILED);
                goto err;
            }
            if (!EC_POINT_get_affine_coordinates_GF2m
                (group, pub_key, tx_bn, ty_bn, ctx)) {
                QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                       QAT_R_ECDH_GET_AFFINE_COORD_FAILED);
                goto err;
            }
            if (BN_cmp(x_bn, tx_bn) || BN_cmp(y_bn, ty_bn)) {
                QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
            if (!EC_KEY_set_public_key(ecdh, pub_key)) {
                QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                       ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            QATerr(QAT_F_QAT_ECDH_GENERATE_KEY_SYNC,
                   QAT_R_ECDH_UNKNOWN_FIELD_TYPE);
            goto err;
        }
    }
    ok = 1;

 err:
    if (order)
        BN_free(order);
    if (alloc_pub)
        EC_POINT_free(pub_key);
    if (alloc_priv)
        BN_free(priv_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    if (temp_buf != NULL)
        OPENSSL_free(temp_buf);
    if (x_bn != NULL)
        BN_free(x_bn);
    if (y_bn != NULL)
        BN_free(y_bn);
    if (tx_bn != NULL)
        BN_free(tx_bn);
    if (ty_bn != NULL)
        BN_free(ty_bn);
    return (ok);
}
#endif

