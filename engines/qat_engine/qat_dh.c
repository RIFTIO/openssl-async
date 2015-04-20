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
 * @file qat_dh.c
 *
 * This file provides implementaiotns for Diffie Hellman operations through an
 * OpenSSL engine
 *
 *****************************************************************************/

#include "qat_dh.h"
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif
#include "qat_asym_common.h"
#include "qat_utils.h"
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_dh.h"
#include "e_qat.h"
#include "e_qat_err.h"
#include <unistd.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_DH_SYNCH
# ifdef OPENSSL_DISABLE_QAT_DH_SYNCH
#  undef OPENSSL_DISABLE_QAT_DH_SYNCH
# endif
#endif

#ifdef OPENSSL_ENABLE_QAT_DH_ASYNCH
# ifdef OPENSSL_DISABLE_QAT_DH_ASYNCH
#  undef OPENSSL_DISABLE_QAT_DH_ASYNCH
# endif
#endif

#ifndef OPENSSL_QAT_ASYNCH
# define OPENSSL_DISABLE_QAT_DH_ASYNCH
#endif

/* To specify the DH op sizes supported by QAT engine */
#define DH_QAT_RANGE_MIN 768
#define DH_QAT_RANGE_MAX 4096

int qat_dh_generate_key_synch(DH *dh);
int qat_dh_generate_key_asynch(DH *dh,
                               int (*cb) (unsigned char *res, size_t reslen,
                                          void *cb_data, int status),
                               void *cb_data);
int qat_dh_compute_key_synch(unsigned char *key, const BIGNUM *pub_key,
                             DH *dh);

int qat_dh_compute_key_asynch(unsigned char *key, int *len,
                              const BIGNUM *pub_key, DH *dh,
                              int (*cb) (unsigned char *res, size_t reslen,
                                         void *cb_data, int status),
                              void *cb_data);

static DH_METHOD qat_dh_method = {
    "QAT DH method",            /* name */
    qat_dh_generate_key_synch,  /* generate_key */
    qat_dh_compute_key_synch,   /* compute_key */
    qat_mod_exp_dh,             /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* generate_params */
#ifdef OPENSSL_QAT_ASYNCH
    qat_dh_generate_key_asynch, /* generate_key asynch */
    qat_dh_compute_key_asynch   /* compute_key asynch */
#endif
};

DH_METHOD *get_DH_methods(void)
{
#ifdef OPENSSL_DISABLE_QAT_DH_SYNCH
# ifndef OPENSSL_DISABLE_QAT_DH_ASYNCH
    const DH_METHOD *def_dh_meth = DH_get_default_method();
    if (def_dh_meth) {
        qat_dh_method.generate_key = def_dh_meth->generate_key;
        qat_dh_method.compute_key = def_dh_meth->compute_key;
        qat_dh_method.bn_mod_exp = def_dh_meth->bn_mod_exp;
    } else {
        qat_dh_method.generate_key = NULL;
        qat_dh_method.compute_key = NULL;
        qat_dh_method.bn_mod_exp = NULL;
    }
# endif
#endif

#ifdef OPENSSL_QAT_ASYNCH
# ifndef OPENSSL_DISABLE_QAT_DH_SYNCH
#  ifdef OPENSSL_DISABLE_QAT_DH_ASYNCH
    qat_dh_method.generate_key_asynch = NULL;
    qat_dh_method.compute_key_asynch = NULL;
#  endif
# endif
# ifndef OPENSSL_DIABLE_QAT_DH_ASYNCH
    qat_dh_method.flags |= DH_FLAG_ASYNCH;
# endif
#endif

#ifdef OPENSSL_DISABLE_QAT_DH_SYNCH
# ifdef OPENSSL_DISABLE_QAT_DH_ASYNCH
    return NULL;
# endif
#endif
    return &qat_dh_method;
}

typedef struct dh_generate_op_data {
    DH *dh;
    BIGNUM *priv_key;
    BIGNUM *pub_key;
    CpaCyDhPhase1KeyGenOpData *opData;
    size_t outlen;
    int (*cb_func) (unsigned char *res, size_t reslen,
                    void *cb_data, int status);
    void *cb_data;
} dh_generate_op_data_t;

typedef struct dh_compute_op_data {
    int *len;
    unsigned char *key;
    CpaCyDhPhase2SecretKeyGenOpData *opData;
    size_t outlen;
    int (*cb_func) (unsigned char *res, size_t reslen,
                    void *cb_data, int status);
    void *cb_data;
} dh_compute_op_data_t;

/*
 * The DH range check is performed so that if the op sizes are not in the
 * range supported by QAT engine then fall back to software
 */

int dh_range_check(int plen)
{
    int range = 0;

    if ((plen >= DH_QAT_RANGE_MIN) && (plen <= DH_QAT_RANGE_MAX))
        range = 1;

    return range;
}

/* Callback to indicate QAT completion of DH generate & compute key */
void qat_dhCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                      CpaFlatBuffer * pPV)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_FALSE);
}

#ifdef OPENSSL_QAT_ASYNCH
/* Callback to indicate QAT completion of DH generate key in asynch mode*/
void qat_dhGenerateAsynchCallbackFn(void *pCallbackTag, CpaStatus status,
                                    void *pOpData, CpaFlatBuffer * pPV)
{
    dh_generate_op_data_t *dh_asynch_data =
        (dh_generate_op_data_t *) (pCallbackTag);
    int cb_status = status == CPA_STATUS_SUCCESS ? 1 : 0;

    if (!dh_asynch_data || !pPV) {
        WARN("[%s] --- parameter NULL!\n", __func__);
        goto err;
    }

    dh_asynch_data->dh->priv_key = dh_asynch_data->priv_key;
    /* Convert the flatbuffer result back to a BN */
    BN_bin2bn(pPV->pData, pPV->dataLenInBytes, dh_asynch_data->pub_key);
    dh_asynch_data->dh->pub_key = dh_asynch_data->pub_key;

    dh_asynch_data->cb_func(NULL, 0, dh_asynch_data->cb_data, cb_status);
 err:

    if (pPV) {
        if (pPV->pData) {
            qaeCryptoMemFree(pPV->pData);
        }
        OPENSSL_free(pPV);
    }

    if (dh_asynch_data) {
        if (dh_asynch_data->opData) {
            if (dh_asynch_data->opData->primeP.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->primeP.pData);
            if (dh_asynch_data->opData->baseG.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->baseG.pData);
            if (dh_asynch_data->opData->privateValueX.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->privateValueX.pData);
            OPENSSL_free(dh_asynch_data->opData);
        }

        if ((dh_asynch_data->pub_key != NULL) &&
            (dh_asynch_data->dh->pub_key == NULL))
            BN_free(dh_asynch_data->pub_key);
        if ((dh_asynch_data->priv_key != NULL) &&
            (dh_asynch_data->dh->priv_key == NULL))
            BN_free(dh_asynch_data->priv_key);
        OPENSSL_free(dh_asynch_data);
    }
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/* Callback to indicate QAT completion of DH compute key asynch mode */
void qat_dhComputeAsynchCallbackFn(void *pCallbackTag, CpaStatus status,
                                   void *pOpData, CpaFlatBuffer * pSecretKey)
{
    dh_compute_op_data_t *dh_asynch_data =
        (dh_compute_op_data_t *) (pCallbackTag);
    int cb_status = status == CPA_STATUS_SUCCESS ? 1 : 0;
    int index = 1;

    if (!dh_asynch_data || !pSecretKey || !dh_asynch_data->len) {
        WARN("[%s] --- parameter NULL!\n", __func__);
        goto err;
    }

    if (!pSecretKey->pData[0]) {
        while (!pSecretKey->pData[index])
            index++;
        pSecretKey->dataLenInBytes = pSecretKey->dataLenInBytes - index;
        memcpy(dh_asynch_data->key, &pSecretKey->pData[index],
               pSecretKey->dataLenInBytes);
    } else {
        memcpy(dh_asynch_data->key, pSecretKey->pData,
               pSecretKey->dataLenInBytes);
    }
    *dh_asynch_data->len = pSecretKey->dataLenInBytes;

    dh_asynch_data->cb_func(dh_asynch_data->key, *dh_asynch_data->len,
                            dh_asynch_data->cb_data, cb_status);
 err:
    if (pSecretKey) {
        if (pSecretKey->pData) {
            qaeCryptoMemFree(pSecretKey->pData);
        }
        OPENSSL_free(pSecretKey);
    }

    if (dh_asynch_data) {
        if (dh_asynch_data->opData) {
            if (dh_asynch_data->opData->primeP.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->primeP.pData);
            if (dh_asynch_data->opData->remoteOctetStringPV.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->
                                 remoteOctetStringPV.pData);
            if (dh_asynch_data->opData->privateValueX.pData)
                qaeCryptoMemFree(dh_asynch_data->opData->privateValueX.pData);
            OPENSSL_free(dh_asynch_data->opData);
        }
        OPENSSL_free(dh_asynch_data);
    }
}
#endif

/******************************************************************************
* function:
*         qat_dh_generate_key(DH * dh,
*                             int (*cb)(unsigned char *res, size_t reslen,
*                             void *cb_data, int status),
*                             void *cb_data)
*
* description:
*   Implement Diffie-Hellman phase 1 operations.
******************************************************************************/
int qat_dh_generate_key(DH *dh,
                        int (*cb) (unsigned char *res, size_t reslen,
                                   void *cb_data, int status), void *cb_data)
{
    int ok = 0, rc = 1;
    int generate_new_key = 0;
    unsigned length = 0;
    BIGNUM *pub_key = NULL, *priv_key = NULL;
    CpaInstanceHandle instanceHandle;
    CpaCyDhPhase1KeyGenOpData *opData = NULL;
    CpaFlatBuffer *pPV = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    struct op_done op_done;
    size_t buflen;
#ifdef OPENSSL_QAT_ASYNCH
    dh_generate_op_data_t *dh_op_done = NULL;
#endif

    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    opData = (CpaCyDhPhase1KeyGenOpData *)
        OPENSSL_malloc(sizeof(CpaCyDhPhase1KeyGenOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        return ok;
    }

    opData->primeP.pData = NULL;
    opData->baseG.pData = NULL;
    opData->privateValueX.pData = NULL;

    if (dh->priv_key == NULL) {
        if ((priv_key = BN_new()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        generate_new_key = 1;
    } else
        priv_key = dh->priv_key;

    if (dh->pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else
        pub_key = dh->pub_key;

    if (generate_new_key) {
        if (dh->q) {
            do {
                if (!BN_rand_range(priv_key, dh->q)) {
                    QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_BN_LIB);
                    goto err;
                }
            }
            while (BN_is_zero(priv_key) || BN_is_one(priv_key));
        } else {
            /* secret exponent length */
            length = dh->length ? dh->length : BN_num_bits(dh->p) - 1;
            if (!BN_rand(priv_key, length, 0, 0)) {
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_BN_LIB);
                goto err;
            }
        }
    }

    buflen = BN_num_bytes(dh->p);
    pPV = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pPV) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pPV->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pPV->pData) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pPV->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)dh->p) != 1) ||
        (qat_BN_to_FB(&(opData->baseG), (BIGNUM *)dh->g) != 1) ||
        (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)priv_key) != 1)) {
        QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!cb) {                  /* Synch mode */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyDhKeyGenPhase1(instanceHandle,
                                         qat_dhCallbackFn,
                                         &op_done, opData, pPV);

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
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        rc = waitForOpToComplete(&op_done);
        cleanupOpDone(&op_done);
        if (rc)
            goto err;

        dh->priv_key = priv_key;
        /* Convert the flatbuffer result back to a BN */
        BN_bin2bn(pPV->pData, pPV->dataLenInBytes, pub_key);
        dh->pub_key = pub_key;

        ok = 1;
    }
#ifdef OPENSSL_QAT_ASYNCH
    else {                      /* Asynch mode */

        dh_op_done = (dh_generate_op_data_t *)
            OPENSSL_malloc(sizeof(dh_generate_op_data_t));
        if (dh_op_done == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        dh_op_done->priv_key = priv_key;
        dh_op_done->pub_key = pub_key;
        dh_op_done->dh = dh;
        dh_op_done->opData = opData;
        dh_op_done->cb_func = cb;
        dh_op_done->cb_data = cb_data;

        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(dh_op_done);
            goto err;
        }

        status = cpaCyDhKeyGenPhase1(instanceHandle,
                                     qat_dhGenerateAsynchCallbackFn,
                                     dh_op_done, opData, pPV);

        if (status != CPA_STATUS_SUCCESS) {
            WARN("[%s] --- Async cpaCyDhKeyGenPhase1 failed,\
                                        status=%d.\n", __func__, status);
            if (status == CPA_STATUS_RETRY) {
                QATerr(QAT_F_QAT_DH_GENERATE_KEY, ERR_R_RETRY);
            }
            OPENSSL_free(dh_op_done);
            goto err;
        }
        return 1;
    }
#endif
 err:
    if (pPV) {
        if (pPV->pData) {
            qaeCryptoMemFree(pPV->pData);
        }
        OPENSSL_free(pPV);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->baseG.pData)
            qaeCryptoMemFree(opData->baseG.pData);
        if (opData->privateValueX.pData)
            qaeCryptoMemFree(opData->privateValueX.pData);
        OPENSSL_free(opData);
    }

    if ((pub_key != NULL) && (dh->pub_key == NULL))
        BN_free(pub_key);
    if ((priv_key != NULL) && (dh->priv_key == NULL))
        BN_free(priv_key);
    return (ok);
}

/******************************************************************************
* function:
*         qat_dh_generate_key_synch(DH * dh)
*
* description:
*   Implement Diffie-Hellman phase 1 operations in synch mode.
******************************************************************************/

int qat_dh_generate_key_synch(DH *dh)
{
    const DH_METHOD *default_dh_method = DH_OpenSSL();

    if (!dh)
        return 0;

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(dh->p))) {
        if (!default_dh_method)
            return 0;
        return default_dh_method->generate_key(dh);
    }

    return qat_dh_generate_key(dh, NULL, NULL);
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         qat_dh_generate_key_asynch(DH * dh,
*                                    int (*cb)(unsigned char *res, size_t reslen,
*                                    void *cb_data, int status),
*                                    void *cb_data)
*
* description:
*   Implement Diffie-Hellman phase 1 operations in asynch mode.
******************************************************************************/

int qat_dh_generate_key_asynch(DH *dh,
                               int (*cb) (unsigned char *res, size_t reslen,
                                          void *cb_data, int status),
                               void *cb_data)
{
    const DH_METHOD *default_dh_method = DH_OpenSSL();
    const DH_METHOD *dh_tmp_meth;
    int ret = 0;

    if (!dh || !cb)
        return 0;

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(dh->p))) {
        if (!default_dh_method)
            return 0;
        dh_tmp_meth = dh->meth;
        dh->meth = default_dh_method;
        ret = default_dh_method->generate_key(dh);
        dh->meth = dh_tmp_meth;
        cb(NULL, 0, cb_data, ret);
        return 1;
    }

    return qat_dh_generate_key(dh, cb, cb_data);
}
#endif

/******************************************************************************
* function:
*         qat_dh_compute_key(unsigned char *key, int *len,
*                            const BIGNUM * pub_key, DH * dh,
*                             int (*cb)(unsigned char *res, size_t reslen,
*                             void *cb_data, int status), void *cb_data)
*
* description:
*   Implement Diffie-Hellman phase 2 operations.
******************************************************************************/
int qat_dh_compute_key(unsigned char *key, int *len, const BIGNUM *pub_key,
                       DH *dh, int (*cb) (unsigned char *res, size_t reslen,
                                          void *cb_data, int status),
                       void *cb_data)
{
    int ret = -1, rc = 1;
    int check_result;
    CpaInstanceHandle instanceHandle;
    CpaCyDhPhase2SecretKeyGenOpData *opData = NULL;
    CpaFlatBuffer *pSecretKey = NULL;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    CpaStatus status;
    struct op_done op_done;
    size_t buflen;
#ifdef OPENSSL_QAT_ASYNCH
    dh_compute_op_data_t *dh_op_done = NULL;
#endif
    int index = 1;

    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("KX - %s\n", __func__);

    opData = (CpaCyDhPhase2SecretKeyGenOpData *)
        OPENSSL_malloc(sizeof(CpaCyDhPhase2SecretKeyGenOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    opData->primeP.pData = NULL;
    opData->remoteOctetStringPV.pData = NULL;
    opData->privateValueX.pData = NULL;

    if (BN_num_bits(dh->p) > OPENSSL_DH_MAX_MODULUS_BITS) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (dh->priv_key == NULL) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    buflen = BN_num_bytes(dh->p);
    pSecretKey = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pSecretKey) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pSecretKey->pData) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pSecretKey->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->primeP), (BIGNUM *)dh->p) != 1) ||
        (qat_BN_to_FB(&(opData->remoteOctetStringPV), (BIGNUM *)pub_key) != 1)
        || (qat_BN_to_FB(&(opData->privateValueX), (BIGNUM *)dh->priv_key) !=
            1)) {
        QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!cb) {                  /* Synch mode */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyDhKeyGenPhase2Secret(instanceHandle,
                                               qat_dhCallbackFn,
                                               &op_done, opData, pSecretKey);

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
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        rc = waitForOpToComplete(&op_done);
        cleanupOpDone(&op_done);
        if (rc)
            goto err;

        if (!pSecretKey->pData[0]) {
            while (!pSecretKey->pData[index])
                index++;
            pSecretKey->dataLenInBytes = pSecretKey->dataLenInBytes - index;
            memcpy(key, &pSecretKey->pData[index],
                   pSecretKey->dataLenInBytes);
        } else {
            memcpy(key, pSecretKey->pData, pSecretKey->dataLenInBytes);
        }
        ret = pSecretKey->dataLenInBytes;
    }
#ifdef OPENSSL_QAT_ASYNCH
    else {                      /* Asynch mode */

        dh_op_done = (dh_compute_op_data_t *)
            OPENSSL_malloc(sizeof(dh_compute_op_data_t));
        if (dh_op_done == NULL) {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        dh_op_done->key = key;
        dh_op_done->len = len;
        dh_op_done->opData = opData;
        dh_op_done->cb_func = cb;
        dh_op_done->cb_data = cb_data;

        if ((instanceHandle = get_next_inst()) == NULL) {
            QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(dh_op_done);
            goto err;
        }

        status = cpaCyDhKeyGenPhase2Secret(instanceHandle,
                                           qat_dhComputeAsynchCallbackFn,
                                           dh_op_done, opData, pSecretKey);

        if (status != CPA_STATUS_SUCCESS) {
            WARN("[%s] --- Asynch cpaCyDhKeyGenPhase2Secret failed, status=%d.\n", __func__, status);
            if (status == CPA_STATUS_RETRY) {
                QATerr(QAT_F_QAT_DH_COMPUTE_KEY, ERR_R_RETRY);
            }
            OPENSSL_free(dh_op_done);
            ret = 0;
            goto err;
        }
        return 1;
    }
#endif

 err:
    if (pSecretKey) {
        if (pSecretKey->pData) {
            qaeCryptoMemFree(pSecretKey->pData);
        }
        OPENSSL_free(pSecretKey);
    }

    if (opData) {
        if (opData->primeP.pData)
            qaeCryptoMemFree(opData->primeP.pData);
        if (opData->remoteOctetStringPV.pData)
            qaeCryptoMemFree(opData->remoteOctetStringPV.pData);
        if (opData->privateValueX.pData)
            qaeCryptoMemFree(opData->privateValueX.pData);
        OPENSSL_free(opData);
    }

    return (ret);
}

/******************************************************************************
* function:
*         qat_dh_compute_key_synch(unsigned char *key,
*                            const BIGNUM * pub_key, DH * dh)
*
* description:
*   Implement Diffie-Hellman phase 2 operations in synch mode.
******************************************************************************/
int qat_dh_compute_key_synch(unsigned char *key, const BIGNUM *pub_key,
                             DH *dh)
{
    const DH_METHOD *default_dh_method = DH_OpenSSL();

    if (!dh)
        return -1;

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(dh->p))) {
        if (!default_dh_method)
            return -1;
        return default_dh_method->compute_key(key, pub_key, dh);
    }

    return qat_dh_compute_key(key, NULL, pub_key, dh, NULL, NULL);
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         qat_dh_compute_key_asynch(unsigned char *key, int *len,
*                            const BIGNUM * pub_key, DH * dh,
*                            int (*cb)(unsigned char *res, size_t reslen,
*                            void *cb_data, int status), void *cb_data)
*
* description:
*   Implement Diffie-Hellman phase 2 operations in asynch mode.
******************************************************************************/
int qat_dh_compute_key_asynch(unsigned char *key, int *len,
                              const BIGNUM *pub_key, DH *dh,
                              int (*cb) (unsigned char *res, size_t reslen,
                                         void *cb_data, int status),
                              void *cb_data)
{
    const DH_METHOD *default_dh_method = DH_OpenSSL();
    const DH_METHOD *dh_tmp_meth;
    int ret = 0;

    if (!dh || !cb)
        return -1;

    /*
     * If the op sizes are not in the range supported by QAT engine then fall
     * back to software
     */

    if (!dh_range_check(BN_num_bits(dh->p))) {
        if (!default_dh_method)
            return -1;
        dh_tmp_meth = dh->meth;
        dh->meth = default_dh_method;
        ret = default_dh_method->compute_key(key, pub_key, dh);
        dh->meth = dh_tmp_meth;
        cb(key, ret, cb_data, ret);
        return 1;
    }

    return qat_dh_compute_key(key, len, pub_key, dh, cb, cb_data);
}
#endif

/******************************************************************************
* function:
*         qat_mod_exp_dh(const DH * dh, BIGNUM * r, const BIGNUM * a,
*                        const BIGNUM * p, const BIGNUM * m, BN_CTX * ctx,
*                        BN_MONT_CTX * m_ctx)
*
* @param dh    [IN] - Pointer to a OpenSSL DH struct.
* @param r     [IN] - Result bignum of mod_exp
* @param a     [IN] - Base used for mod_exp
* @param p     [IN] - Exponent used for mod_exp
* @param m     [IN] - Modulus used for mod_exp
* @param ctx   [IN] - EVP context.
* @param m_ctx [IN] - EVP context for Montgomery multiplication.
*
* description:
*   Overridden modular exponentiation function used in DH.
*
******************************************************************************/
int qat_mod_exp_dh(const DH *dh, BIGNUM *r, const BIGNUM *a,
                   const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
                   BN_MONT_CTX *m_ctx)
{
    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("KX - %s\n", __func__);
    return qat_mod_exp(r, a, p, m);
}
