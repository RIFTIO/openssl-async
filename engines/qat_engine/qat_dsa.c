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
 * @file qat_dsa.c
 *
 * This file provides an implementation of DSA operations for an OpenSSL
 * engine
 *
 *****************************************************************************/

#include "qat_dsa.h"
#include "qat_utils.h"
#include "cpa_cy_dsa.h"
#include "qat_asym_common.h"

#include <openssl/dsa.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_dh.h"
#include "e_qat.h"
#include "e_qat_err.h"
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif

#include <string.h>
#include <unistd.h>

#ifdef OPENSSL_ENABLE_QAT_DSA_SYNCH
# ifdef OPENSSL_DISABLE_QAT_DSA_SYNCH
#  undef OPENSSL_DISABLE_QAT_DSA_SYNCH
# endif
#endif


DSA_SIG *qat_dsa_do_sign_synch(const unsigned char *dgst, int dlen, DSA *dsa);
int qat_dsa_do_verify_synch(const unsigned char *dgst, int dgst_len,
                            DSA_SIG *sig, DSA *dsa);

/* Qat DSA method structure declaration. */
static DSA_METHOD qat_dsa_method = {
    "QAT DSA method",           /* name */
    qat_dsa_do_sign_synch,      /* do_sign */
    qat_dsa_sign_setup,         /* sign_setup */
    qat_dsa_do_verify_synch,    /* do_verify */
    NULL,                       /* mod_exp */
    qat_mod_exp_dsa,            /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* dsa_paramgen */
    NULL                        /* dsa_keygen */
};

DSA_METHOD *get_DSA_methods(void)
{
#ifdef OPENSSL_DISABLE_QAT_DSA_SYNCH
# ifndef OPENSSL_DISABLE_QAT_DSA_ASYNCH
    const DSA_METHOD *def_dsa_meth = DSA_get_default_method();
    if (def_dsa_meth) {
        qat_dsa_method.dsa_do_sign = def_dsa_meth->dsa_do_sign;
        qat_dsa_method.dsa_sign_setup = def_dsa_meth->dsa_sign_setup;
        qat_dsa_method.dsa_do_verify = def_dsa_meth->dsa_do_verify;
        qat_dsa_method.bn_mod_exp = def_dsa_meth->bn_mod_exp;
    } else {
        qat_dsa_method.dsa_do_sign = NULL;
        qat_dsa_method.dsa_sign_setup = NULL;
        qat_dsa_method.dsa_do_verify = NULL;
        qat_dsa_method.bn_mod_exp = NULL;
    }
# endif
#endif

#ifdef OPENSSL_DISABLE_QAT_DSA_SYNCH
# ifdef OPENSSL_DISABLE_QAT_DSA_ASYNCH
    return NULL;
# endif
#endif
    return &qat_dsa_method;
}

typedef struct dsa_sign_op_data {
    BIGNUM *r;
    BIGNUM *s;
    unsigned char *sig;
    unsigned int *siglen;
    CpaCyDsaRSSignOpData *opData;
    int (*cb_func) (unsigned char *res, size_t reslen, void *cb_data,
                    int status);
    void *cb_data;
} dsa_sign_op_data_t;

typedef struct dsa_verify_op_data {
    CpaCyDsaVerifyOpData *opData;
    int (*cb_func) (void *cb_data, int status);
    void *cb_data;
} dsa_verify_op_data_t;

/*
 * DSA range Supported in QAT {L,N} = {1024, 160}, {2048, 224} {2048, 256},
 * {3072, 256}
 */
int dsa_qat_range[4][2] = {
    {1024, 160},
    {2048, 224},
    {2048, 256},
    {3072, 256}
};

/*
 * DSA range check is performed so that if the sizes of P and Q are not in
 * the range supported by QAT engine then fall back to software
 */

int dsa_range_check(int plen, int qlen)
{
    int i, j, range = 0;

    for (i = 0, j = 0; i < 4; i++) {
        if ((plen == dsa_qat_range[i][j])
            && (qlen == dsa_qat_range[i][j + 1])) {
            range = 1;
            break;
        }
    }
    return range;
}

/* Callback to indicate QAT sync completion of DSA Sign */
void qat_dsaSignCallbackFn(void *pCallbackTag, CpaStatus status,
                           void *pOpData, CpaBoolean bDsaSignStatus,
                           CpaFlatBuffer * pResultR, CpaFlatBuffer * pResultS)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_FALSE);
}

/* Callback to indicate QAT sync completion of DSA Verify */
void qat_dsaVerifyCallbackFn(void *pCallbackTag, CpaStatus status,
                             void *pOpData, CpaBoolean bDsaVerifyStatus)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, bDsaVerifyStatus);
}

/******************************************************************************
* function:
*         qat_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
*                         const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
*
* @param dsa   [IN] - Pointer to a OpenSSL DSA struct.
* @param r     [IN] - Result bignum of mod_exp
* @param a     [IN] - Base used for mod_exp
* @param p     [IN] - Exponent used for mod_exp
* @param m     [IN] - Modulus used for mod_exp
* @param ctx   [IN] - EVP context.
* @param m_ctx [IN] - EVP context for Montgomery multiplication.
*
* description:
*   Overridden modular exponentiation function used in DSA.
*
******************************************************************************/
int qat_mod_exp_dsa(DSA *dsa, BIGNUM *r, BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
    DEBUG("%s been called \n", __func__);
    CRYPTO_QAT_LOG("AU - %s\n", __func__);
    return qat_mod_exp(r, a, p, m);
}

/******************************************************************************
* function:
*         qat_dsa_do_sign(const unsigned char *dgst, int dlen,
*                         unsigned char *sig, unsigned int *siglen,
*                         DSA *dsa, int (*cb)(unsigned char *res,
*                         size_t reslen, void *cb_data, int status),
*                         void *cb_data)
*
* description:
*   Generate DSA R and S Signatures.
******************************************************************************/
DSA_SIG *qat_dsa_do_sign(const unsigned char *dgst, int dlen,
                         unsigned char *sig, unsigned int *siglen,
                         DSA *dsa, int (*cb) (unsigned char *res,
                                              size_t reslen, void *cb_data,
                                              int status), void *cb_data)
{
    BIGNUM *r = NULL, *s = NULL;
    BIGNUM *k = NULL;
    BN_CTX *ctx = NULL;
    DSA_SIG *ret = NULL;
    CpaFlatBuffer *pResultR = NULL;
    CpaFlatBuffer *pResultS = NULL;
    CpaInstanceHandle instanceHandle;
    CpaCyDsaRSSignOpData *opData = NULL;
    CpaBoolean bDsaSignStatus;
    CpaStatus status;
    size_t buflen;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    int rc = 1;

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    if (!dsa->p || !dsa->q || !dsa->g) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    opData = (CpaCyDsaRSSignOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaRSSignOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyDsaRSSignOpData));

    if ((r = BN_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((s = BN_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((k = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (dlen > BN_num_bytes(dsa->q))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dlen = BN_num_bytes(dsa->q);
    do {
        if (!BN_rand_range(k, dsa->q)) {
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    while (BN_is_zero(k));

    buflen = BN_num_bytes(dsa->q);
    pResultR = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultR) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultR->pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultR->dataLenInBytes = (Cpa32U) buflen;
    pResultS = (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (!pResultS) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->pData = qaeCryptoMemAlloc(buflen, __FILE__, __LINE__);
    if (!pResultS->pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    pResultS->dataLenInBytes = (Cpa32U) buflen;

    if ((qat_BN_to_FB(&(opData->P), dsa->p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), dsa->q) != 1) ||
        (qat_BN_to_FB(&(opData->G), dsa->g) != 1) ||
        (qat_BN_to_FB(&(opData->X), dsa->priv_key) != 1) ||
        (qat_BN_to_FB(&(opData->K), k) != 1)) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    opData->Z.pData = qaeCryptoMemAlloc(dlen, __FILE__, __LINE__);
    if (!opData->Z.pData) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    opData->Z.dataLenInBytes = (Cpa32U) dlen;

    memcpy(opData->Z.pData, dgst, dlen);

    ret = DSA_SIG_new();
    if (!ret) {
        QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!cb) {                  /* Synch mode */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                DSA_SIG_free(ret);
                ret = NULL;
                goto err;
            }

            status = cpaCyDsaSignRS(instanceHandle,
                                    qat_dsaSignCallbackFn,
                                    &op_done,
                                    opData,
                                    &bDsaSignStatus, pResultR, pResultS);

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
            QATerr(QAT_F_QAT_DSA_DO_SIGN, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            DSA_SIG_free(ret);
            ret = NULL;
            goto err;
        }

        rc = waitForOpToComplete(&op_done);
        cleanupOpDone(&op_done);
        if (rc) {
            DSA_SIG_free(ret);
            ret = NULL;
            goto err;
        }

        /* Convert the flatbuffer results back to a BN */
        BN_bin2bn(pResultR->pData, pResultR->dataLenInBytes, r);
        BN_bin2bn(pResultS->pData, pResultS->dataLenInBytes, s);
        ret->r = r;
        ret->s = s;
    }
 err:
    if (!ret) {
        BN_free(r);
        BN_free(s);
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
        if (opData->P.pData)
            qaeCryptoMemFree(opData->P.pData);
        if (opData->Q.pData)
            qaeCryptoMemFree(opData->Q.pData);
        if (opData->G.pData)
            qaeCryptoMemFree(opData->G.pData);
        if (opData->X.pData)
            qaeCryptoMemFree(opData->X.pData);
        if (opData->K.pData)
            qaeCryptoMemFree(opData->K.pData);
        if (opData->Z.pData)
            qaeCryptoMemFree(opData->Z.pData);
        OPENSSL_free(opData);
    }

    if (ctx)
        BN_CTX_end(ctx);
    if (ctx)
        BN_CTX_free(ctx);

    return (ret);
}

/******************************************************************************
* function:
*         qat_dsa_do_sign_synch(const unsigned char *dgst, int dlen, DSA *dsa)
*
* description:
*   Generate DSA R and S Signatures in synch mode.
******************************************************************************/
DSA_SIG *qat_dsa_do_sign_synch(const unsigned char *dgst, int dlen, DSA *dsa)
{
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();

    if (!dsa)
        return NULL;

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(dsa->p), BN_num_bits(dsa->q))) {
        if (!default_dsa_method)
            return NULL;
        return default_dsa_method->dsa_do_sign(dgst, dlen, dsa);
    }

    return qat_dsa_do_sign(dgst, dlen, NULL, NULL, dsa, NULL, NULL);
}


/******************************************************************************
* function:
*         qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
*                            BIGNUM **rp)
*
* description:
*   Wrapper around the default OpenSSL DSA dsa_sign_setup() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
int qat_dsa_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp)
{
    const DSA_METHOD *openssl_dsa_method = DSA_OpenSSL();
    DEBUG("%s been called \n", __func__);

    return openssl_dsa_method->dsa_sign_setup(dsa, ctx_in, kinvp, rp);
}

/******************************************************************************
* function:
*         qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
*                           DSA_SIG *sig, DSA *dsa,
*                           int (*cb)(void *cb_data, int status), void *cb_data)
*
* description:
*   Verify DSA R and S Signatures.
******************************************************************************/
int qat_dsa_do_verify(const unsigned char *dgst, int dgst_len,
                      DSA_SIG *sig, DSA *dsa,
                      int (*cb) (void *cb_data, int status), void *cb_data)
{
    BN_CTX *ctx;
    BIGNUM *z = NULL;
    int ret = -1, i = 0, rc = 1;
    CpaInstanceHandle instanceHandle;
    CpaCyDsaVerifyOpData *opData = NULL;
    CpaBoolean bDsaVerifyStatus;
    CpaStatus status;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("AU - %s\n", __func__);

    if (!dsa->p || !dsa->q || !dsa->g) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    i = BN_num_bits(dsa->q);
    /* fips 186-3 allows only different sizes for q */
    if (i != 160 && i != 224 && i != 256) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        return ret;
    }

    opData = (CpaCyDsaVerifyOpData *)
        OPENSSL_malloc(sizeof(CpaCyDsaVerifyOpData));
    if (opData == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    memset(opData, 0, sizeof(CpaCyDsaVerifyOpData));

    if ((ctx = BN_CTX_new()) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(ctx);

    if ((z = BN_CTX_get(ctx)) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
        BN_ucmp(sig->r, dsa->q) >= 0) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BN_is_zero(sig->s) || BN_is_negative(sig->s) ||
        BN_ucmp(sig->s, dsa->q) >= 0) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (dgst_len > (i >> 3))
        /*
         * if the digest length is greater than the size of q use the
         * BN_num_bits(dsa->q) leftmost bits of the digest, see fips 186-3,
         * 4.2
         */
        dgst_len = (i >> 3);
    if (BN_bin2bn(dgst, dgst_len, z) == NULL) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((qat_BN_to_FB(&(opData->P), dsa->p) != 1) ||
        (qat_BN_to_FB(&(opData->Q), dsa->q) != 1) ||
        (qat_BN_to_FB(&(opData->G), dsa->g) != 1) ||
        (qat_BN_to_FB(&(opData->Y), dsa->pub_key) != 1) ||
        (qat_BN_to_FB(&(opData->Z), z) != 1) ||
        (qat_BN_to_FB(&(opData->R), sig->r) != 1) ||
        (qat_BN_to_FB(&(opData->S), sig->s) != 1)) {
        QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!cb) {                  /* Synch mode */
        initOpDone(&op_done);

        do {
            if ((instanceHandle = get_next_inst()) == NULL) {
                QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
                cleanupOpDone(&op_done);
                goto err;
            }

            status = cpaCyDsaVerify(instanceHandle,
                                    qat_dsaVerifyCallbackFn,
                                    &op_done, opData, &bDsaVerifyStatus);

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
            QATerr(QAT_F_QAT_DSA_DO_VERIFY, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            goto err;
        }

        rc = waitForOpToComplete(&op_done);
        if (op_done.verifyResult == CPA_TRUE)
            ret = 1;

        cleanupOpDone(&op_done);
        if (rc) {
            ret = 0;
            goto err;
        }
    }

 err:
    if (opData) {
        if (opData->P.pData)
            qaeCryptoMemFree(opData->P.pData);
        if (opData->Q.pData)
            qaeCryptoMemFree(opData->Q.pData);
        if (opData->G.pData)
            qaeCryptoMemFree(opData->G.pData);
        if (opData->Y.pData)
            qaeCryptoMemFree(opData->Y.pData);
        if (opData->Z.pData)
            qaeCryptoMemFree(opData->Z.pData);
        if (opData->R.pData)
            qaeCryptoMemFree(opData->R.pData);
        if (opData->S.pData)
            qaeCryptoMemFree(opData->S.pData);
        OPENSSL_free(opData);
    }

    if (ctx)
        BN_CTX_end(ctx);
    if (ctx)
        BN_CTX_free(ctx);

    return (ret);
}

/******************************************************************************
* function:
*         qat_dsa_do_verify_synch(const unsigned char *dgst, int dgst_len,
*                           DSA_SIG *sig, DSA *dsa)
*
* description:
*   Verify DSA R and S Signatures in synch mode.
******************************************************************************/
int qat_dsa_do_verify_synch(const unsigned char *dgst, int dgst_len,
                            DSA_SIG *sig, DSA *dsa)
{
    const DSA_METHOD *default_dsa_method = DSA_OpenSSL();

    if (!dsa)
        return -1;

    /*
     * If the sizes of P and Q are not in the range supported by QAT engine
     * then fall back to software
     */

    if (!dsa_range_check(BN_num_bits(dsa->p), BN_num_bits(dsa->q))) {
        if (!default_dsa_method)
            return -1;
        return default_dsa_method->dsa_do_verify(dgst, dgst_len, sig, dsa);
    }

    return qat_dsa_do_verify(dgst, dgst_len, sig, dsa, NULL, NULL);
}

