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
 * @file qat_prf.c
 *
 * This file provides an implementaion of the PRF operations for an
 * OpenSSL engine
 *
 *****************************************************************************/

/*To avoid including PRF Offload in QAT SYNCH Baseline*/
#ifdef OPENSSL_QAT_ASYNCH

#include <string.h>

#include "openssl/ossl_typ.h"
#include "openssl/prf.h"
#include "openssl/evp.h"
#include "openssl/tls1.h"

#include "evp_locl.h"
#include "qat_prf.h"
#include "qat_utils.h"
#include "qat_asym_common.h"
#include "e_qat.h"
#include "e_qat_err.h"

#ifdef USE_QAT_MEM
#include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
#include "qat_mem_drv_inf.h"
#endif

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_key.h"


#ifdef OPENSSL_ENABLE_QAT_PRF_SYNCH
#ifdef OPENSSL_DISABLE_QAT_PRF_SYNCH
#undef OPENSSL_DISABLE_QAT_PRF_SYNCH
#endif
#endif

/* PRF methods */
static EVP_PKEY_METHOD *qat_prf_pmeth = NULL;

/* PRF nid */ 
int qat_prf_nids[] = {
    EVP_PKEY_PRF
};
#ifndef OPENSSL_DISABLE_QAT_PRF_SYNCH
static int qat_prf_pmeth_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *olen);
#endif

/******************************************************************************
* function:
*         qat_prf_cleanup()
*
* description:
*   To clear the qat_prf_pmeth. Invoked while destroying the engine
******************************************************************************/
void qat_prf_cleanup()
{
    qat_prf_pmeth = NULL;
}
/******************************************************************************
* function:
*         qat_register_prf_pmeths()
*
* description:
*   Helper function for registration of PRF methods
******************************************************************************/
static int qat_register_prf_pmeths()
{
    const EVP_PKEY_METHOD *pmeth;

    pmeth = EVP_PKEY_meth_find(EVP_PKEY_PRF);
    if(!pmeth)
    {
        QATerr(QAT_F_QAT_REGISTER_PRF_PMETHS, EVP_R_UNSUPPORTED_ALGORITHM);
        return 0;
    }

    qat_prf_pmeth = EVP_PKEY_meth_new(EVP_PKEY_PRF, 0);
    if(!qat_prf_pmeth)
    {
        QATerr(QAT_F_QAT_REGISTER_PRF_PMETHS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    EVP_PKEY_meth_copy(qat_prf_pmeth, pmeth);

#ifndef OPENSSL_DISABLE_QAT_PRF_SYNCH
    DEBUG("Registering the method\n");
    EVP_PKEY_meth_set_derive(qat_prf_pmeth, pmeth->derive_init, qat_prf_pmeth_derive);
#endif

#ifndef OPENSSL_DISABLE_QAT_PRF_ASYNCH
    /* TODO add asynch 
     * EVP_PKEY_meth_set_derive_asynch(qat_prf_pmeth, qat_prf_pmeth_derive_asynch);
     */
#endif

    return 1;
}

/******************************************************************************
* function:
*         qat_prf_pkey_meths(ENGINE *e,
*                     const EVP_PKEY_METHOD **pmeth,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param pmeth  [IN] - PRF methods structure pointer
* @param nids   [IN] - PRF functions nids
* @param nid    [IN] - PRF operation id
*
* description:
*   Qat engine digest operations registrar
******************************************************************************/
int qat_prf_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
        const int **nids, int nid)
{
    if(!pmeth)
    {
        *nids=qat_prf_nids;
        return 1;
    }

    if(!qat_prf_pmeth)
        qat_register_prf_pmeths();

    if(pmeth)
        *pmeth=qat_prf_pmeth;

    return 1;
}

#ifndef OPENSSL_DISABLE_QAT_PRF_SYNCH /* In future include OR OPENSSL_DISABLE_QAT_PRF_ASYNCH*/
/******************************************************************************
* function:
*         void qat_prf_cb(
*                   void *pCallbackTag, 
*                   CpaStatus status,
*                   void *pOpdata, 
*                   CpaFlatBuffer *pOut)
*
* @param pCallbackTag   [IN]  - Pointer to user data
* @param status         [IN]  - Status of the operation
* @param pOpData        [IN]  - Pointer to operation data of the request
* @param out            [IN]  - Pointer to the output buffer
*
* description:
*   Callback to indicate the completion of PRF (sync case)
******************************************************************************/
void qat_prf_cb(void *pCallbackTag, CpaStatus status, 
        void *pOpData, CpaFlatBuffer *pOut)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
            NULL, CPA_FALSE);
}

/******************************************************************************
* function:
*         qat_get_hash_algorithm(
*                   PRF *qat_prf_ctx
*                   CpaCySymHashAlgorithm *hash_algorithm)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param hash_algorithm [OUT] - Ptr to hash algorithm in CPA format 
*
* description:
*   Retrieve the hash algorithm from the prf context and convert it to
*   the CPA format
******************************************************************************/
static int qat_get_hash_algorithm(PRF *qat_prf_ctx, CpaCySymHashAlgorithm *hash_algorithm)
{
    if (!qat_prf_ctx || !hash_algorithm) {
        WARN("[%s] Error: NULL input variables\n", __func__);
        return 0;
    }

    int ssl_version = qat_prf_ctx->version;
    if (ssl_version < TLS1_2_VERSION)
    {
        return 1;
    }

    const EVP_MD *md;
    md = *(qat_prf_ctx->md);
    if (!md)
    {
        WARN("[%s] --- md is NULL.\n", __func__);
        return 0;
    }

    switch (EVP_MD_type(md))
    {
        case NID_sha1:
            *hash_algorithm = CPA_CY_SYM_HASH_SHA1;
            break;
        case NID_sha224:
            *hash_algorithm = CPA_CY_SYM_HASH_SHA224;
            break;
        case NID_sha256:
            *hash_algorithm = CPA_CY_SYM_HASH_SHA256;
            break;
        case NID_sha384:
            *hash_algorithm = CPA_CY_SYM_HASH_SHA384;
            break;
        case NID_sha512:
            *hash_algorithm = CPA_CY_SYM_HASH_SHA512;
            break;
        case NID_md5:
            *hash_algorithm = CPA_CY_SYM_HASH_MD5;
            break;
        default:
            WARN("[%s] --- Unsupported PRF hash type\n", __func__);
            return 0;   
    }
    
    return 1;
}

#ifdef QAT_DEBUG
void print_prf_op_data(const char *func, CpaCyKeyGenTlsOpData *prf_op_data) {
    if (!prf_op_data || !func) {
        DEBUG("[%s] Error: null pointer\n", func);
        return;
    }
    
    DEBUG("[%s] ----- PRF Op Data -----\n", func);
    
    if (prf_op_data->tlsOp == CPA_CY_KEY_TLS_OP_MASTER_SECRET_DERIVE)
        DEBUG("tlsOp: MASTER_SECRET_DERIVE\n");
    else if (prf_op_data->tlsOp == CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE)
        DEBUG("tlsOp: KEY_MATERIAL_DERIVE\n");
    else if (prf_op_data->tlsOp == CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE)
        DEBUG("tlsOp: CLIEN_FINISHED_DERIVE\n");
    else if (prf_op_data->tlsOp == CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE)
        DEBUG("tlsOp: SERVER_FINISHED_DERIVE\n");
    else if (prf_op_data->tlsOp == CPA_CY_KEY_TLS_OP_USER_DEFINED)
        DEBUG("tlsOp: USER_DEFINED:\n");

    DUMPL("Secret", prf_op_data->secret.pData, prf_op_data->secret.dataLenInBytes);
    DUMPL("Seed", prf_op_data->seed.pData, prf_op_data->seed.dataLenInBytes);
    DUMPL("User Label", prf_op_data->userLabel.pData, prf_op_data->userLabel.dataLenInBytes);
    DEBUG("---");

}
#define DEBUG_PRF_OP_DATA(prf) print_prf_op_data(__func__,prf)
#else
#define DEBUG_PRF_OP_DATA(...)
#endif

/******************************************************************************
* function:
*         build_tls_prf_op_data(
*                   PRF *qat_prf_ctx,
*                   CpaCyKeyGenTlsOpData *prf_op_data)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param prf_op_data    [OUT] - Ptr to TlsOpData used as destination 
*
* description:
*   Build the TlsOpData based on the values stored in the PRF context
*   Note: prf_op_data must be allocated outside this function
******************************************************************************/
static int build_tls_prf_op_data(PRF *qat_prf_ctx, CpaCyKeyGenTlsOpData *prf_op_data)
{
    /* TODO: The check on the inputs could be removed becuase this function is 
     * called only from this file and the input variables are never NULL... */
    if (!qat_prf_ctx || !prf_op_data) {
        WARN("[%s] Error: NULL input variables\n", __func__);
        return 0;
    }

    /* Allocate and copy the secret data */
    prf_op_data->secret.pData = (Cpa8U*) copyAllocPinnedMemory((void*) qat_prf_ctx->sec, qat_prf_ctx->sec_len, __FILE__, __LINE__);
    if (NULL == prf_op_data->secret.pData)
    {
        WARN("[%s] --- Secret data malloc failed!\n", __func__);
        return 0;
    }
    prf_op_data->secret.dataLenInBytes = qat_prf_ctx->sec_len;


    /* The label is stored in seed1 as a string
     * Conversion from string to CPA constant  */
    const void *label = qat_prf_ctx->seed1;
    DEBUG("Value of label = %s\n", label);

    prf_op_data->userLabel.pData = NULL;
    prf_op_data->userLabel.dataLenInBytes = 0;

    if (0 == strncmp(label, TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE))
    {
        prf_op_data->tlsOp = CPA_CY_KEY_SSL_OP_MASTER_SECRET_DERIVE;
    }
    else if (0 == strncmp(label, TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE))
    {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_KEY_MATERIAL_DERIVE;
    }
    else if (0 == strncmp(label, TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE))
    {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_CLIENT_FINISHED_DERIVE;
    }
    else if (0 == strncmp(label, TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE))
    {
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_SERVER_FINISHED_DERIVE;
    }
    else
    {
        /* Allocate and copy the user label contained in seed1 */
        /* TODO we must test this case to see if it works OK */
        DEBUG("Using USER_DEFINED label");
        prf_op_data->tlsOp = CPA_CY_KEY_TLS_OP_USER_DEFINED;
        prf_op_data->userLabel.pData = (Cpa8U*) copyAllocPinnedMemory((void*) qat_prf_ctx->seed1, qat_prf_ctx->seed1_len, __FILE__, __LINE__);
        if (NULL == prf_op_data->userLabel.pData)
        {
            WARN("[%s] --- User label malloc failed!\n", __func__);
            return 0;
        }
        prf_op_data->userLabel.dataLenInBytes = qat_prf_ctx->seed1_len;
    }

    /* The seed for prf_op_data is obtained by concatenating seed2...5 in the context */
    int total_seed_len = qat_prf_ctx->seed2_len + qat_prf_ctx->seed3_len + qat_prf_ctx->seed4_len + qat_prf_ctx->seed5_len;
    prf_op_data->seed.pData = qaeCryptoMemAlloc(total_seed_len, __FILE__, __LINE__);
    if (NULL == prf_op_data->seed.pData)
    {
        WARN("[%s] --- Seed data malloc failed!\n", __func__);
        return 0;
    }

    prf_op_data->seed.dataLenInBytes = total_seed_len;

    int accum_len = 0;
    /* TODO the client and server randoms are reversed on the QAT API for Key Derive.
     * This shouldn't be a problem because OpenSSL calls the function with the variables in the correct order 
     */
    if (qat_prf_ctx->seed2_len)
    {
        memcpy(prf_op_data->seed.pData, qat_prf_ctx->seed2, qat_prf_ctx->seed2_len);
        accum_len += qat_prf_ctx->seed2_len;
    }
    if (qat_prf_ctx->seed3_len)
    {
        memcpy((prf_op_data->seed.pData) + accum_len, qat_prf_ctx->seed3, qat_prf_ctx->seed3_len);
        accum_len += qat_prf_ctx->seed3_len;
    }
    if (qat_prf_ctx->seed4_len)
    {
        memcpy((prf_op_data->seed.pData) + accum_len, qat_prf_ctx->seed4, qat_prf_ctx->seed4_len);
        accum_len += qat_prf_ctx->seed4_len;
    }
    if (qat_prf_ctx->seed5_len)
    {
        memcpy((prf_op_data->seed.pData) + accum_len, qat_prf_ctx->seed5, qat_prf_ctx->seed5_len);
    }

    return 1;
}


/******************************************************************************
* function:
*         qat_prf_tls_derive(
*                   PRF *qat_prf_ctx,
*                   unsigned char *key,
*                   size_t *olen)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param key            [OUT] - Ptr to the key that will be generated
* @param olen           [IN]  - Length of the key
*
* description:
*   PRF derive function for sync TLS case 
******************************************************************************/
static int qat_prf_tls_derive(PRF *qat_prf_ctx, unsigned char *key, size_t *olen)
{
    int ret = 0;
    CpaCyKeyGenTlsOpData *prf_op_data = NULL;
    CpaFlatBuffer* generated_key = NULL;

    if (NULL == qat_prf_ctx || NULL == key || NULL == olen)
    {
        WARN("[%s] --- Input parameters cannot be NULL\n", __func__);
        goto err;
    }

    /* ---- Hash algorithm ---- */  
    CpaCySymHashAlgorithm hash_algo;
    int ssl_version = qat_prf_ctx->version;

    /* Only required for TLS1.2 as previous versions always use MD5 and SHA-1 */
    if (TLS1_2_VERSION == ssl_version)
    {
        if (!qat_get_hash_algorithm(qat_prf_ctx, &hash_algo))
        {
            WARN("[%s] --- Cannot obtain hash algorithm\n", __func__);
            goto err;
        }
    }

    /* ---- Tls Op Data ---- */
    prf_op_data = OPENSSL_malloc(sizeof(CpaCyKeyGenTlsOpData));
    if (NULL == prf_op_data)
    {
        WARN("[%s] --- PRF OP data structure malloc failed\n", __func__);
        goto err;
    }
    memset(prf_op_data, 0, sizeof(CpaCyKeyGenTlsOpData));

    if (!build_tls_prf_op_data(qat_prf_ctx, prf_op_data))
    {
        WARN("[%s] --- Failed to build prf_op_data\n", __func__);
        goto err;
    }

    /* ---- Generated Key ---- */
    int key_length = *olen;
    prf_op_data->generatedKeyLenInBytes = key_length;
    
    generated_key = (CpaFlatBuffer*)qaeCryptoMemAlloc(sizeof(CpaFlatBuffer), __FILE__, __LINE__);
    if (NULL == generated_key)
    {
        WARN("[%s] --- Generated Key malloc failed!\n", __func__);
        goto err;
    }

    generated_key->pData = (Cpa8U*)qaeCryptoMemAlloc(key_length, __FILE__, __LINE__);
    if (NULL == generated_key->pData)
    {
        WARN("[%s] --- Generated Key Data malloc failed!\n", __func__);
        goto err;
    }
    generated_key->dataLenInBytes = key_length;

    /* ---- Perform the operation ---- */
    CpaInstanceHandle instance_handle = NULL;
    if(NULL == (instance_handle = get_next_inst()))
    {
        WARN("instance Handle is NULL\n");
        goto err;
    }

    CpaStatus status = CPA_STATUS_FAIL;
    struct op_done op_done;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    unsigned long int ulPollInterval = getQatPollInterval();

    DEBUG_PRF_OP_DATA(prf_op_data);

    initOpDone(&op_done);

    do
    {
        /* Call the function of CPA according the to the version of TLS */
        if (TLS1_2_VERSION == ssl_version)
        {
            DEBUG("Calling cpaCyKeyGenTls2\n");
            status = cpaCyKeyGenTls2(instance_handle, qat_prf_cb, &op_done,
                    prf_op_data, hash_algo, generated_key);
        }
        else
        {
            DEBUG("Calling cpaCyKeyGenTls\n");
            status = cpaCyKeyGenTls(instance_handle, qat_prf_cb, &op_done,
                    prf_op_data, generated_key);
        }

        if (CPA_STATUS_RETRY == status)
        {
            usleep(ulPollInterval + 
                    (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            qatPerformOpRetries++;
        }
    } 
    while (status == CPA_STATUS_RETRY &&
            ((qatPerformOpRetries < iMsgRetry) || 
             (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

    if (CPA_STATUS_SUCCESS != status)
    {
        QATerr(QAT_F_QAT_PRF_TLS_DERIVE, ERR_R_INTERNAL_ERROR);
        cleanupOpDone(&op_done);
        goto err;
    }
   
    int rc = waitForOpToComplete(&op_done);
    cleanupOpDone(&op_done);

    if (rc)
    {
        goto err;
    }

    DUMPL("Generated key", generated_key->pData, key_length);
    memcpy(key, generated_key->pData, key_length);
    ret = 1;

err:
    /* ----- Free memory ----- */
    if (NULL != prf_op_data)
    {
        if (NULL != prf_op_data->secret.pData)
            qaeCryptoMemFree(prf_op_data->secret.pData);
        if (NULL != prf_op_data->seed.pData)
            qaeCryptoMemFree(prf_op_data->seed.pData);
        if (NULL != prf_op_data->userLabel.pData)
            qaeCryptoMemFree(prf_op_data->userLabel.pData);
        OPENSSL_free(prf_op_data);
    }
    if (NULL != generated_key)
    {
        if (NULL != generated_key->pData)
            qaeCryptoMemFree(generated_key->pData);
        qaeCryptoMemFree(generated_key);
    }
    return ret;
}

/******************************************************************************
* function:
*         qat_prf_pmeth_derive(
*                   PRF *qat_prf_ctx,
*                   unsigned char *key,
*                   size_t *olen)
*
* @param qat_prf_ctx    [IN]  - PRF context
* @param key            [OUT] - Ptr to the key that will be generated
* @param olen           [IN]  - Length of the key
*
* description:
*   PRF derive function for sync case 
******************************************************************************/
static int qat_prf_pmeth_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *olen)
{
    if (!ctx || !key || !olen)
    {
        WARN("[%s] --- Invalid input parameters.\n", __func__);
        return 0;
    }

    PRF *qat_prf_ctx = ctx->data;
    if(!qat_prf_ctx)
    {
        WARN("[%s] --- qat_prf_ctx is NULL.\n", __func__);
        return 0;
    }

    if (qat_prf_ctx->version >= TLS1_VERSION)
    {
        return qat_prf_tls_derive(qat_prf_ctx, key, olen);
    }
    else
    {
        /* TODO: add SSL case */
        WARN("[%s] --- SSL case is not supported\n", __func__);
        return 0;
    }
}
#endif


#endif
