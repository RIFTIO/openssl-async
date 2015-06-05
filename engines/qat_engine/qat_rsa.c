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
 * @file qat_rsa.c
 *
 * This file contains the engine implementations for RSA operations
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#define _GNU_SOURCE
#define __USE_GNU

#include <openssl/rsa.h>
#include <openssl/async.h>
#include <openssl/err.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "e_qat.h"

#include "cpa.h"
#include "cpa_types.h"

#include "cpa_cy_rsa.h"
#include "qat_rsa.h"
#include "qat_asym_common.h"
#include "e_qat_err.h"

#include <../../crypto/async/cpu_cycles.h>

#ifdef OPENSSL_ENABLE_QAT_RSA_SYNCH
# ifdef OPENSSL_DISABLE_QAT_RSA_SYNCH
#  undef OPENSSL_DISABLE_QAT_RSA_SYNCH
# endif
#endif

#define QAT_RSA_PERFORMOP_RETRIES_SYNC 3

/* Callback to indicate QAT completion of RSA. */
void qat_rsaCallbackFn(void *pCallbackTag,
                       CpaStatus status, void *pOpData, CpaFlatBuffer * pOut);

static RSA_METHOD qat_rsa_method = {
    "QAT RSA method",           /* name */
    qat_rsa_pub_enc_synch,      /* rsa_pub_enc */
    qat_rsa_pub_dec_synch,      /* rsa_pub_dec */
    qat_rsa_priv_enc_synch,     /* rsa_priv_enc */
    qat_rsa_priv_dec_synch,     /* rsa_priv_dec */
    NULL,                       /* rsa_mod_exp */
    NULL,                       /* bn_mod_exp */
    NULL,                       /* init */
    NULL,                       /* finish */
    0,                          /* flags */
    NULL,                       /* app_data */
    NULL,                       /* rsa_sign */
    NULL,                       /* rsa_verify */
    NULL,                       /* rsa_keygen */
};

RSA_METHOD *get_RSA_methods(void)
{
#ifdef OPENSSL_DISABLE_QAT_RSA_SYNCH
    const RSA_METHOD *def_rsa_meth = RSA_get_default_method();

    qat_rsa_method.rsa_pub_enc = def_rsa_meth->rsa_pub_enc;
    qat_rsa_method.rsa_pub_dec = def_rsa_meth->rsa_pub_dec;
    qat_rsa_method.rsa_priv_enc = def_rsa_meth->rsa_priv_enc;
    qat_rsa_method.rsa_priv_dec = def_rsa_meth->rsa_priv_dec;
    qat_rsa_method.rsa_mod_exp = def_rsa_meth->rsa_mod_exp;
    qat_rsa_method.bn_mod_exp = def_rsa_meth->bn_mod_exp;
    qat_rsa_method.init = def_rsa_meth->init;
    qat_rsa_method.finish = def_rsa_meth->finish;
#endif

#ifdef OPENSSL_DISABLE_QAT_RSA_SYNCH
    return NULL;
#endif
    return &qat_rsa_method;
}

/******************************************************************************
* function:
*         qat_alloc_pad(unsigned char *in,
*                       int len,
*                       int rLen,
*                       int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param len  [IN] - length of input data (hash)
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to add PKCS#1 padding into input data buffer
*   before it pass to cpaCyRsaDecrypt() function.
*   The function returns a pointer to unsigned char buffer
******************************************************************************/
static unsigned char *qat_alloc_pad(unsigned char *in, int len,
                                    int rLen, int sign)
{
    int i = 0;

    /* out data buffer should have fix length */
    unsigned char *out = qaeCryptoMemAlloc(rLen, __FILE__, __LINE__);

    if (NULL == out) {
        WARN("[%s] --- out buffer malloc failed.\n", __func__);
        return NULL;
    }

    /* First two char are (0x00, 0x01) or (0x00, 0x02) */
    out[0] = 0x00;

    if (sign) {
        out[1] = 0x01;
    } else {
        out[1] = 0x02;
    }

    /*
     * Fill 0xff and end up with 0x00 in out buffer until the length of
     * actual data space left
     */
    for (i = 2; i < (rLen - len - 1); i++) {
        out[i] = 0xff;
    }
    /*
     * i has been incremented on beyond the last padding byte to exit for
     * loop
     */
    out[i] = 0x00;

    /* shift actual data to the end of out buffer */
    memcpy((out + rLen - len), in, len);

    return out;
}

/******************************************************************************
* function:
*         qat_data_len(unsigned char *in
*                      int  rLen, int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to calculate the length of actual data
*   and padding size inside of outputBuffer returned from cpaCyRsaEncrypt() function.
*   The function counts the padding length (i) and return the length
*   of actual data (dLen) contained in the outputBuffer
******************************************************************************/
static int qat_data_len(unsigned char *in, int rLen, int sign)
{
    /* first two bytes are 0x00, 0x01 */
    int i = 0;
    int dLen = 0;
    int pLen = 0;

    /* First two char of padding should be 0x00, 0x01 */
    if (sign) {
        /* First two char of padding should be 0x00, 0x01 */
        if (in[0] != 0x00 || in[1] != 0x01) {
            WARN("[%s] --- [%d] Padding format unknown!\n", __func__, sign);
            return 0;
        }
    } else {
        /* First two char of padding should be 0x00, 0x02 for decryption */
        if (in[0] != 0x00 || in[1] != 0x02) {
            WARN("[%s] --- [%d] Padding format unknown!\n", __func__, sign);
            return 0;
        }
    }

    /*
     * while loop is design to reach the 0x00 value and count all the 0xFF
     * value where filled by PKCS#1 padding
     */
    while (in[i + 2] != 0x00 && i < rLen)
        i++;

    /* padding length = 2 + length of 0xFF + 0x00 */
    pLen = 2 + i + 1;
    dLen = rLen - pLen;

    return dLen;
}

/******************************************************************************
* function:
*         qat_remove_pad(unsigned char *in,
*                        int len,
*                        int rLen,
*                        int sign)
*
* @param in   [IN] - pointer to Flat Buffer
* @param len  [IN] - length of output buffer
* @param rLen [IN] - length of RSA
* @param sign [IN] - 1 for sign operation and 0 for decryption
*
* description:
*   This function is used to remove PKCS#1 padding from outputBuffer
*   after cpaCyRsaEncrypt() function during RSA verify.
******************************************************************************/
static int qat_remove_pad(unsigned char *out, unsigned char *in,
                          int r_len, int *out_len, int sign)
{
    int p_len = 0;
    int d_len = 0;

    if (0 == (d_len = qat_data_len(in, r_len, sign))) {
        return 0;
    }
    p_len = r_len - d_len;

    /* shift actual data to the beginning of out buffer */
    memcpy(out, in + p_len, d_len);
    *out_len = d_len;

    return 1;
}

/******************************************************************************
* function:
*         qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status,
*                           void *pOpData, CpaFlatBuffer * pOut)
*
* @param instanceHandle [IN]  - Instance handle.
* @param pRsaEncryptCb  [IN]  - Pointer to callback function to be invoked
*                               when the operation is complete.
* @param pCallbackTag   [IN]  - Opaque User Data for this specific call. Will
*                               be returned unchanged in the callback.
* @param pEncryptOpData [IN]  - Structure containing all the data needed to
*                               perform the RSA encryption operation.
* @param pOutputData    [Out] - Pointer to structure into which the result of
*                               the RSA encryption primitive is written.
* description:
*   Callback function used by cpaCyRsaEncrypt to indicate completion.
*   Calls back to qat_crypto_callbackFn().
*
******************************************************************************/
void qat_rsaCallbackFn(void *pCallbackTag, CpaStatus status, void *pOpData,
                       CpaFlatBuffer * pOut)
{
    qat_crypto_callbackFn(pCallbackTag, status, CPA_CY_SYM_OP_CIPHER, pOpData,
                          NULL, CPA_FALSE);
}

typedef struct rsa_op_data {
    CpaCyRsaPublicKey *cpa_pub_key;
    CpaCyRsaDecryptOpData *dec_op_data;
    CpaCyRsaEncryptOpData *enc_op_data;
    CpaFlatBuffer *output_buffer;
    int rsa_len;
    int padding;
    unsigned char *cb_output;
    int (*cb_func) (unsigned char *res, size_t reslen,
                    void *cb_data, int status);
    void *cb_data;
} rsa_op_data_t;

#define NO_PADDING 0
#define PADDING    1

static void
rsa_decrypt_op_buf_free(CpaCyRsaDecryptOpData * dec_op_data,
                        CpaFlatBuffer * out_buf, int padding)
{
    if (dec_op_data) {
        if (dec_op_data->inputData.pData && (!isZeroCopy() || padding))
            qaeCryptoMemFree(dec_op_data->inputData.pData);

        if (dec_op_data->pRecipientPrivateKey) {
            if (dec_op_data->pRecipientPrivateKey->privateKeyRep2.
                prime1P.pData)
                qaeCryptoMemFree(dec_op_data->
                                 pRecipientPrivateKey->privateKeyRep2.prime1P.
                                 pData);

            if (dec_op_data->pRecipientPrivateKey->privateKeyRep2.
                prime2Q.pData)
                qaeCryptoMemFree(dec_op_data->
                                 pRecipientPrivateKey->privateKeyRep2.prime2Q.
                                 pData);

            if (dec_op_data->pRecipientPrivateKey->privateKeyRep2.
                exponent1Dp.pData)
                qaeCryptoMemFree(dec_op_data->
                                 pRecipientPrivateKey->privateKeyRep2.
                                 exponent1Dp.pData);

            if (dec_op_data->pRecipientPrivateKey->privateKeyRep2.
                exponent2Dq.pData)
                qaeCryptoMemFree(dec_op_data->
                                 pRecipientPrivateKey->privateKeyRep2.
                                 exponent2Dq.pData);

            if (dec_op_data->pRecipientPrivateKey->
                privateKeyRep2.coefficientQInv.pData)
                qaeCryptoMemFree(dec_op_data->
                                 pRecipientPrivateKey->privateKeyRep2.
                                 coefficientQInv.pData);

            OPENSSL_free(dec_op_data->pRecipientPrivateKey);
        }
        OPENSSL_free(dec_op_data);
    }

    if (out_buf) {
        if (!isZeroCopy() && out_buf->pData)
            qaeCryptoMemFree(out_buf->pData);
        OPENSSL_free(out_buf);
    }
}

int
qat_rsa_decrypt(CpaCyRsaDecryptOpData * dec_op_data,
                CpaFlatBuffer * output_buf)
{
    struct op_done op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    CpaInstanceHandle instanceHandle = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();
    int rc = 1;

    initOpDone(&op_done);

    /*
     * cpaCyRsaDecrypt() is the function called for RSA verify in API, the
     * DecOpData [IN] contains both private key value and input file (hash)
     * value, the outputBuffer [OUT] stores the signature as the output
     * message, the sts value return 0 if successful
     */
    do {
        if (NULL == (instanceHandle = get_next_inst())) {
            WARN("instanceHandle is NULL\n");
            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            return 0;
        }
        sts = cpaCyRsaDecrypt(instanceHandle, qat_rsaCallbackFn, &op_done,
                              dec_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            //usleep(ulPollInterval +
            //       (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            //qatPerformOpRetries++;

            QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_RETRY);
            // fprintf(stderr, "Retry decrypt\n");

            ASYNC_pause_job();
            if(!getEnableExternalPolling())
                poll_instances();
        }
    }
    while (sts == CPA_STATUS_RETRY);
    //while (sts == CPA_STATUS_RETRY && ((qatPerformOpRetries < iMsgRetry)
    //                                   || (iMsgRetry ==
    //                                       QAT_INFINITE_MAX_NUM_RETRIES)));

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCyRsaDecrypt failed, sts=%d.\n", __func__, sts);
        QATerr(QAT_F_QAT_RSA_DECRYPT, ERR_R_INTERNAL_ERROR);
        cleanupOpDone(&op_done);
        return 0;
    }

    //rc = waitForOpToComplete(&op_done);
    do {
        ASYNC_pause_job();

#ifdef QAT_CPU_CYCLES_COUNT
        // This is the cpu cycles count for the switch of the current fibre
        // TODO the variable fibre_switch_start is not set correctly...
        cpucycle_t fibre_switch_current = rdtsc() - fibre_switch_start;

        // Update the current max and min
        fibre_switch_max = MAX(fibre_switch_max, fibre_switch_current);
        fibre_switch_min = MIN(fibre_switch_min, fibre_switch_current);

        // // This is a very primitive way to detect outliers
        // if (fibre_switch_current > 2 * fibre_switch_min) {
        //     fprintf(stderr, "Fibre switch: outlier = %llu \n", fibre_switch_current);
        // }
        // else {
            // fprintf(stderr, "Fibre switch: current = %llu \n", fibre_switch_current);
            ++fibre_switch_num;
            fibre_switch_acc += fibre_switch_current;
        // }

        // Every QAT_FIBRE_STARTUP_SAMPLE measures I print the avg e reset
        if (fibre_switch_num == QAT_FIBRE_STARTUP_SAMPLE) {
            fprintf(stderr, "Fibre switch: avg = %.2f\tmax = %llu\tmin = %llu \n",
                    (double) 1.0 * fibre_switch_acc / fibre_switch_num,
                    fibre_switch_max, fibre_switch_min);
            fibre_switch_num = 0;
            fibre_switch_acc = 0;
            fibre_switch_min = 999999;
            fibre_switch_max = 0;
        }
#endif
        if(!getEnableExternalPolling())
            poll_instances();
    }
    while (!op_done.flag);
    cleanupOpDone(&op_done);
    //if (rc) {
    //    WARN("[%s] --- cpaCyRsaDecrypt timed out.\n", __func__);
    //    return 0;
    //}
    return 1;
}

static int
build_decrypt_op_buf(int flen, const unsigned char *from, unsigned char *to,
                     RSA *rsa, int padding,
                     CpaCyRsaDecryptOpData ** dec_op_data,
                     CpaFlatBuffer ** output_buffer, int alloc_pad)
{
    int rsa_len = 0;
    CpaCyRsaPrivateKey *cpa_prv_key = NULL;

    cpa_prv_key =
        (CpaCyRsaPrivateKey *) OPENSSL_malloc(sizeof(CpaCyRsaPrivateKey));
    if (NULL == cpa_prv_key) {
        WARN("[%s] --- Private Key malloc failed!\n", __func__);
        return 0;
    }

    DEBUG("[%s] --- flen =%d, padding = %d \n", __func__, flen, padding);
    /* output signature should have same length as RSA(128) */
    rsa_len = RSA_size(rsa);

    /* output and input data MUST allocate memory for sign process */
    /* memory allocation for DecOpdata[IN] */
    *dec_op_data = OPENSSL_malloc(sizeof(CpaCyRsaDecryptOpData));
    if (NULL == *dec_op_data) {
        WARN("[%s] --- OpData malloc failed!\n", __func__);
        OPENSSL_free(cpa_prv_key);
        return 0;
    }

    /* Setup the DecOpData structure */
    (*dec_op_data)->pRecipientPrivateKey = cpa_prv_key;

    /* Padding check */
    if (padding != RSA_PKCS1_PADDING) {
        DEBUG("[%s] --- Unknown Padding!\n", __func__);
        return 0;
    }

    cpa_prv_key->version = CPA_CY_RSA_VERSION_TWO_PRIME;

    /* Setup the private key rep type 2 structure */
    cpa_prv_key->privateKeyRepType = CPA_CY_RSA_PRIVATE_KEY_REP_TYPE_2;
    if (qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime1P, rsa->p) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.prime2Q, rsa->q) != 1 ||
        qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent1Dp, rsa->dmp1) != 1
        || qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.exponent2Dq,
                        rsa->dmq1) != 1
        || qat_BN_to_FB(&cpa_prv_key->privateKeyRep2.coefficientQInv,
                        rsa->iqmp) != 1) {
        WARN("[%s] --- qat_BN_to_FB failed for privateKeyRep2 elements\n",
             __func__);
        return 0;
    }

    if (alloc_pad) {
        (*dec_op_data)->inputData.pData =
            qat_alloc_pad((Cpa8U *) from, flen, rsa_len, 1);
    } else if (isZeroCopy()) {
        (*dec_op_data)->inputData.pData = (Cpa8U *) from;
    } else {
        (*dec_op_data)->inputData.pData =
            (Cpa8U *) copyAllocPinnedMemory((void *)from, flen, __FILE__,
                                            __LINE__);
    }

    if (NULL == (*dec_op_data)->inputData.pData) {
        WARN("[%s] --- InputData malloc failed!\n", __func__);
        return 0;
    }

    if (alloc_pad)
        (*dec_op_data)->inputData.dataLenInBytes = rsa_len;
    else
        (*dec_op_data)->inputData.dataLenInBytes = flen;

    *output_buffer = OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == *output_buffer) {
        WARN("[%s] --- OutputBuffer malloc failed!\n", __func__);
        return 0;
    }

    if (isZeroCopy()) {
        /* Assign outputBuffer to output pointer */
        (*output_buffer)->pData = (Cpa8U *) to;
    } else {
        /*
         * Memory allocation for DecOpdata[IN] the size of outputBuffer
         * should big enough to contain RSA_size
         */
        (*output_buffer)->pData =
            (Cpa8U *) qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);
    }

    if (NULL == (*output_buffer)->pData) {
        WARN("[%s] --- OutputBuffer Data malloc failed!\n", __func__);
        return 0;
    }
    (*output_buffer)->dataLenInBytes = rsa_len;

    return 1;
}

static void
rsa_encrypt_op_buf_free(CpaCyRsaEncryptOpData * enc_op_data,
                        CpaFlatBuffer * out_buf, int padding)
{
    if (enc_op_data) {
        if (enc_op_data->pPublicKey) {
            if (enc_op_data->pPublicKey->modulusN.pData)
                qaeCryptoMemFree(enc_op_data->pPublicKey->modulusN.pData);
            if (enc_op_data->pPublicKey->publicExponentE.pData)
                qaeCryptoMemFree(enc_op_data->pPublicKey->
                                 publicExponentE.pData);
            OPENSSL_free(enc_op_data->pPublicKey);
        }
        if ((!isZeroCopy() || padding) && enc_op_data->inputData.pData)
            qaeCryptoMemFree(enc_op_data->inputData.pData);
        OPENSSL_free(enc_op_data);
    }

    if (out_buf) {
        if (!isZeroCopy() && out_buf->pData)
            qaeCryptoMemFree(out_buf->pData);
        OPENSSL_free(out_buf);
    }
}

int
qat_rsa_encrypt(CpaCyRsaEncryptOpData * enc_op_data,
                CpaFlatBuffer * output_buf)
{
    struct op_done op_done;
    CpaStatus sts = CPA_STATUS_FAIL;
    int qatPerformOpRetries = 0;
    CpaInstanceHandle instanceHandle = NULL;

    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();
    int rc = 1;

    initOpDone(&op_done);

    /*
     * cpaCyRsaDecrypt() is the function called for RSA verify in API, the
     * DecOpData [IN] contains both private key value and input file (hash)
     * value, the outputBuffer [OUT] stores the signature as the output
     * message, the sts value return 0 if successful
     */
    do {
        if (NULL == (instanceHandle = get_next_inst())) {
            WARN("instanceHandle is NULL\n");
            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
            cleanupOpDone(&op_done);
            return 0;
        }

        sts = cpaCyRsaEncrypt(instanceHandle, qat_rsaCallbackFn, &op_done,
                              enc_op_data, output_buf);
        if (sts == CPA_STATUS_RETRY) {
            //usleep(ulPollInterval +
            //       (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            //qatPerformOpRetries++;

            QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_RETRY);
            // fprintf(stderr, "Retry encrypt\n");
            ASYNC_pause_job();
            if(!getEnableExternalPolling())
                poll_instances();
        }
    }
    while (sts == CPA_STATUS_RETRY );
    //while (sts == CPA_STATUS_RETRY && ((qatPerformOpRetries < iMsgRetry)
    //                                   || (iMsgRetry ==
    //                                       QAT_INFINITE_MAX_NUM_RETRIES)));

    if (sts != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCyRsaEncrypt failed, sts=%d.\n", __func__, sts);
        QATerr(QAT_F_QAT_RSA_ENCRYPT, ERR_R_INTERNAL_ERROR);
        cleanupOpDone(&op_done);
        return 0;
    }

    //rc = waitForOpToComplete(&op_done);
    do {
        ASYNC_pause_job();
        if(!getEnableExternalPolling())
            poll_instances();
    }
    while (!op_done.flag);
    cleanupOpDone(&op_done);
//    if (rc) {
//        WARN("[%s] --- cpaCyRsaEncrypt timed out.\n", __func__);
//        return 0;
//    }
    return 1;
}

static int
build_encrypt_op(int flen, const unsigned char *from, unsigned char *to,
                 RSA *rsa, int padding,
                 CpaCyRsaEncryptOpData ** enc_op_data,
                 CpaFlatBuffer ** output_buffer, int alloc_pad)
{
    CpaCyRsaPublicKey *cpa_pub_key = NULL;
    int rsa_len = 0;

    cpa_pub_key = OPENSSL_malloc(sizeof(CpaCyRsaPublicKey));
    if (NULL == cpa_pub_key) {
        WARN("[%s] --- Public Key malloc failed!\n", __func__);
        return 0;
    }

    rsa_len = RSA_size(rsa);

    /* Output and input data MUST allocate memory for RSA verify process */
    /* Memory allocation for EncOpData[IN] */
    *enc_op_data = OPENSSL_malloc(sizeof(CpaCyRsaEncryptOpData));
    if (NULL == *enc_op_data) {
        WARN("[%s] --- OpData malloc failed!\n", __func__);
        OPENSSL_free(cpa_pub_key);
        return 0;
    }

    /* Setup the Encrypt operation Data structure */
    (*enc_op_data)->pPublicKey = cpa_pub_key;

    if (padding != RSA_PKCS1_PADDING) {
        WARN("[%s] --- Unknown Padding!\n", __func__);
        return 0;
    }

    DEBUG("[%s] --- flen=%d padding=%d\n", __func__, flen, padding);

    /* Passing Public key from big number format to big endian order binary */
    if (qat_BN_to_FB(&cpa_pub_key->modulusN, rsa->n) != 1 ||
        qat_BN_to_FB(&cpa_pub_key->publicExponentE, rsa->e) != 1) {
        WARN("[%s] --- qat_BN_to_FB failed for cpa_pub_key elements\n",
             __func__);
        return 0;
    }

    if (alloc_pad) {
        (*enc_op_data)->inputData.pData =
            qat_alloc_pad((Cpa8U *) from, flen, rsa_len, 0);
    } else if (isZeroCopy()) {
        (*enc_op_data)->inputData.pData = (Cpa8U *) from;
    } else {
        (*enc_op_data)->inputData.pData =
            (Cpa8U *) copyAllocPinnedMemory((void *)from, flen, __FILE__,
                                            __LINE__);
    }

    if (NULL == (*enc_op_data)->inputData.pData) {
        WARN("[%s] --- Input buffer assignment failed!\n", __func__);
        return 0;
    }

    if (alloc_pad)
        (*enc_op_data)->inputData.dataLenInBytes = rsa_len;
    else
        (*enc_op_data)->inputData.dataLenInBytes = flen;

    /*
     * Memory allocation for outputBuffer[OUT] OutputBuffer size initialize
     * as the size of rsa size
     */
    (*output_buffer) =
        (CpaFlatBuffer *) OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == (*output_buffer)) {
        WARN("[%s] --- OutputBuffer malloc failed!\n", __func__);
        return 0;
    }

    /*
     * outputBuffer size should large enough to hold the Hash value but
     * smaller than (RSA_size(rsa)-11)
     */
    (*output_buffer)->dataLenInBytes = rsa_len;
    (*output_buffer)->pData = qaeCryptoMemAlloc(rsa_len, __FILE__, __LINE__);
    if (NULL == (*output_buffer)->pData) {
        WARN("[%s] --- OutputBuffer pData malloc failed!\n", __func__);
        return 0;;
    }

    return 1;
}

/******************************************************************************
* function:
*         qat_rsa_priv_enc (int flen,
*                                  const unsigned char *from,
*                                  unsigned char *to,
*                                  RSA *rsa,
*                                  int padding,
*                                  int (*cb)(unsigned char *res, int reslen,
*                                            void *cb_data, int status),
*                                  void *cb_data)
*
* @param flen    [IN]  - length in bytes of input file (hash value)
* @param from    [IN]  - pointer to the input file
* @param to      [OUT] - pointer to output signature
* @param rsa     [IN]  - pointer to private key structure
* @param padding [IN]  - Padding scheme
* @param cb      [IN]  - callback function
* @param cb_data [IN]  - data to sent in the callback
*
* description:
******************************************************************************/
static int
qat_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                 RSA *rsa, int padding,
                 int (*cb) (unsigned char *res, size_t reslen,
                            void *cb_data, int status), void *cb_data)
{
    int rsa_len = 0;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);

    /* Parameter Checking */
    /*
     * The input message length should less than RSA size and also have
     * minimum space of PKCS1 padding(4 bytes)
     */
    if (!rsa || !from || !to || (flen > ((rsa_len = RSA_size(rsa)) - 4))
        || flen == 0) {
        DEBUG("[%s] --- Invalid Parameter\n", __func__);
        goto exit;
    }

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, PADDING)) {
        sts = 0;
        goto exit;
    }

    if (!cb) {                  /* Sync Mode */
        if (1 != qat_rsa_decrypt(dec_op_data, output_buffer)) {
            /* set output all 0xff if failed */
            DEBUG("[%s] --- cpaCyRsaDecrypt failed! \n", __func__);
            sts = 0;
            goto exit;
        }
        if (!isZeroCopy())
            memcpy(to, output_buffer->pData, rsa_len);

        DEBUG("[%s] --- cpaCyRsaDecrypt finished! \n", __func__);

        rsa_decrypt_op_buf_free(dec_op_data, output_buffer, PADDING);
    }
    return rsa_len;

 exit:

    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, PADDING);
    if (!sts)
        memset(to, 0xff, rsa_len);

    /* Return an error */
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_priv_dec(int flen, const unsigned char *from,
*                          unsigned char *to, RSA * rsa, int padding)
*
* description:
*   Wrapper around the default OpenSSL RSA rsa_priv_dec() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
static int qat_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding,
                            int (*cb) (unsigned char *res, size_t reslen,
                                       void *cb_data, int status),
                            void *cb_data)
{
    int rsa_len = 0;
    int output_len = 0;
    int sts = 1;
    CpaCyRsaDecryptOpData *dec_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);

    /* parameter checks */
    if (!rsa || !from || !to || (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("[%s] --- Invalid Parameter\n", __func__);
        return 0;
    }

    if (1 != build_decrypt_op_buf(flen, from, to, rsa, padding,
                                  &dec_op_data, &output_buffer, NO_PADDING)) {
        sts = 0;
        goto exit;
    }

    if (!cb) {                  /* Sync Mode Only */
        if (1 != qat_rsa_decrypt(dec_op_data, output_buffer)) {
            WARN("[%s] --- RsaDecrypt failed.\n", __func__);
            sts = 0;
            goto exit;
        }
        /* Copy output to output buffer */
        if (qat_remove_pad(to, output_buffer->pData, rsa_len, &output_len, 0)
            != 1) {
            /* set output all 0xff if failed */
            WARN("[%s] --- pData remove padding detected an error!\n",
                 __func__);
            DEBUG("[%s] --- cpaCyRsaDecrypt failed! \n", __func__);
            sts = 0;
            goto exit;
        }

        rsa_decrypt_op_buf_free(dec_op_data, output_buffer, NO_PADDING);
        DEBUG("[%s] --- cpaCyRsaDecrypt finished! \n", __func__);
        return output_len;
    }

 exit:
    /* Free all the memory allocated in this function */
    rsa_decrypt_op_buf_free(dec_op_data, output_buffer, NO_PADDING);
    if (!sts && to && !cb)      /* Only in Sync Mode */
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_enc(int flen,const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,int padding)
*
* description:
*   Wrapper around the default OpenSSL RSA qat_rsa_pub_enc() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
static int qat_rsa_pub_enc(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding,
                           int (*cb) (unsigned char *res, size_t reslen,
                                      void *cb_data, int status),
                           void *cb_data)
{
    int rsa_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);

    /* parameter checks */
    if (!rsa || !from || !to || (flen > (rsa_len = RSA_size(rsa)) - 11)) {
        WARN("[%s] --- Invalid Parameter\n", __func__);
        goto exit;
    }

    if (1 != build_encrypt_op(flen, from, to, rsa, padding,
                              &enc_op_data, &output_buffer, PADDING)) {
        sts = 0;
        goto exit;
    }

    if (!cb) {                  /* Sync Mode only */
        if (1 != qat_rsa_encrypt(enc_op_data, output_buffer)) {
            /* set output all 0xff if failed */
            DEBUG("[%s] --- cpaCyRsaEncrypt failed! \n", __func__);
            sts = 0;
            goto exit;

        } else {
            DEBUG("[%s] --- cpaCyRsaEncrypt finished! \n", __func__);
            memcpy(to, output_buffer->pData, output_buffer->dataLenInBytes);
        }
        rsa_encrypt_op_buf_free(enc_op_data, output_buffer, PADDING);
        return rsa_len;
    }
 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, PADDING);

    /* set output all 0xff if failed */
    DEBUG("[%s] --- cpaCyRsaEncrypt failed! \n", __func__);
    if (!sts)
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_pub_dec(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input signature
* @param from    [IN]  - pointer to the signature file
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_dec() function for RSA verify process.
*   All the inputs are pass form the above OpenSSL layer to the corresponding API
*   RSA verify function cpaCyRsaEncrypt().
*   The function returns the RSA recovered message output.
******************************************************************************/
static int
qat_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
                RSA *rsa, int padding,
                int (*cb) (unsigned char *res, size_t reslen,
                           void *cb_data, int status), void *cb_data)
{
    int rsa_len = 0;
    int output_len = 0;
    CpaCyRsaEncryptOpData *enc_op_data = NULL;
    CpaFlatBuffer *output_buffer = NULL;
    int sts = 1;

    DEBUG("[%s] --- called.\n", __func__);
    CRYPTO_QAT_LOG("RSA - %s\n", __func__);

    /* parameter checking */
    if (!rsa || !from || !to || (flen != (rsa_len = RSA_size(rsa)))) {
        WARN("[%s] --- Invalid Parameter flen = %d, rsa_len = %d\n", __func__,
             flen, rsa_len);
        goto exit;
    }

    if (1 != build_encrypt_op(flen, from, to, rsa, padding,
                              &enc_op_data, &output_buffer, NO_PADDING)) {
        sts = 0;
        goto exit;
    }

    if (!cb) {                  /* Sync Mode */
        if (1 != qat_rsa_encrypt(enc_op_data, output_buffer)) {
            WARN("[%s] --- RsaEncrypt failed.\n", __func__);
            sts = 0;
            goto exit;
        }

        /* remove the padding from outputBuffer */
        /* only RSA_PKCS1_PADDING scheme supported by qat engine */
        if (qat_remove_pad(to, output_buffer->pData, rsa_len, &output_len, 1)
            != 1) {
            WARN("[%s] --- pData remove padding detected an error!\n",
                 __func__);
            sts = 0;
            goto exit;
        }

        rsa_encrypt_op_buf_free(enc_op_data, output_buffer, NO_PADDING);
        return output_len;

    }

 exit:
    /* Free all the memory allocated in this function */
    rsa_encrypt_op_buf_free(enc_op_data, output_buffer, NO_PADDING);

    /* set output all 0xff if failed */
    DEBUG("[%s] --- cpaCyRsaEncrypt failed! \n", __func__);
    if (!sts)
        memset(to, 0xff, rsa_len);
    return 0;
}

/******************************************************************************
* function:
*         qat_rsa_priv_enc_synch (int flen,
*                           const unsigned char *from,
*                           unsigned char *to,
*                           RSA *rsa,
*                           int padding)
*
* @param flen    [IN]  - length in bytes of input file (hash value)
* @param from    [IN]  - pointer to the input file
* @param to      [OUT] - pointer to output signature
* @param rsa     [IN]  - pointer to private key structure
* @param padding [IN]  - Padding scheme
*
* description:
*   This function is rewrite of OpenSSL RSA_priv_enc() function for RSA sign process.
*   All the inputs are pass form the above OpenSSL layer to the corresponding API
*   RSA sign function cpaCyRsaDecrypt().
*   The function returns the RSA signature output.
******************************************************************************/
int
qat_rsa_priv_enc_synch(int flen, const unsigned char *from, unsigned char *to,
                       RSA *rsa, int padding)
{
    return qat_rsa_priv_enc(flen, from, to, rsa, padding, NULL, NULL);
}

/******************************************************************************
* function:
*         qat_rsa_priv_dec_synch(int flen, const unsigned char *from,
*                          unsigned char *to, RSA * rsa, int padding)
*
* description:
*   Wrapper around the default OpenSSL RSA rsa_priv_dec() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
int qat_rsa_priv_dec_synch(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    return qat_rsa_priv_dec(flen, from, to, rsa, padding, NULL, NULL);
}

/******************************************************************************
* function:
*         qat_rsa_pub_enc_synch(int flen,const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,int padding)
*
* description:
*   Wrapper around the default OpenSSL RSA qat_rsa_pub_enc() function to avoid
*   a null function pointer.
*   See the OpenSSL documentation for parameters.
******************************************************************************/
int qat_rsa_pub_enc_synch(int flen, const unsigned char *from,
                          unsigned char *to, RSA *rsa, int padding)
{
    return qat_rsa_pub_enc(flen, from, to, rsa, padding, NULL, NULL);
}

/******************************************************************************
* function:
*         qat_rsa_pub_dec_synch(int flen,
*                         const unsigned char *from,
*                         unsigned char *to,
*                         RSA *rsa,
*                         int padding)
*
* @param flen    [IN]  - size in bytes of input signature
* @param from    [IN]  - pointer to the signature file
* @param to      [OUT] - pointer to output data
* @param rsa     [IN]  - pointer to public key structure
* @param padding [IN]  - Padding scheme
*
* description:
*   This function is rewrite of OpenSSL RSA_pub_dec() function for RSA verify process.
*   All the inputs are pass form the above OpenSSL layer to the corresponding API
*   RSA verify function cpaCyRsaEncrypt().
*   The function returns the RSA recovered message output.
******************************************************************************/
int
qat_rsa_pub_dec_synch(int flen, const unsigned char *from, unsigned char *to,
                      RSA *rsa, int padding)
{
    return qat_rsa_pub_dec(flen, from, to, rsa, padding, NULL, NULL);
}
