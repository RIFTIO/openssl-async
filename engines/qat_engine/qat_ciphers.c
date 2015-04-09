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
 * @file qat_ciphers.c
 *
 * This file contains the engine implementations for cipher operations
 *
 *****************************************************************************/

#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif

#include "qat_utils.h"
#include "e_qat.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_ciphers.h"
#include "qat_chain.h"
#include "qat_sym_common.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <openssl/async.h>
#include <string.h>

#ifdef OPENSSL_ENABLE_QAT_CIPHERS_SYNCH
# ifdef OPENSSL_DISABLE_QAT_CIPHERS_SYNCH
#  undef OPENSSL_DISABLE_QAT_CIPHERS_SYNCH
# endif
#endif

static int qat_cipher_init_synch(EVP_CIPHER_CTX *ctx,
                                 const unsigned char *key,
                                 const unsigned char *iv, int enc);
static int qat_do_cipher_synch(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl);
static int common_cipher_cleanup(EVP_CIPHER_CTX *ctx);

/* Qat cipher RC4 function structure declaration */
EVP_CIPHER qat_rc4 = {
    NID_rc4,                    /* nid */
    RC4_BLOCK_SIZE,             /* block_size */
    RC4_KEY_SIZE,               /* key_size in Bytes - defined in header */
    RC4_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cipher_flags,    /* flags defined in header */
    qat_cipher_init_synch,
    qat_do_cipher_synch,
    common_cipher_cleanup,
    sizeof(qat_ctx),            /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Qat cipher DES function structure declaration */
EVP_CIPHER qat_des_cbc = {
    NID_des_cbc,                /* nid */
    DES_BLOCK_SIZE,             /* block_size */
    DES_KEY_SIZE,               /* key_size in Bytes - defined in header */
    DES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags,       /* flags defined in header */
    qat_cipher_init_synch,
    qat_do_cipher_synch,
    common_cipher_cleanup,
    sizeof(qat_ctx),            /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Qat cipher 3DES function structure declaration */
EVP_CIPHER qat_des_ede3_cbc = {
    NID_des_ede3_cbc,           /* nid */
    DES3_BLOCK_SIZE,            /* block_size */
    DES3_KEY_SIZE,              /* key_size in Bytes - defined in header */
    DES3_IV_LEN,                /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags,       /* flags defined in header */
    qat_cipher_init_synch,
    qat_do_cipher_synch,
    common_cipher_cleanup,
    sizeof(qat_ctx),            /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Qat cipher AES128 function structure declaration */
EVP_CIPHER qat_aes_128_cbc = {
    NID_aes_128_cbc,            /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_128,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags,       /* flags defined in header */
    qat_cipher_init_synch,
    qat_do_cipher_synch,
    common_cipher_cleanup,
    sizeof(qat_ctx),            /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Qat cipher AES256 function structure declaration */
EVP_CIPHER qat_aes_256_cbc = {
    NID_aes_256_cbc,            /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_256,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags,       /* flags defined in header */
    qat_cipher_init_synch,
    qat_do_cipher_synch,
    common_cipher_cleanup,
    sizeof(qat_ctx),            /* ctx_size */
    NULL,                       /* set_asn1_parameters */
    NULL,                       /* get_asn1_parameters */
    NULL,                       /* ctrl */
    NULL                        /* app_data */
};

/* Qat Symmetric cipher function register */
int qat_cipher_nids[] = {
    NID_aes_128_cbc,
    NID_aes_256_cbc,
    NID_rc4,
    NID_des_cbc,
    NID_des_ede3_cbc,
    NID_aes_128_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha1
};

/******************************************************************************
* function:
*         qat_ciphers(ENGINE *e,
*                     const EVP_CIPHER **cipher,
*                     const int **nids,
*                     int nid,
*                     int isAsynch)
*
* @param e      [IN] - OpenSSL engine pointer
* @param cipher [IN] - cipher structure pointer
* @param nids   [IN] - cipher function nids
* @param nid    [IN] - cipher operation id
* @param isAsynch [IN] - Whether the operation is synchronous (0)
*                        or asynchronous (1)
*
* description:
*   Qat engine cipher operations registrar
******************************************************************************/
static int
qat_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
            int nid, int isAsynch)
{
    int ok = 1;

    /* No specific cipher => return a list of supported nids ... */
    if (!cipher) {
        *nids = qat_cipher_nids;
        /* num ciphers supported (size of array/size of 1 element) */
        return (sizeof(qat_cipher_nids) / sizeof(qat_cipher_nids[0]));
    }

    if (!isAsynch) {
#ifndef OPENSSL_DISABLE_QAT_CIPHERS_SYNCH
        switch (nid) {
        case NID_aes_128_cbc:
            *cipher = &qat_aes_128_cbc;
            break;
        case NID_aes_256_cbc:
            *cipher = &qat_aes_256_cbc;
            break;
        case NID_rc4:
            *cipher = &qat_rc4;
            break;
        case NID_des_cbc:
            *cipher = &qat_des_cbc;
            break;
        case NID_des_ede3_cbc:
            *cipher = &qat_des_ede3_cbc;
            break;
        case NID_aes_128_cbc_hmac_sha1:
            *cipher = &qat_aes_128_cbc_hmac_sha1;
            break;
        case NID_aes_256_cbc_hmac_sha1:
            *cipher = &qat_aes_256_cbc_hmac_sha1;
            break;
        default:
            ok = 0;
            *cipher = NULL;
        }
#else
        switch (nid) {
        case NID_aes_128_cbc:
            *cipher = EVP_aes_128_cbc();
            break;
        case NID_aes_256_cbc:
            *cipher = EVP_aes_256_cbc();
            break;
        case NID_rc4:
            *cipher = EVP_rc4();
            break;
        case NID_des_cbc:
            *cipher = EVP_des_cbc();
            break;
        case NID_des_ede3_cbc:
            *cipher = EVP_des_ede3_cbc();
            break;
        case NID_aes_128_cbc_hmac_sha1:
            *cipher = EVP_aes_128_cbc_hmac_sha1();
            break;
        case NID_aes_256_cbc_hmac_sha1:
            *cipher = EVP_aes_256_cbc_hmac_sha1();
            break;
        default:
            ok = 0;
            *cipher = NULL;
        }
#endif
    } else {
        ok = 0;
        *cipher = NULL;
    }
    return ok;
}

int
qat_ciphers_synch(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                  int nid)
{
    return qat_ciphers(e, cipher, nids, nid, 0);
}


/******************************************************************************
* function:
*         cipher_init( EVP_CIPHER_CTX *ctx,
*                          const unsigned char *key,
*                          const unsigned char *iv,
*                          int enc,
                           int (*cb)(unsigned char *out, int outl,
                                     void *cb_data, int status))
*
* @param ctx [IN] - cipher ctx
* @param key [IN] - pointer to the key value. Must be set.
* @param iv  [IN] - pointer to initial vector (can be NULL)
* @param enc [IN] - encryption indicator
* @param cb  [IN] - callback function pointer
*
* description:
*   All the inputs are passed form the OpenSSL layer to the
*   corresponding API cpaCySymInitSession() function.
*   It is the first function called in cipher routine sequences,
*   in order to initialize the cipher ctx structure and CpaCySymSession.
*   The function will return 1 if successful.
******************************************************************************/
static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc,
                       int (*cb) (unsigned char *out, int outl,
                                  void *cb_data, int status))
{

    CpaCySymSessionSetupData *sessionSetupData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    qat_ctx *qat_context = NULL;
    CpaStatus sts = 0;
    CpaInstanceHandle instanceHandle;
    void *srcPrivateMetaData = NULL;
    void *dstPrivateMetaData = NULL;
    Cpa32U metaSize = 0;
    int cipherType;
    CpaCySymCbFunc qat_eng_cb = NULL;

    DEBUG("[%s] ---- CIPHER init %p, enc %d...\n\n", __func__, ctx, enc);

    if ((!key) || (!ctx)) {
        WARN("[%s] --- key or ctx is NULL.\n", __func__);
        return 0;
    }

    if (NULL == ctx->cipher_data) {
        WARN("[%s] --- ctx->cipher_data is NULL.\n", __func__);
        return 0;
    }

    if (NULL != iv) {
        memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    } else {
        memset(ctx->iv, 0, EVP_CIPHER_CTX_iv_length(ctx));
    }

    if (NULL ==
        (sessionSetupData =
         OPENSSL_malloc(sizeof(CpaCySymSessionSetupData)))) {
        WARN("[%s] --- unable to allocate memory for session info.\n",
             __func__);
        return 0;
    }

    /* Priority of this session */
    sessionSetupData->sessionPriority = CPA_CY_PRIORITY_HIGH;
    sessionSetupData->symOperation = CPA_CY_SYM_OP_CIPHER;
    /* Cipher algorithm and mode */
    cipherType = EVP_CIPHER_CTX_nid(ctx);
    switch (cipherType) {
    case NID_aes_128_cbc:
    case NID_aes_256_cbc:
        sessionSetupData->cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_AES_CBC;
        break;
    case NID_rc4:
        sessionSetupData->cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_ARC4;
        break;
    case NID_des_cbc:
        sessionSetupData->cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_DES_CBC;
        break;
    case NID_des_ede3_cbc:
        sessionSetupData->cipherSetupData.cipherAlgorithm =
            CPA_CY_SYM_CIPHER_3DES_CBC;
        break;
    default:
        WARN("[%s] --- Unsupported Cipher Type.\n", __func__);
        OPENSSL_free(sessionSetupData);
        return 0;
    }

    sessionSetupData->cipherSetupData.cipherKeyLenInBytes =
        (Cpa32U) EVP_CIPHER_CTX_key_length(ctx);

    /* Cipher key */
    sessionSetupData->cipherSetupData.pCipherKey = (Cpa8U *) key;
    sessionSetupData->verifyDigest = CPA_FALSE;

    /* Operation to perform */
    if (enc)
        sessionSetupData->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
    else
        sessionSetupData->cipherSetupData.cipherDirection =
            CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;

    instanceHandle = get_next_inst();
    if ((sts = cpaCySymSessionCtxGetSize
         (instanceHandle, sessionSetupData,
          &sessionCtxSize)) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCySymSessionCtxGetSize failed, sts = %d.\n",
             __func__, sts);
        OPENSSL_free(sessionSetupData);
        return 0;
    }

    pSessionCtx =
        (CpaCySymSessionCtx) qaeCryptoMemAlloc(sessionCtxSize, __FILE__,
                                               __LINE__);
    DEBUG("session %p size %d alloc\n", pSessionCtx, sessionCtxSize);

    if (NULL == pSessionCtx) {
        WARN("[%s] --- pSessionCtx malloc failed !\n", __func__);
        OPENSSL_free(sessionSetupData);
        return 0;
    }
    if (!cb) {
        /* Assign thestandard sync callback function */
        qat_eng_cb = qat_crypto_callbackFn;
    }

    if ((sts = cpaCySymInitSession
         (instanceHandle, qat_eng_cb, sessionSetupData,
          pSessionCtx)) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCySymInitSession failed, sts = %d \n", __func__,
             sts);
        OPENSSL_free(sessionSetupData);
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if ((sts = cpaCyBufferListGetMetaSize(instanceHandle,
                                          1,
                                          &metaSize)) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed sts=%d.\n",
             __func__, sts);
        OPENSSL_free(sessionSetupData);
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if (metaSize) {
        srcPrivateMetaData = qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!srcPrivateMetaData) {
            WARN("[%s] --- srcBufferList.pPrivateMetaData is NULL.\n",
                 __func__);
            qaeCryptoMemFree(pSessionCtx);
            return 0;
        }
        dstPrivateMetaData = qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!dstPrivateMetaData) {
            WARN("[%s] --- dstBufferList.pPrivateMetaData is NULL.\n",
                 __func__);
            OPENSSL_free(sessionSetupData);
            qaeCryptoMemFree(pSessionCtx);
            qaeCryptoMemFree(srcPrivateMetaData);
            return 0;
        }
    } else {
        srcPrivateMetaData = NULL;
        dstPrivateMetaData = NULL;
    }

    /* pinned memory is not required for qat_context */
    qat_context = ctx->cipher_data;
    qat_context->meta_size = metaSize;

    if (NULL == qat_context) {
        WARN("[%s] --- qat_context not allocated.\n", __func__);
        OPENSSL_free(sessionSetupData);
        qaeCryptoMemFree(pSessionCtx);
        if (srcPrivateMetaData)
            qaeCryptoMemFree(srcPrivateMetaData);
        if (dstPrivateMetaData)
            qaeCryptoMemFree(dstPrivateMetaData);
        return 0;
    }

    qat_context->paramNID = cipherType;

    qat_context->ctx = pSessionCtx;
    qat_context->session_data = sessionSetupData;
    qat_context->cipher_cb = cb;
    qat_context->srcPrivateMetaData = srcPrivateMetaData;
    qat_context->dstPrivateMetaData = dstPrivateMetaData;

    qat_context->enc = enc;
    qat_context->instanceHandle = instanceHandle;
    qat_context->init = 1;

    return 1;
}

/******************************************************************************
* function:
*         qat_cipher_init_synch( EVP_CIPHER_CTX *ctx,
*                                const unsigned char *key,
*                                const unsigned char *iv,
*                                int enc)
*
* @param ctx [IN] - cipher ctx
* @param key [IN] - pointer to the key value.
* @param iv  [IN] - pointer to initial vector.
* @param enc [IN] - encryption indicator
*
* description:
*   Wrapper to the cipher_init function for synchronous calls
*   The function will return 1 if successful.
******************************************************************************/
static int
qat_cipher_init_synch(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                      const unsigned char *iv, int enc)
{
    DEBUG("[%s] --- called.\n", __func__);

    return cipher_init(ctx, key, iv, enc, NULL);
}

/******************************************************************************
* function:
*         qat_do_cipher_synch(EVP_CIPHER_CTX *ctx,
*                                   unsigned char *out,
*                                   const unsigned char *in,
*                                   size_t inl)
*
* @param ctx [IN]  - pointer to cipher ctx
* @param out [OUT] - pointer to the output file
* @param in  [IN]  - pointer to input data
* @param inl [IN]  - Message length to cipher in bytes
*
* description:
*    This function is rewrite of aes_xxx_cbc_do_cipher() in OpenSSL.
*    All the inputs are passed form the above OpenSSL layer to the
*    corresponding API cpaCySymPerformOp() function.
*    The function encrypt inl bytes from the buffer pointer in and writes
*    the encrypted version to the output pointer.
*    It is the second function called in cipher routine sequences
*    and return 1 if successful
******************************************************************************/
static int qat_do_cipher_synch(EVP_CIPHER_CTX *ctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{

    CpaCySymSessionCtx pSessionCtx = NULL;
    CpaCySymOpData OpData = { 0, };
    CpaBufferList srcBufferList = { 0, };
    CpaFlatBuffer srcFlatBuffer = { 0, };
    CpaBufferList dstBufferList = { 0, };
    CpaFlatBuffer dstFlatBuffer = { 0, };
    qat_ctx *qat_context = NULL;
    CpaStatus sts = 0;
    struct op_done opDone;
    int cipherType = 0;
    int inMemAlloc = 0;
    int rc = 1;

    DEBUG("\n[%s] --- do_cipher %p BEGIN, inl %d\n", __func__, ctx, (int)inl);
    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if ((!in) || (!out) || (!ctx)) {
        WARN("[%s] --- in, out or ctx is NULL.\n", __func__);
        return 0;
    }

    DUMPL("Input", in, inl);

    // Identify the Cipher algorithm being requested
    cipherType = EVP_CIPHER_CTX_nid(ctx);

    if (!(ctx->cipher_data)) {
        WARN("[%s] --- ctx->cipher_data has not been initialised.\n",
             __func__);
        return 0;
    }
    qat_context = (qat_ctx *) (ctx->cipher_data);

    if (!(qat_context->init)) {
        WARN("[%s] --- context has not been initialised with a key.\n",
             __func__);
        return 0;
    }

    pSessionCtx = qat_context->ctx;

    OpData.sessionCtx = pSessionCtx;
    if (NID_rc4 != cipherType)
        OpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    else
        OpData.packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;

    /* Initialization Vector or Counter. */
    DEBUG("%s iv len is %d\n", __func__, EVP_CIPHER_CTX_iv_length(ctx));
    DUMPL("ctx->iv", ctx->iv, EVP_CIPHER_CTX_iv_length(ctx));

    if (isZeroCopy()) {
        if (NID_rc4 != cipherType)
            OpData.pIv =
                copyAllocPinnedMemory(ctx->iv, EVP_CIPHER_CTX_iv_length(ctx),
                                      __FILE__, __LINE__);
        else
            OpData.pIv = NULL;

        /*
         * There are cases where ctx is created on stack instead of in memory
         * driver like it is in ssl3_send_newsession_ticket and passed on the
         * same down to this function. The QAT Engine must receive a buffer
         * that has been allocated by the memory driver. There is no
         * mechanism to tell whether the in buffer is pointing to a ctx->buf
         * that was allocated on the stack or in the memory driver. To be
         * sure of having a memory driver allocated buffer in all cases we
         * must always allocate a new buffer even though there are times when
         * this is not necessary.
         */
        if (in == ctx->buf) {
            srcFlatBuffer.pData =
                (Cpa8U *) copyAllocPinnedMemory((void *)in, inl, __FILE__,
                                                __LINE__);
            inMemAlloc = 1;
        } else {
            srcFlatBuffer.pData = (Cpa8U *) in;
        }
        // TODO: Need to put a check in here to ensure that it's in place for
        // RC4
        dstFlatBuffer.pData = (Cpa8U *) out;
    } else {
        srcFlatBuffer.pData =
            (Cpa8U *) copyAllocPinnedMemory((void *)in, inl, __FILE__,
                                            __LINE__);
        // TODO for non-chained this could be an inplace operation.
        // Investigate
        if (NID_rc4 == cipherType) {
            OpData.pIv = NULL;
            dstFlatBuffer.pData = srcFlatBuffer.pData;
        } else {
            OpData.pIv =
                (Cpa8U *) copyAllocPinnedMemory(ctx->iv,
                                                EVP_CIPHER_CTX_iv_length(ctx),
                                                __FILE__, __LINE__);
            dstFlatBuffer.pData =
                (Cpa8U *) qaeCryptoMemAlloc(inl, __FILE__, __LINE__);
        }
    }

    /*
     * Starting point for cipher processing - given as number of bytes from
     * start of data in the source buffer. The result of the cipher operation
     * will be written back into the output buffer starting at this location.
     */
    OpData.cryptoStartSrcOffsetInBytes = 0;
    /*
     * Starting point for hash processing - given as number of bytes from
     * start of packet in source buffer.
     */
    OpData.hashStartSrcOffsetInBytes = 0;
    /*
     * The message length, in bytes, of the source buffer that the hash will
     * be computed on.
     */
    OpData.messageLenToHashInBytes = 0;
    /*
     * Pointer to the location where the digest result either exists or will
     * be inserted.
     */
    OpData.pDigestResult = NULL;
    /*
     * Pointer to Additional Authenticated Data (AAD) needed for
     * authenticated cipher mechanisms - CCM and GCM. For other
     * authentication mechanisms this pointer is ignored.
     */
    OpData.pAdditionalAuthData = NULL;
    /*
     * The message length, in bytes, of the source buffer that the crypto
     * operation will be computed on. This must be a multiple to the block
     * size if a block cipher is being used.
     */
    OpData.messageLenToCipherInBytes = inl;

    /*
     * Cipher IV length in bytes.  Determines the amount of valid IV data
     * pointed to by the pIv parameter.
     */
    OpData.ivLenInBytes = (Cpa32U) EVP_CIPHER_CTX_iv_length(ctx);

    srcFlatBuffer.dataLenInBytes = (Cpa32U) inl;
    /* Number of pointers */
    srcBufferList.numBuffers = 1;
    /*
     * Pointer to an unbounded array containing the number of CpaFlatBuffers
     * defined by numBuffers
     */
    srcBufferList.pBuffers = &srcFlatBuffer;
    srcBufferList.pUserData = NULL;

    srcBufferList.pPrivateMetaData = qat_context->srcPrivateMetaData;

    dstFlatBuffer.dataLenInBytes = (Cpa32U) inl;
    /* Number of pointers */
    dstBufferList.numBuffers = 1;
    /*
     * Pointer to an unbounded array containing the number of CpaFlatBuffers
     * defined by numBuffers
     */
    dstBufferList.pBuffers = &dstFlatBuffer;
    /* This is an opaque field that is not read or modified internally. */
    dstBufferList.pUserData = NULL;

    dstBufferList.pPrivateMetaData = qat_context->dstPrivateMetaData;

    DEBUG("[%s] performing with %d bytes (iv-len=%d)\n", __func__, (int)inl,
          EVP_CIPHER_CTX_iv_length(ctx));

    initOpDone(&opDone);

    if ((sts = myPerformOp(qat_context->instanceHandle,
                            &opDone,
                            &OpData,
                            &srcBufferList,
                            &dstBufferList,
                            CPA_FALSE)) != CPA_STATUS_SUCCESS) {
       // ||
       // ((rc = waitForOpToComplete(&opDone)) != 0)) {
       // if (sts != CPA_STATUS_SUCCESS) {
            WARN("[%s] --- cpaCySymPerformOp failed sts=%d.\n", __func__,
                 sts);
        //}
        //else {
        //    WARN("[%s] --- cpaCySymPerformOp timed out.\n", __func__);
        //}
        if (!isZeroCopy()) {
            if (NID_rc4 != cipherType) // RC4 is an inplace operation
            {
                if (OpData.pIv) {
                    qaeCryptoMemFree(OpData.pIv);
                    OpData.pIv = NULL;
                }
                if (srcFlatBuffer.pData) {
                    qaeCryptoMemFree(srcFlatBuffer.pData);
                    srcFlatBuffer.pData = NULL;
                }
            }
            if (dstFlatBuffer.pData) {
                qaeCryptoMemFree(dstFlatBuffer.pData);
                dstFlatBuffer.pData = NULL;
            }
        } else if (isZeroCopy() && inMemAlloc && srcFlatBuffer.pData) {
            qaeCryptoMemFree(srcFlatBuffer.pData);
            srcFlatBuffer.pData = NULL;
        }

        cleanupOpDone(&opDone);
        return 0;
    }

    do {
        ASYNC_pause_job();
        if(!getEnableExternalPolling())
            poll_instances();
    } while(!opDone->flag);
     
    cleanupOpDone(&opDone);

    /*
     * If encrypting, the IV is the last block of the destination
     * (ciphertext) buffer.  If decrypting, the source buffer is the
     * ciphertext.
     */
    if (NID_rc4 != cipherType) {
        if (qat_context->enc) {
            memcpy(ctx->iv,
                   (dstBufferList.pBuffers[0].pData + inl -
                    EVP_CIPHER_CTX_iv_length(ctx)),
                   EVP_CIPHER_CTX_iv_length(ctx));
        } else {
            memcpy(ctx->iv,
                   (srcBufferList.pBuffers[0].pData + inl -
                    EVP_CIPHER_CTX_iv_length(ctx)),
                   EVP_CIPHER_CTX_iv_length(ctx));
        }
    }

    if (!isZeroCopy()) {
        if (NID_rc4 != cipherType) // RC4 is an inplace operation
        {
            qaeCryptoMemFree(OpData.pIv);
            qaeCryptoMemFree(srcFlatBuffer.pData);
        }
        copyFreePinnedMemory(out, dstFlatBuffer.pData, inl);
    }

    DEBUG("[%s] --- do_cipher END\n\n", __func__);

    return 1;
}

/******************************************************************************
* function:
*         common_cipher_cleanup(EVP_CIPHER_CTX *ctx)
*
* @param ctx [IN]  - pointer to cipher ctx
*
* description:
*    This function is rewrite of aes_xxx_cbc_cleanup() in OpenSSL. The function is design
*    to clears all information form a cipher context and free up any allocated memory
*    associate it. It is the last function called in cipher routine sequences.
*    The function will return 1 if successful
******************************************************************************/
static int common_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    CpaStatus sts = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    qat_ctx *qat_context = NULL;
    int count = 0;
    Cpa64U num_inflight = 0;
    struct timespec reqTime = { 0 };
    struct timespec remTime = { 0 };

    DEBUG("[%s] --- cleaning\n\n", __func__);

    if (!ctx) {
        WARN("[%s] --- ctx is NULL.\n", __func__);
        return 0;
    }

    if (!ctx->cipher_data) {
        WARN("[%s] --- ctx->cipher_data is NULL.\n", __func__);
        return 0;
    }

    qat_context = (qat_ctx *) (ctx->cipher_data);

    if (!(qat_context->init)) {
        /*
         * It is valid to call cleanup on a context that hasn't been
         * initialised
         */
        return 1;
    }

    pSessionCtx = qat_context->ctx;

    /* Check for inflight requests */
    num_inflight = qat_context->noRequests - qat_context->noResponses;
    while ((0 != num_inflight) && (count < QAT_CIPHER_CLEANUP_RETRY_COUNT)) {
        count++;
        /* Wait for some time */
        reqTime.tv_nsec = QAT_CIPHER_CLEANUP_WAIT_TIME_NS;
        do {
            nanosleep(&reqTime, &remTime);
            reqTime.tv_sec = remTime.tv_sec;
            reqTime.tv_nsec = remTime.tv_nsec;
            if ((errno < 0) && (EINTR != errno)) {
                WARN("nanosleep system call failed: errno %i\n", errno);
                break;
            }
        } while (EINTR == errno);

        num_inflight = qat_context->noRequests - qat_context->noResponses;
    }

    if (0 != num_inflight) {
        WARN("[%s] --- Still %ld cipher messages in flight.\n",
             __func__, num_inflight);
        return 0;

    }

    if ((sts =
         cpaCySymRemoveSession(qat_context->instanceHandle,
                               pSessionCtx)) != CPA_STATUS_SUCCESS) {
        WARN("[%s] --- cpaCySymRemoveSession failed, sts = %d.\n",
             __func__, sts);
        return 0;
    }

    if (qat_context->session_data)
        OPENSSL_free(qat_context->session_data);
    if (pSessionCtx)
        qaeCryptoMemFree(pSessionCtx);
    if (qat_context->srcPrivateMetaData)
        qaeCryptoMemFree(qat_context->srcPrivateMetaData);
    if (qat_context->dstPrivateMetaData)
        qaeCryptoMemFree(qat_context->dstPrivateMetaData);

    qat_context->init = 0;
    return 1;

}
