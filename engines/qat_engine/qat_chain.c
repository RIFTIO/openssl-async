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
 * @file qat_chain.c
 *
 * This file contains the engine implementations for Chain cipher operations
 *
 *****************************************************************************/

#ifdef USE_QAT_MEM
#include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
#include "qat_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "e_qat.h"
#include "e_qat_err.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"
#include "qat_chain.h"
#include "qat_ciphers.h"
#include "qat_sym_common.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/tls1.h>
#include <string.h>

/* Qat cipher AES128-SHA1 function structure declaration */
EVP_CIPHER qat_aes_128_cbc_hmac_sha1 = {
    NID_aes_128_cbc_hmac_sha1,  /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_128,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags | EVP_CIPH_FLAG_AEAD_CIPHER,
#ifdef OPENSSL_QAT_ASYNCH
    { qat_aes_cbc_hmac_sha1_init_sync },
    { qat_aes_cbc_hmac_sha1_cipher_sync },
#else
    qat_aes_cbc_hmac_sha1_init_sync,
    qat_aes_cbc_hmac_sha1_cipher_sync,
#endif
    qat_aes_cbc_hmac_sha1_cleanup_sync,
    sizeof(qat_chained_ctx),    /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_get_asn1_iv,
    qat_aes_cbc_hmac_sha1_ctrl_sync,
    NULL
};

#ifdef OPENSSL_QAT_ASYNCH
/* Qat cipher AES128-SHA1 function structure declaration */
EVP_CIPHER qat_aes_128_cbc_hmac_sha1_asynch = {
    NID_aes_128_cbc_hmac_sha1,  /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_128,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_ASYNCH,
    { .asynch = qat_aes_cbc_hmac_sha1_init_asynch },
    { .asynch = qat_aes_cbc_hmac_sha1_cipher_asynch },
    qat_aes_cbc_hmac_sha1_cleanup_asynch,
    sizeof(qat_chained_ctx),    /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_get_asn1_iv,
    qat_aes_cbc_hmac_sha1_ctrl_asynch,
    NULL
};
#endif

/* Qat cipher AES256-SHA1 function structure declaration */
EVP_CIPHER qat_aes_256_cbc_hmac_sha1 = {
    NID_aes_256_cbc_hmac_sha1,  /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_256,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags | EVP_CIPH_FLAG_AEAD_CIPHER,
#ifdef OPENSSL_QAT_ASYNCH
    { qat_aes_cbc_hmac_sha1_init_sync },
    { qat_aes_cbc_hmac_sha1_cipher_sync },
#else
    qat_aes_cbc_hmac_sha1_init_sync,
    qat_aes_cbc_hmac_sha1_cipher_sync,
#endif
    qat_aes_cbc_hmac_sha1_cleanup_sync,
    sizeof(qat_chained_ctx),    /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_get_asn1_iv,
    qat_aes_cbc_hmac_sha1_ctrl_sync,
    NULL
};

#ifdef OPENSSL_QAT_ASYNCH
/* Qat cipher AES256-SHA1 function structure declaration */
EVP_CIPHER qat_aes_256_cbc_hmac_sha1_asynch = {
    NID_aes_256_cbc_hmac_sha1,  /* nid */
    AES_BLOCK_SIZE,             /* block_size */
    AES_KEY_SIZE_256,           /* key_size in Bytes - defined in header */
    AES_IV_LEN,                 /* iv_len in Bytes - defined in header */
    qat_common_cbc_flags | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_ASYNCH,
    { .asynch = qat_aes_cbc_hmac_sha1_init_asynch },
    { .asynch = qat_aes_cbc_hmac_sha1_cipher_asynch },
    qat_aes_cbc_hmac_sha1_cleanup_asynch,
    sizeof(qat_chained_ctx),    /* ctx_size */
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_set_asn1_iv,
    EVP_CIPH_FLAG_DEFAULT_ASN1?NULL:EVP_CIPHER_get_asn1_iv,
    qat_aes_cbc_hmac_sha1_ctrl_asynch,
    NULL
};
#endif


 /******************************************************************************
* function:
*         cipher_int_chained(EVP_CIPHER_CTX *evp_ctx,
*                            qat_chained_ctx *qat_ctx,
*                            const unsigned char* key,
*                            const unsigned char* iv,
*                            int enc)
*
* @param evp_ctx [IN] - pointer to the evp context
* @param qat_ctx [IN] - pointer to the qat context
* @param key     [IN] - pointer to the cipher key
* @param iv      [IN] - pointer to the iv this maybe NULL.
* @param enc     [IN] - whether we are doing encryption (1) or decryption (0).
*
* description:
*    This function is to create QAT specific session data
*    It is called from the session init function.
*    it will return 1 if successful and 0 on failure.
******************************************************************************/
static int cipher_init_chained(EVP_CIPHER_CTX *evp_ctx, qat_chained_ctx *qat_ctx,
                const unsigned char* key, const unsigned char* iv,
                int enc)
{
    if ((!qat_ctx) || (!key) || (!evp_ctx))
    {
        WARN("[%s] --- qat_ctx or key or ctx is NULL.\n", __func__);
        return 0;
    }

    qat_ctx->session_data = OPENSSL_malloc(sizeof(CpaCySymSessionSetupData));
    if(NULL == qat_ctx->session_data)
    {
        WARN("OPENSSL_malloc() failed for session setup data allocation.\n");
        return 0;
    }

    if (NULL != iv)
        memcpy(evp_ctx->iv, iv, EVP_CIPHER_CTX_iv_length(evp_ctx));
    else
        memset(evp_ctx->iv, 0, EVP_CIPHER_CTX_iv_length(evp_ctx));

    DUMPL("iv", iv, EVP_CIPHER_CTX_iv_length(evp_ctx));
    DUMPL("key", key, EVP_CIPHER_CTX_key_length(evp_ctx));

    /* Priority of this session */
    qat_ctx->session_data->sessionPriority = CPA_CY_PRIORITY_HIGH;
    qat_ctx->session_data->symOperation = CPA_CY_SYM_OP_ALGORITHM_CHAINING;

    /* Cipher algorithm and mode */
    qat_ctx->session_data->cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_CBC;
    /* Cipher key length 256 bits (32 bytes) */
    qat_ctx->session_data->cipherSetupData.cipherKeyLenInBytes = (Cpa32U)EVP_CIPHER_CTX_key_length(evp_ctx);
    /* Cipher key */
    if(NULL == (qat_ctx->session_data->cipherSetupData.pCipherKey = OPENSSL_malloc(EVP_CIPHER_CTX_key_length(evp_ctx))))
    {
        WARN("[%s] --- unable to allocate memory for Cipher key.\n", __func__);
        goto end;
    }

    memcpy(qat_ctx->session_data->cipherSetupData.pCipherKey, key, EVP_CIPHER_CTX_key_length(evp_ctx));

    /* Operation to perform */
    if(enc)
    {
        qat_ctx->session_data->cipherSetupData.cipherDirection =
                        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
        qat_ctx->session_data->algChainOrder =
                        CPA_CY_SYM_ALG_CHAIN_ORDER_HASH_THEN_CIPHER;
    } else
    {
        qat_ctx->session_data->cipherSetupData.cipherDirection =
                        CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
        qat_ctx->session_data->algChainOrder =
                        CPA_CY_SYM_ALG_CHAIN_ORDER_CIPHER_THEN_HASH;
    }

    /* Hash Configuration */
    qat_ctx->session_data->hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
    qat_ctx->session_data->hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_AUTH;
    qat_ctx->session_data->hashSetupData.digestResultLenInBytes = SHA_DIGEST_LENGTH;
    qat_ctx->session_data->hashSetupData.authModeSetupData.aadLenInBytes = 0;

    qat_ctx->hmac_key = OPENSSL_malloc(HMAC_KEY_SIZE);
    if(NULL == qat_ctx->hmac_key)
    {
        WARN("[%s] Unable to allocate memory or HMAC Key\n", __func__);
        goto end;
    }
    memset(qat_ctx->hmac_key, 0, HMAC_KEY_SIZE);
    qat_ctx->session_data->hashSetupData.authModeSetupData.authKey = qat_ctx->hmac_key;
    qat_ctx->session_data->hashSetupData.authModeSetupData.authKeyLenInBytes = HMAC_KEY_SIZE;

    qat_ctx->initParamsSet = 1;
    qat_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;

    return 1;

    end:
      if (NULL != qat_ctx->session_data)
      {
          if (NULL != qat_ctx->session_data->cipherSetupData.pCipherKey)
          {
              OPENSSL_free(qat_ctx->session_data->cipherSetupData.pCipherKey);
              qat_ctx->session_data->cipherSetupData.pCipherKey = NULL;
          }
          OPENSSL_free(qat_ctx->session_data);
          qat_ctx->session_data = NULL;
      }
      return 0;
}

/******************************************************************************
* function:
*         qat_aes_cbc_hmac_sha1_init(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv,
*                                    int enc)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
static int qat_aes_cbc_hmac_sha1_init(EVP_CIPHER_CTX *ctx,
                        const unsigned char *inkey,
                        const unsigned char *iv, int enc,
                        int (*cb)(unsigned char *out, int outl,
                                  void *cb_data, int status))
{

    /* Initialise a QAT session  and set the cipher keys*/
    qat_chained_ctx* qat_ctx = NULL;

    if (!ctx || !inkey)
    {
        WARN("[%s] ctx or inkey is NULL.\n", __func__);
        return 0;
    }

    qat_ctx = data(ctx);
    if (!qat_ctx)
    {
        WARN("[%s] --- qat_ctx is NULL.\n", __func__);
        return 0;
    }

    if(cb) /*Async Mode*/
    {
        qat_ctx->cipher_cb = cb;
    }
    else /*Sync Mode*/
    {
        /* Pre-allocate necessary memory */
        /* This is a whole block the size of the memory alignment.
           If the alignment was to become smaller than the header size
           (TLS_VIRT_HEADER_SIZE) which is unlikely then we would need
            to add some more logic here to work how many blocks of size
            QAT_BYTE_ALIGNMENT we need to allocate to fit the header in. */
        qat_ctx->tls_virt_hdr = qaeCryptoMemAlloc(QAT_BYTE_ALIGNMENT, __FILE__, __LINE__);
        if(NULL == qat_ctx->tls_virt_hdr)
        {
            WARN("[%s] Unable to allcoate memory for MAC preamble\n", __func__);
            return 0;
        }
        memset(qat_ctx->tls_virt_hdr, 0, QAT_BYTE_ALIGNMENT);
        qat_ctx->srcFlatBuffer[0].pData = qat_ctx->tls_virt_hdr;
        qat_ctx->srcFlatBuffer[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;
        qat_ctx->dstFlatBuffer[0].pData = qat_ctx->srcFlatBuffer[0].pData;
        qat_ctx->dstFlatBuffer[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;

        qat_ctx->pIv = qaeCryptoMemAlloc(EVP_CIPHER_CTX_iv_length(ctx), __FILE__, __LINE__);
        if(!qat_ctx->pIv)
        {
            WARN("[%s] --- pIv is NULL.\n", __func__);
            goto end;
        }
    }

    if(!cipher_init_chained(ctx, qat_ctx, inkey, iv, enc))
    {
        WARN("[%s] cipher_init_chained failed.\n", __func__);
        goto end;
    }

    return 1;

    end:
        if(NULL != qat_ctx->tls_virt_hdr)
        {
            qaeCryptoMemFree(qat_ctx->tls_virt_hdr);
            qat_ctx->tls_virt_hdr = NULL;
        }
        if(NULL != qat_ctx->pIv)
        {
            qaeCryptoMemFree(qat_ctx->pIv);
            qat_ctx->pIv=NULL;
        }

        return 0;

}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx,
*                               int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
static int qat_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr, int enableAsync)
{
    qat_chained_ctx *evp_ctx = NULL;
    int retVal = 0;

    if (!ctx)
    {
        WARN("[%s] --- ctx parameter is NULL.\n", __func__);
        return -1;
    }

    evp_ctx = data(ctx);

    if (!evp_ctx)
    {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return -1;
    }

    switch (type)
    {
        case EVP_CTRL_AEAD_SET_MAC_KEY:
        {
            unsigned char *hmac_key = evp_ctx->hmac_key;
            CpaCySymSessionSetupData* sessionSetupData = evp_ctx->session_data;

            if(NULL == hmac_key || NULL == sessionSetupData)
            {
                WARN("[%s] --- HMAC Key or sessionSetupData are NULL", __func__);
                return -1;
            }

            memset (hmac_key,0,HMAC_KEY_SIZE);

            if (arg > HMAC_KEY_SIZE)
            {
                SHA1_Init(&(evp_ctx->key_wrap));
                SHA1_Update(&(evp_ctx->key_wrap),ptr,arg);
                SHA1_Final(hmac_key,&(evp_ctx->key_wrap));
                sessionSetupData->hashSetupData.authModeSetupData.authKeyLenInBytes = HMAC_KEY_SIZE;
            }
            else
            {
                memcpy(hmac_key,ptr,arg);
                sessionSetupData->hashSetupData.authModeSetupData.authKeyLenInBytes = arg;
            }

            DUMPL("hmac_key", hmac_key, arg);

            evp_ctx->initHmacKeySet = 1;
            retVal = 1;
            break;
        }
        case EVP_CTRL_AEAD_TLS1_AAD:
        {
            /* Values to include in the record MAC calculation are included in this type
               This returns the amount of padding required for the send/encrypt direction */
            unsigned char *p=ptr;
            unsigned int   len=(p[arg-QAT_TLS_PAYLOADLENGTH_MSB_OFFSET]<<QAT_BYTE_SHIFT
                               | p[arg-QAT_TLS_PAYLOADLENGTH_LSB_OFFSET]);

            if (arg < TLS_VIRT_HDR_SIZE)
            {
                retVal = -1;
                break;
            }
            evp_ctx->tls_version = (p[arg-QAT_TLS_VERSION_MSB_OFFSET]<<QAT_BYTE_SHIFT
                    | p[arg-QAT_TLS_VERSION_LSB_OFFSET]);
            if(enableAsync)
            {
                evp_ctx->payload_length = len;
                memcpy(evp_ctx->tls_hdr,ptr,TLS_VIRT_HDR_SIZE);
            }

            if (ctx->encrypt)
            {
                if(!enableAsync)
                {
                    evp_ctx->payload_length = len;
                    if (evp_ctx->tls_version >= TLS1_1_VERSION)
                    {
                        len -= AES_BLOCK_SIZE;
                        //BWILL: Why does this code reduce the len in the TLS header by the IV for the framework?
                        p[arg-QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] = len>>QAT_BYTE_SHIFT;
                        p[arg-QAT_TLS_PAYLOADLENGTH_LSB_OFFSET] = len;
                    }

                    if(NULL == evp_ctx->tls_virt_hdr)
                    {
                        WARN("Unable to allocate memory for mac preamble in qat/n");
                        return -1;
                    }
                    /* Copy the header from p into the QAT_BYTE_ALIGNMENT sized buffer so that
                       the header is in the final part of the buffer*/
                    memcpy(evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), p, TLS_VIRT_HDR_SIZE);
                    DUMPL("tls_virt_hdr", evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), arg);
                }
                retVal = (int)(((len+SHA_DIGEST_LENGTH+AES_BLOCK_SIZE)&-AES_BLOCK_SIZE) - len);
                break;
            }
            else
            {
                if(!enableAsync)
                {
                    /* Copy the header from ptr into the QAT_BYTE_ALIGNMENT sized buffer so that
                       the header is in the final part of the buffer*/
                    if (arg> TLS_VIRT_HDR_SIZE) arg =  TLS_VIRT_HDR_SIZE;
                    memcpy(evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE) ,ptr,arg);
                    evp_ctx->payload_length = arg;
                }
                retVal = SHA_DIGEST_LENGTH;
                break;
            }
        }
        default:
        {
            WARN("[%s] --- unknown type parameter.\n", __func__);
            return -1;
        }
    }
    return retVal;
}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx, unsigned int enableAsync)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param enableAsync    [IN]  - Type of mode(.i.e,) Sync or Async
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
static int qat_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx, unsigned int enableAsync)
{
    qat_chained_ctx* evp_ctx = NULL;
    CpaStatus sts = 0;
    CpaCySymSessionSetupData* sessSetup = NULL;
    int retVal = 1;
#ifdef OPENSSL_QAT_ASYNCH
    int count = 0;
    Cpa64U num_inflight = 0;
    struct timespec reqTime = {0};
    struct timespec remTime = {0};
#endif

    if (!ctx)
    {
        WARN("[%s] ctx parameter is NULL.\n", __func__);
        return 0;
    }

    evp_ctx = data(ctx);

    if (!evp_ctx)
    {
        WARN("[%s] evp_ctx parameter is NULL.\n", __func__);
        return 0;
    }

    if(!(evp_ctx->init))
    {
        /* It is valid to call cleanup even if the context has not been initialised. */
        return retVal;
    }

    sessSetup = evp_ctx->session_data;
    if(sessSetup)
    {
        if(evp_ctx->qat_ctx)
        {
#ifdef OPENSSL_QAT_ASYNCH
			if(enableAsync)
			{
				/* Check for inflight requests */
				num_inflight = evp_ctx->noRequests - evp_ctx->noResponses;
				DEBUG("async chaining clean up %lu inflight\n",(evp_ctx->noRequests-evp_ctx->noResponses));
				while((0 != num_inflight) && (count < QAT_CIPHER_CLEANUP_RETRY_COUNT))
				{
					count++;
					/* Wait for some time */
					reqTime.tv_nsec = QAT_CIPHER_CLEANUP_WAIT_TIME_NS;
					do
					{
						nanosleep(&reqTime, &remTime);
						reqTime.tv_sec = remTime.tv_sec;
						reqTime.tv_nsec = remTime.tv_nsec;
						if((errno < 0) && (EINTR != errno))
						{
							WARN("nanosleep system call failed: errno %i\n", errno);
							break;
						}
					} while (EINTR == errno);

					num_inflight = evp_ctx->noRequests - evp_ctx->noResponses;
				}

				if(0 != num_inflight)
				{
					WARN("[%s] --- Still %ld chained messages in flight.\n",
					__func__, num_inflight);
					return 0;
				}
			}
#endif
            if((sts = cpaCySymRemoveSession(evp_ctx->instanceHandle, evp_ctx->qat_ctx))
               != CPA_STATUS_SUCCESS)
            {
                WARN("[%s] cpaCySymRemoveSession FAILED, sts = %d.!\n", __func__, sts);
                retVal = 0;
                /* Lets not return yet and instead make a best effort to
                   cleanup the rest to avoid memory leaks*/
            }
            qaeCryptoMemFree(evp_ctx->qat_ctx);
            evp_ctx->qat_ctx = NULL;
        }
        if(sessSetup->hashSetupData.authModeSetupData.authKey)
        {
            OPENSSL_free(sessSetup->hashSetupData.authModeSetupData.authKey);
            sessSetup->hashSetupData.authModeSetupData.authKey = NULL;
        }
		if(!enableAsync)
		{
			if(evp_ctx->tls_virt_hdr)
			{
				qaeCryptoMemFree(evp_ctx->tls_virt_hdr);
				evp_ctx->tls_virt_hdr = NULL;
			}
			if(evp_ctx->srcBufferList.pPrivateMetaData)
			{
				qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
				evp_ctx->srcBufferList.pPrivateMetaData = NULL;
			}
			if(evp_ctx->dstBufferList.pPrivateMetaData)
			{
				qaeCryptoMemFree(evp_ctx->dstBufferList.pPrivateMetaData);
				evp_ctx->dstBufferList.pPrivateMetaData = NULL;
			}
			if(evp_ctx->pIv)
			{
				qaeCryptoMemFree(evp_ctx->pIv);
				evp_ctx->pIv = NULL;

			}
		}
        if(sessSetup->cipherSetupData.pCipherKey)
        {
            OPENSSL_free(sessSetup->cipherSetupData.pCipherKey);
            sessSetup->cipherSetupData.pCipherKey = NULL;
        }
        OPENSSL_free(sessSetup);
    }
    evp_ctx->init = 0;
	if(!enableAsync)
	{
		evp_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;
	}
    return retVal;
}


/******************************************************************************
* function:
*         qat_aes_sha1_session_init(EVP_CIPHER_CTX *ctx)
*
* @param ctx [IN] - pointer to context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function synchronises the initialisation of the QAT session and
*  pre-allocates the necessary buffers for the session.
******************************************************************************/
static int qat_aes_sha1_session_init(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx* evp_ctx = NULL;
    CpaCySymSessionSetupData *sessionSetupData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    Cpa32U metaSize = 0;

    if(!ctx)
    {
        WARN("[%s] --- parameters ctx is NULL.\n", __func__);
        return 0;
    }

    evp_ctx = data(ctx);

    if (!evp_ctx)
    {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return 0;
    }

    /* All parameters have not been set yet or we have already been initialised. */
    if((1 != evp_ctx->initParamsSet) ||
	(1 == evp_ctx->init))
    {
	WARN("[%s] --- parameters not set or initialised yet.\n", __func__);
        return 0;
    }

    sessionSetupData = evp_ctx->session_data;
    evp_ctx->instanceHandle = get_next_inst();

    if (!evp_ctx->instanceHandle || !sessionSetupData)
    {
        WARN("[%s] --- evp_ctx->instanceHandle or sessionSetupData are NULL.\n", __func__);
        return 0;
    }

    if (cpaCySymSessionCtxGetSize(evp_ctx->instanceHandle, sessionSetupData,
                        &sessionCtxSize) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCySymSessionCtxGetSize failed.\n", __func__);
        return 0;
    }

    pSessionCtx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sessionCtxSize, __FILE__, __LINE__);
    if (NULL == pSessionCtx)
    {
        WARN("[%s] --- pSessionCtx malloc failed !\n", __func__);
        return 0;
    }

    if(ctx->encrypt)
        sessionSetupData->verifyDigest = CPA_FALSE;
    else
        sessionSetupData->verifyDigest = CPA_TRUE;

    sessionSetupData->digestIsAppended =  CPA_TRUE;

    if (cpaCySymInitSession(evp_ctx->instanceHandle, qat_crypto_callbackFn, sessionSetupData,
              pSessionCtx) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCySymInitSession failed.\n", __func__);
        qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    evp_ctx->qat_ctx = pSessionCtx;

    evp_ctx->srcBufferList.numBuffers = 2;
    evp_ctx->srcBufferList.pBuffers = (evp_ctx->srcFlatBuffer);
    evp_ctx->srcBufferList.pUserData = NULL;

    evp_ctx->dstBufferList.numBuffers = 2;
    evp_ctx->dstBufferList.pBuffers = (evp_ctx->dstFlatBuffer);
    evp_ctx->dstBufferList.pUserData = NULL;

    /* setup meta data for buffer lists */
    if (cpaCyBufferListGetMetaSize(evp_ctx->instanceHandle,
                                   evp_ctx->srcBufferList.numBuffers,
                                   &metaSize) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed.\n",__func__);
	qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if (metaSize)
    {
        evp_ctx->srcBufferList.pPrivateMetaData = qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!(evp_ctx->srcBufferList.pPrivateMetaData))
        {
            WARN("[%s] --- srcBufferList.pPrivateMetaData is NULL.\n", __func__);
	    qaeCryptoMemFree(pSessionCtx);
            return 0;
        }
    }
    else
    {
        evp_ctx->srcBufferList.pPrivateMetaData = NULL;
    }
    metaSize = 0;

    if (cpaCyBufferListGetMetaSize(evp_ctx->instanceHandle,
                                   evp_ctx->dstBufferList.numBuffers,
                                   &metaSize) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed.\n",__func__);
	if (evp_ctx->srcBufferList.pPrivateMetaData)
	{
	    qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
	    evp_ctx->srcBufferList.pPrivateMetaData=NULL;
	}
	qaeCryptoMemFree(pSessionCtx);
        return 0;
    }

    if (metaSize)
    {
        evp_ctx->dstBufferList.pPrivateMetaData = qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);
        if (!(evp_ctx->dstBufferList.pPrivateMetaData))
        {
            WARN("[%s] --- dstBufferList.pPrivateMetaData is NULL.\n", __func__);
	    if (evp_ctx->srcBufferList.pPrivateMetaData)
            {
                qaeCryptoMemFree(evp_ctx->srcBufferList.pPrivateMetaData);
                evp_ctx->srcBufferList.pPrivateMetaData=NULL;
            }
            qaeCryptoMemFree(pSessionCtx);
            return 0;
        }
    }
    else
    {
        evp_ctx->dstBufferList.pPrivateMetaData = NULL;
    }

    /* Create the OpData structure to remove this processing from the data path */
    evp_ctx->OpData.sessionCtx = evp_ctx->qat_ctx;
    evp_ctx->OpData.packetType = CPA_CY_SYM_PACKET_TYPE_FULL;

    evp_ctx->OpData.pIv = evp_ctx->pIv;
    evp_ctx->OpData.ivLenInBytes = (Cpa32U)EVP_CIPHER_CTX_iv_length(ctx);
    /* We want to ensure the start of crypto data is on a 64 byte, aligned
       boundary. This is for QAT internal performance reasons. */
    evp_ctx->OpData.cryptoStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT;
    /* We start hashing from the start of the header. Due to needing the crypto
       data aligned to a 64 byte boundary we need to start the header that comes
       first at an offset into the 64 byte aligned block so the header will
       end on a 64 byte alignment. */
    evp_ctx->OpData.hashStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE;
    evp_ctx->OpData.pAdditionalAuthData = NULL;

    evp_ctx->init = 1;

    return 1;
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         qat_cipherAsynchCallbackFnChained(void *callbackTag,
*                                           CpaStatus status,
*                                           const CpaCySymOp operationType,
*                                           void *pOpData,
*                                           CpaBufferList * pDstBuffer,
*                                           CpaBoolean verifyResult)
*
* @param callbackTag  [IN] - the op_done_asynch structure
* @param status       [IN] - whether the operation was successful.
* @param operationType[IN] - the type of operation.
* @param pOpData      [IN] - pointer to callback data (not currently used
*                            in this function apart from debug).
* @param pDstBuffer   [IN] - buffer containing data that has been
*                            encrypted/decrypted
* @param verifyResult [IN] - flag whether to verify the result.
*
* description:
*    Asynch callback function for chained operations.
******************************************************************************/
static void qat_cipherAsynchCallbackFnChained(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
{
    struct op_done_asynch *op_done = (struct op_done_asynch *)callbackTag;
    qat_chained_ctx* qat_context;

    if(NULL == op_done)
    {
        WARN("[%s] --- Invalid input parameter to callback.\n", __func__);
        QATerr(QAT_F_QAT_CIPHERASYNCHCALLBACKFNCHAINED, QAT_R_INVALID_INPUT_PARAMETER);
        return;
    }

    qat_context = (qat_chained_ctx*)op_done->qat_ctx.chain;

    DEBUG("[%s]: status %d verifyResult %d\n", __func__, status,
          verifyResult);
    op_done->verifyResult = verifyResult;

    if(EVP_CIPHER_CTX_flags(op_done->cipher_ctx) & EVP_CIPH_CBC_MODE)
    {
        if(op_done->cipher_ctx->encrypt)
        {
            memcpy(op_done->cipher_ctx->iv,
                   (pDstBuffer->pBuffers[1].pData +
			pDstBuffer->pBuffers[1].dataLenInBytes  -
			EVP_CIPHER_CTX_iv_length(op_done->cipher_ctx)),
                   EVP_CIPHER_CTX_iv_length(op_done->cipher_ctx));
        }
    }

    DUMPREQ(qat_context->instanceHandle, op_done, (CpaCySymOpData* )pOpData,
            qat_context->session_data, pDstBuffer, pDstBuffer);

    if (!isZeroCopy())
    {
        memcpy(op_done->cur_out, pDstBuffer->pBuffers[1].pData,
	       pDstBuffer->pBuffers[1].dataLenInBytes);
    }
    else
    {
        op_done->cur_out = pDstBuffer->pBuffers[1].pData;
    }

    int cb_status = 0;
    if (op_done->cipher_ctx->encrypt)
    {
        cb_status = (status == CPA_STATUS_SUCCESS);
    }
    else
    {
        cb_status = (status == CPA_STATUS_SUCCESS && verifyResult);
    }

    qat_context->cipher_cb(op_done->orig_out, op_done->orig_len,
			   op_done->cb_data, cb_status);

    /* QAT structure allocations */
    if(NULL != op_done->agg_req)
	destroy_request(op_done->agg_req);
    if(NULL != op_done)
        OPENSSL_free(op_done);

    /* Update Reception stats */
    qat_context->noResponses++;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         qat_aes_sha1_session_init_asynch(EVP_CIPHER_CTX *ctx)
*
* @param ctx [IN] - pointer to context
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function synchronises the initialisation of the QAT session and
*  pre-allocates the necessary buffers for the session.
******************************************************************************/
static int qat_aes_sha1_session_init_asynch(EVP_CIPHER_CTX *ctx)
{
    qat_chained_ctx* evp_ctx = NULL;
    CpaCySymSessionSetupData *sessionSetupData = NULL;
    Cpa32U sessionCtxSize = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;

    if (!ctx)
    {
        WARN("[%s] --- ctx parameter is NULL.\n", __func__);
        goto end;
    }

	evp_ctx = data(ctx);

    if (!evp_ctx)
    {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        goto end;
    }

    /* All parameters have not been set yet or the CTX has already been initialised */
    if((1 != evp_ctx->initParamsSet) ||
	(1 == evp_ctx->init))
        goto end;

    sessionSetupData = evp_ctx->session_data;
    evp_ctx->instanceHandle = get_next_inst();
	if (!evp_ctx->instanceHandle || !sessionSetupData)
	{
        WARN("[%s] --- evp_ctx->instanceHandle or sessionSetupData are NULL.\n", __func__);
        goto end;
    }

    if (cpaCySymSessionCtxGetSize(evp_ctx->instanceHandle, sessionSetupData,
                        &sessionCtxSize) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCySymSessionCtxGetSize failed.\n", __func__);
        goto end;
    }

    pSessionCtx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sessionCtxSize, __FILE__, __LINE__);

    if (NULL == pSessionCtx)
    {
        WARN("[%s] --- pSessionCtx qaeCryptoMemAlloc failed !\n", __func__);
        goto end;
    }

    if(ctx->encrypt)
       sessionSetupData->verifyDigest = CPA_FALSE;
    else
       sessionSetupData->verifyDigest = CPA_TRUE;

    sessionSetupData->digestIsAppended =  CPA_TRUE;

    if (cpaCyBufferListGetMetaSize(evp_ctx->instanceHandle,
                                   2,
                                   &(evp_ctx->meta_size)) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed.\n",__func__);
        goto end;
    }

    if (cpaCySymInitSession(evp_ctx->instanceHandle, qat_cipherAsynchCallbackFnChained,
                            sessionSetupData, pSessionCtx) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCySymInitSession failed.\n", __func__);
        goto end;
    }

    evp_ctx->qat_ctx = pSessionCtx;
    evp_ctx->init = 1;

    return 1;

    end:
	if (NULL != pSessionCtx)
	    qaeCryptoMemFree(pSessionCtx);
	return 0;
}
#endif


/******************************************************************************
* function:
*         qat_aes_cbc_hmac_sha1_init_sync(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv,
*                                    int enc)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_init_sync(EVP_CIPHER_CTX *ctx,
                        const unsigned char *inkey,
                        const unsigned char *iv, int enc)
{
    return qat_aes_cbc_hmac_sha1_init(ctx, inkey,iv,enc,NULL);
}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_cipher_sync(EVP_CIPHER_CTX *ctx, unsigned char *out,
*                                 const unsigned char *in, size_t len)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param out   [OUT]  - output buffer for transform result
* @param in     [IN]  - input buffer
* @param len    [IN]  - length of input buffer
*
* @retval 0      function failed
* @retval 1      function succeeded
*
* description:
*    This function performs the cryptographic transform according to the
*  parameters setup during initialisation.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_cipher_sync(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                        const unsigned char *in, size_t len)
{
    CpaStatus sts = 0;
    unsigned int pad_len = 0;
    struct op_done opDone;
    qat_chained_ctx *evp_ctx = NULL;
    int retVal = 0, rc = 1;
    size_t plen = 0,
           iv   = 0; /* explicit IV in TLS 1.1 and later */

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if (!ctx || !in || !out)
    {
        WARN("[%s] --- ctx, in or out parameters are NULL.\n", __func__);
        return 0;
    }

    evp_ctx = data(ctx);

    if (!evp_ctx)
    {
        WARN("[%s] --- evp_ctx is NULL.\n", __func__);
        return 0;
    }

    if (len%AES_BLOCK_SIZE)
    {
    WARN("[%s] --- len is not a multiple of the AES_BLOCK_SIZE.\n", __func__);
        return 0;
    }

    if (!(evp_ctx->init))
    {
        if(0 == qat_aes_sha1_session_init(ctx))
        {
            WARN("[%s] --- Unable to initialise Cipher context.\n", __func__);
            return 0;
        }
    }

    plen = evp_ctx->payload_length;
    if (NO_PAYLOAD_LENGTH_SPECIFIED == plen)
        plen = len - SHA_DIGEST_LENGTH;
    else if (ctx->encrypt && len!=((plen+SHA_DIGEST_LENGTH+AES_BLOCK_SIZE)&-AES_BLOCK_SIZE))
        return 0;
    else if (evp_ctx->tls_version >= TLS1_1_VERSION)
    {
        iv = AES_BLOCK_SIZE;
        memcpy(evp_ctx->OpData.pIv, in, EVP_CIPHER_CTX_iv_length(ctx));
        /* Note: The OpenSSL framework assumes that the IV field will be part of the
         * encrypted data, yet never looks at the output of the encryption/decryption
         * process for this field. In order to chain HASH and CIPHER we need to present
         * contiguous SGL to QAT, thus we need to copy the IV from input to output in
         * in order to skip this field in encryption */
        if(in != out)
            memcpy(out, in, EVP_CIPHER_CTX_iv_length(ctx));
        in += iv;
        out += iv;
        len -= iv;
        evp_ctx->payload_length -= iv;
        plen -= iv;
    }
    else
        memcpy(evp_ctx->OpData.pIv, ctx->iv, EVP_CIPHER_CTX_iv_length(ctx));

    /* Build request/response buffers */
    if (isZeroCopy())
    {
        evp_ctx->srcFlatBuffer[1].pData = (Cpa8U*)in;
        evp_ctx->dstFlatBuffer[1].pData = (Cpa8U*)out;
    }
    else
    {
        evp_ctx->srcFlatBuffer[1].pData = qaeCryptoMemAlloc(len, __FILE__, __LINE__);
        if(!(evp_ctx->srcFlatBuffer[1].pData))
        {
            WARN("[%s] --- src/dst buffer allocation.\n", __func__);
            return 0;
        }
        evp_ctx->dstFlatBuffer[1].pData = evp_ctx->srcFlatBuffer[1].pData;
        memcpy(evp_ctx->dstFlatBuffer[1].pData, in, len);
    }
    evp_ctx->srcFlatBuffer[1].dataLenInBytes = len;
    evp_ctx->srcBufferList.pUserData = NULL;
    evp_ctx->dstFlatBuffer[1].dataLenInBytes = len;
    evp_ctx->dstBufferList.pUserData = NULL;

    evp_ctx->OpData.messageLenToCipherInBytes = len;

    if(NO_PAYLOAD_LENGTH_SPECIFIED == evp_ctx->payload_length)
    {
        evp_ctx->OpData.messageLenToHashInBytes = (TLS_VIRT_HDR_SIZE + len) - SHA_DIGEST_LENGTH;
    }
    else if(!(ctx->encrypt))
    {
        AES_KEY aes_key;
        unsigned char in_blk[AES_BLOCK_SIZE] = {0x0};
        unsigned char *key = evp_ctx->session_data->cipherSetupData.pCipherKey;
        unsigned int  key_len = EVP_CIPHER_CTX_key_length(ctx);
        unsigned char ivec[AES_BLOCK_SIZE] = {0x0};
        unsigned char out_blk[AES_BLOCK_SIZE] = {0x0};

        key_len = key_len * 8; //convert to bits
        memcpy(in_blk, (in + (len - AES_BLOCK_SIZE)), AES_BLOCK_SIZE);
        memcpy(ivec, (in + (len - (AES_BLOCK_SIZE + AES_BLOCK_SIZE))), AES_BLOCK_SIZE);

        /* Dump input parameters */
        DUMPL("Key :", key, EVP_CIPHER_CTX_key_length(ctx));
        DUMPL("IV :", ivec, AES_BLOCK_SIZE);
        DUMPL("Input Blk :", in_blk, AES_BLOCK_SIZE);

        AES_set_decrypt_key(key, key_len, &aes_key);
        AES_cbc_encrypt(in_blk, out_blk, AES_BLOCK_SIZE, &aes_key, ivec, 0);

        DUMPL("Output Blk :", out_blk, AES_BLOCK_SIZE);

        /* Extract pad length */
        pad_len = out_blk[AES_BLOCK_SIZE - 1];

        /* Calculate and update length */
        evp_ctx->payload_length = len - (pad_len + 1 + SHA_DIGEST_LENGTH);
        /* Take into account that the field is part of the header that is
           offset into a byte aligned buffer. */
        evp_ctx->tls_virt_hdr[QAT_BYTE_ALIGNMENT-QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] =
                              evp_ctx->payload_length>>QAT_BYTE_SHIFT;
         /* Take into account that the field is part of the header that is
           offset into a byte aligned buffer. */
        evp_ctx->tls_virt_hdr[QAT_BYTE_ALIGNMENT-QAT_TLS_PAYLOADLENGTH_LSB_OFFSET] =
                              evp_ctx->payload_length;

        /* HMAC Length */
        evp_ctx->OpData.messageLenToHashInBytes = TLS_VIRT_HDR_SIZE + evp_ctx->payload_length;
        /* Only copy the offset header data itself and not the whole block */
        memcpy(evp_ctx->dstFlatBuffer[0].pData + (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), evp_ctx->tls_virt_hdr + (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), TLS_VIRT_HDR_SIZE);
    }
    else
    {
        evp_ctx->OpData.messageLenToHashInBytes = TLS_VIRT_HDR_SIZE + evp_ctx->payload_length;
    }

    /* Add record padding */
    if(ctx->encrypt)
    {
        plen += SHA_DIGEST_LENGTH;
        for (pad_len=len-plen-1;plen<len;plen++) evp_ctx->dstFlatBuffer[1].pData[plen]=pad_len;
    }

    initOpDone(&opDone);

    if(!(ctx->encrypt) &&
    (NO_PAYLOAD_LENGTH_SPECIFIED != evp_ctx->payload_length) &&
    ((evp_ctx->tls_version) < TLS1_1_VERSION))
        memcpy(ctx->iv, in + len - AES_BLOCK_SIZE, EVP_CIPHER_CTX_iv_length(ctx));

    DEBUG("Pre Perform Op\n");
    DUMPREQ(evp_ctx->instanceHandle, &opDone, &(evp_ctx->OpData),
            evp_ctx->session_data, &(evp_ctx->srcBufferList),
            &(evp_ctx->dstBufferList));

    if (((sts = myPerformOp(evp_ctx->instanceHandle,
						   &opDone,
						   &(evp_ctx->OpData),
						   &(evp_ctx->srcBufferList),
						   &(evp_ctx->dstBufferList),
						   &(evp_ctx->session_data->verifyDigest))) != CPA_STATUS_SUCCESS) ||
		((rc = waitForOpToComplete(&opDone)) != 0))
    {
        if (!isZeroCopy())
        {
            qaeCryptoMemFree(evp_ctx->srcFlatBuffer[1].pData);
            evp_ctx->srcFlatBuffer[1].pData = NULL;
            evp_ctx->dstFlatBuffer[1].pData = NULL;
        }
        cleanupOpDone(&opDone);
        if (sts != CPA_STATUS_SUCCESS)
        {
            WARN("[%s] --- cpaCySymPerformOp failed sts=%d.\n", __func__, sts);
        }
        else
        {
            WARN("[%s] --- cpaCySymPerformOp timed out.\n", __func__);
        }
        return 0;
    }

    if(ctx->encrypt)
        retVal = 1;
    else if(CPA_TRUE == opDone.verifyResult)
        retVal = 1;

    DEBUG("Post Perform Op\n");
    DUMPREQ(evp_ctx->instanceHandle, &opDone, &(evp_ctx->OpData),
            evp_ctx->session_data, &(evp_ctx->srcBufferList),
            &(evp_ctx->dstBufferList));

    cleanupOpDone(&opDone);

    if((ctx->encrypt) && ((evp_ctx->tls_version) < TLS1_1_VERSION))
        memcpy(ctx->iv,
            evp_ctx->dstBufferList.pBuffers[1].pData + len - AES_BLOCK_SIZE,
            EVP_CIPHER_CTX_iv_length(ctx));
    evp_ctx->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;

    if (!isZeroCopy())
    {
        memcpy(out, evp_ctx->dstFlatBuffer[1].pData, len);
        qaeCryptoMemFree(evp_ctx->srcFlatBuffer[1].pData);
        evp_ctx->srcFlatBuffer[1].pData = NULL;
        evp_ctx->dstFlatBuffer[1].pData = NULL;
    }

    return retVal;
}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_ctrl_sync(EVP_CIPHER_CTX *ctx,
*                               int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_ctrl_sync(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return qat_aes_cbc_hmac_sha1_ctrl(ctx, type, arg, ptr,0);
}

/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_cleanup_sync(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_cleanup_sync(EVP_CIPHER_CTX *ctx)
{
    return qat_aes_cbc_hmac_sha1_cleanup(ctx, 0);
}


#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         qat_aes_cbc_hmac_sha1_init_asynch(EVP_CIPHER_CTX *ctx,
*                                    const unsigned char *inkey,
*                                    const unsigned char *iv, int enc,
*                                    int (*cb)(unsigned char *out, int outl,
*                                              void *cb_data, int status))
*
* @param ctx    [IN]  - pointer to existing ctx
* @param inKey  [IN]  - input cipher key
* @param iv     [IN]  - initialisation vector
* @param enc    [IN]  - 1 encrypt 0 decrypt
* @param cb     [IN]  - callback function pointer
*
* @retval 0      function succeeded
* @retval 1      function failed
*
* description:
*    This function initialises the cipher and hash algorithm parameters for this
*  EVP context.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_init_asynch(EVP_CIPHER_CTX *ctx,
                        const unsigned char *inkey,
                        const unsigned char *iv, int enc,
                        int (*cb)(unsigned char *out, int outl,
                                  void *cb_data, int status))
{
    if (!cb)
    {
        WARN("[%s] --- cb parameters are NULL.\n", __func__);
        return 0;
    }
    return qat_aes_cbc_hmac_sha1_init(ctx, inkey,iv,enc,cb);
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_cipher_asynch(EVP_CIPHER_CTX *ctx,
*                                        unsigned char *out,
*                                        const unsigned char *in,
*                                        size_t len
*                                        void *cb_data)
*
* @param ctx     [IN]  - pointer to existing ctx
* @param out     [OUT] - output buffer for transform result
* @param in      [IN]  - input buffer
* @param len     [IN]  - length of input buffer
* @param cb_data [IN]  - pointer to the callback data
*
* @retval 0      function succeeded
* @retval 1      function failed
*
* description:
*    This function perfrom the cryptographic transfornm according to the
*  parameters setup during initialisation.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_cipher_asynch(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                               const unsigned char *in, size_t len,
                                               void *cb_data)
{
    CpaStatus sts = 0;
    unsigned int pad_len = 0;
    struct op_done_asynch *op_done = NULL;
    qat_chained_ctx *qat_context = NULL;
    int retVal = 0;
    size_t payload_len = 0;
    const unsigned char *explicit_iv = NULL;
    const unsigned char *cur_in = in;
    AGG_REQ *agg_req = NULL;

    CRYPTO_QAT_LOG("CIPHER - %s\n", __func__);

    if (!ctx || !in || !out || !cb_data)
    {
        WARN("[%s] --- ctx, in, out or cb_data parameters are NULL.\n", __func__);
        goto end;
    }

    qat_context = data(ctx);

    if (!qat_context)
    {
        WARN("[%s] --- qat_context is NULL.\n", __func__);
        goto end;
    }

    if(!(qat_context->init))
    {
        if(0 == qat_aes_sha1_session_init_asynch(ctx))
        {
            WARN("[%s] --- Unable to initialise Cipher context.\n", __func__);
            goto end;
        }
    }

    /* QAT structure allocations */
    op_done = OPENSSL_malloc(sizeof(struct op_done_asynch));
    if(!op_done)
    {
        WARN("[%s] --- opDone is NULL.\n", __func__);
        goto end;
    }

    op_done->cipher_ctx = ctx;
    op_done->orig_out = op_done->cur_out = out;
    op_done->orig_len = op_done->cur_len = len;
    op_done->cb_data = cb_data;
    op_done->qat_ctx.chain = qat_context;

    if (len%AES_BLOCK_SIZE) goto end;

    payload_len = qat_context->payload_length;
    if (payload_len == NO_PAYLOAD_LENGTH_SPECIFIED)
        payload_len = op_done->cur_len - SHA_DIGEST_LENGTH;
    else if (ctx->encrypt && op_done->cur_len!=
        ((payload_len+SHA_DIGEST_LENGTH+AES_BLOCK_SIZE)&-AES_BLOCK_SIZE))
        goto end;
    else if (qat_context->tls_version >= TLS1_1_VERSION)
    {
        /* TODO: This should just be a check for IGNORE_IV but for backward compatibility
         * we check version and the IGNORE_IV field. IGNORE field check is done in the request
         * creation. */

        /* Note: The OpenSSL framework assumes that the IV field will be part of the
         * encrypted data, yet never looks at the output of the encryption/decryption
         * process for this field. In order to chain HASH and CIPHER we need to present
         * contiguous SGL to QAT, thus we need to copy the IV from input to output in
         * order to skip this field in encryption */
    explicit_iv = cur_in;
        if(cur_in != op_done->cur_out)
            memcpy(op_done->cur_out, cur_in, EVP_CIPHER_CTX_iv_length(ctx));
        cur_in += EVP_CIPHER_CTX_iv_length(ctx);
        op_done->cur_out += EVP_CIPHER_CTX_iv_length(ctx);
        op_done->cur_len -= EVP_CIPHER_CTX_iv_length(ctx);
        payload_len -= EVP_CIPHER_CTX_iv_length(ctx);
    }

    if(!(ctx->encrypt) && (NO_PAYLOAD_LENGTH_SPECIFIED != qat_context->payload_length))
    {
        AES_KEY aes_key;
        unsigned char in_blk[AES_BLOCK_SIZE] = {0x0};
        unsigned char *key = qat_context->session_data->cipherSetupData.pCipherKey;
        unsigned int  key_len = EVP_CIPHER_CTX_key_length(ctx) * 8; /* convert to bits */
        unsigned char ivec[AES_BLOCK_SIZE] = {0x0};
        unsigned char out_blk[AES_BLOCK_SIZE] = {0x0};

        memcpy(in_blk, (cur_in + (op_done->cur_len - AES_BLOCK_SIZE)), AES_BLOCK_SIZE);
        memcpy(ivec, (cur_in + (op_done->cur_len - (AES_BLOCK_SIZE + AES_BLOCK_SIZE))), AES_BLOCK_SIZE);

        /* Dump input parameters */
        DUMPL("Key :", key, EVP_CIPHER_CTX_key_length(ctx));
        DUMPL("IV :", ivec, AES_BLOCK_SIZE);
        DUMPL("Input Blk :", in_blk, AES_BLOCK_SIZE);

        AES_set_decrypt_key(key, key_len, &aes_key);
        AES_cbc_encrypt(in_blk, out_blk, AES_BLOCK_SIZE, &aes_key, ivec, 0);

        DUMPL("Output Blk :", out_blk, AES_BLOCK_SIZE);

        /* Extract pad length, calculate and update length */
        payload_len = op_done->cur_len - ((out_blk[AES_BLOCK_SIZE - 1]) + 1 + SHA_DIGEST_LENGTH);
    }

    qat_context->tls_hdr[TLS_VIRT_HDR_SIZE-QAT_TLS_PAYLOADLENGTH_MSB_OFFSET] =
                             payload_len>>QAT_BYTE_SHIFT;
    qat_context->tls_hdr[TLS_VIRT_HDR_SIZE-QAT_TLS_PAYLOADLENGTH_LSB_OFFSET] =
                             payload_len;

    if (NULL == (agg_req = create_chained_request(ctx, op_done->cur_out,
                    cur_in, op_done->cur_len,
                                        qat_context->qat_ctx,
                                        qat_context->meta_size,
                                        SHA_DIGEST_LENGTH,
                                        qat_context->tls_hdr,
                                        TLS_VIRT_HDR_SIZE)))
    {
        WARN("%s: Unable to create request structure.\n", __func__);
        goto end;
    }
    op_done->agg_req = agg_req;

    if (NULL != explicit_iv)
    {
        memcpy(OPDATA_PTR(agg_req)->pIv, explicit_iv, EVP_CIPHER_CTX_iv_length(ctx));
        OPDATA_PTR(agg_req)->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    }

    /* TLS VIRT header is allocated when creating the request */
    /* Create the OpData structure to remove this processing from the data path */
    OPDATA_PTR(agg_req)->cryptoStartSrcOffsetInBytes += TLS_VIRT_HDR_SIZE;

    /* HMAC Length */
    OPDATA_PTR(agg_req)->messageLenToHashInBytes = TLS_VIRT_HDR_SIZE + payload_len;

    /* Add record padding */
    if(ctx->encrypt)
    {
        payload_len += SHA_DIGEST_LENGTH;
        for (pad_len=op_done->cur_len-payload_len-1;payload_len<op_done->cur_len;payload_len++)
        DST_BUFFER_DATA(agg_req)[1].pData[payload_len]=pad_len;
    }

    if(!(ctx->encrypt) &&
    (NO_PAYLOAD_LENGTH_SPECIFIED != qat_context->payload_length) &&
    ((qat_context->tls_version) < TLS1_1_VERSION))
        memcpy(ctx->iv, in + len - AES_BLOCK_SIZE, EVP_CIPHER_CTX_iv_length(ctx));

    DEBUG("Pre Perform Op\n");
    DEBUG("Session Ptr: %p\n", qat_context->qat_ctx);
    DUMPREQ(qat_context->instanceHandle, op_done, OPDATA_PTR(agg_req),
            qat_context->session_data, SRC_BUFFER_LIST(agg_req),
            DST_BUFFER_LIST(agg_req));

    if ((sts = cpaCySymPerformOp(qat_context->instanceHandle,
                                 op_done,
                                 OPDATA_PTR(agg_req),
                                 SRC_BUFFER_LIST(agg_req),
                                 DST_BUFFER_LIST(agg_req),
                                 &(qat_context->session_data->verifyDigest))) != CPA_STATUS_SUCCESS)
    {
        WARN("%s: cpaCySymPerformOp failed sts=%d.\n", __func__, sts);
        if (CPA_STATUS_RETRY == sts)
            QATerr(QAT_F_QAT_AES_CBC_HMAC_SHA1_CIPHER_ASYNCH, ERR_R_RETRY);
        goto end;
    }

    /* message has been sent to CPM */
    retVal = 1;
    qat_context->payload_length = NO_PAYLOAD_LENGTH_SPECIFIED;

    /* Update transmission stats */
    qat_context->noRequests++;

    //DEBUG("Post Perform Op\n");
    //DUMPREQ(qat_context->instanceHandle, op_done, OPDATA_PTR(agg_req),
    //        qat_context->session_data, SRC_BUFFER_LIST(agg_req),
    //        DST_BUFFER_LIST(agg_req));

    return retVal;

    end:
    /* QAT structure allocations */
    if(NULL != agg_req)
        destroy_request(agg_req);
    if(NULL != op_done)
        OPENSSL_free(op_done);

    return 0;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_ctrl_asynch(EVP_CIPHER_CTX *ctx,
*                               int type, int arg, void *ptr)
*
* @param ctx    [IN]  - pointer to existing ctx
* @param type   [IN]  - type of request either
*                       EVP_CTRL_AEAD_SET_MAC_KEY or EVP_CTRL_AEAD_TLS1_AAD
* @param arg    [IN]  - size of the pointed to by ptr
* @param ptr    [IN]  - input buffer contain the necessary parameters
*
* @retval x      The return value is dependent on the type of request being made
*       EVP_CTRL_AEAD_SET_MAC_KEY return of 1 is success
*       EVP_CTRL_AEAD_TLS1_AAD return value indicates the amount fo padding to
*               be applied to the SSL/TLS record
* @retval -1     function failed
*
* description:
*    This function is a generic control interface provided by the EVP API. For
*  chained requests this interface is used fro setting the hmac key value for
*  authentication of the SSL/TLS record. The second type is used to specify the
*  TLS virtual header which is used in the authentication calculationa nd to
*  identify record payload size.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_ctrl_asynch(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
    return qat_aes_cbc_hmac_sha1_ctrl(ctx, type, arg, ptr,1);
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*    qat_aes_cbc_hmac_sha1_cleanup_asynch(EVP_CIPHER_CTX *ctx)
*
* @param ctx    [IN]  - pointer to existing ctx
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function will cleanup all allocated resources required to perfrom the
*  cryptographic transform.
*
******************************************************************************/
int qat_aes_cbc_hmac_sha1_cleanup_asynch(EVP_CIPHER_CTX *ctx)
{
    return qat_aes_cbc_hmac_sha1_cleanup(ctx, 1);
}
#endif

