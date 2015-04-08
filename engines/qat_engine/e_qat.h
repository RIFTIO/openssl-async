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
 * @file e_qat.h
 *
 * This file provides and interface for an OpenSSL QAT engine implemenation
 *
 *****************************************************************************/

#ifndef E_QAT_H
# define E_QAT_H

# include <openssl/sha.h>
# include <openssl/aes.h>
# include <sys/types.h>
# include <unistd.h>

# include "cpa.h"
# include "cpa_types.h"
# include "cpa_cy_sym.h"
# include "cpa_cy_drbg.h"

# include "qat_sym_common.h"
# include "qat_digests.h"
# include "qat_ciphers.h"

# define QAT_RETRY_BACKOFF_MODULO_DIVISOR 8
# define QAT_INFINITE_MAX_NUM_RETRIES -1

# ifndef ERR_R_RETRY
#  define ERR_R_RETRY 57
# endif

typedef struct qat_chained_ctx_t {
    /*
     * While decryption is done in SW the first elements of this structure
     * need to be the elements present in EVP_AES_HMAC_SHA1 defined in
     * crypto/evp/e_aes_cbc_hmac_sha1.c
     */
    AES_KEY ks;
    SHA_CTX head, tail, md;
    size_t payload_length;      /* AAD length in decrypt case */
    union {
        unsigned int tls_ver;
        unsigned char tls_aad[16]; /* 13 used */
    } aux;

    /* QAT Session Params */
    CpaInstanceHandle instanceHandle;
    CpaCySymSessionSetupData *session_data;
    CpaCySymSessionCtx qat_ctx;
    int initParamsSet;
    int initHmacKeySet;
    int init;

    /* QAT Op Params */
    CpaCySymOpData OpData;
    CpaBufferList srcBufferList;
    CpaBufferList dstBufferList;
    CpaFlatBuffer srcFlatBuffer[2];
    CpaFlatBuffer dstFlatBuffer[2];

    /* Crypto */
    unsigned char *hmac_key;
    Cpa8U *pIv;
    SHA_CTX key_wrap;

    /* TLS SSL proto */
    /*
     * Reintroduce when QAT decryption added size_t payload_length;
     */
    Cpa8U *tls_virt_hdr;
    Cpa8U tls_hdr[TLS_VIRT_HDR_SIZE];
    unsigned int tls_version;

    int (*cipher_cb) (unsigned char *out, int outl, void *cb_data,
                      int status);

    /* Request tracking stats */
    Cpa64U noRequests;
    Cpa64U noResponses;

    unsigned int meta_size;

} qat_chained_ctx;

/* qat_buffer structure for partial hash */
typedef struct qat_buffer_t {
    struct qat_buffer_t *next;  /* next buffer in the list */
    void *data;                 /* point to data buffer */
    int len;                    /* length of data */
} qat_buffer;

/* Qat ctx structure declaration */
typedef struct qat_ctx_t {
    int paramNID;               /* algorithm nid */
    CpaCySymSessionCtx ctx;     /* session context */
    unsigned char hashResult[SHA512_DIGEST_LENGTH];
    /* hash digest result */
    int enc;                    /* encryption flag */
    int init;                   /* has been initialised */
    int copiedCtx;              /* whether this is a copied context for
                                 * initialisation purposes */
    CpaInstanceHandle instanceHandle;
    Cpa32U nodeId;
    /*
     * the memory for the private meta data must be allocated as contiguous
     * memory. The cpaCyBufferListGetMetaSize() will return the size (in
     * bytes) for memory allocation routine to allocate the private meta data
     * memory
     */
    void *srcPrivateMetaData;   /* meta data pointer */
    void *dstPrivateMetaData;   /* meta data pointer */
    /*
     * For partial operations, we maintain a linked list of buffers to be
     * processed in the final function.
     */
    qat_buffer *first;          /* first buffer pointer for partial op */
    qat_buffer *last;           /* last buffer pointe for partial op */
    int buff_count;             /* buffer count */
    int buff_total_bytes;       /* total number of bytes in buffer */
    int failed_submission;      /* flag as a failed submission to aid cleanup */
    /* Request tracking stats */
    Cpa64U noRequests;
    Cpa64U noResponses;
    int (*cipher_cb) (unsigned char *out, int outl, void *cb_data,
                      int status);
    int (*md_cb) (unsigned char *md, unsigned int size, void *cb_data,
                  int status);
    CpaCySymSessionSetupData *session_data;
    Cpa32U meta_size;
} qat_ctx;

/* Struct for tracking threaded QAT operation completion. */
struct op_done {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int flag;
    CpaBoolean verifyResult;
};

struct op_done_asynch {
    EVP_CIPHER_CTX *cipher_ctx;
    EVP_MD_CTX *md_ctx;
    unsigned char *orig_out;
    unsigned int orig_len;
    unsigned char *cur_out;
    unsigned int cur_len;
    CpaBufferList *srcBufferList;
    CpaFlatBuffer *srcFlatBuffer;
    CpaBufferList *dstBufferList;
    CpaFlatBuffer *dstFlatBuffer;
    CpaBoolean verifyResult;
    void *cb_data;
    union {
        qat_ctx *single;
        qat_chained_ctx *chain;
    } qat_ctx;
    AGG_REQ *agg_req;
};

CpaInstanceHandle get_next_inst(void);
void initOpDone(struct op_done *opDone);
void cleanupOpDone(struct op_done *opDone);
int waitForOpToComplete(struct op_done *opDone);
void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer,
                           CpaBoolean verifyResult);
CpaStatus myPerformOp(const CpaInstanceHandle instanceHandle,
                      void *pCallbackTag, const CpaCySymOpData * pOpData,
                      const CpaBufferList * pSrcBuffer,
                      CpaBufferList * pDstBuffer, CpaBoolean * pVerifyResult);
int isZeroCopy();
useconds_t getQatPollInterval();
int getQatMsgRetryCount();
#endif                          // E_QAT_H
