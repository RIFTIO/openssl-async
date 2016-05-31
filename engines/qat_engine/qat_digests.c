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
 * @file qat_digests.c
 *
 * This file provides an implementaion of the digest operations for an
 * OpenSSL engine
 *
 *****************************************************************************/

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#include <string.h>
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
#include "qat_digests.h"

/* Qat digest function register */
static int qat_digest_nids[] = {
    NID_sha1,
    NID_md5,
    NID_sha256,
    NID_sha512,
};

#ifndef QAT_MAX_DIGEST_CHAIN_LENGTH
#define QAT_MAX_DIGEST_CHAIN_LENGTH 1000000000
#endif

#ifdef OPENSSL_ENABLE_QAT_DIGEST_SYNCH
#ifdef OPENSSL_DISABLE_QAT_DIGEST_SYNCH
#undef OPENSSL_DISABLE_QAT_DIGEST_SYNCH
#endif
#endif

#ifdef OPENSSL_ENABLE_QAT_DIGEST_ASYNCH
#ifdef OPENSSL_DISABLE_QAT_DIGEST_ASYNCH
#undef OPENSSL_DISABLE_QAT_DIGEST_ASYNCH
#endif
#endif


#ifndef OPENSSL_QAT_ASYNCH
#define OPENSSL_DISABLE_QAT_DIGEST_ASYNCH
#endif

/* How long to wait for inflight messages before cleanup */
#define QAT_CLEANUP_RETRY_COUNT 10
#define QAT_CLEANUP_WAIT_TIME_NS 1000000

#define CTX_NOT_CLEAN       255

static int digest_init_synch(EVP_MD_CTX * ctx);
static int digest_update(EVP_MD_CTX * ctx, const void *data, size_t count);
static int digest_final_synch(EVP_MD_CTX * ctx, unsigned char *md);

#ifdef OPENSSL_QAT_ASYNCH
static int digest_init_asynch(EVP_MD_CTX *ctx,
                   int (*cb)(unsigned char *md, unsigned int size,
                              void *cb_data, int status));
static int digest_update_asynch(EVP_MD_CTX * ctx, const void *data, size_t count,
                                void *cb_data);
static int digest_final_asynch(EVP_MD_CTX *ctx, unsigned char *md, void *cb_data);
static int digest_cleanup_asynch(EVP_MD_CTX * ctx);
#endif

static int qat_digest_copy(EVP_MD_CTX * ctx_out, const EVP_MD_CTX *ctx_in);
static int digest_cleanup(EVP_MD_CTX * ctx);

/* Qat digest SHA1 function structure declaration */
static const EVP_MD qat_sha1 = {
    NID_sha1,                   /* nid */
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE| /* flags */
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef OPENSSL_QAT_ASYNCH
    { digest_init_synch },
    { digest_update },
    { digest_final_synch },
#else
    digest_init_synch,
    digest_update,
    digest_final_synch,
#endif  
    qat_digest_copy,
    digest_cleanup,
#ifdef OPENSSL_QAT_ASYNCH
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
#else
    NULL,                       /* qat_digest_sign */
    NULL,                       /* qat_digest_verify */
#endif
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA_LBLOCK,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};

#ifdef OPENSSL_QAT_ASYNCH
EVP_MD qat_sha1_asynch = {
    NID_sha1,                   /* nid */
    NID_sha1WithRSAEncryption,
    SHA_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT|
    EVP_MD_FLAG_ASYNCH,     /* flags */
    { .asynch = digest_init_asynch },
    { .asynch = digest_update_asynch },
    { .asynch = digest_final_asynch },
    qat_digest_copy,
    digest_cleanup_asynch,
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA_LBLOCK,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};
#endif

/* Qat digest SHA256 function structure declaration */
static const EVP_MD qat_sha256 = {
    NID_sha256,                   /* nid */
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE| /* flags */
    EVP_MD_FLAG_DIGALGID_ABSENT,
#ifdef OPENSSL_QAT_ASYNCH
    { digest_init_synch },
    { digest_update },
    { digest_final_synch },
#else
    digest_init_synch,
    digest_update,
    digest_final_synch,
#endif
    qat_digest_copy,
    digest_cleanup,
#ifdef OPENSSL_QAT_ASYNCH
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
#else
    NULL,                       /* qat_digest_sign */
    NULL,                       /* qat_digest_verify */
#endif
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA256_BLOCK_SIZE,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};

#ifdef OPENSSL_QAT_ASYNCH
EVP_MD qat_sha256_asynch = {
    NID_sha256,                   /* nid */
    NID_sha256WithRSAEncryption,
    SHA256_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT|
    EVP_MD_FLAG_ASYNCH,     /* flags */
    { .asynch = digest_init_asynch },
    { .asynch = digest_update_asynch },
    { .asynch = digest_final_asynch },
    qat_digest_copy,
    digest_cleanup_asynch,
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA256_BLOCK_SIZE,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};
#endif

/* Qat digest SHA384 function structure declaration */
static const EVP_MD qat_sha384 = {
    NID_sha384,                   /* nid */
    NID_sha384WithRSAEncryption,
    SHA384_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT,   /* flags defined above */
#ifdef OPENSSL_QAT_ASYNCH
    { digest_init_synch },
    { digest_update },
    { digest_final_synch },
#else
    digest_init_synch,
    digest_update,
    digest_final_synch,
#endif
    qat_digest_copy,
    digest_cleanup,
#ifdef OPENSSL_QAT_ASYNCH
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
#else
    NULL,                       /* qat_digest_sign */
    NULL,                       /* qat_digest_verify */
#endif
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA512_BLOCK_SIZE,                 /* block size: same of sha512 */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};

#ifdef OPENSSL_QAT_ASYNCH
EVP_MD qat_sha384_asynch = {
    NID_sha384,                   /* nid */
    NID_sha384WithRSAEncryption,
    SHA384_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT|
    EVP_MD_FLAG_ASYNCH,          /* flags defined above */
    { .asynch = digest_init_asynch },
    { .asynch = digest_update_asynch },
    { .asynch = digest_final_asynch },
    qat_digest_copy,
    digest_cleanup_asynch,
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA512_BLOCK_SIZE,                 /* block size: same of sha512 */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};
#endif

/* Qat digest SHA512 function structure declaration */
static const EVP_MD qat_sha512 = {
    NID_sha512,                   /* nid */
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT,   /* flags defined above */
#ifdef OPENSSL_QAT_ASYNCH
    { digest_init_synch },
    { digest_update },
    { digest_final_synch },
#else
    digest_init_synch,
    digest_update,
    digest_final_synch,
#endif
    qat_digest_copy,
    digest_cleanup,
#ifdef OPENSSL_QAT_ASYNCH
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
#else
    NULL,                       /* qat_digest_sign */
    NULL,                       /* qat_digest_verify */
#endif
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA512_BLOCK_SIZE,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};

#ifdef OPENSSL_QAT_ASYNCH
EVP_MD qat_sha512_asynch = {
    NID_sha512,                   /* nid */
    NID_sha512WithRSAEncryption,
    SHA512_DIGEST_LENGTH,          /* output size */
    EVP_MD_FLAG_PKEY_METHOD_SIGNATURE|
    EVP_MD_FLAG_DIGALGID_ABSENT|
    EVP_MD_FLAG_ASYNCH,          /* flags defined above */
    { .asynch = digest_init_asynch },
    { .asynch = digest_update_asynch },
    { .asynch = digest_final_asynch },
    qat_digest_copy,
    digest_cleanup_asynch,
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
    {0, 0, 0, 0, 0}
    ,                           /* EVP pkey */
    SHA512_BLOCK_SIZE,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};
#endif
/* Qat digest MD5 function structure declaration */
static const EVP_MD qat_md5 = {
    NID_md5,                    /* nid */
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,          /* output size */
    0,                          /* flags defined above */
#ifdef OPENSSL_QAT_ASYNCH
    { digest_init_synch },
    { digest_update },
    { digest_final_synch },
#else
    digest_init_synch,
    digest_update,
    digest_final_synch,
#endif
    qat_digest_copy,
    digest_cleanup,
#ifdef OPENSSL_QAT_ASYNCH
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
#else
    NULL,                       /* qat_digest_sign */
    NULL,                       /* qat_digest_verify */
#endif
    {0, 0, 0, 0, 0},            /* EVP pkey */
    MD5_LBLOCK,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};

#ifdef OPENSSL_QAT_ASYNCH
EVP_MD qat_md5_asynch = {
    NID_md5,                   /* nid */
    NID_md5WithRSAEncryption,
    MD5_DIGEST_LENGTH,          /* output size */
    0 | EVP_MD_FLAG_ASYNCH,     /* flags defined above */
    { .asynch = digest_init_asynch },
    { .asynch = digest_update_asynch },
    { .asynch = digest_final_asynch },
    qat_digest_copy,
    digest_cleanup_asynch,
    { NULL },                       /* qat_digest_sign */
    { NULL },                       /* qat_digest_verify */
    {0, 0, 0, 0, 0},            /* EVP pkey */
    MD5_LBLOCK,                 /* block size */
    sizeof(qat_ctx),            /* ctx_size */
    NULL                        /* qat_digest_ctrl */
};
#endif

static
void buffer_list_cleanup(qat_buffer** buff, int count)
{
    qat_buffer* buff_cur = *buff;
    qat_buffer* buff_next = NULL;
    int j = 0;

    for(j=0; j<count; j++)
    {
    if(NULL != buff_cur->data)
            qaeCryptoMemFree (buff_cur->data);
        buff_next = buff_cur->next;
        OPENSSL_free (buff_cur);
        buff_cur = buff_next;
    }
    *buff = NULL;
}

/******************************************************************************
* function:
*         qat_digest_context_copy(EVP_MD_CTX *ctx_out,
*                                 const EVP_MD_CTX *ctx_in)
*
* @param ctx_out [OUT] - pointer to new ctx
* @param ctx_in  [IN]  - pointer to existing context
*
* @retval 0      function succeeded
* @retval 1      function failed
*
* description:
*    This function copies a context.  All buffers are also
*    copied.
******************************************************************************/
static int qat_digest_context_copy (EVP_MD_CTX *ctx_out,
                                    const EVP_MD_CTX *ctx_in)
{
    qat_ctx *qat_out = NULL;
    qat_ctx *qat_in = NULL;
    qat_buffer *buff_in = NULL;
    qat_buffer *buff_out = NULL;
    int i = 0;

    DEBUG("[%s] Function Started \n", __func__);
    if ((!ctx_in) || (!ctx_out))
    {
        WARN("[%s] --- ctx_in or ctx_out is NULL.\n", __func__);
        return 0;
    }

    DEBUG("[%s] %p->%p\n", __func__, ctx_in->md_data, ctx_out->md_data);

    qat_out = (qat_ctx *) (ctx_out->md_data);
    qat_in = (qat_ctx *) (ctx_in->md_data);


    /*  If source or dest context has not yet been initialised, there is nothing
     *  we can do except return success.
     */
    if (!qat_in || !qat_out)
    {
        return 1;
    }

    buff_in = qat_in->first;
    qat_out->first = NULL;

    for (i = 0; i < qat_in->buff_count; i++)
    {
    DEBUG("[%s] --- buff_in %p for iteration %d\n", __func__, buff_in, i);
        buff_out = OPENSSL_malloc (sizeof (qat_buffer));

        if(NULL == buff_out)
        {
           WARN("[%s] --- buff_out is null for iteration %d\n", __func__, i);
           goto end;
        }

        buff_out->data = copyAllocPinnedMemory ((void*) buff_in->data, buff_in->len, __FILE__, __LINE__);
        if(NULL == buff_out->data)
        {
           /* Free resources for this iteration */
           OPENSSL_free (buff_out);
           WARN("[%s] --- buff_out data is null for iteration %d\n", __func__, i);
           goto end;
        }

        buff_out->len = buff_in->len;
        buff_out->next = NULL;

        if (qat_out->first)
        {
            qat_out->last->next = buff_out;
            qat_out->last = buff_out;
        }
        else
        {
            qat_out->first = buff_out;
            qat_out->last = buff_out;
        }

        buff_in = buff_in->next;
    }

    qat_out->buff_count = qat_in->buff_count;
    qat_out->buff_total_bytes = qat_in->buff_total_bytes;
    qat_out->init = qat_in->init;
    qat_out->failed_submission = qat_in->failed_submission;

    DEBUG("[%s] --- qat_out->buff_count = %d\n", __func__, qat_out->buff_count);
    DEBUG("[%s] --- qat_out->buff_total_bytes = %d\n", __func__, qat_out->buff_total_bytes);
    DEBUG("[%s] Function Finished \n", __func__);

    return 1;

end:
    /* Free allocated memory in case of error */
    buffer_list_cleanup(&(qat_out->first), i);
    return 0;

}


/******************************************************************************
* function:
*         qat_digestAsynchCallbackFn(void *callbackTag, CpaStatus status,
*                         const CpaCySymOp operationType, void *pOpData,
*                         CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*
* @param ctx_out [OUT] - pointer to new ctx
* @param ctx_in  [IN]  - pointer to existing context
*
* @retval none
*
* description:
*    In asynchronous mode this is callback we register for the session. This
*    function completes the digest processing before calling the users callback
*
******************************************************************************/
static void qat_digestAsynchCallbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
{
    int sts = 0;
    CpaCySymSessionCtx pSessionCtx = NULL;
    struct op_done_asynch *opDone = callbackTag;
    int cb_status = status == CPA_STATUS_SUCCESS ? 1 : 0;
    CpaCySymOpData *opData = pOpData;

    DEBUG("[%s] Function Started \n", __func__);
    /* Check Params */
    if(NULL == opDone || NULL == pDstBuffer)
    {
        WARN("[%s] --- Invalid input parameter to callback - op_done - pDstBuff.\n", __func__);
    QATerr(QAT_F_QAT_DIGESTASYNCHCALLBACKFN, QAT_R_INVALID_INPUT_PARAMETER);
        return;
    }
    if(NULL == opData)
    {
        WARN("[%s] --- Invalid input parameter to callback - opData.\n", __func__);
        QATerr(QAT_F_QAT_DIGESTASYNCHCALLBACKFN, QAT_R_INVALID_INPUT_PARAMETER);
        return;
    }

    /* Update result */
    memcpy(opDone->orig_out, opData->pDigestResult, EVP_MD_CTX_size(opDone->md_ctx));

    /* Update Reception stats */
    opDone->qat_ctx.single->noResponses++;

    pSessionCtx = opDone->qat_ctx.single->ctx;

    if (NULL == pSessionCtx) {
        WARN("[%s] -- pSessionCtx is NULL\n", __func__);
    }

    sts = cpaCySymRemoveSession(opDone->qat_ctx.single->instanceHandle,
                               pSessionCtx);
    if(CPA_STATUS_SUCCESS != sts)
    {
        WARN("[%s] --- cpaCySymRemoveSession failed, sts = %d.\n",
             __func__, sts);
        /* Carry on trying to clean up */
    }

    /* Free Memory */
    qaeCryptoMemFree (pSessionCtx);

    if(NULL != pDstBuffer->pPrivateMetaData)
       qaeCryptoMemFree(pDstBuffer->pPrivateMetaData);

    OPENSSL_free(pDstBuffer->pBuffers);

    buffer_list_cleanup(&(opDone->qat_ctx.single->first),
         opDone->qat_ctx.single->buff_count);
    opDone->qat_ctx.single->first = NULL;
    opDone->qat_ctx.single->last = NULL;
    opDone->qat_ctx.single->buff_count = 0;
    opDone->qat_ctx.single->buff_total_bytes = 0;

    /* Call user callback */
    opDone->qat_ctx.single->md_cb(opDone->orig_out,
                                     EVP_MD_CTX_size(opDone->md_ctx),
                                     opDone->cb_data, cb_status);

    OPENSSL_free(pDstBuffer);

    qaeCryptoMemFree(opData->pDigestResult);
    OPENSSL_free(opData);

    OPENSSL_free(opDone);

    DEBUG("[%s] Function Finished \n", __func__);

}

/******************************************************************************
* function:
*   digest_init(EVP_MD_CTX *ctx,
*               int (*cb)(unsigned char *md, unsigned int size,
*                       void *cb_data, int status))
*
*
* @param ctx [IN] - pointer to digest ctx
* @param cb [IN]  - function pointer to callback function for async requests
*
* description:
*    This function is rewrite of sha/MD5_init() function in OpenSSL
*    It is the first function called in SHA/MD5 digest routine sequence
*    Function will return 1 if successful
******************************************************************************/
static int
digest_init(EVP_MD_CTX * ctx,
            int (*cb)(unsigned char *md, unsigned int size,
                       void *cb_data, int status))
{
    qat_ctx *qat_context = NULL;

    DEBUG("[%s] Function Started \n", __func__);
    /* Check params */
    if(NULL == ctx)
    {
       WARN("[%s] --- ctx is NULL\n", __func__);
       return 0;
    }

    /*  It does sometimes happen that we are asked to initialise a
     *  context before md_data has been allocated.  We politely refuse
     *  since we have nowhere to store our data but return success anyway.
     *  It will be initialised later on.
     */
    if (NULL == ctx->md_data)
    {
        DEBUG("[%s] --- qat_context not allocated.\n", __func__);
        return 1;
    }

    qat_context = (qat_ctx *) ctx->md_data;

    /* If this ctx has called Init before and been updated
     * with out a clean or final call we must free up the buffers
     * That were created in the update
     */
    if ((CTX_NOT_CLEAN == qat_context->init) && !qat_context->copiedCtx)
    {
        DEBUG("[%s] ---- Init with unclean ctx\n", __func__);
        DEBUG("%s: qat_context->buff_count = %d, ctx = %p\n", __func__, qat_context->buff_count, qat_context);
        buffer_list_cleanup(&(qat_context->first), qat_context->buff_count);
    }

    memset(qat_context ,0x00, sizeof(qat_ctx));

    qat_context->init = 1;
    qat_context->md_cb = cb;

    DEBUG("%s: qat_context %p\n", __func__, qat_context);
    DEBUG("[%s] Function Finished \n", __func__);

    return 1;
}

/******************************************************************************
* function:
*   digest_init_sync(EVP_MD_CTX *ctx)
*
* @param ctx [IN] - pointer to digest ctx
*
* description:
*    Digest init - sync case
******************************************************************************/
static int
digest_init_synch(EVP_MD_CTX * ctx)
{
    return digest_init(ctx, NULL);
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*   digest_init_asynch(EVP_MD_CTX *ctx,
*               int (*cb)(unsigned char *md, unsigned int size,
*
*
* @param ctx [IN] - pointer to digest ctx
* @param cb [IN]  - function pointer to callback function
*
* description:
*    Digest init - asynch case
******************************************************************************/
static int
digest_init_asynch(EVP_MD_CTX *ctx,
                   int (*cb)(unsigned char *md, unsigned int size,
                              void *cb_data, int status))
{
    if(NULL == cb)
    {
       WARN("[%s] --- cb NULL.\n", __func__);
       return 0;
    }
    else
    {
       return digest_init(ctx, cb);
    }
}
#endif

/******************************************************************************
* function:
*         digest_update(EVP_MD_CTX *ctx,
*                         const void *data,
*                         size_t count)
*
* @param ctx   [IN] - pointer to MD ctx
* @param data  [IN] - pointer to chunks of inputdata
* @param count [IN] - message Length To Hash In Bytes
*
* description:
*   This function is rewrite of sha/MD5_update() in OpenSSL,
*   It will be called repeatedly with chunks of target message to be
*   hashed before it pass to cpaCy function.
*   The second function called in SHA/MD5 digest routine sequence
*   and return 1 if successful
******************************************************************************/
static int digest_update(EVP_MD_CTX * ctx, const void *data, size_t count)
{
    qat_ctx *qat_context = NULL;
    qat_buffer *buff;

    DEBUG("[%s] Function Started \n", __func__);
    if (0 == count)
        return 1;

    if (isZeroCopy())
    {
        WARN("[%s] --- digest acceleration does not support zero copy.\n", __func__);
    }

    if ((!ctx) || (!data))
    {
        WARN("[%s] --- ctx or data is NULL.\n", __func__);
        return 0;
    }

    if (NULL == ctx->md_data)
    {
        WARN("[%s] --- qat_context not allocated.\n", __func__);
        return 0;
    }

    qat_context = (qat_ctx *) (ctx->md_data);

    if (0 == qat_context->init)
    {
        WARN("[%s] --- update called before init\n", __func__);
        return 0;
    }

    if (qat_context->buff_total_bytes + count > QAT_MAX_DIGEST_CHAIN_LENGTH)
    {
        WARN("[%s] --- Maximum digest chain length exceeded.\n", __func__);
        return 0;
    }

    buff = OPENSSL_malloc (sizeof (qat_buffer));

    if (!buff)
    {
        WARN("[%s] --- alloc failure.\n", __func__);
        return 0;
    }

    buff->data = copyAllocPinnedMemory ((void*) data, count, __FILE__, __LINE__);
    if (!buff->data)
    {
        WARN("[%s] --- alloc failure.\n", __func__);
        OPENSSL_free (buff);
    buff = NULL;
        return 0;
    }
    buff->len = count;
    buff->next = NULL;

    if (NULL == qat_context->first )
    {
        qat_context->first = buff;
        qat_context->last = buff;
    }
    else
    {
        qat_context->last->next = buff;
        qat_context->last = buff;
    }

    DEBUG("%s: After update: qat_context->first = %p\n", __func__, qat_context->first);
    DEBUG("%s: After update: qat_context->last = %p\n", __func__, qat_context->last);
    qat_context->buff_count++;
    qat_context->buff_total_bytes += count;
    qat_context->init = CTX_NOT_CLEAN;

    DEBUG("%s: added buffer len %d to chain, count now %d len %d, ctx %p\n",
          __func__, (int) count, qat_context->buff_count,
          (int) qat_context->buff_total_bytes, qat_context);

    DEBUG("[%s] Function Finished \n", __func__);

    return 1;
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         digest_update_asynch(EVP_MD_CTX *ctx, const void *data, size_t count,
*                         void *cb_data)
*
* @param ctx   [IN] - pointer to MD ctx
* @param data  [IN] - pointer to chunks of inputdata
* @param count [IN] - message Length To Hash In Bytes
* @param cb_data [IN] - users callback data
*
* description:
*   This function is rewrite of sha/MD5_update() in OpenSSL,
*   It will be called repeatedly with chunks of target message to be
*   processed. It will also call the user's callback function.
*   The second function called in SHA/MD5 digest routine sequence
*   and return 1 if successful
******************************************************************************/
static int
digest_update_asynch(EVP_MD_CTX * ctx, const void *data, size_t count,
                     void *cb_data)
{
    qat_ctx *qat_context = NULL;
    int status = 0;

    DEBUG("[%s] Function Started \n", __func__);
    if ((!ctx) || (!ctx->md_data))
    {
        WARN("[%s] --- ctx or md_data is NULL.\n", __func__);
        return 0;
    }

    status = digest_update(ctx, data, count);

    qat_context = (qat_ctx*)(ctx->md_data);
    if (!status)
        qat_context->failed_submission=1;

    if(!qat_context->md_cb)
    {
        WARN("[%s] --- md_cb is NULL.\n", __func__);
        return 0;
    }

    qat_context->md_cb(NULL, 0, cb_data, status);
    DEBUG("[%s] Function Finished \n", __func__);
    return 1;

}
#endif

/******************************************************************************
* function:
*   digest_final(EVP_MD_CTX *ctx, unsigned char *md, void *cb_data, unsigned int enableAsync)
*
* @param ctx [IN]  - pointer to MD ctx
* @param md  [OUT] - digest message output
* @param cb_data [IN] - users callback data
* @param mode [IN}  - Sync or Async mode.
*
* description:
*   This function is the rewrite of OpenSSL sha/MD5_final() function.
*   It places the digested message in md in case of Sync mode.
*     In Async mode, the digest message is placed in md through associated callback.
*   The third function called in SHA/MD5 digest routine sequence
*   and return 1 if successful
******************************************************************************/
static int
digest_final(EVP_MD_CTX * ctx, unsigned char *md, void *cb_data, unsigned int enableAsync)
{
    CpaCySymSessionCtx pSessionCtx = NULL;
    CpaCySymOpData *OpData = NULL;
    CpaBufferList *srcBufferList = NULL;
    CpaFlatBuffer *srcFlatBuffer = NULL;
    CpaStatus sts = 0;
    Cpa32U metaSize = 0;
    void *srcPrivateMetaData = NULL;
    struct op_done opDoneSync;
    struct op_done_asynch *opDoneAsync = NULL;
    qat_ctx *qat_context = NULL;
    qat_buffer *buff = NULL;
    int i = 0;
    int success = 1;
    int rc = 1;

    CpaCySymSessionSetupData sessionSetupData = { 0 };
    Cpa32U sessionCtxSize = 0;
    CpaInstanceHandle instanceHandle;

    DEBUG("[%s] Function Started \n", __func__);
    CRYPTO_QAT_LOG("DIGEST - %s\n", __func__);

    if ((!ctx) || (!md))
    {
        WARN("[%s] --- ctx or md is NULL.\n", __func__);
        return 0;
    }

    if (!ctx->md_data )
    {
        WARN("[%s] --- qat_context not allocated.\n", __func__);
        return 0;
    }

    qat_context = (qat_ctx *) (ctx->md_data);

    if (0 == qat_context->init)
    {
        WARN("[%s] --- final called before init\n", __func__);
        return 0;
    }

    sessionSetupData.sessionPriority = CPA_CY_PRIORITY_HIGH;
    sessionSetupData.symOperation = CPA_CY_SYM_OP_HASH;
    sessionSetupData.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    sessionSetupData.verifyDigest = CPA_FALSE;
    switch(EVP_MD_CTX_type(ctx))
    {
        case NID_sha1:
            sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA1;
          break;
        case NID_sha256:
            sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
          break;
        case NID_sha384:
            sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA384;
          break;
        case NID_sha512:
            sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA512;
          break;
        case NID_md5:
            sessionSetupData.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_MD5;
          break;
        default:
            WARN("[%s] --- Unsupported Digest Type\n", __func__);
            return 0;
    }
    sessionSetupData.hashSetupData.digestResultLenInBytes = EVP_MD_CTX_size(ctx);

    /* Operation to perform */
    instanceHandle = get_next_inst();
    if ((sts = cpaCySymSessionCtxGetSize(instanceHandle,
                                         &sessionSetupData,
                                         &sessionCtxSize)) !=
        CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCySymSessionCtxGetSize failed, sts = %d.\n",
             __func__, sts);
        return 0;
    }

    /* setup session ctx */
    pSessionCtx = (CpaCySymSessionCtx) qaeCryptoMemAlloc(sessionCtxSize, __FILE__, __LINE__);
    if (NULL == pSessionCtx)
    {
        WARN("[%s] --- pSessionCtx malloc failed.\n", __func__);
        success = 0;
        goto end;
    }
    if(enableAsync)
    {
        if ((sts = cpaCySymInitSession
            (instanceHandle, qat_digestAsynchCallbackFn, &sessionSetupData,
            pSessionCtx)) != CPA_STATUS_SUCCESS)
        {
            WARN("[%s] --- cpaCySymInitSession failed, sts = %d.\n", __func__, sts);
            success = 0;
            goto end;
        }
    }
    else
    {
        if ((sts = cpaCySymInitSession
            (instanceHandle, qat_crypto_callbackFn, &sessionSetupData,
             pSessionCtx)) != CPA_STATUS_SUCCESS)
        {
            WARN("[%s] --- cpaCySymInitSession failed, sts = %d.\n", __func__, sts);
            success = 0;
            goto end;
        }
    }

    qat_context->ctx = pSessionCtx;
    qat_context->instanceHandle = instanceHandle;

    if((NULL == (OpData = OPENSSL_malloc(sizeof(CpaCySymOpData)))) ||
       (NULL == (srcBufferList = OPENSSL_malloc(sizeof(CpaBufferList)))))
    {
        WARN("[%s] --- alloc failure OpData or \
                  srcBufferList \n", __func__);
        success = 0;
        goto end;
    }


    /* OpData structure setup */
    OpData->pDigestResult = qaeCryptoMemAlloc(EVP_MD_CTX_size(ctx), __FILE__, __LINE__);

    if (!OpData->pDigestResult)
    {
        WARN("[%s] --- alloc failure.\n", __func__);
        success = 0;
        goto end;
    }

    OpData->sessionCtx = pSessionCtx;
    OpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    OpData->hashStartSrcOffsetInBytes = 0;
    OpData->messageLenToHashInBytes = qat_context->buff_total_bytes;
    OpData->pAdditionalAuthData = NULL;

    /*  Allocate meta data and flat buffer array for as many buffers
     *  as we are holding in our context linked list.
     */
    if ((sts = cpaCyBufferListGetMetaSize(qat_context->instanceHandle,
                                          qat_context->buff_count, &metaSize)) != CPA_STATUS_SUCCESS)
    {
        WARN("[%s] --- cpaCyBufferListGetBufferSize failed sts=%d.\n",
             __func__, sts);
        success = 0;
        goto end;
    }

    if (metaSize)
    {
        srcPrivateMetaData = qaeCryptoMemAlloc(metaSize, __FILE__, __LINE__);

        if (!srcPrivateMetaData)
        {
            WARN("[%s] --- srcBufferList.pPrivateMetaData is NULL.\n",
                 __func__);
            success = 0;
            goto end;
        }
    }
    else
    {
        srcPrivateMetaData = NULL;
    }

    if (qat_context->buff_count > 0) /* zero length plaintext supported */
    {
        srcFlatBuffer = OPENSSL_malloc (((int) (qat_context->buff_count)) * sizeof (CpaFlatBuffer));
        if (NULL == srcFlatBuffer)
        {
            WARN("[%s] --- FlatBuffer malloc failed.\n", __func__);
            success = 0;
            goto end;
        }
    }

    /*  Populate the pData and length elements of the flat buffer array
     *  from the context linked list of qat_buffers
     */
    buff = qat_context->first;

    for (i = 0; i < qat_context->buff_count; i++)
    {
        srcFlatBuffer[i].pData = buff->data;
        srcFlatBuffer[i].dataLenInBytes = (Cpa32U) buff->len;
        buff = buff->next;
    }

    /* Number of pointers */
    srcBufferList->numBuffers = qat_context->buff_count;

    /* Pointer to an unbounded array containing the number of CpaFlatBuffers
       defined by numBuffers */
    srcBufferList->pBuffers = srcFlatBuffer;
    /* This is an opaque field that is not read or modified internally. */
    srcBufferList->pUserData = NULL;

    srcBufferList->pPrivateMetaData = srcPrivateMetaData;

    if(enableAsync)
    {
        if(NULL == (opDoneAsync = OPENSSL_malloc(sizeof(struct op_done_asynch))))
        {
            WARN("[%s] --- alloc op_done", __func__);
            success = 0;
            goto end;
        }
        qat_context->failed_submission=0;
        opDoneAsync->md_ctx = ctx;
        opDoneAsync->orig_out = md;
        opDoneAsync->qat_ctx.single = qat_context;
        opDoneAsync->cb_data = cb_data;
        if((sts = cpaCySymPerformOp(qat_context->instanceHandle,
            opDoneAsync,
            OpData,
            srcBufferList,
            srcBufferList,
            CPA_FALSE )) != CPA_STATUS_SUCCESS)
        {
            if(CPA_STATUS_RETRY == sts) {
                QATerr(QAT_F_DIGEST_FINAL, ERR_R_RETRY);
            }
            success = 0;
            goto end;
        }
        /* Update transmission stats */
        qat_context->noRequests++;
        DEBUG("[%s] Function Finished \n", __func__);
        return 1;
    }
    else
    {
        initOpDone(&opDoneSync);

        if (((sts = myPerformOp(qat_context->instanceHandle,
            &opDoneSync,
            OpData,
            srcBufferList,
            srcBufferList,
            CPA_FALSE )) != CPA_STATUS_SUCCESS) ||
            ((rc = waitForOpToComplete(&opDoneSync)) != 0))
        {
            if (sts != CPA_STATUS_SUCCESS)
            {
                WARN("[%s] --- cpaCySymPerformOp failed sts=%d.\n", __func__, sts);
            }
            else
            {
                WARN("[%s] --- cpaCySymPerformOp timed out.\n", __func__);
            }
            cleanupOpDone(&opDoneSync);
            success = 0;
        }
        else
        {
            cleanupOpDone(&opDoneSync);
            memcpy(md, OpData->pDigestResult, EVP_MD_CTX_size(ctx));
        }

        sts = cpaCySymRemoveSession(qat_context->instanceHandle,
                               pSessionCtx);
        if(CPA_STATUS_SUCCESS != sts)
        {
            WARN("[%s] --- cpaCySymRemoveSession failed, sts = %d.\n",
             __func__, sts);
            success = 0;
        }

        qat_context->ctx = NULL;
        qat_context->init = 0;


        DEBUG("[%s] Function Finished \n", __func__);
    }

    end:
    if(NULL != pSessionCtx)
    {
        qaeCryptoMemFree(pSessionCtx);
        qat_context->ctx = NULL;
    }

    if( NULL != OpData )
    {
        if(NULL != OpData->pDigestResult)
        qaeCryptoMemFree(OpData->pDigestResult);
        OPENSSL_free(OpData);
    }

    if(NULL != srcBufferList)
        OPENSSL_free(srcBufferList);

    if(NULL != srcPrivateMetaData)
        qaeCryptoMemFree (srcPrivateMetaData);

    if(NULL != srcFlatBuffer)
        OPENSSL_free(srcFlatBuffer);
    /*  Free the list of chained buffers
     */
    if(!enableAsync && NULL != qat_context->first)
    {
        buffer_list_cleanup(&(qat_context->first), qat_context->buff_count);
        qat_context->first = NULL;
        qat_context->last = NULL;
        qat_context->buff_count = 0;
        qat_context->buff_total_bytes = 0;
    }
    if(NULL != opDoneAsync)
        OPENSSL_free(opDoneAsync);

    return success;
}



/******************************************************************************
* function:
*   digest_final_synch(EVP_MD_CTX *ctx,
*                unsigned char *md)
*
* @param ctx [IN]  - pointer to MD ctx
* @param md  [OUT] - digest message output
*
* description:
*   Digest Final in synch case
******************************************************************************/
static int digest_final_synch(EVP_MD_CTX * ctx, unsigned char *md)
{
    return digest_final( ctx, md, NULL, 0);
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*   digest_final_asynch(EVP_MD_CTX *ctx, void *cb_data)
*
* @param ctx [IN]  - pointer to MD ctx
* @param cb_data [IN] - users callback data
*
* description:
*   Digest Final in asynch case
******************************************************************************/
static int
digest_final_asynch(EVP_MD_CTX * ctx, unsigned char *md, void *cb_data)
{
    qat_ctx *qat_context = NULL;
    int status = 0;

    DEBUG("[%s] Function Started \n", __func__);
    if ((!ctx) || (!ctx->md_data))
    {
        WARN("[%s] --- ctx or md_data is NULL.\n", __func__);
        return status;
    }

    status = digest_final( ctx, md, cb_data, 1);

    if (!status)
    {
        qat_context = (qat_ctx*)(ctx->md_data);
        qat_context->failed_submission=1;
    }

    DEBUG("[%s] Function Finished \n", __func__);
    return status;
}
#endif

/******************************************************************************
* function:
*   int digest_cleanup(EVP_MD_CTX *ctx)
*
* @param ctx [IN] - pointer to sha ctx
*
* description:
*     This function is the rewrite of OpenSSL digest xxx_cleanup() function.
*     It design to set digested message in ctx to zeros if there is still values in it.
*     The last function called in the digest routine sequence
*     and return 1 if successful
******************************************************************************/
static int digest_cleanup(EVP_MD_CTX * ctx)
{
    qat_ctx *qat_context = NULL;

    DEBUG("[%s] Function Started \n", __func__);
    if (!ctx)
    {
        WARN("[%s] --- ctx is NULL.\n", __func__);
        return 0;
    }

    if ( NULL == ctx->md_data )
    {
        DEBUG ("[%s] --- qat_context not allocated.\n", __func__);
        return 1;
    }

    qat_context = (qat_ctx *) (ctx->md_data);

    if (0 == qat_context->init)
    {
        return 1;
    }

    buffer_list_cleanup(&(qat_context->first), qat_context->buff_count);

    qat_context->first = NULL;
    qat_context->last = NULL;
    qat_context->buff_count = 0;
    qat_context->buff_total_bytes = 0;
    qat_context->init = 0;

    DEBUG("[%s] Function Finished \n", __func__);
    return 1;
}

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*   int digest_cleanup_asynch(EVP_MD_CTX *ctx)
*
* @param ctx [IN] - pointer to sha ctx
*
* description:
*     This function is the rewrite of OpenSSL digest xxx_cleanup() function.
*     It design to set digested message in ctx to zeros if there is still values in it.
*     The last function called in the digest routine sequence
*     and return 1 if successful
******************************************************************************/
static int digest_cleanup_asynch(EVP_MD_CTX * ctx)
{
    qat_ctx *qat_context = NULL;

    DEBUG("[%s] Function Started \n", __func__);
    if (!ctx)
    {
        WARN("[%s] --- ctx is NULL.\n", __func__);
        return 0;
    }

    if ( NULL == ctx->md_data )
    {
        DEBUG ("[%s] --- qat_context not allocated.\n", __func__);
        return 1;
    }

    qat_context = (qat_ctx *) (ctx->md_data);

    if (0 == qat_context->init)
    {
        /*No warning here as this maybe legitimate if the callback has cleaned up already. */
        return 1;
    }

    if (1 == qat_context->failed_submission)
    {
        buffer_list_cleanup(&(qat_context->first), qat_context->buff_count);

        qat_context->first = NULL;
        qat_context->last = NULL;
        qat_context->buff_count = 0;
        qat_context->buff_total_bytes = 0;
        qat_context->init = 0;
        qat_context->failed_submission = 0;
    }

    DEBUG("[%s] Function Finished \n", __func__);
    return 1;
}
#endif

/******************************************************************************
* function:
*         qat_digest_copy(EVP_MD_CTX *ctx_out,
*                        const EVP_MD_CTX *ctx_in)
*
* @param ctx_out [OUT] - pointer to new ctx
* @param ctx_in  [IN]  - pointer to existing context
*
* description:
*    This function copies a context and creates a new session
*    to be associated with this context.  All buffers are also
*    copied.
******************************************************************************/
static int qat_digest_copy (EVP_MD_CTX *ctx_out, const EVP_MD_CTX *ctx_in)
{
    int sts = 1;
    qat_ctx *qat_context = NULL;

    DEBUG("[%s] Function Started \n", __func__);
    if ((!ctx_in) || (!ctx_out))
    {
        WARN("[%s] --- ctx_in or ctx_out is NULL.\n", __func__);
        return 0;
    }

    qat_context = ctx_out?ctx_out->md_data:NULL;

    if(qat_context != NULL)
    {
       qat_context->copiedCtx = 1;
       sts = digest_init(ctx_out, qat_context->md_cb);
    }

    if(sts)
       sts = qat_digest_context_copy (ctx_out, ctx_in);

    DEBUG("[%s] Function Finished \n", __func__);
    return sts;
}

/******************************************************************************
* function:
*         qat_digests(ENGINE *e,
*                     const EVP_MD **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param digest [IN] - digest structure pointer
* @param nids   [IN] - digest functions nids
* @param nid    [IN] - digest operation id
*
* description:
*   Qat engine digest operations registrar
******************************************************************************/
static int
qat_digests(ENGINE * e, const EVP_MD ** digest, const int **nids, int nid,
            int isAsynch)
{
    int ok = 1;

    /* No specific digest => return a list of supported nids ... */
    if (!digest)
    {
        *nids = qat_digest_nids;
        /* num digests supported (array/numelements -1) */
        return (sizeof(qat_digest_nids) / sizeof(qat_digest_nids[0]));
    }

    if(!isAsynch)
    {
#ifndef OPENSSL_DISABLE_QAT_DIGEST_SYNCH
        switch (nid)
        {
            case NID_sha1:
                *digest = &qat_sha1;
                break;
            case NID_sha256:
                *digest = &qat_sha256;
                break;
            case NID_sha384:
                *digest = &qat_sha384;
                break;
            case NID_sha512:
                *digest = &qat_sha512;
                break;
            case NID_md5:
                *digest = &qat_md5;
                break;
            default:
                WARN("[%s] --- Algorithm not supported by QAT engine\n", __func__);
                ok = 0;
                *digest = NULL;
        }
#else
        switch (nid)
        {
            case NID_sha1:
                *digest = EVP_sha1();
                break;
            case NID_sha256:
                *digest = EVP_sha256();
                break;
            case NID_sha384:
                *digest = EVP_sha384();
                break;
            case NID_sha512:
                *digest = EVP_sha512();
                break;
            case NID_md5:
                *digest = EVP_md5();
                break;
            default:
                WARN("[%s] --- Algorithm not supported by QAT engine\n", __func__);
                ok = 0;
                *digest = NULL;
        }
#endif /* OPENSSL_DISABLE_QAT_DIGEST_SYNCH  */
    }
else
    {
#ifndef OPENSSL_DISABLE_QAT_DIGEST_ASYNCH
        switch (nid)
        {
            case NID_sha1:
                *digest = &qat_sha1_asynch;
                break;
            case NID_sha256:
                *digest = &qat_sha256_asynch;
                break;
            case NID_sha384:
                *digest = &qat_sha384_asynch;
                break;
            case NID_sha512:
                *digest = &qat_sha512_asynch;
                break;
            case NID_md5:
                *digest = &qat_md5_asynch;
                break;
            default:
                WARN("[%s] --- Algorithm not supported by QAT engine\n", __func__);
                ok = 0;
                *digest = NULL;
        }
#else
    WARN("[%s] --- Algorithm not supported by QAT engine\n", __func__);
    ok = 0;
    *digest = NULL;
#endif /* OPENSSL_DISABLE_QAT_DIGEST_ASYNCH */
    }
    return ok;
}

/******************************************************************************
* function:
*   qat_digests_sync(ENGINE *e,
*                     const EVP_MD **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param digest [IN] - digest structure pointer
* @param nids   [IN] - digest functions nids
* @param nid    [IN] - digest operation id
*
* description:
*    Qat Digests - sync case
******************************************************************************/

int
qat_digests_synch(ENGINE * e, const EVP_MD ** digest, const int **nids, int nid)
{
    return qat_digests(e, digest, nids, nid, 0);
}

/******************************************************************************
* function:
*   qat_digests_asynch(ENGINE *e,
*                     const EVP_MD **digest,
*                     const int **nids,
*                     int nid)
*
* @param e      [IN] - OpenSSL engine pointer
* @param digest [IN] - digest structure pointer
* @param nids   [IN] - digest functions nids
* @param nid    [IN] - digest operation id
*
* description:
*    Qat Digests - asynch case
******************************************************************************/

int
qat_digests_asynch(ENGINE * e, const EVP_MD ** digest, const int **nids, int nid)
{
    return qat_digests(e, digest, nids, nid, 1);
}
