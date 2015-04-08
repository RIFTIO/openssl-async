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
 * @file qat_sym_common.c
 *
 * This file provides an implementation of Symmetric common functions
 *
 *****************************************************************************/

#include <openssl/evp.h>
#include "cpa.h"
#include "cpa_cy_sym.h"

#include "qat_sym_common.h"
#include "qat_utils.h"
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif
#include "e_qat.h"

#include "string.h"

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         alloc_req_phys( Cpa32U meta_size,
*                          unsigned int req_len,
*                          unsigned int iv_len,
*                          unsigned int digest_len,
*                          AGG_REQ_PHYS* req_phys,
*                          unsigned int first_blk_size )
*
* @param meta_size  [IN] - size of the metadata to be allocated
* @param req_len    [IN] - length of the request data
* @param iv_len     [IN] - length of the iv
* @param digest_len [IN] - length of the digest
* @param req_phys   [IN] - Pointer to the required physical structure
* @param first_blk_size [IN] - length of the first block before the iv
* @retval int - Return 1 on success.
*               Return 0 on failure.
*
* description:
*   This function gets the required physical memory for
*   symetric operations.
******************************************************************************/
int alloc_req_phys(Cpa32U meta_size, unsigned int req_len,
                   unsigned int iv_len, unsigned int digest_len,
                   AGG_REQ_PHYS * req_phys, unsigned int first_blk_size)
{
    unsigned int total_alloc_size = 0;
    unsigned char *mem_blk = NULL;

    if (0 == meta_size || NULL == req_phys) {
        WARN("%s: Input parameters INVALID.\n");
        return 0;
    }

    if (isZeroCopy()) {
        /*
         * Calculate the entire size required 2*meta_size == src/dst private
         * meta data 2*64 bytes in chaining case, 0 in cipher == src/dst data
         * iv_len digest_len 5*64 - space for alignment In zero copy chaining
         * case we allocate 64 byte buffers to place TLS header at the end
         * them. Due PCI performance reasons it is better to have the TLS
         * header at the end of a 64 byte buffer than 13byte buffer
         */
        total_alloc_size =
            (2 * meta_size) + (first_blk_size ? 2 * QAT_BYTE_ALIGNMENT : 0) +
            iv_len + digest_len + 5 * QAT_BYTE_ALIGNMENT;
    } else {
        /*
         * Calculate the entire size required 2*meta_size == src/dst private
         * meta data 2*req_len + 2*first_blk_size== src/dst data iv_len
         * digest_len 5*64 - space for alignment
         */
        total_alloc_size = (2 * meta_size) + (2 * req_len)
            + (2 * first_blk_size) + iv_len + digest_len +
            5 * QAT_BYTE_ALIGNMENT;
    }

    mem_blk = qaeCryptoMemAlloc(total_alloc_size, __FILE__, __LINE__);
    if (!mem_blk) {
        WARN("%s: Unable to allocate request physical memory.\n", __func__);
        return 0;
    }
    // TODO need to handle a meta_size of 0
    req_phys->base_addr = mem_blk;
    req_phys->src_priv_meta = mem_blk;
    req_phys->dst_priv_meta = QAT_MEM_ALIGN(mem_blk + meta_size);

    req_phys->src_data = QAT_MEM_ALIGN(req_phys->dst_priv_meta + meta_size);
    if (isZeroCopy()) {
        /*
         * in zero copy mode 64 byte buffer is used to store the header
         * located at the end of that buffer
         */
        req_phys->dst_data =
            QAT_MEM_ALIGN(req_phys->src_data +
                          (first_blk_size ? QAT_BYTE_ALIGNMENT : 0));
        req_phys->iv =
            QAT_MEM_ALIGN(req_phys->dst_data +
                          (first_blk_size ? QAT_BYTE_ALIGNMENT : 0));
    } else {
        req_phys->dst_data =
            QAT_MEM_ALIGN(req_phys->src_data + (req_len + first_blk_size));
        req_phys->iv =
            QAT_MEM_ALIGN(req_phys->dst_data + (req_len + first_blk_size));
    }
    req_phys->digest_res = QAT_MEM_ALIGN(req_phys->iv + iv_len);

    return 1;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         free_req_phys( AGG_REQ_PHYS* req_phys )
*
* @param req_phys   [IN/OUT] - Pointer to the required physical structure
*
* description:
*   This function frees the required physical memory for
*   symetric operations allocated in the alloc_req_phys function.
******************************************************************************/
void free_req_phys(AGG_REQ_PHYS * req_phys)
{
    if (NULL != req_phys) {
        if (NULL != req_phys->base_addr)
            qaeCryptoMemFree(req_phys->base_addr);
    }
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         populate_op_data( CpaCySymOpData *op_data,
*                           CpaCySymSessionCtx sess_ctx,
*                           EVP_CIPHER_CTX *evp_ctx
*                           size_t inl,
*                           AGG_REQ_PHYS* req_phys )
*
* @param op_data  [IN] - The op_data structure to populate
* @param sess_ctx [IN] - The session context to assign
* @param evp_ctx  [IN] - The evp context used to get the iv info from
* @param inl      [IN] - length of the message to cipher
* @param req_phys [IN] - Pointer to the required physical structure
*                            containing iv data.
* @param header_size [IN] - Size of the header. To distinguish between cipher and chaining
* @retval int - Return 1 on success.
*               Return 0 on failure.
*
* description:
*   This function populates the op_data structure with the required
*   data to make a request.
******************************************************************************/
int populate_op_data(CpaCySymOpData * op_data, CpaCySymSessionCtx sess_ctx,
                     EVP_CIPHER_CTX *evp_ctx, size_t inl,
                     AGG_REQ_PHYS * req_phys, int header_size)
{
    if (NULL == op_data || NULL == evp_ctx) {
        WARN("[%s] Invalid parameters for request\n", __func__);
        return 0;
    }

    op_data->sessionCtx = sess_ctx;
    if (NID_rc4 != EVP_CIPHER_CTX_nid(evp_ctx) &&
        EVP_CIPHER_CTX_test_flags(evp_ctx, EVP_CIPH_CTX_FLAG_CAN_IGNORE_IV))
        op_data->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    else                        // TODO this may be incorrect for chained
        // requests. Test
        op_data->packetType = CPA_CY_SYM_PACKET_TYPE_PARTIAL;

    if (NID_rc4 == EVP_CIPHER_CTX_nid(evp_ctx)) {
        op_data->pIv = NULL;
    } else {
        if (NULL == req_phys) {
            WARN("[%s] Invalid parameter for request\n", __func__);
            return 0;
        }
        op_data->pIv = req_phys->iv;
    }

    if (EVP_CIPHER_CTX_test_flags(evp_ctx, EVP_CIPH_CTX_FLAG_CAN_IGNORE_IV)) {
        // In the case where the CAN_IGNORE_FLAG is set the IV for this
        // request
        // is the first block of the request and is not dependent on any
        // other requests
        if (op_data->pIv)
            memset(op_data->pIv, 0, EVP_CIPHER_CTX_iv_length(evp_ctx));
    } else {
        // This is done to ensure IV is in 64 byte aligned buffer
        if (op_data->pIv)
            memcpy(op_data->pIv, evp_ctx->iv,
                   EVP_CIPHER_CTX_iv_length(evp_ctx));
    }

    if (isZeroCopy() && header_size) {
        op_data->cryptoStartSrcOffsetInBytes =
            QAT_BYTE_ALIGNMENT - header_size;
        op_data->hashStartSrcOffsetInBytes = QAT_BYTE_ALIGNMENT - header_size;
    } else {
        /*
         * Starting point for cipher processing - given as number of bytes
         * from start of data in the source buffer. The result of the cipher
         * operation will be written back into the output buffer starting at
         * this location.
         */
        op_data->cryptoStartSrcOffsetInBytes = 0;
        /*
         * Starting point for hash processing - given as number of bytes from
         * start of packet in source buffer.
         */
        op_data->hashStartSrcOffsetInBytes = 0;
    }
    /*
     * The message length, in bytes, of the source buffer that the hash will
     * be computed on.
     */
    op_data->messageLenToHashInBytes = 0;
    /*
     * Pointer to the location where the digest result either exists or will
     * be inserted.
     */
    op_data->pDigestResult = NULL;
    /*
     * Pointer to Additional Authenticated Data (AAD) needed for
     * authenticated cipher mechanisms - CCM and GCM. For other
     * authentication mechanisms this pointer is ignored.
     */
    op_data->pAdditionalAuthData = NULL;
    /*
     * The message length, in bytes, of the source buffer that the crypto
     * operation will be computed on. This must be a multiple to the block
     * size if a block cipher is being used.
     */
    op_data->messageLenToCipherInBytes = inl;
    /*
     * Cipher IV length in bytes.  Determines the amount of valid IV data
     * pointed to by the pIv parameter.
     */
    op_data->ivLenInBytes = (Cpa32U) EVP_CIPHER_CTX_iv_length(evp_ctx);

    return 1;

}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         link_buffers( AGG_REQ_VIRT* req_virt,
*                       AGG_REQ_PHYS* req_phys,
*                       unsigned int req_len,
*                       unsigned int hdr_size )
*
* @param req_virt [IN] - Pointer to the required virtual structure
* @param req_phys [IN] - Pointer to the required physical structure
* @param req_len  [IN] - The length of the request in bytes
* @param hdr_size [IN] - The size of the header in bytes
*
* @retval int - Return 1 on success.
*               Return 0 on failure.
*
* description:
*   This function populates the virtual data structure from the
*   physical structure.
******************************************************************************/
int link_buffers(AGG_REQ_VIRT * req_virt, AGG_REQ_PHYS * req_phys,
                 unsigned int req_len, unsigned int hdr_size)
{
    if (NULL == req_virt || NULL == req_phys) {
        WARN("[%s] Invalid parameters for request\n", __func__);
        return 0;
    }
    /* TODO: Can we populate this structure with one SIMD operation */
    /* Src Buffer */

    req_virt->src_buf_list.pPrivateMetaData = req_phys->src_priv_meta;

    /* Dst Buffer */
    req_virt->dst_buf_list.pPrivateMetaData = req_phys->dst_priv_meta;

    if (0 != hdr_size) {
        req_virt->src_buf_list.pBuffers = (req_virt->src_buf.chained);
        req_virt->src_buf_list.numBuffers = 2;
        req_virt->dst_buf_list.pBuffers = (req_virt->dst_buf.chained);
        req_virt->dst_buf_list.numBuffers = 2;
        if (isZeroCopy())
            req_virt->src_buf.chained[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;
        else
            req_virt->src_buf.chained[0].dataLenInBytes = (Cpa32U) hdr_size;
        req_virt->src_buf.chained[0].pData = req_phys->src_data;
        req_virt->src_buf.chained[1].dataLenInBytes = (Cpa32U) req_len;
        req_virt->src_buf.chained[1].pData = req_phys->src_data + hdr_size;

        if (isZeroCopy())
            req_virt->dst_buf.chained[0].dataLenInBytes = QAT_BYTE_ALIGNMENT;
        else
            req_virt->dst_buf.chained[0].dataLenInBytes = (Cpa32U) hdr_size;
        req_virt->dst_buf.chained[0].pData = req_phys->dst_data;
        req_virt->dst_buf.chained[1].dataLenInBytes = (Cpa32U) req_len;
        req_virt->dst_buf.chained[1].pData = req_phys->dst_data + hdr_size;
    } else {
        req_virt->src_buf_list.pBuffers = &(req_virt->src_buf.single);
        req_virt->src_buf_list.numBuffers = 1;
        req_virt->src_buf.single.dataLenInBytes = (Cpa32U) req_len;
        req_virt->src_buf.single.pData = req_phys->src_data;

        req_virt->dst_buf_list.pBuffers = &(req_virt->dst_buf.single);
        req_virt->dst_buf_list.numBuffers = 1;
        req_virt->dst_buf.single.dataLenInBytes = (Cpa32U) req_len;
        req_virt->dst_buf.single.pData = req_phys->dst_data;
    }

    return 1;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         set_buf_data( AGG_REQ *agg_req,
*                       EVP_CIPHER_CTX *evp_ctx,
*                       unsigned char *out,
*                       const unsigned char *in,
*                       size_t inl,
*                       const unsigned char *header )
*
* @param agg_req [IN] - Pointer to the request
* @param evp_ctx [IN] - Pointer to the evp context
* @param out     [OUT] - The output buffer to populate
* @param in      [IN] - The input buffer we copy from
* @param inl     [IN] - Length of the input buffer
* @param header  [IN] - The header data if any
*
* @retval int - Return 1 on success.
*               Return 0 on failure.
*
* description:
*   This function populates the output buffer from the input
*   buffer and assignes it into the request
******************************************************************************/
int set_buf_data(AGG_REQ * agg_req, EVP_CIPHER_CTX *evp_ctx,
                 unsigned char *out, const unsigned char *in, size_t inl,
                 const unsigned char *header)
{
    /*
     * TODO: Remove these decisions from the sata path as they are static
     * across the session
     */
    if (NULL == agg_req || NULL == evp_ctx || NULL == in || NULL == out) {
        WARN("[%s] Invalid parameters for request\n", __func__);
        return 0;
    }

    if (isZeroCopy()) {
        if (NID_rc4 == EVP_CIPHER_CTX_nid(evp_ctx) || !EVP_CIPHER_CTX_test_flags(evp_ctx, EVP_CIPH_CTX_FLAG_CAN_IGNORE_IV)) { /* Partial
                                                                                                                               * Packet
                                                                                                                               * processing */
            /*
             * TODO : investigate if this can be avoided in the zero copy
             * mode
             */
            if (in != out)
                memcpy(out, in, inl);

            if (NULL == header)
                agg_req->req_virt.src_buf.single.pData = (Cpa8U *) out;
            else
                agg_req->req_virt.src_buf.chained[1].pData = out;
            agg_req->p_src_buf_list = &(agg_req->req_virt.src_buf_list);
            agg_req->p_dst_buf_list = agg_req->p_src_buf_list;
        } else {
            if (NULL == header) {
                agg_req->req_virt.src_buf.single.pData = (Cpa8U *) in;
                agg_req->req_virt.dst_buf.single.pData = (Cpa8U *) out;
            } else {
                agg_req->req_virt.src_buf.chained[1].pData = (Cpa8U *) in;
                agg_req->req_virt.dst_buf.chained[1].pData = (Cpa8U *) out;
            }
            agg_req->p_src_buf_list = &(agg_req->req_virt.src_buf_list);
            if (in != out)
                agg_req->p_dst_buf_list = &(agg_req->req_virt.dst_buf_list);
            else
                agg_req->p_dst_buf_list = agg_req->p_src_buf_list;
        }
    } else {
        if (NULL == header)
            memcpy(agg_req->req_virt.src_buf.single.pData, in, inl);
        else
            memcpy(agg_req->req_virt.src_buf.chained[1].pData, in, inl);

        agg_req->p_src_buf_list = &(agg_req->req_virt.src_buf_list);
        agg_req->p_dst_buf_list = agg_req->p_src_buf_list;
    }

    if (NULL != header) {
        if (isZeroCopy()) {
            memcpy(agg_req->req_virt.src_buf.chained[0].pData +
                   (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE), header,
                   agg_req->req_virt.src_buf.chained[0].dataLenInBytes -
                   (QAT_BYTE_ALIGNMENT - TLS_VIRT_HDR_SIZE));
        } else {
            memcpy(agg_req->req_virt.src_buf.chained[0].pData, header,
                   agg_req->req_virt.src_buf.chained[0].dataLenInBytes);
        }
    }

    return 1;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         create_chained_request( EVP_CIPHER_CTX *evp_ctx,
*                                 unsigned char* out,
*                                 const unsigned char *in,
*                                 size_t inl,
*                                 CpaCySymSessionCtx sess_ctx,
*                                 Cpa32U meta_size,
*                                 unsigned int digest_len,
*                                 const unsigned char* header,
*                                 unsigned int hdr_size )
*
* @param evp_ctx    [IN] - Pointer to the evp context
* @param out        [OUT] - The output buffer to populate
* @param in         [IN] - The input buffer we copy from
* @param inl        [IN] - Length of the input buffer
* @param sess_ctx   [IN] - The QAT Session Context
* @param meta_size  [IN] - The size of the meta data
* @param digest_len [IN] - The length of the digest in bytes
* @param header     [IN] - The header data if any
* @param hdr_size   [IN] - The header size in bytes
*
* @retval AGG_REQ - Return pointer to request.
*                   Return NULL on failure.
*
* description:
*   This function creates a chained request from the
*   parameters passed in.
******************************************************************************/
AGG_REQ *create_chained_request(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
                                const unsigned char *in, size_t inl,
                                CpaCySymSessionCtx sess_ctx, Cpa32U meta_size,
                                unsigned int digest_len,
                                const unsigned char *header,
                                unsigned int hdr_size)
{
    AGG_REQ *agg_req = NULL;

    if (NULL == (agg_req = OPENSSL_malloc(sizeof(AGG_REQ)))) {
        WARN("[%s] Unable to malloc space for request\n", __func__);
        goto end;
    }

    memset(agg_req, 0, sizeof(AGG_REQ));

    if (0 ==
        alloc_req_phys(meta_size, (unsigned int)inl,
                       EVP_CIPHER_CTX_iv_length(evp_ctx), digest_len,
                       &(agg_req->req_phys), hdr_size))
        goto end;

    if (0 ==
        link_buffers(&(agg_req->req_virt), &(agg_req->req_phys),
                     (unsigned int)inl, hdr_size))
        goto end;

    if (0 == set_buf_data(agg_req, evp_ctx, out, in, inl, header))
        goto end;

    if (0 ==
        populate_op_data(&(agg_req->req_virt.op_data), sess_ctx, evp_ctx, inl,
                         &(agg_req->req_phys), hdr_size))
        goto end;

    return agg_req;

 end:
    if (NULL != agg_req)
        OPENSSL_free(agg_req);
    return NULL;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         create_request( EVP_CIPHER_CTX *evp_ctx,
*                         unsigned char* out,
*                         const unsigned char *in,
*                         size_t inl,
*                         CpaCySymSessionCtx sess_ctx,
*                         Cpa32U meta_size)
*
* @param evp_ctx    [IN] - Pointer to the evp context
* @param out        [OUT] - The output buffer to populate
* @param in         [IN] - The input buffer we copy from
* @param inl        [IN] - Length of the input buffer
* @param sess_ctx   [IN] - The QAT Session Context
* @param meta_size  [IN] - The size of the meta data
*
* @retval AGG_REQ - Return pointer to request.
*                   Return NULL on failure.
*
* description:
*   This function creates a request from the
*   parameters passed in.
******************************************************************************/
AGG_REQ *create_request(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
                        const unsigned char *in, size_t inl,
                        CpaCySymSessionCtx sess_ctx, Cpa32U meta_size)
{
    AGG_REQ *agg_req = NULL;

    if (NULL == (agg_req = OPENSSL_malloc(sizeof(AGG_REQ)))) {
        WARN("[%s] Unable to malloc space for request\n", __func__);
        goto end;
    }

    memset(agg_req, 0, sizeof(AGG_REQ));

    if (0 ==
        alloc_req_phys(meta_size, (unsigned int)inl,
                       EVP_CIPHER_CTX_iv_length(evp_ctx), 0,
                       &(agg_req->req_phys), 0))
        goto end;

    link_buffers(&(agg_req->req_virt), &(agg_req->req_phys),
                 (unsigned int)inl, 0);
    set_buf_data(agg_req, evp_ctx, out, in, inl, NULL);
    populate_op_data(&(agg_req->req_virt.op_data), sess_ctx, evp_ctx, inl,
                     &(agg_req->req_phys), 0);

    return agg_req;

 end:
    if (NULL != agg_req)
        OPENSSL_free(agg_req);
    return NULL;
}
#endif

#ifdef OPENSSL_QAT_ASYNCH
/******************************************************************************
* function:
*         destroy_request( AGG_REQ* agg_req )
*
* @param agg_req    [IN] - The request
*
* description:
*   This function cleans up memory
*   associated with a request.
******************************************************************************/
void destroy_request(AGG_REQ * agg_req)
{
    free_req_phys(&(agg_req->req_phys));
    OPENSSL_free(agg_req);
    agg_req = NULL;
}
#endif
