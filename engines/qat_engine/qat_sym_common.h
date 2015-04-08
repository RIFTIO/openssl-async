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
 * @file qat_sym_common.h
 *
 * This file provides an interface to Common Symmetric functions
 *
 *****************************************************************************/

#ifndef QAT_SYM_COMMON_H
# define QAT_SYM_COMMON_H

# include <openssl/ossl_typ.h>

# include "cpa.h"
# include "cpa_cy_sym.h"

typedef struct agg_req_virt_st AGG_REQ_VIRT;

struct agg_req_virt_st {
    CpaBufferList src_buf_list;
    CpaBufferList dst_buf_list;
    union {
        CpaFlatBuffer single;
        CpaFlatBuffer chained[2];
    } src_buf;
    union {
        CpaFlatBuffer single;
        CpaFlatBuffer chained[2];
    } dst_buf;

    CpaCySymOpData op_data;
};

typedef struct agg_req_phys_st AGG_REQ_PHYS;
struct agg_req_phys_st {
    void *base_addr;
    void *src_priv_meta;
    void *dst_priv_meta;
    Cpa8U *src_data;
    Cpa8U *dst_data;
    Cpa8U *iv;
    Cpa8U *digest_res;
};

typedef struct agg_req_st AGG_REQ;
struct agg_req_st {
    AGG_REQ_VIRT req_virt;
    AGG_REQ_PHYS req_phys;
    /*
     * These are pointers to the CpaBufferLists in req_virt and are needed to
     * support partial packets
     */
    CpaBufferList *p_src_buf_list;
    CpaBufferList *p_dst_buf_list;
};

# define SRC_BUFFER_LIST(agg_req) (agg_req->p_src_buf_list)
# define SRC_BUFFER_DATA(agg_req) (agg_req->p_src_buf_list->pBuffers)
# define DST_BUFFER_LIST(agg_req) (agg_req->p_dst_buf_list)
# define DST_BUFFER_DATA(agg_req) (agg_req->p_dst_buf_list->pBuffers)
# define OPDATA_PTR(agg_req) (&(agg_req->req_virt.op_data))

AGG_REQ *create_request(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
                        const unsigned char *in, size_t inl,
                        CpaCySymSessionCtx sess_ctx, Cpa32U meta_size);

AGG_REQ *create_chained_request(EVP_CIPHER_CTX *evp_ctx, unsigned char *out,
                                const unsigned char *in, size_t inl,
                                CpaCySymSessionCtx sess_ctx, Cpa32U meta_size,
                                unsigned int digest_len,
                                const unsigned char *header,
                                unsigned int hdr_size);

void destroy_request(AGG_REQ * agg_req);

#endif                          // QAT_SYM_COMMON_H
