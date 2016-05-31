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
 * @file qat_ciphers.h
 *
 * This file provides a interface for engine cipher operations
 *
 *****************************************************************************/

#ifndef QAT_CIPHERS_H
#define QAT_CIPHERS_H

#include <openssl/engine.h>

#define RC4_BLOCK_SIZE	    1
#define RC4_IV_LEN  	    0
#define RC4_KEY_SIZE  	    16
#define RC4_FLAGS      	    0

#define DES_BLOCK_SIZE	    8
#define DES_KEY_SIZE	    8
#define DES_IV_LEN	        8

#define DES3_BLOCK_SIZE	    8
#define DES3_KEY_SIZE	    24
#define DES3_IV_LEN	        8

#define AES_BLOCK_SIZE      16
#define AES_IV_LEN          16
#define AES_KEY_SIZE_256    32
#define AES_KEY_SIZE_192    24
#define AES_KEY_SIZE_128    16

#define data(ctx) ((qat_chained_ctx *)(ctx)->cipher_data)
#define HMAC_KEY_SIZE       64
#define TLS_VIRT_HDR_SIZE   13

#define NO_PAYLOAD_LENGTH_SPECIFIED ((size_t)-1)

/* How long to wait for inflight messages before cleanup */
#define QAT_CIPHER_CLEANUP_RETRY_COUNT 10
#define QAT_CIPHER_CLEANUP_WAIT_TIME_NS 1000000

#define qat_common_cipher_flags EVP_CIPH_FLAG_DEFAULT_ASN1
#define qat_common_cbc_flags    (qat_common_cipher_flags | EVP_CIPH_CBC_MODE \
                                | EVP_CIPH_CUSTOM_IV)

#define QAT_TLS_PAYLOADLENGTH_MSB_OFFSET 2
#define QAT_TLS_PAYLOADLENGTH_LSB_OFFSET 1
#define QAT_TLS_VERSION_MSB_OFFSET       4
#define QAT_TLS_VERSION_LSB_OFFSET       3
#define QAT_BYTE_SHIFT                   8

int qat_ciphers_synch(ENGINE * e, const EVP_CIPHER ** cipher, const int **nids, int nid);
int qat_ciphers_asynch(ENGINE * e, const EVP_CIPHER ** cipher, const int **nids, int nid);

#endif //QAT_CIPHERS_H
