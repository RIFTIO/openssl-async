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
 * @file qat_chain.h
 *
 * This file provides a interface for engine chain cipher operations
 *
 *****************************************************************************/

#ifndef QAT_CHAIN_H
#define QAT_CHAIN_H

#include <openssl/engine.h>


/* Qat engine AES-SHA1 sync chaining function declarations */
int qat_aes_cbc_hmac_sha1_init_sync(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *inkey,
                                      const unsigned char *iv, int enc);
int qat_aes_cbc_hmac_sha1_cipher_sync(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                        const unsigned char *in, size_t len);
int qat_aes_cbc_hmac_sha1_cleanup_sync(EVP_CIPHER_CTX *ctx);
int qat_aes_cbc_hmac_sha1_ctrl_sync(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

/* Qat engine AES-SHA1 async chaining function declarations */
int qat_aes_cbc_hmac_sha1_init_asynch(EVP_CIPHER_CTX *ctx,
                                      const unsigned char *inkey,
                                      const unsigned char *iv, int enc,
                                      int (*cb)(unsigned char *out, int outl,
                                                void *cb_data, int status));
int qat_aes_cbc_hmac_sha1_cipher_asynch(EVP_CIPHER_CTX *ctx, 
					unsigned char *out,
                                        const unsigned char *in, size_t len,
                                        void *cb_data);
int qat_aes_cbc_hmac_sha1_cleanup_asynch(EVP_CIPHER_CTX *ctx);
int qat_aes_cbc_hmac_sha1_ctrl_asynch(EVP_CIPHER_CTX *ctx, int type, 
					     int arg, void *ptr);

EVP_CIPHER qat_aes_128_cbc_hmac_sha1, qat_aes_256_cbc_hmac_sha1;
EVP_CIPHER qat_aes_128_cbc_hmac_sha1_asynch, qat_aes_256_cbc_hmac_sha1_asynch;
			 
#endif //QAT_CHAIN_H
