
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
 * @file qat_rsa.h
 *
 * This file provides an RSA interface for an OpenSSL engine
 *
 *****************************************************************************/

#ifndef QAT_RSA_H
#define QAT_RSA_H

#include <openssl/rsa.h>

/* Qat engine RSA methods declaration */
int qat_rsa_priv_enc_synch(int flen, const unsigned char *from, 
                     unsigned char *to, RSA * rsa, int padding);
int qat_rsa_pub_dec_synch(int flen, const unsigned char *from, 
                    unsigned char *to, RSA * rsa, int padding);
int qat_rsa_priv_dec_synch(int flen, const unsigned char *from, 
                     unsigned char *to, RSA * rsa, int padding);
int qat_rsa_mod_exp(BIGNUM * r0, const BIGNUM * I, RSA * rsa, BN_CTX * ctx);
int qat_bn_mod_exp(BIGNUM * r, const BIGNUM * a, const BIGNUM * p,
                   const BIGNUM * m, BN_CTX * ctx, BN_MONT_CTX * m_ctx);
int qat_rsa_pub_enc_synch(int flen, const unsigned char *from, unsigned char *to, 
                    RSA * rsa, int padding);

int qat_rsa_priv_enc_asynch(int flen, const unsigned char *from, unsigned char *to,
                        RSA * rsa, int padding,
                        int (*cb)(unsigned char *res, size_t reslen,
                                  void *cb_data, int status),
                        void *cb_data);
int qat_rsa_priv_dec_asynch(int flen, const unsigned char *from,
                            unsigned char *to, RSA * rsa, int padding,
                            int (*cb)(unsigned char *res, size_t reslen,
                                      void *cb_data, int status),
                            void *cb_data);
int qat_rsa_pub_enc_asynch(int flen, const unsigned char *from,
                           unsigned char *to, RSA * rsa, int padding,
                           int (*cb)(unsigned char *res, size_t reslen,
                                void *cb_data, int status),
                           void *cb_data);
int qat_rsa_pub_dec_asynch(int flen, const unsigned char *from, unsigned char *to,
                        RSA * rsa, int padding,
                        int (*cb)(unsigned char *res, size_t reslen,
                                void *cb_data, int status),
                        void *cb_data);

RSA_METHOD *get_RSA_methods(void);

#endif //QAT_RSA_H
