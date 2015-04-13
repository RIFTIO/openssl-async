/* crypto/ui/ui.h -*- mode:C; c-file-style: "eay" -*- */
/*
 * Written by Richard Levitte (richard@levitte.org) for the OpenSSL project
 * 2013.
 */
/* ====================================================================
 * Copyright (c) 2001 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef HEADER_POOL_H
# define HEADER_POOL_H

# ifndef OPENSSL_NO_DEPRECATED
#  include <openssl/crypto.h>
# endif
# include <openssl/ossl_typ.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct openssl_pool_st POOL;

POOL *POOL_init(size_t itemsize, size_t maxitems);
void POOL_free(POOL * p);
void *POOL_alloc_item(POOL * p);
void POOL_free_item(POOL * p, void *item);

# define IMPLEMENT_TYPED_POOL(t,n)                               \
        static POOL *pool_##t = NULL;                           \
        static t* alloc_##t()                                   \
                {                                               \
                if (pool_##t == NULL)                           \
                        {                                       \
                        pool_##t = POOL_init(sizeof(t),(n));    \
                        }                                       \
                return (t *)POOL_alloc_item(pool_##t);          \
                }                                               \
        static void free_##t(t *item)                           \
                {                                               \
                POOL_free_item(pool_##t, item);                 \
                }

# define IMPLEMENT_TYPED_LOCKED_POOL(t,n,l)                      \
        static POOL *pool_##t = NULL;                           \
        static t* alloc_##t()                                   \
                {                                               \
                t *ret = NULL;                                  \
                CRYPTO_w_lock(l);                               \
                if (pool_##t == NULL)                           \
                        {                                       \
                        pool_##t = POOL_init(sizeof(t),(n));    \
                        }                                       \
                ret = (t *)POOL_alloc_item(pool_##t);           \
                CRYPTO_w_unlock(l);                             \
                return ret;                                     \
                }                                               \
        static void free_##t(t *item)                           \
                {                                               \
                CRYPTO_w_lock(l);                               \
                POOL_free_item(pool_##t, item);                 \
                CRYPTO_w_unlock(l);                             \
                }

#ifdef  __cplusplus
}
#endif
#endif
