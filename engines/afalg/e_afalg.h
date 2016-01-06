/* ====================================================================
 * Copyright (c) 1999-2016 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef _E_AFALG_H_
# define _E_AFALG_H_

/*
 * If compiling with Unit Tests disable local linkage.
 */
# ifndef AFALG_NO_UNIT_TEST
#  define STATIC static
# else
#  define STATIC
# endif

#define ALG_DGB(x, args...) fprintf(stderr, "ALG_DBG: " x, ##args)
#define ALG_INFO(x, args...) fprintf(stderr, "ALG_INFO: " x, ##args)
#define ALG_WARN(x, args...) fprintf(stderr, "ALG_WARN: " x, ##args)
#define ALG_ERR(x, args...) fprintf(stderr, "ALG_ERR: " x, ##args)
#define ALG_PERR(x, args...) \
                do { \
                    fprintf(stderr, "ALG_PERR: " x, ##args); \
                    perror(NULL); \
                } while(0)

# ifndef AES_BLOCK_SIZE
#  define AES_BLOCK_SIZE   16
# endif
# define AES_KEY_SIZE_128 16
# define AES_IV_LEN       16

# define MAGIC_INIT_NUM 0x1890671

struct afalg_ctx_st {
    int init_done;
    int sfd;
# ifdef ALG_ZERO_COPY
    int zc_pipe[2];
# endif
    void *aio;
};

typedef struct afalg_ctx_st afalg_ctx;
#endif
