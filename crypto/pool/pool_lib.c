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

#include <openssl/pool.h>
#include "pool_lcl.h"
#include <stdlib.h>

POOL *POOL_init(size_t itemsize, size_t maxitems)
{
    /* Make sure the itemsize is a multiple of 8 */
    size_t allocated_itemsize = sizeof(POOL_ITEM) + ((itemsize + 7) / 8) * 8;
    size_t poolsize = sizeof(POOL) + allocated_itemsize * maxitems;
    POOL *p = (POOL *) OPENSSL_malloc(poolsize);
    if (p) {
        p->brk = 0;
        p->items = maxitems;
        p->itemsize = allocated_itemsize;
        p->totalsize = poolsize;
        p->next_free = NULL;
    }
    return p;
}

void POOL_free(POOL * p)
{
    OPENSSL_free(p);
}

void *POOL_alloc_item(POOL * p)
{
    POOL_ITEM *pi = NULL;
    if (!p)
        return NULL;
    if (p->next_free) {
        pi = p->next_free;
        p->next_free = p->next_free->next_free;
    } else if (p->brk < p->items) {
        pi = (void *)((char *)(p + 1)
                      + p->itemsize * (p->brk++));
    }
    if (pi)
        return pi + 1;          /* This returns the content, which comes
                                 * directly after the POOL_ITEM structure */
    return NULL;
}

void POOL_free_item(POOL * p, void *item)
{
    if (p && item) {
        /* adjust item so that it points to POOL_ITEM */
        item = item - sizeof(POOL_ITEM);
        /* check that the position is correct and within the pool */
        ssize_t poolpos = item - (void *)p;
        if (poolpos > 0 && poolpos < p->totalsize
            && ((poolpos - sizeof(POOL)) % p->itemsize) == 0) {
            POOL_ITEM *pi = item;
            pi->next_free = p->next_free;
            p->next_free = pi;
        }
    }
}
