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
 * @file qat_mem_drv_inf.c
 *
 * This file provides an interface to use a memory driver to provide contig
 * pinned memory.
 *
 *****************************************************************************/

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include "qat_utils.h"
#include "qat_mem_drv_inf.h"
#include "qae_mem.h"

static int mem_inited = 0;
static int ref_count = 0;
static pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER;
static CpaStatus qaeCryptoMemInit(void);
static void qaeCryptoMemDestroy(void);

#ifdef QAT_DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define ERROR(...) fprintf(stderr, __VA_ARGS__)


#ifdef QAT_WARN
#define WARN(...) fprintf (stderr, __VA_ARGS__)
#else
#define WARN(...)
#endif

void qaeCryptoMemFree(void* ptr) 
{
    int rc;

    DEBUG("%s: Address: %p\n", __func__, ptr);

    if (!mem_inited || NULL == ptr)
    {
        WARN("qaeCryptoMemFree trying to free NULL pointer or Memory Driver not initialised.\n");
	return;
    }

    DEBUG("%s: pthread_mutex_lock\n", __func__);
    if ((rc = pthread_mutex_lock(&mem_mutex)) != 0) {
	    ERROR("pthread_mutex_lock: %s\n", strerror(rc));
	    return;
    }

    qaeMemFreeNUMA(&ptr);
    ref_count--;

    if (0 == ref_count)
    {
	    qaeCryptoMemDestroy();
    }

    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
	    ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
	    return;	
    }
    DEBUG("%s: pthread_mutex_unlock\n", __func__);
}

void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    int rc;
    void *pAddress=NULL;

    DEBUG("%s: pthread_mutex_lock\n", __func__);
    if ((rc = pthread_mutex_lock(&mem_mutex)) != 0) {
	    ERROR("pthread_mutex_lock: %s\n", strerror(rc));
	    return NULL;
    }

    if (!mem_inited)
    {
	    status = qaeCryptoMemInit();
	    if (CPA_STATUS_SUCCESS != status)
	    {
		    WARN("qaeCryptoMemAlloc failed, status=%d\n", status);
                    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
	               ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
	               return NULL;	
	            }
                    return NULL;
            }
    }

    ref_count++;

    pAddress = qaeMemAllocNUMA(memsize, 0, QAT_BYTE_ALIGNMENT);
    DEBUG("%s: Address: %p Size: %d File: %s:%d\n", __func__, pAddress, memsize, file, line);
    if ((rc = pthread_mutex_unlock(&mem_mutex)) != 0) {
	    ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
    }
    DEBUG("%s: pthread_mutex_unlock\n", __func__);
    return pAddress;
}

void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file, int line) 
{
    void *nptr;

    nptr = copyAllocPinnedMemory(ptr, memsize, file, line);
    if (nptr) 
    {
        qaeCryptoMemFree(ptr);
    }
    return nptr;
}

void *qaeCryptoMemReallocClean(void *ptr, size_t memsize, size_t original_size, const char *file, int line)
{
    void *nptr;

    if (original_size > memsize)
       return NULL;

    nptr = copyAllocPinnedMemoryClean(ptr, memsize, original_size, file, line);
    if (nptr)
    {
        qaeCryptoMemFree(ptr);
    }
    return nptr;
}

void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file, int line)
{
    void *nptr;

    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL)
    {
        WARN("%s: pinned memory allocation failure\n", __func__);
        return NULL;
    }
    memcpy (nptr, ptr, size);
    return nptr;
}

void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size, const char *file, int line)
{
    void *nptr;

    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL)
    {
        WARN("%s: pinned memory allocation failure\n", __func__);
        return NULL;
    }
    memcpy (nptr, ptr, original_size);
    return nptr;
}

void copyFreePinnedMemory(void *uptr, void *kptr, int size)
{
    memcpy (uptr, kptr, size);
    qaeCryptoMemFree(kptr);
}

CpaPhysicalAddr qaeCryptoMemV2P(void *v)
{
    return qaeVirtToPhysNUMA(v);
}

void qaeCryptoAtFork()
{
    qaeAtFork();
}


/* Note: these functions are internal and not part of the interface.
   Ensure they are called from within a locked mutex as they do not
   implement locking themselves. */ 


static CpaStatus qaeCryptoMemInit(void)
{
    CpaStatus status=CPA_STATUS_SUCCESS;

    if (!mem_inited)
    {
	    mem_inited = 1;
            ref_count = 0;
            status = qaeMemInit();
    }

    return status;
}

static void qaeCryptoMemDestroy(void)
{
    if (mem_inited)
    {
	    mem_inited = 0;
	    qaeMemDestroy();
    }
}
