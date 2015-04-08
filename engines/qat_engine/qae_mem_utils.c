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
 * @file qae_mem_utils.c
 *
 * This file provides linux kernel memory allocation for quick assist API
 *
 *****************************************************************************/
#define _GNU_SOURCE
#include "qae_mem_utils.h"
#ifdef USE_QAT_MEM
# include "qat_mem.h"
#endif
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

#ifdef QAT_DEBUG
# define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
# define DEBUG(...)
#endif

#define ERROR(...) fprintf(stderr, __VA_ARGS__)

#ifdef QAT_WARN
# define WARN(...) fprintf (stderr, __VA_ARGS__)
#else
# define WARN(...)
#endif

/*
 * Error from file descriptor operation
 */
#define FD_ERROR -1

/* flag for mutex lock */
static int crypto_inited = 0;

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define MAX_PAGES_SHIFT 5
#define MAX_PAGES (1UL << MAX_PAGES_SHIFT)

#ifdef USE_QAT_MEM
/* qat_mem ioctl open file descriptor */
static int crypto_qat_memfd = FD_ERROR;
#endif

/* Big Slab Allocator Lock */
static pthread_mutex_t crypto_bsal = PTHREAD_MUTEX_INITIALIZER;

/*
 * We allocate memory in slabs consisting of a number of slots to avoid
 * fragmentation and also to reduce cost of allocation There are six
 * predefined slot sizes: 256 bytes, 1024 bytes, 4096 bytes, 8192 bytes,
 * 16384 bytes and 32768 bytes.  Slabs are 128KB in size.  This implies
 * the most slots that a slab can hold is 128KB/256 = 512.  The first slot
 * is used for meta info, so actual is 511.
 */
#define SLAB_SIZE       (0x20000 - sizeof(qat_mem_config))

/* Slot sizes */
#define NUM_SLOT_POOLS 7
#define SLOT_256_BYTES  0x0100
#define SLOT_1_KILOBYTES  0x0400
#define SLOT_4_KILOBYTES  0x1000
#define SLOT_8_KILOBYTES  0x2000
#define SLOT_16_KILOBYTES  0x4000
#define SLOT_32_KILOBYTES  0x8000
#define SLOT_DEFAULT_INIT -1
/* slot free signature */
#define SIG_FREE        0xF1F2F3F4

/* slot allocate signature */
#define SIG_ALLOC       0xA1A2A3A4

/* maxmium slot size */
#define MAX_ALLOC       (SLAB_SIZE - sizeof (qae_slab)-QAE_BYTE_ALIGNMENT)

static int slot_sizes_available[] = {
    SLOT_256_BYTES,
    SLOT_1_KILOBYTES,
    SLOT_4_KILOBYTES,
    SLOT_8_KILOBYTES,
    SLOT_16_KILOBYTES,
    SLOT_32_KILOBYTES
};

typedef struct _qae_slot {
    struct _qae_slot *next;
    int sig;
    int pool_index;
    char *file;
    int line;
} qae_slot;

typedef struct _qae_slab {
    qat_mem_config memCfg;
    int slot_size;
    int sig;
    struct _qae_slab *next_slab;
    struct _qae_slot *next_slot;
} qae_slab;

typedef struct _qae_pool {
    int slot_size;
    struct _qae_slot *next_free_slot;
} qae_pool;

qae_slab *crypto_slab_list = 0;

qae_pool crypto_slot_pools[NUM_SLOT_POOLS] = { {0, NULL},
{0, NULL},
{0, NULL},
{0, NULL},
{0, NULL},
{0, NULL},
{0, NULL}
};

static void crypto_init(void);

/******************************************************************************
* function:
*         copyAllocPinnedMemory(void *ptr, size_t size, const char *file, int line)
*
* @param ptr [IN]  - Pointer to data to be copied
* @param size [IN] - Size of data to be copied
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
* @retval NULL      failed to allocate memory
* @retval non-NULL  pointer to allocated memory
******************************************************************************/
void *copyAllocPinnedMemory(void *ptr, size_t size, const char *file,
                            int line)
{
    void *nptr;

    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL) {
        WARN("%s: pinned memory allocation failure\n", __func__);
        return NULL;
    }

    memcpy(nptr, ptr, size);
    return nptr;
}

/******************************************************************************
* function:
*         copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size, const char *file, int line)
*
* @param ptr [IN]  - Pointer to data to be copied
* @param size [IN] - Size of data to be copied
* @param original_size [IN] - Original size
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
* @retval NULL      failed to allocate memory
* @retval non-NULL  pointer to allocated memory
******************************************************************************/
void *copyAllocPinnedMemoryClean(void *ptr, size_t size, size_t original_size,
                                 const char *file, int line)
{
    void *nptr;

    if ((nptr = qaeCryptoMemAlloc(size, file, line)) == NULL) {
        WARN("%s: pinned memory allocation failure\n", __func__);
        return NULL;
    }

    memcpy(nptr, ptr, original_size);
    return nptr;
}

/******************************************************************************
* function:
*         copyFreePinnedMemory(void *kptr, void *uptr, int size)
*
* @param uptr [IN] - Pointer to user data
* @param kptr [IN] - Pointer to pinned memory to be copied
* @param size [IN] - Size of data to be copied
*
* description:
*   Internal API to allocate a pinned memory
*   buffer and copy data to it.
*
******************************************************************************/
void copyFreePinnedMemory(void *uptr, void *kptr, int size)
{
    memcpy(uptr, kptr, size);
    qaeCryptoMemFree(kptr);
}

/*****************************************************************************
 * function:
 *         crypto_create_slab(int size)
 *
 * @param[in] size, the size of the slots within the slab. Note that this is
 *                  not the size of the slab itself
 * @retval qae_slab*, a pointer to the new slab.
 *
 * @description
 *      create a new slab and add it to the global linked list
 *      retval pointer to the new slab
 *
 *****************************************************************************/
static qae_slab *crypto_create_slab(int size, int pool_index)
{
    int i = 0;
    int nslot = 0;
    qat_mem_config qmcfg = { 0, (uintptr_t) NULL, 0, (uintptr_t) NULL };
    qae_slab *result = NULL;
    qae_slab *slb = NULL;
    qae_slot *slt = NULL;
    QAE_UINT alignment;

    qmcfg.length = SLAB_SIZE;
#ifdef USE_QAT_MEM
    if (ioctl(crypto_qat_memfd, QAT_MEM_MALLOC, &qmcfg) == -1) {
        static char errmsg[LINE_MAX];

        snprintf(errmsg, LINE_MAX, "ioctl QAT_MEM_MALLOC(%d)", qmcfg.length);
        perror(errmsg);
        goto exit;
    }
    if ((slb =
         mmap(NULL, qmcfg.length, PROT_READ | PROT_WRITE,
              MAP_SHARED | MAP_LOCKED, crypto_qat_memfd,
              qmcfg.virtualAddress)) == MAP_FAILED) {
        static char errmsg[LINE_MAX];
        snprintf(errmsg, LINE_MAX, "mmap: %d %s", errno, strerror(errno));
        perror(errmsg);
        goto exit;
    }
#endif
    DEBUG("%s slot size %d\n", __func__, size);
    slb->slot_size = size;
    slb->next_slot = NULL;
    slb->sig = SIG_ALLOC;

    for (i = sizeof(qae_slab); SLAB_SIZE - i >= size; i += size) {
        slt = (qae_slot *) ((unsigned char *)slb + i);
        alignment =
            QAE_BYTE_ALIGNMENT -
            (((QAE_UINT) slt + sizeof(qae_slot)) % QAE_BYTE_ALIGNMENT);
        slt = (qae_slot *) (((QAE_UINT) slt) + alignment);
        slt->next = slb->next_slot;
        slt->pool_index = pool_index;
        slt->sig = SIG_FREE;
        slt->file = NULL;
        slt->line = 0;
        slb->next_slot = slt;
        nslot++;
    }
    slb->next_slab = crypto_slab_list;
    /*
     * Make sure update of the slab list is the last thing to be done.  This
     * means it is not necessary to lock against anyone iterating the list
     * from the head
     */
    crypto_slab_list = slb;
    crypto_slot_pools[pool_index].next_free_slot = slb->next_slot;

    result = slb;
    DEBUG("%s slab %p last slot is %p, count is %d\n", __func__, slb, slt,
          nslot);
 exit:
    return result;
}

/*****************************************************************************
 * function:
 *         crypto_alloc_from_slab(int size, const char *file, int line)
 *
 * @param[in] size, the size of the memory block required
 * @param[in] file, the C source filename of the call site
 * @param[in] line, the line number withing the C source file of the call site
 *
 * @description
 *      allocate a slot of memory from some slab
 *      retval pointer to the allocated block
 *
 *****************************************************************************/
static void *crypto_alloc_from_slab(int size, const char *file, int line)
{
    qae_slab *slb = NULL;
    qae_slot *slt;
    int slot_size;
    void *result = NULL;
    int rc;
    int i;

    if (!crypto_inited)
        crypto_init();

    size += sizeof(qae_slot);
    size += QAE_BYTE_ALIGNMENT;

    slot_size = SLOT_DEFAULT_INIT;

    for (i = 0; i < sizeof(slot_sizes_available) / sizeof(int); i++) {
        if (size < slot_sizes_available[i]) {
            slot_size = slot_sizes_available[i];
            break;
        }
    }

    if (SLOT_DEFAULT_INIT == slot_size) {
        if (size <= MAX_ALLOC)
            slot_size = MAX_ALLOC;
        else {
            ERROR("%s Allocation of %d bytes is too big\n", __func__, size);
            goto exit;
        }
    }

    if (crypto_slot_pools[i].slot_size != slot_size) {
        ERROR("%s Unsupported slot size %d\n", __func__, slot_size);
        goto exit;
    }

    DEBUG("%s: pthread_mutex_lock\n", __func__);
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        ERROR("pthread_mutex_lock: %s\n", strerror(rc));
        return result;
    }

    if (crypto_slot_pools[i].next_free_slot == NULL) {
        /* no free slots need to allocate new slab */
        slb = crypto_create_slab(slot_size, i);

        if (NULL == slb) {
            ERROR("%s error, create_slab failed - memory allocation error\n",
                  __func__);
            if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
                ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
            DEBUG("%s: pthread_mutex_unlock\n", __func__);
            goto exit;
        }
    }

    if (NULL == crypto_slot_pools[i].next_free_slot) {
        ERROR("%s error, no slots\n", __func__);
        if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
            ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
        DEBUG("%s: pthread_mutex_unlock\n", __func__);
        goto exit;
    }

    slt = crypto_slot_pools[i].next_free_slot;

    if (slt->sig != SIG_FREE) {
        ERROR("%s error alloc slot that isn't free %p\n", __func__, slt);
        exit(1);
    }

    crypto_slot_pools[i].next_free_slot = slt->next;
    slt->next = NULL;
    slt->sig = SIG_ALLOC;
    slt->file = strdup(file);
    slt->line = line;
    result = (void *)((unsigned char *)slt + sizeof(qae_slot));

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
        ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
    DEBUG("%s: pthread_mutex_unlock\n", __func__);

 exit:
    return result;
}

/*****************************************************************************
 * function:
 *         crypto_free_to_slab(void *ptr)
 *
 * @param[in] ptr, pointer to the memory to be freed
 *
 * @description
 *      free a slot of memory back to its slab
 *
 *****************************************************************************/
static void crypto_free_to_slab(void *ptr)
{
    qae_slot *slt = (void *)((unsigned char *)ptr - sizeof(qae_slot));
    int rc;

    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        ERROR("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }

    DEBUG("%s: pthread_mutex_lock\n", __func__);
    if (!slt) {
        ERROR("Error freeing memory - unknown address\n");
        goto exit;
    }
    if (slt->sig != SIG_ALLOC) {
        ERROR("%s error trying to free slot that hasn't been alloc'd %p\n",
              __func__, slt);
        goto exit;
    }

    free(slt->file);
    slt->sig = SIG_FREE;
    slt->file = NULL;
    slt->line = 0;
    slt->next = crypto_slot_pools[slt->pool_index].next_free_slot;
    crypto_slot_pools[slt->pool_index].next_free_slot = slt;
 exit:
    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
        ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
    DEBUG("%s: pthread_mutex_unlock\n", __func__);
}

/*****************************************************************************
 * function:
 *         crypto_slot_get_size(void *ptr)
 *
 * @param[in] ptr, pointer to the slot memory
 * @retval int, the size of the slot in bytes
 *
 * @description
 *      get the slot memory size in bytes
 *
 *****************************************************************************/
static int crypto_slot_get_size(void *ptr)
{
    if (NULL == ptr) {
        ERROR("%s error can't find %p\n", __func__, ptr);
        return 0;
    }
    qae_slot *slt = (void *)((unsigned char *)ptr - sizeof(qae_slot));
    if (slt->pool_index == (NUM_SLOT_POOLS - 1)) {
        return MAX_ALLOC;
    } else if (slt->pool_index >= 0 && slt->pool_index <= NUM_SLOT_POOLS - 2) {
        return slot_sizes_available[slt->pool_index] - sizeof(qae_slot) -
            QAE_BYTE_ALIGNMENT;
    } else {
        ERROR("%s error invalid pool_index %d\n", __func__, slt->pool_index);
        return 0;
    }
}

/*****************************************************************************
 * function:
 *         qaeCryptoAtFork()
 *
 * @description
 *      allocate and remap momory following a fork
 *
 *****************************************************************************/
void qaeCryptoAtFork()
{
    int rc = 0;
    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        ERROR("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }
    DEBUG("%s: pthread_mutex_lock\n", __func__);
    qae_slab *old_slb = crypto_slab_list;
    qae_slab *new_slb = NULL;
    qat_mem_config qmcfg =
        { 0, (uintptr_t) NULL, SLAB_SIZE, (uintptr_t) NULL };

    while (old_slb != NULL) {
#ifdef USE_QAT_MEM
        if (ioctl(crypto_qat_memfd, QAT_MEM_MALLOC, &qmcfg) == -1) {
            static char errmsg[LINE_MAX];

            snprintf(errmsg, LINE_MAX, "ioctl QAT_MEM_MALLOC(%d)",
                     qmcfg.length);
            perror(errmsg);
            exit(EXIT_FAILURE);
        }

        if ((new_slb =
             mmap(NULL, qmcfg.length, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_LOCKED, crypto_qat_memfd,
                  qmcfg.virtualAddress)) == MAP_FAILED) {
            static char errmsg[LINE_MAX];
            snprintf(errmsg, LINE_MAX, "mmap: %d %s", errno, strerror(errno));
            perror(errmsg);
            exit(EXIT_FAILURE);
        }
        memcpy((void *)new_slb + sizeof(qat_mem_config),
               (void *)old_slb + sizeof(qat_mem_config), SLAB_SIZE);

#endif
        qae_slab *to_unmap = old_slb;
        old_slb = old_slb->next_slab;
        if (munmap(to_unmap, SLAB_SIZE) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }
        qae_slab *remap = mremap(new_slb, SLAB_SIZE, SLAB_SIZE,
                                 MREMAP_FIXED | MREMAP_MAYMOVE, to_unmap);
        if ((remap == MAP_FAILED) || (remap != to_unmap)) {
            perror("mremap");
            exit(EXIT_FAILURE);
        }
    }

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
        ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
    DEBUG("%s: pthread_mutex_unlock\n", __func__);
}

/*****************************************************************************
 * function:
 *         crypto_cleanup_slabs(void)
 *
 * @description
 *      Free all memory managed by the slab allocator. This function is
 *      intended to be registered as an atexit() handler.
 *
 *****************************************************************************/
static void crypto_cleanup_slabs(void)
{
    qae_slab *slb, *s_next_slab;
    int rc;
    QAE_UINT alignment;
#ifdef USE_QAT_MEM
    qat_mem_config qmcfg;
#endif

    if ((rc = pthread_mutex_lock(&crypto_bsal)) != 0) {
        ERROR("pthread_mutex_lock: %s\n", strerror(rc));
        return;
    }

    DEBUG("%s: pthread_mutex_lock\n", __func__);
    for (slb = crypto_slab_list; slb != NULL; slb = s_next_slab) {
        qae_slot *slt = NULL;
        int i;

        for (i = sizeof(qae_slab); SLAB_SIZE - i >= slb->slot_size;
             i += slb->slot_size) {
            slt = (qae_slot *) ((unsigned char *)slb + i);
            alignment =
                QAE_BYTE_ALIGNMENT -
                (((QAE_UINT) slt + sizeof(qae_slot)) % QAE_BYTE_ALIGNMENT);
            slt = (qae_slot *) (((QAE_UINT) slt) + alignment);

            if (slt->sig == SIG_ALLOC && slt->file != NULL && slt->line != 0)
                DEBUG("Leak : %p %s:%d\n", slt, slt->file, slt->line);
        }

        /*
         * Have to save this off before unmapping. This is why we can't have
         * slb = slb->next_slab in the for loop above.
         */
        s_next_slab = slb->next_slab;

#ifdef USE_QAT_MEM

        DEBUG("%s do munmap  of %p\n", __func__, slb);
        qmcfg = *((qat_mem_config *) slb);

        if (munmap(slb, SLAB_SIZE) == -1) {
            perror("munmap");
            exit(EXIT_FAILURE);
        }
        DEBUG("%s ioctl free of %p\n", __func__, slb);
        if (ioctl(crypto_qat_memfd, QAT_MEM_FREE, &qmcfg) == -1) {
            perror("ioctl QAT_MEM_FREE");
            exit(EXIT_FAILURE);
        }
#endif

    }
    DEBUG("%s done\n", __func__);

    if ((rc = pthread_mutex_unlock(&crypto_bsal)) != 0)
        ERROR("pthread_mutex_unlock: %s\n", strerror(rc));
    DEBUG("%s: pthread_mutex_unlock\n", __func__);
}

/******************************************************************************
* function:
*         crypto_init(void)
*
* @description
*   Initialise the user-space part of the QAT memory allocator.
*
******************************************************************************/
static void crypto_init(void)
{
    int i = 0;
#ifdef USE_QAT_MEM
    if ((crypto_qat_memfd = open("/dev/qat_mem", O_RDWR)) == FD_ERROR) {
        perror("open qat_mem");
        exit(EXIT_FAILURE);
    }
#endif
    for (i = 0; i < sizeof(slot_sizes_available) / sizeof(int); i++) {
        crypto_slot_pools[i].slot_size = slot_sizes_available[i];
        crypto_slot_pools[i].next_free_slot = NULL;
    }
    crypto_slot_pools[i].slot_size = MAX_ALLOC;
    crypto_slot_pools[i].next_free_slot = NULL;

    atexit(crypto_cleanup_slabs);
    crypto_inited = 1;
}

/******************************************************************************
* function:
*         qaeCryptoMemV2P(void *v)
*
* @param[in] v, virtual memory address pointer
* @retval CpaPhysicalAddress, the physical memory address pointer, it
*         returns 0 if not found.
*
* description:
*       map virtual memory address to physical memory address
*
******************************************************************************/
CpaPhysicalAddr qaeCryptoMemV2P(void *v)
{
    qat_mem_config *memCfg = NULL;
    void *pVirtPageAddress = NULL;
    ptrdiff_t offset = 0;
    int pagecount = 0;
    if (v == NULL) {
        WARN("%s: NULL address passed to function\n", __func__);
        return (CpaPhysicalAddr) 0;
    }

    pVirtPageAddress = ((int *)((((ptrdiff_t) v)) & (PAGE_MASK)));

    offset = (char *)v - (char *)pVirtPageAddress;

    do {
        DEBUG("addr %p, page addr %p, offset %d\n", v, pVirtPageAddress,
              offset);
        memCfg = (qat_mem_config *) pVirtPageAddress;
        if (memCfg->signature == QAT_MEM_ALLOC_SIG) {
            break;
        }
        pVirtPageAddress = (void *)((ptrdiff_t) pVirtPageAddress - PAGE_SIZE);

        offset += PAGE_SIZE;
        pagecount++;
    }
    while ((memCfg->signature != QAT_MEM_ALLOC_SIG)
           && (pagecount <= MAX_PAGES));
    if (memCfg->signature != QAT_MEM_ALLOC_SIG) {
        WARN("%s: unable to find physical address\n", __func__);
        return (CpaPhysicalAddr) 0;
    }

    return (CpaPhysicalAddr) (memCfg->physicalAddress + offset);
}

/**************************************
 * Memory functions
 *************************************/

/******************************************************************************
* function:
*         qaeCryptoMemAlloc(size_t memsize, , const char *file, int line)
*
* @param[in] memsize,  size of usable memory requested
* @param[in] file,     the C source filename of the call site
* @param[in] line,     the line number withing the C source file of the call site
*
* description:
*   Allocate a block of pinned memory.
*
******************************************************************************/
void *qaeCryptoMemAlloc(size_t memsize, const char *file, int line)
{
    void *pAddress = crypto_alloc_from_slab(memsize, file, line);
    DEBUG("%s: Address: %p Size: %d File: %s:%d\n", __func__, pAddress,
          memsize, file, line);
    return pAddress;
}

/******************************************************************************
* function:
*         qaeCryptoMemFree(void *ptr)
*
* @param[in] ptr, address of start of usable memory
*
* description:
*   Free a block of memory previously allocated by this allocator.
*
******************************************************************************/
void qaeCryptoMemFree(void *ptr)
{
    DEBUG("%s: Address: %p\n", __func__, ptr);
    if (NULL != ptr)
        crypto_free_to_slab(ptr);
}

/******************************************************************************
* function:
*         qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file, int line)
*
* @param[in] ptr,     address of start of usable memory for old allocation
* @param[in] memsize, size of new block required
* @param[in] file,    the C source filename of the call site
* @param[in] line,    the line number withing the C source file of the call site
*
* description:
*   Change the size of usable memory in an allocated block. This may allocate
*   a new block and copy the data to it.
*
******************************************************************************/
void *qaeCryptoMemRealloc(void *ptr, size_t memsize, const char *file,
                          int line)
{
    int copy = crypto_slot_get_size(ptr);
    void *n = crypto_alloc_from_slab(memsize, file, line);
    DEBUG("%s: Alloc Address: %p Size: %d File: %s:%d\n", __func__, n,
          memsize, file, line);

    if (memsize < copy)
        copy = memsize;
    memcpy(n, ptr, copy);
    DEBUG("%s: Free Address: %p\n", __func__, ptr);
    crypto_free_to_slab(ptr);
    return n;
}

/*************************************************************************************************************
* function:
*         qaeCryptoMemReallocClean(void *ptr, size_t memsize, size_t original_size, const char *file, int line)
*
* @param[in] ptr,               address of start of usable memory for old allocation
* @param[in] memsize,           size of new block required
* @param[in] original_size,     original size
* @param[in] file,              the C source filename of the call site
* @param[in] line,              the line number withing the C source file of the call site
*
* description:
*   Change the size of usable memory in an allocated block. This may allocate
*   a new block and copy the data to it.
*
***************************************************************************************************************/
void *qaeCryptoMemReallocClean(void *ptr, size_t memsize,
                               size_t original_size, const char *file,
                               int line)
{
    int copy = crypto_slot_get_size(ptr);
    void *n = crypto_alloc_from_slab(memsize, file, line);
    DEBUG("%s: Alloc Address: %p Size: %d File: %s:%d\n", __func__, n,
          memsize, file, line);

    if (memsize < copy)
        copy = memsize;
    memcpy(n, ptr, copy);
    DEBUG("%s: Free Address: %p\n", __func__, ptr);
    crypto_free_to_slab(ptr);
    return n;
}
