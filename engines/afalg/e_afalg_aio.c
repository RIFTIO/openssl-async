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

#include <stdio.h>
#include <string.h>
#define _GNU_SOURCE
#include <unistd.h>

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/async.h>

#include "e_afalg.h"
#include "e_afalg_err.h"

#define MAX_INFLIGHTS 1

struct afalg_aio_st {
    int efd;
    unsigned int received, retrys, fdnotset, ring_fulls, failed;
    aio_context_t aio_ctx;
    struct io_event events[MAX_INFLIGHTS];
    struct iocb cbt[MAX_INFLIGHTS];
};

typedef struct afalg_aio_st afalg_aio;

static inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static inline int eventfd(int n)
{
    return syscall(__NR_eventfd, n);
}

static inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static inline int io_read(aio_context_t ctx, long n, struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}

static inline int io_getevents(aio_context_t ctx, long min, long max,
                               struct io_event *events,
                               struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
}

void *afalg_init_aio(void)
{
    int r = -1;
    afalg_aio *aio;

    aio = (afalg_aio *) OPENSSL_malloc(sizeof(afalg_aio));
    if (!aio) {
        AFALGerr(AFALG_F_AFALG_INIT_AIO, AFALG_R_MEM_ALLOC_FAILED);
        goto err;
    }

    /* Initialise for AIO */
    aio->aio_ctx = 0;
    r = io_setup(MAX_INFLIGHTS, &aio->aio_ctx);
    if (r < 0) {
        ALG_PERR("%s: io_setup error", __func__);
        r = 0;
        goto err;
    }

    aio->efd = eventfd(0);
    aio->received = 0;
    aio->retrys = 0;
    aio->fdnotset = 0;
    aio->ring_fulls = 0;
    aio->failed = 0;
    memset(aio->cbt, 0, sizeof(aio->cbt));

    if (ASYNC_get_current_job() != NULL) {
        /* make efd non-blocking in async mode */
        if (fcntl(aio->efd, F_SETFL, O_NONBLOCK) != 0) {
            ALG_PERR("%s: Failed to set event fd as NONBLOCKING", __func__);
        }
    }

    return (void *)aio;

 err:
    if (aio)
        free(aio);
    return NULL;
}

int afalg_fin_cipher_aio(void *ptr, int sfd, unsigned char *buf, size_t len)
{
    int r;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];
    afalg_aio *aio = (afalg_aio *) ptr;
    ASYNC_JOB *job;
    u_int64_t eval = 0;

    if (!aio) {
        ALG_ERR("%s: ALG AIO CTX Null Pointer\n", __func__);
        return 0;
    }

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    cb = &(aio->cbt[0 % MAX_INFLIGHTS]);
    memset(cb, '\0', sizeof(*cb));
    cb->aio_fildes = sfd;
    cb->aio_lio_opcode = IOCB_CMD_PREAD;
    cb->aio_buf = (unsigned long)buf;
    cb->aio_offset = 0;
    cb->aio_data = 0;
    cb->aio_nbytes = len;
    cb->aio_flags = IOCB_FLAG_RESFD;
    cb->aio_resfd = aio->efd;

    if ((job = ASYNC_get_current_job()) != NULL) {
        /* Not sure of best approach to connect our efd to jobs wait_fd */
        ASYNC_set_wait_fd(job, aio->efd);
    }

    r = io_read(aio->aio_ctx, 1, &cb);
    if (r < 0) {
        ALG_PERR("%s: io_read failed", __func__);
        return 0;
    }

    do {
        if (ASYNC_get_current_job() != NULL)
            ASYNC_pause_job();

        r = read(aio->efd, &eval, sizeof(eval));
        if (r > 0 && eval > 0) {
            r = io_getevents(aio->aio_ctx, 1, 1, events, &timeout);
            if (r > 0) {
                cb = (void *)events[0].obj;
                cb->aio_fildes = 0;
                if (events[0].res == -EBUSY)
                    aio->ring_fulls++;
                else if (events[0].res != 0) {
                    ALG_WARN("aio_getevents failed with %lld\n", events[0].res);
                    aio->failed++;
                }
            } else if (r < 0) {
                ALG_PERR("%s: io_getevents failed", __func__);
                return 0;
            } else {
                aio->retrys++;
            }
        } else
            ALG_PERR("%s: read failed for event fd", __func__);

    } while (cb->aio_fildes != 0);

    return 1;
}

void afalg_cipher_cleanup_aio(void *ptr)
{
    afalg_aio *aio = (afalg_aio *) ptr;
    close(aio->efd);
    /* close(aio->bfd); */
    io_destroy(aio->aio_ctx);
    free(aio);
}
