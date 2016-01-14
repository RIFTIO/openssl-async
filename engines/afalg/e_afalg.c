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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/async.h>

#include <linux/version.h>
#define K_MAJ   4
#define K_MIN1  1
#define K_MIN2  0
#if LINUX_VERSION_CODE <= KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)
# error "AFALG ENGINE requires Kernel Headers >= 4.1.0"
#endif

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <errno.h>

#include "e_afalg.h"

#define AFALG_LIB_NAME "AFALG"
#include "e_afalg_err.h"

#ifndef SOL_ALG
# define SOL_ALG 279
#endif

#ifdef ALG_ZERO_COPY
# ifndef SPLICE_F_GIFT
#  define SPLICE_F_GIFT    (0x08)
# endif
#endif

#define ALG_AES_MAX_IV_LEN 16
#define ALG_IV_LEN(len) (sizeof(struct af_alg_iv) + (len))
#define ALG_OP_TYPE     unsigned int
#define ALG_OP_LEN      (sizeof(ALG_OP_TYPE))

/* Local Linkage Functions */
static int afalg_init_aio(afalg_aio *aio);
static int afalg_fin_cipher_aio(afalg_aio *ptr, int sfd,
                         unsigned char *buf, size_t len);
static int afalg_create_bind_sk(void);
static int afalg_destroy(ENGINE *e);
static int afalg_init(ENGINE *e);
static int afalg_finish(ENGINE *e);
static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid);
static int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl);
static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx);
static int afalg_chk_platform(void);

/* Engine Id and Name */
static const char *engine_afalg_id = "afalg";
static const char *engine_afalg_name = "AFLAG engine support";

int afalg_cipher_nids[] = {
    NID_aes_128_cbc
};

EVP_CIPHER afalg_aes_128_cbc = {
    NID_aes_128_cbc,
    AES_BLOCK_SIZE,
    AES_KEY_SIZE_128,
    AES_IV_LEN,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1,
    afalg_cipher_init,
    afalg_do_cipher,
    afalg_cipher_cleanup,
    sizeof(afalg_ctx),
    NULL,
    NULL,
    NULL,
    NULL
};

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

int afalg_init_aio(afalg_aio *aio)
{
    int r = -1;

    /* Initialise for AIO */
    aio->aio_ctx = 0;
    r = io_setup(MAX_INFLIGHTS, &aio->aio_ctx);
    if (r < 0) {
        ALG_PERR("%s: io_setup error : ", __func__);
        AFALGerr(AFALG_F_AFALG_INIT_AIO, AFALG_R_IO_SETUP_FAILED);
        return 0;
    }

    aio->efd = eventfd(0);
    if (aio->efd == -1) {
        ALG_PERR("%s: Failed to get eventfd : ", __func__);
        AFALGerr(AFALG_F_AFALG_INIT_AIO, AFALG_R_EVENTFD_FAILED);
        io_destroy(aio->aio_ctx);
        return 0;
    }
    aio->retrys = 0;
    aio->ring_fulls = 0;
    aio->failed = 0;
    memset(aio->cbt, 0, sizeof(aio->cbt));

    if (ASYNC_get_current_job() != NULL) {
        /* make efd non-blocking in async mode */
        if (fcntl(aio->efd, F_SETFL, O_NONBLOCK) != 0) {
            ALG_WARN("%s: Failed to set event fd as NONBLOCKING", __func__);
        }
    }

    return 1;
}

int afalg_fin_cipher_aio(afalg_aio *aio, int sfd, unsigned char *buf,
                         size_t len)
{
    int r;
    unsigned int done = 0;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];
    ASYNC_JOB *job;
    u_int64_t eval = 0;

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
        ASYNC_set_wait_fd(job, aio->efd);
    }

    r = io_read(aio->aio_ctx, 1, &cb);
    if (r < 0) {
        ALG_PERR("%s: io_read failed : ", __func__);
        return 0;
    }

    do {
        ASYNC_pause_job();

        r = read(aio->efd, &eval, sizeof(eval));
        if (r < 0) {
            if (errno == EAGAIN)
                continue;
            ALG_PERR("%s: read failed for event fd : ", __func__);
            return 0;
        } else if (r == 0 || eval <= 0) {
            ALG_WARN("%s: eventfd read %d bytes, eval = %lu\n", __func__, r,
                     eval);
        }
        if (eval > 0) {
            r = io_getevents(aio->aio_ctx, 1, 1, events, &timeout);
            if (r > 0) {
                done = 1;
                if (events[0].res == -EBUSY)
                    aio->ring_fulls++;
                else if (events[0].res < 0) {
                    ALG_WARN("%s: Crypto Operation failed with code %lld\n",
                             __func__, events[0].res);
                    aio->failed++;
                }
            } else if (r < 0) {
                ALG_PERR("%s: io_getevents failed : ", __func__);
                return 0;
            } else {
                aio->retrys++;
                ALG_WARN("%s: io_geteventd read %d bytes\n", __func__, r);
            }
        }
    } while (!done);

    return 1;
}

static int afalg_create_bind_sk(void)
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "skcipher",
        .salg_name = "cbc(aes)"
    };

    int sfd;
    int r = -1;

    sfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sfd == -1) {
        ALG_PERR("%s: Failed to open socket : ", __func__);
        AFALGerr(AFALG_F_AFALG_CREATE_BIND_SK, AFALG_R_SOCKET_CREATE_FAILED);
        goto err;
    }

    r = bind(sfd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0) {
        ALG_PERR("%s: Failed to bind socket : ", __func__);
        AFALGerr(AFALG_F_AFALG_CREATE_BIND_SK, AFALG_R_SOCKET_BIND_FAILED);
        goto err;
    }

    return sfd;

 err:
    if (sfd >= 0)
        close(sfd);
    return r;
}

static inline void afalg_set_op_sk(struct cmsghdr *cmsg,
                                   const unsigned int op)
{
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(ALG_OP_LEN);
    *CMSG_DATA(cmsg) = (char)op;
}

static void afalg_set_iv_sk(struct cmsghdr *cmsg, const unsigned char *iv,
                            const unsigned int len)
{
    struct af_alg_iv *aiv;

    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(ALG_IV_LEN(len));
    aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = len;
    memcpy(aiv->iv, iv, len);
}

static void  afalg_socket(afalg_ctx *actx, const unsigned char *key, 
                          const int klen)
{
    int ret;

    actx->bfd = actx->sfd = -1;

    actx->bfd = afalg_create_bind_sk();
    if (actx->bfd < 0) {
        return;
    }

    ret = setsockopt(actx->bfd, SOL_ALG, ALG_SET_KEY, key, klen);
    if (ret < 0) {
        ALG_PERR("%s: Failed to set socket option : ", __func__);
        AFALGerr(AFALG_F_AFALG_SOCKET, AFALG_R_SOCKET_SET_KEY_FAILED);
        goto err;
    }

    actx->sfd = accept(actx->bfd, NULL, 0);
    if (actx->sfd < 0) {
        ALG_PERR("%s: Socket Accept Failed : ", __func__);
        AFALGerr(AFALG_F_AFALG_SOCKET, AFALG_R_SOCKET_BIND_FAILED);
        goto err;
    }

    return;

 err:
    if (actx->bfd >= 0)
        close(actx->bfd);
    if (actx->sfd >= 0)
        close(actx->sfd);
    actx->bfd = actx->sfd = -1;
    return;
}

static int afalg_start_cipher_sk(afalg_ctx * actx, const unsigned char *in,
                                 size_t inl, unsigned char *iv,
                                 unsigned int enc)
{
    struct msghdr msg = { };
    struct cmsghdr *cmsg;
    struct iovec iov;
    ssize_t sbytes;

    const ssize_t cbuf_sz = CMSG_SPACE(ALG_IV_LEN(ALG_AES_MAX_IV_LEN)) 
                            + CMSG_SPACE(ALG_OP_LEN);
    char cbuf[cbuf_sz];
    
    memset(cbuf, 0, cbuf_sz);
    msg.msg_control = cbuf;
    msg.msg_controllen = cbuf_sz;

    cmsg = CMSG_FIRSTHDR(&msg);
    afalg_set_op_sk(cmsg, enc);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    afalg_set_iv_sk(cmsg, iv, ALG_AES_MAX_IV_LEN);

    iov.iov_base = (unsigned char *)in;
    iov.iov_len = inl;
    msg.msg_flags = MSG_MORE;

#ifdef ALG_ZERO_COPY
    /*
     * ZERO_COPY mode
     * OPENS: out of place processing (i.e. out != in)
     * alignment effects
     */
    msg.msg_iovlen = 0;
    msg.msg_iov = NULL;

    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s: sendmsg failed for zero copy cipher operation : ",
                 __func__);
        return 0;
    }

    ret = vmsplice(actx->zc_pipe[1], &iov, 1, SPLICE_F_GIFT);
    if (ret < 0) {
        ALG_PERR("%s: vmsplice failed : ", __func__);
        return 0;
    }

    ret = splice(actx->zc_pipe[0], NULL, actx->sfd, NULL, inl, 0);
    if (ret < 0) {
        ALG_PERR("%s: splice failed : ", __func__);
        return 0;
    }
#else
    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;

    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        ALG_PERR("%s: sendmsg failed for cipher operation : ", __func__);
        return 0;
    }
#endif

    return 1;
}

static int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ciphertype;
    afalg_ctx *actx;

    if (!ctx || !key) {
        ALG_WARN("Null Parameter to %s\n", __func__);
        return 0;
    }

    if (!ctx->cipher) {
        ALG_WARN("Cipher object NULL\n");
        return 0;
    }

    if (!ctx->cipher_data) {
        ALG_WARN("cipher data NULL\n");
        return 0;
    }
    actx = ctx->cipher_data;

    ciphertype = EVP_CIPHER_CTX_nid(ctx);
    switch (ciphertype) {
    case NID_aes_128_cbc:
        break;
    default:
        ALG_WARN("Unsupported Cipher type %d\n", ciphertype);
        return 0;
    }

    afalg_socket(actx, key, EVP_CIPHER_CTX_key_length(ctx));
    if (actx->sfd < 0) {
        return 0;
    }

    if (!afalg_init_aio(&actx->aio)) {
        close(actx->sfd);
        close(actx->bfd);
        return 0;
    }
#ifdef ALG_ZERO_COPY
    pipe(actx->zc_pipe);
#endif

    actx->init_done = MAGIC_INIT_NUM;

    return 1;
}

static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    afalg_ctx *actx;
    int ret;

    if (!ctx || !out || !in) {
        ALG_WARN("NULL parameter passed to function %s\n", __func__);
        return 0;
    }

    actx = (afalg_ctx *) ctx->cipher_data;
    if (!actx || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n", !ctx ? "NULL" : "Uninitialised");
        return 0;
    }

    ret = afalg_start_cipher_sk(actx, (unsigned char *)in, inl, ctx->iv,
                                ctx->encrypt);
    if (ret < 1) {
        return 0;
    }

    ret = afalg_fin_cipher_aio(&actx->aio, actx->sfd, out, inl);
    if (ret < 1) {
        ALG_WARN("Socket cipher operation failed\n");
        return 0;
    }

    if (ctx->encrypt) {
        memcpy(ctx->iv, out + (inl - EVP_CIPHER_CTX_iv_length(ctx)),
               EVP_CIPHER_CTX_iv_length(ctx));
    } else {
        memcpy(ctx->iv, in + (inl - EVP_CIPHER_CTX_iv_length(ctx)),
               EVP_CIPHER_CTX_iv_length(ctx));
    }

    return 1;
}

static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    afalg_ctx *actx;

    if (!ctx) {
        ALG_WARN("NULL parameter passed to function %s\n", __func__);
        return 0;
    }

    actx = (afalg_ctx *) ctx->cipher_data;
    if (!actx || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n", !ctx ? "NULL" : "Uninitialised");
        return 0;
    }

    close(actx->sfd);
#ifdef ALG_ZERO_COPY
    close(actx->zc_pipe[0]);
    close(actx->zc_pipe[1]);
#endif
    if (actx->aio.efd >= 0)
        close(actx->aio.efd);
    io_destroy(actx->aio.aio_ctx);

    return 1;
}

static int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                         const int **nids, int nid)
{
    int r = 1;

    if (!cipher) {
        *nids = afalg_cipher_nids;
        return (sizeof(afalg_cipher_nids) / sizeof(afalg_cipher_nids[0]));
    }

    switch (nid) {
    case NID_aes_128_cbc:
        *cipher = &afalg_aes_128_cbc;
        break;
    default:
        *cipher = NULL;
        r = 0;
    }

    return r;
}

static int bind_afalg(ENGINE *e)
{
    /* Ensure the afalg error handling is set up */
    ERR_load_AFALG_strings();

    if (!ENGINE_set_id(e, engine_afalg_id)
        || !ENGINE_set_name(e, engine_afalg_name)
        || !ENGINE_set_destroy_function(e, afalg_destroy)
        || !ENGINE_set_init_function(e, afalg_init)
        || !ENGINE_set_finish_function(e, afalg_finish)) {
        AFALGerr(AFALG_F_BIND_AFALG, AFALG_R_INIT_FAILED);
        return 0;
    }
#if 1
    if (!ENGINE_set_ciphers(e, afalg_ciphers)) {
        AFALGerr(AFALG_F_BIND_AFALG, AFALG_R_INIT_FAILED);
        return 0;
    }
#endif

    return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_afalg_id) != 0))
        return 0;

    if (!afalg_chk_platform())
        return 0;

    if (!bind_afalg(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif
static int afalg_chk_platform(void)
{
    int ret;
    int i;
    int kver[3] = { -1, -1, -1 };
    char *str;
    struct utsname ut;

    ret = uname(&ut);
    if (ret != 0) {
        ALG_ERR("Failed to get system information\n");
        return 0;
    }

    str = strtok(ut.release, ".");
    for (i = 0; i < 3 && str != NULL; i++) {
        kver[i] = atoi(str);
        str = strtok(NULL, ".");
    }

    if (KERNEL_VERSION(kver[0], kver[1], kver[2])
        < KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)) {
        ALG_WARN("ASYNC AFALG not supported this kernel(%d.%d.%d)\n",
                 kver[0], kver[1], kver[2]);
        ALG_WARN("ASYNC AFALG requires kernel version %d.%d.%d or later\n",
                 K_MAJ, K_MIN1, K_MIN2);
        AFALGerr(AFALG_F_AFALG_CHK_PLATFORM,
                 AFALG_R_KERNEL_DOES_NOT_SUPPORT_ASYNC_AFALG);
        return 0;
    }

    return 1;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_afalg(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_afalg(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

static void ENGINE_load_afalg(void)
{
    ENGINE *toadd;

    if (!afalg_chk_platform())
        return;

    toadd = engine_afalg();
    if (!toadd)
        return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif

static int afalg_init(ENGINE *e)
{
    return 1;
}

static int afalg_finish(ENGINE *e)
{
    return 1;
}

static int afalg_destroy(ENGINE *e)
{
    ERR_unload_AFALG_strings();
    return 1;
}
