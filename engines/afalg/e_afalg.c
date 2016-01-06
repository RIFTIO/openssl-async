/* Based on engines/e_dasync.c */
#define _GNU_SOURCE             /* for vmsplice */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <linux/version.h>
#define K_MAJ   4
#define K_MIN1  1
#define K_MIN2  0
#if LINUX_VERSION_CODE <= KERNEL_VERSION(K_MAJ, K_MIN1, K_MIN2)
# error "AFALG ENGINE reguires Kernel Headers >= 4.1.0"
#endif

/* AF_ALG Socket based headers */
#include <linux/if_alg.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#include "e_afalg.h"

#define AFALG_LIB_NAME "AFALG"
#include "e_afalg_err.c"

/* OUTPUTS */
#define ALG_DGB(x, args...) fprintf(stderr, "ALG_DBG: " x, ##args)
#define ALG_INFO(x, args...) fprintf(stderr, "ALG_INFO: " x, ##args)
#define ALG_WARN(x, args...) fprintf(stderr, "ALG_WARN: " x, ##args)
#define ALG_ERR(x, args...) fprintf(stderr, "ALG_ERR: " x, ##args)

/* AF_ALG Socket based defines */
#ifndef SOL_ALG
# define SOL_ALG 279
#endif

#ifdef ALG_ZERO_COPY
/* For zero copy mode */
# ifndef SPLICE_F_GIFT
/* pages passed in are a gift */
#  define SPLICE_F_GIFT    (0x08)
# endif
#endif

#define ALG_IV_LEN(len) (sizeof(struct af_alg_iv) + (len))
#define ALG_OP_TYPE     unsigned int
#define ALG_OP_LEN      (sizeof(ALG_OP_TYPE))

extern void *afalg_init_aio(void);
extern int afalg_fin_cipher_aio(void *ptr, int sfd,
                                unsigned char *buf, size_t len);
extern void afalg_cipher_cleanup_aio(void *ptr);

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
    EVP_CIPH_CBC_MODE,          /* flags */
    afalg_cipher_init,
    afalg_do_cipher,
    afalg_cipher_cleanup,
    sizeof(afalg_ctx),
    NULL,
    NULL,
    NULL,
    NULL
};

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
        perror("Failed to open socket");
        goto err;
    }

    r = bind(sfd, (struct sockaddr *)&sa, sizeof(sa));
    if (r < 0) {
        perror("Failed to bind socket");
        goto err;
    }

    return sfd;

 err:
    if (sfd >= 0)
        close(sfd);
    return r;
}

static int afalg_set_key_sk(int sfd, const unsigned char *key,
                            unsigned int keylen)
{
    int r = -1;

    if (!key)
        return 0;

    r = setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, keylen);
    if (r < 0) {
        perror("Failed to set socket option");
        return -1;
    }

    return 1;
}

static inline void afalg_set_op_sk(struct cmsghdr *cmsg,
                                   const unsigned int op)
{
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(ALG_OP_LEN);
    *(ALG_OP_TYPE *) CMSG_DATA(cmsg) = op;
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

static int afalg_socket(const unsigned char *key, const int klen,
                        const unsigned char *iv, const int ivlen, int enc)
{
    int bfd = 0;
    int sfd = 0;
    int ret = -1;

    bfd = afalg_create_bind_sk();
    if (bfd < 1) {
        /*
         * TODO: Create a generic socket setup error code for openssl
         */
        return 0;
    }

    ret = afalg_set_key_sk(bfd, key, klen);
    if (ret < 1) {
        ALG_WARN("Failed to set key\n");
        goto err;
    }

    sfd = accept(bfd, NULL, 0);
    if (sfd < 0) {
        perror("Socket Accept Failed");
        goto err;
    }

    if (ret < 1)
        goto err;
    return sfd;

 err:
    if (bfd >= 0)
        close(bfd);
    if (sfd >= 0)
        close(sfd);
    return -1;
}

static int afalg_start_cipher_sk(afalg_ctx *actx, const unsigned char *in,
                                 size_t inl, unsigned char *iv,
                                 unsigned int ivlen, unsigned int enc)
{
    struct msghdr msg = { };
    struct cmsghdr *cmsg;
    char *cbuf;
    struct iovec iov;
    ssize_t sbytes;
    int ret = 0;

    ssize_t cbuf_sz = CMSG_SPACE(ALG_IV_LEN(ivlen)) + CMSG_SPACE(ALG_OP_LEN);
    cbuf = (char *)OPENSSL_malloc(cbuf_sz);
    if (!cbuf) {
        ALG_WARN("Failed to allocate memory for cmsg\n");
        goto err;
    }
    /*
     * Clear out the buffer to avoid surprises with CMSG_ macros.
     */
    memset(cbuf, 0, cbuf_sz);

    msg.msg_control = cbuf;
    msg.msg_controllen = cbuf_sz;

    cmsg = CMSG_FIRSTHDR(&msg);
    afalg_set_op_sk(cmsg, enc);
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    afalg_set_iv_sk(cmsg, iv, ivlen);

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
        perror("Sendmsg failed for zero copy cipher operation");
        goto err;
    }

    ret = vmsplice(actx->zc_pipe[1], &iov, 1, SPLICE_F_GIFT);
    if (ret < 0) {
        printf("vmsplice returned Error: %d\n", errno);
        goto err;
    }
    ret = splice(actx->zc_pipe[0], NULL, actx->sfd, NULL, inl, 0);
    if (ret < 0) {
        printf("splice returned Error: %d\n", errno);
        goto err;
    }
#else
    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;

    sbytes = sendmsg(actx->sfd, &msg, 0);
    if (sbytes < 0) {
        perror("Sendmsg failed for cipher operation");
        goto err;
    }

    if (sbytes != inl)
        ALG_WARN("Cipher operation send bytes %zd != inlen %zd\n", sbytes,
                 inl);
#endif

    ret = 1;

 err:
    if (cbuf)
        free(cbuf);
    return ret;
}

static int afalg_do_cipher_sk(afalg_ctx *actx, unsigned char *out,
                              const unsigned char *in, size_t inl,
                              unsigned char *iv, unsigned int ivlen,
                              unsigned int enc)
{
    int ret;

    ret =
        afalg_start_cipher_sk(actx, (unsigned char *)in, inl, iv, ivlen, enc);
    if (ret < 1) {
        goto err;
    }

    ret = afalg_fin_cipher_aio(actx->aio, actx->sfd, out, inl);

 err:
    return ret;
}

STATIC int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
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

    actx->sfd = afalg_socket(key, EVP_CIPHER_CTX_key_length(ctx),
                             iv, EVP_CIPHER_CTX_iv_length(ctx), enc);
    if (actx->sfd < 0) {
        return 0;
    }

    actx->aio = afalg_init_aio();
    if (!actx->aio) {
        return 0;
    }
#ifdef ALG_ZERO_COPY
    pipe(actx->zc_pipe);
#endif

    actx->init_done = MAGIC_INIT_NUM;

    if (iv) {
        memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
        memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    } else {
        memset(ctx->oiv, 0, EVP_CIPHER_CTX_iv_length(ctx));
        memset(ctx->iv, 0, EVP_CIPHER_CTX_iv_length(ctx));
    }

    return 1;
}

STATIC int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
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

    ret = afalg_do_cipher_sk(actx, out, in, inl,
                             ctx->iv, EVP_CIPHER_CTX_iv_length(ctx),
                             ctx->encrypt);
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
    afalg_cipher_cleanup_aio(actx->aio);

    return 1;
}

int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
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
    if (!bind_afalg(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
    IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif
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

static int afalg_chk_platform(void)
{
    int ret;
    int i;
    int kver[3] = { -1 };
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
        ALG_WARN("AFALG not supported this kernel(%d.%d.%d)\n",
                 kver[0], kver[1], kver[2]);
        return 0;
    }

    return 1;
}

void ENGINE_load_afalg(void)
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
