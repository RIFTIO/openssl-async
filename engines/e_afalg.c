/* Based on engines/e_dasync.c */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* AF_ALG Socket based headers */
#include <linux/if_alg.h>
#include <sys/socket.h>

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
#define SOL_ALG 279
#endif 

#define ALG_IV_LEN(len) (sizeof(struct af_alg_iv) + (len))

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
    EVP_CIPH_CBC_MODE , /* flags */
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
    if (sfd == -1)
    {
        perror("Failed to open socket");
        goto err;
    }

    r = bind(sfd, (struct sockaddr *)&sa, sizeof(sa));
    if ( r < 0 )
    {
        perror("Failed to bind socket");
        goto err;
    }

    return sfd;

err:
    if(sfd >= 0)
        close(sfd);
    return r;
}

static int afalg_set_key_sk(int sfd, const char *key, 
                            unsigned int keylen)
{
    int r = -1;

    if (!key)
        return 0;

    r = setsockopt(sfd, SOL_ALG, ALG_SET_KEY, key, keylen);
    if ( r < 0 )
    {
        perror("Failed to set socket option");
        return -1;
    }

    return 1;
}

static int afalg_set_iv_sk(int sfd, const unsigned char *iv, 
                           const unsigned int len)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char *cbuf;
    struct af_alg_iv *aiv;
    int ret = 1;
    int sbytes;

    cbuf = (char *)OPENSSL_malloc(CMSG_SPACE(ALG_IV_LEN(len)));
    if (!cbuf) {
        ALG_WARN("Failed to allocate memory for cmsg\n");
        return 0;
    }

    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(ALG_IV_LEN(len));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(ALG_IV_LEN(len));
    aiv = (struct af_alg_iv *)CMSG_DATA(cmsg);
    aiv->ivlen = len;
    memcpy(aiv->iv, iv, len);
    
    sbytes = sendmsg(sfd, &msg, 0);
    if (sbytes < 0) {
        perror("Sendmsg to set IV failed\n");
        ret = 0;
    }
    
    OPENSSL_free(cbuf);
    return ret;
}

static int afalg_set_op_sk(int sfd, int enc)
{
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    char *cbuf;
    int ret = 1;
    int sbytes;

    cbuf = (char *)OPENSSL_malloc(CMSG_SPACE(sizeof(unsigned int)));
    if (!cbuf) {
        ALG_WARN("Failed to allocate memory for cmsg\n");
        return 0;
    }

    msg.msg_control = cbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(unsigned int));

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(unsigned int));
    *(unsigned int *)CMSG_DATA(cmsg) = enc;
    
    sbytes = sendmsg(sfd, &msg, 0);
    if (sbytes < 0) {
        perror("Sendmsg to set IV failed\n");
        ret = 0;
    }
    
    OPENSSL_free(cbuf);
    return ret;
    
}

static int afalg_socket(const char *key, const int klen,
                        const char *iv, const int ivlen, int enc)
{
    int bfd, sfd;
    int ret = -1;

    bfd = afalg_create_bind_sk();
    if (bfd < 1) {
        /*TODO: Create a generic socket setup error code for openssl*/
        return 0;       
    }

    ret = afalg_set_key_sk(bfd, key, klen);
    if (ret < 1)
    {
        ALG_WARN("Failed to set key\n");
        goto err;
    }

    sfd = accept(bfd, NULL, 0);
    if (sfd < 0) {
        perror("Socket Accept Failed");
        goto err;
    }

    if (iv) { 
        ret = afalg_set_iv_sk(sfd, iv, ivlen);
        if (ret < 1)
            goto err;
    }

    ret = afalg_set_op_sk(sfd, 
                           enc ? ALG_OP_ENCRYPT : ALG_OP_DECRYPT);
    if (ret < 1)                       
        goto err;
    
    return sfd;

err:
    if (bfd >= 0)
        close (bfd);
    if (sfd >= 0)
        close (sfd);
    return -1;
}

STATIC int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    int ciphertype;
    int bfd;
    int ret = 0;
    afalg_ctx *actx;

    if (!ctx || !key ) {
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
                             iv, EVP_CIPHER_CTX_iv_length(ctx),
                             enc);
    if (actx->sfd < 0 ) {
        return 0;
    }
    actx->init_done = MAGIC_INIT_NUM; 

    if (iv) 
        memcpy(ctx->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    else
        memset(ctx->iv, 0, EVP_CIPHER_CTX_iv_length(ctx));

    return 1;
}

static int afalg_start_cipher_sk(int sfd, const unsigned char *in, size_t inl)
{
    struct msghdr msg = {};
    struct iovec iov;
    int sbytes;
    int ret = 1;

    iov.iov_base = (unsigned char *)in;
    iov.iov_len = inl;
    msg.msg_flags = MSG_MORE;

    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;

    sbytes = sendmsg(sfd, &msg, 0);
    if (sbytes < 0) {
        perror("Sendmsg failed for cipher operation");
        return 0;
    }
    
    if(sbytes != inl)
        ALG_WARN("Cipher operation send bytes %d != inlen %d\n", sbytes, inl);

    return 1;
}

static int afalg_fin_cipher_sk(int sfd, unsigned char* buf, size_t len)
{
    struct msghdr msg = {};
    struct iovec iov;
    int rbytes;
    int ret = 1;

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_iovlen = 1;
    msg.msg_iov = &iov;

    rbytes = recvmsg(sfd, &msg, 0);
    if (rbytes < 0) {
        perror("Sendmsg failed for cipher operation");
        return 0;
    }
    
    if(rbytes != len)
        ALG_WARN("Cipher operation send bytes %d != inlen %d\n", rbytes, len);

    return 1;
    
}

static int afalg_do_cipher_sk(int sfd, unsigned char *out,
                              const unsigned char *in, size_t inl)
{
    int ret;
    
    ret = afalg_start_cipher_sk(sfd, (unsigned char *)in, inl);
    if (ret < 1) {
        goto err;
    }

    ret = afalg_fin_cipher_sk(sfd, out, inl);

err:
    return ret;
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
    
    actx = (afalg_ctx *)ctx->cipher_data;
    if (!actx || actx->init_done != MAGIC_INIT_NUM) {
        ALG_WARN("%s afalg ctx passed\n", !ctx ? "NULL" : "Uninitialised");
        return 0;
    }

    ret = afalg_do_cipher_sk(actx->sfd, out, in, inl);
    if (ret < 1) {
        ALG_WARN("Socket cipher operation failed\n");
        return 0;
    }

    return 1;
}


static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    return 0;
}

int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher, 
                  const int **nids, int nid)
{
    int r = 1;

    if(!cipher) {
        *nids = afalg_cipher_nids;
        return (sizeof(afalg_cipher_nids)/sizeof(afalg_cipher_nids[0]));
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

    if (!ENGINE_set_ciphers(e, afalg_ciphers)) {
        AFALGerr(AFALG_F_BIND_AFALG, AFALG_R_INIT_FAILED);
        return 0;
    }

    return 1;
}

# ifndef OPENSSL_NO_DYNAMIC_ENGINE
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
# endif

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

void ENGINE_load_afalg(void)
{
    ENGINE *toadd = engine_afalg();
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
