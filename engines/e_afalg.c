/* Based on engines/e_dasync.c */

#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include "e_afalg.h"

#define AFALG_LIB_NAME "AFALG"
#include "e_afalg_err.c"

/* OUTPUTS */
#define ALG_DGB(x, args...) fprintf(stderr, "ALG_DBG: ", x, ##args);
#define ALG_INFO(x, args...) fprintf(stderr, "ALG_INFO: ", x, ##args);
#define ALG_WARN(x, args...) fprintf(stderr, "ALG_WARN: " x, ##args);
#define ALG_ERR(x, args...) fprintf(stderr, "ALG_ERR: ", x, ##args);

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

STATIC int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc)
{
    if (!ctx || !key || !iv) {
        ALG_WARN("Null Parameter to %s\n", __func__); 
        return 0;
    }

    memcpy(ctx->iv, iv, AES_IV_LEN);

    return 0;
}

static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl)
{
    return 0;
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
