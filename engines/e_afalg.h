#ifndef _E_AFALG_H_
#define _E_AFALG_H_

/* If compiling with Unit Tests
 * disable local linkage.
 * */
#ifndef AFALG_NO_UNIT_TEST
#define STATIC static
#else
#define STATIC
#endif

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE   16
#endif
#define AES_KEY_SIZE_128 16
#define AES_IV_LEN       16

struct afalg_ctx_st {
    int fd;
};
typedef struct afalg_ctx_st afalg_ctx;

/* Engine Lifetime functions */
static int afalg_destroy(ENGINE *e);
static int afalg_init(ENGINE *e);
static int afalg_finish(ENGINE *e);
void ENGINE_load_afalg(void);
int afalg_ciphers(ENGINE *e, const EVP_CIPHER **cipher, 
                  const int **nids, int nid);
STATIC int afalg_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);
static int afalg_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl);
static int afalg_cipher_cleanup(EVP_CIPHER_CTX *ctx);

#endif
