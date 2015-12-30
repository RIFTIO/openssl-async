#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#include <openssl/ossl_typ.h>
#include <e_afalg.h>
#include <openssl/evp.h>

#define PRINT_INFO(x, args...) printf("UT: "x, ##args);
#define ALIGN_B 32
#define BUFSZ (ALIGN_B*4)
char buf[BUFSZ] __attribute__((__aligned__(BUFSZ)));
#define RBUFSZ BUFSZ
char rbuf[RBUFSZ] __attribute__((__aligned__(RBUFSZ)));
#define DBUFSZ BUFSZ
char dbuf[DBUFSZ] __attribute__((__aligned__(DBUFSZ)));

# ifdef TEST_DEBUG
# define PRINT_DBG(x, args...) printf("UT: "x, ##args);
# define PRINT_ARRAY(x,l)  \
    for(int ii=0; ii < (l); ii++) \
            printf("%02x%c", *(((unsigned char *)(x))+ii), \
                           (ii+1)%32 ? ' ' : '\n')
# else
# define PRINT_DBG(x, args...) 
# define PRINT_ARRAY(x,l)
# endif

static void evp_cipher_ctx_init(EVP_CIPHER_CTX *ctx, 
                                int clen, int klen, 
                                int nid, int op )
{
    EVP_CIPHER *c;
    c = (EVP_CIPHER *)malloc(sizeof(EVP_CIPHER));
    c->iv_len = clen;
    c->nid = nid;
    ctx->cipher = c;
    ctx->encrypt = op;

    ctx->key_len = klen;
    ctx->cipher_data = malloc(sizeof(afalg_ctx));
}

static void test_afalg_cipher_init(void)
{
    int ret;
    int cmp;
    char *s = "afalg_cipher_init";
    EVP_CIPHER_CTX st_ctx = {};
    EVP_CIPHER_CTX *ctx = &st_ctx;
    unsigned char key[AES_KEY_SIZE_128] = "USETHISKEYTOENC";
    unsigned char iv[AES_IV_LEN] = "0123456789ABCDEF";
    unsigned char z_iv[AES_IV_LEN];
    memset(z_iv, 0, AES_IV_LEN);

    PRINT_INFO("\n---- Start %s Tests ----\n", s);

    ret = afalg_cipher_init(NULL, key, iv, 1); 
    assert (ret == 0
            && "Cipher Init Failed for NULL paramter for ctx");
    PRINT_INFO("%s: Passed NULL Parameter Test for ctx\n", s);

    ret = afalg_cipher_init(ctx, NULL, iv, 1); 
    assert (ret == 0
            && "Cipher Init Failed for NULL paramter for key");
    PRINT_INFO("%s: Passed NULL Parameter Test for key\n", s);
    
    /* Cipher should be set */
    ctx->cipher = NULL;
    ret = afalg_cipher_init(ctx, key, iv, 1);
    assert (ret == 0 && "afalg_cipher_init failed NULL cipher check");
    PRINT_INFO("%s: Passed NULL Cipher Test\n", s);

    /* Cipher should be supported */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    ret = afalg_cipher_init(ctx, key, iv, 1);
    assert (ret == 1 && 
            "afalg_cipher_init: Supported Cipher NID_aes_128_cbc Test Failed");
    PRINT_INFO("%s: Supported Cipher NID_aes_128_cbc Test passed\n", s);

    /* Check for unsupported ciphers */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_des_cbc, 1);
    ret = afalg_cipher_init(ctx, key, iv, 1);
    assert (ret == 0 && 
            "afalg_cipher_init: Unsupported Cipher NID_des_cbc Test Failed");
    PRINT_INFO("%s: Unsupported Cipher Test passed\n", s);

    /* NULL IV should get memset to 0 */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    ret = afalg_cipher_init(ctx, key, NULL, 1); 
    cmp = memcmp(ctx->iv, z_iv, EVP_CIPHER_CTX_iv_length(ctx));    
    assert (cmp == 0
            && "Cipher Init Failed for NULL paramter for iv");
    PRINT_INFO("%s: Passed NULL Parameter Test for iv\n", s);
    
    /* Non NULL IV should be copied in CTX */
    ret = afalg_cipher_init(ctx, key, iv, 1); 
    cmp = memcmp(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    assert (cmp == 0 && "afalg_cipher_init failed Original IV fill test");
    cmp = memcmp(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
    assert (cmp == 0 && "afalg_cipher_init failed IV fill test");
    PRINT_INFO("%s: Passed IV Fill Test\n", s);

    /* Space allocated for App data */
    ctx->cipher_data = NULL;
    ret = afalg_cipher_init(ctx, key, iv, 1); 
    assert (ret == 0 && "afalg_cipher_init Failed NULL cipher data test");
    PRINT_INFO("%s: Passed NULL Cipher data test\n", s);

    /* When successful, valid fd should be returned */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    ret = afalg_cipher_init(ctx, key, iv, 1);
    assert (ret = 1 && 
            ((afalg_ctx *)ctx->cipher_data)->sfd > 1 &&
            ((afalg_ctx *)ctx->cipher_data)->init_done == MAGIC_INIT_NUM &&
            ((afalg_ctx *)ctx->cipher_data)->aio != NULL &&
            "afalg_cipher_init Failed valid socket fd test");
    PRINT_INFO("%s: Passed valid socket fd test\n", s);

    PRINT_INFO("\n---- End %s Tests ----\n", s);
}

static int test_afalg_do_cipher()
{
    EVP_CIPHER_CTX st_ctx = {};
    EVP_CIPHER_CTX *ctx = &st_ctx;
    unsigned char key[AES_KEY_SIZE_128] = "USETHISKEYTOENC";
    unsigned char iv[AES_IV_LEN] = "0123456789ABCDEF";
    int ret;
    int t = 0;

    /* NULL parameter check */
    ret = afalg_do_cipher(NULL, buf, rbuf, BUFSZ);
    assert ( ret == 0 && "test_afalg_do_cipher: Failed Parameter ctx NULL test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Parameter ctx NULL test\n");
 
    ret = afalg_do_cipher(ctx, NULL, rbuf, BUFSZ);
    assert ( ret == 0 && "test_afalg_do_cipher: Failed Parameter ibuffer NULL test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Parameter ibuffer NULL test\n");

    ret = afalg_do_cipher(ctx, buf, NULL, BUFSZ);
    assert ( ret == 0 && "test_afalg_do_cipher: Failed Parameter obuffer NULL test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Parameter obuffer NULL test\n");

    /* Check for NULL cipher data */
    ret = afalg_do_cipher(ctx, buf, rbuf, BUFSZ);
    assert ( ret == 0 && "test_afalg_do_cipher: Failed cipher_data NULL test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed cipher_data NULL test\n");
    
    /* Check for unitialised cipher data */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    ret = afalg_do_cipher(ctx, buf, rbuf, BUFSZ);
    assert ( ret == 0 && "test_afalg_do_cipher: Failed uninitialised cipher_data test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed uninitialised cipher_data test\n");

    afalg_cipher_init(ctx, key, iv, 1);
    /* ALLOW for zero len encryption/Decryption */
    ret = afalg_do_cipher(ctx, buf, rbuf, 0);
    assert ( ret == 1 && "test_afalg_do_cipher: Failed zero length test");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Parameter zero length test\n");

    /* Encrypt a block size */
    memcpy(buf, "Encrypt this   \0", 16);
    memcpy(rbuf, "Encrypt this   \0", 16);
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    afalg_cipher_init(ctx, key, iv, 1);
    ret = afalg_do_cipher(ctx, rbuf, buf, 16);
    if (ret < 1) {
        assert ("test_afalg_do_cipher: Failed to encrypt");
    }
    assert( memcmp(buf, rbuf, 16) != 0 && "test_afalg_do_cipher: Failed Plain txt = Enc txt");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Encryption test\n");
    
    /* Decrypt previously encrypted message */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 0);
    afalg_cipher_init(ctx, key, iv, 0);
    ret = afalg_do_cipher(ctx, dbuf, rbuf, 16);
    if (ret < 1) {
        assert ("test_afalg_do_cipher: Failed to decrypt");
    }

    PRINT_ARRAY(buf,16);
    PRINT_DBG("\n");
    PRINT_ARRAY(rbuf, 16);
    PRINT_DBG("\n");
    PRINT_ARRAY(dbuf,16);
    PRINT_DBG("\n");
    assert( memcmp(buf, dbuf, 16) == 0 && "test_afalg_do_cipher: Failed Dec(Enc(P)) != P");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed Encryption Decryption Test\n");

    /* Encrypt a BIG Block */
    memset(buf, 'A', BUFSZ);
    memset(rbuf, 'A', BUFSZ);
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    afalg_cipher_init(ctx, key, iv, 1);
    ret = afalg_do_cipher(ctx, rbuf, buf, BUFSZ);
    if (ret < 1) {
        assert ("test_afalg_do_cipher: Failed to encrypt");
    }
    assert( memcmp(buf, rbuf, BUFSZ) != 0 && 
            "test_afalg_do_cipher: Failed Single big block Plain txt = Enc txt");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed single big block Encryption test\n");
    
    /* Decrypt previously encrypted message */
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 0);
    afalg_cipher_init(ctx, key, iv, 0);
    ret = afalg_do_cipher(ctx, dbuf, rbuf, BUFSZ);
    if (ret < 1) {
        assert ("test_afalg_do_cipher: Failed to decrypt single big block");
    }
    assert( memcmp(buf, dbuf, BUFSZ) == 0 && 
            "test_afalg_do_cipher: Failed Single big block Dec(Enc(P)) != P");
    t++;
    PRINT_INFO("test_afalg_do_cipher: Passed single big block Encryption Decryption Test\n");
    
    /* Encrypt a big block in one go and 
     * Decrypt in chunks */
    memset(buf, 'B', BUFSZ);
    memset(rbuf, 'B', BUFSZ);
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 1);
    afalg_cipher_init(ctx, key, iv, 1);
    ret = afalg_do_cipher(ctx, rbuf, buf, BUFSZ);
    if (ret < 1) {
        assert ("test_afalg_do_cipher: Failed to encrypt");
    }
    assert( memcmp(buf, rbuf, BUFSZ) != 0 && 
            "test_afalg_do_cipher: Failed Single big block Plain txt = Enc txt");
    
    evp_cipher_ctx_init(ctx, AES_IV_LEN, AES_KEY_SIZE_128, NID_aes_128_cbc, 0);
    afalg_cipher_init(ctx, key, iv, 0);
    for (int c = 0; c < BUFSZ/ALIGN_B; c++) {
        ret = afalg_do_cipher(ctx, dbuf+(c*ALIGN_B), rbuf+(c*ALIGN_B), ALIGN_B);
        if (ret < 1) 
            assert ("test_afalg_do_cipher: Failed to decrypt single big block");
        
    }

    PRINT_DBG("--------- Original Buffer ------------\n");
    PRINT_ARRAY(buf, BUFSZ);
    PRINT_DBG("\n--------- Encrypted Buffer ------------\n");
    PRINT_ARRAY(rbuf, BUFSZ);
    PRINT_DBG("\n--------- Decrypted Buffer ------------\n");
    PRINT_ARRAY(dbuf, BUFSZ);
    assert( memcmp(buf, dbuf, BUFSZ) == 0 && 
            "test_afalg_do_cipher: Failed multiple big block Dec(Enc(P)) != P");
    PRINT_INFO("test_afalg_do_cipher: Passed Single Enc Multiple Dec Test\n");
}

int main ( int argc, char **argv)
{
    test_afalg_cipher_init();
    test_afalg_do_cipher();
    return 0;
}

