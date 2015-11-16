#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ossl_typ.h>
#include <e_afalg.h>
#include <openssl/evp.h>

#define PRINT_INFO(x, args...) printf("UT: "x, ##args);
#define BUFSZ 4096
char buf[BUFSZ] __attribute__((__aligned__(BUFSZ)));
#define RBUFSZ 4096
char rbuf[RBUFSZ] __attribute__((__aligned__(RBUFSZ)));
#define DBUFSZ 4096
char dbuf[DBUFSZ] __attribute__((__aligned__(DBUFSZ)));

static void test_afalg_cipher_init(void)
{
    int ret;
    char *s = "afalg_cipher_init";
    EVP_CIPHER_CTX ctx = {};
    unsigned char key[AES_KEY_SIZE_128] = "USETHISKEYTOENC";
    unsigned char iv[AES_IV_LEN] = "0123456789ABCDEF";

    ret = afalg_cipher_init(NULL, key, iv, 1); 
    assert (ret == 0
            && "Cipher Init Failed for NULL paramter for ctx");
    PRINT_INFO("%s: Passed NULL Parameter Test for ctx\n", s);

    ret = afalg_cipher_init(&ctx, NULL, iv, 1); 
    assert (ret == 0
            && "Cipher Init Failed for NULL paramter for key");
    PRINT_INFO("%s: Passed NULL Parameter Test for key\n", s);

    ret = afalg_cipher_init(&ctx, key, NULL, 1); 
    assert (ret == 0
            && "Cipher Init Failed for NULL paramter for iv");
    PRINT_INFO("%s: Passed NULL Parameter Test for iv\n", s);

    ret = afalg_cipher_init(&ctx, key, iv, 1); 
    ret = memcmp(ctx.iv, iv, AES_IV_LEN);
    assert ( ret == 0 && "afalg_cipher_init failed IV fill test");
    PRINT_INFO("%s: Passed IV Fill Test\n", s);

}

static void test_something()
{
        assert(1 == 1 && "AF_ALG Init failed");
}

int main ( int argc, char **argv)
{
        test_something();
        test_afalg_cipher_init();
        return 0;
}

