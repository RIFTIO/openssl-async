/* crypto/prf/prftest.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../e_os.h"

#ifdef OPENSSL_NO_PRF
int main(int argc, char *argv[])
{
    printf("No PRF support\n");
    return (0);
}
#else
# include <openssl/prf.h>
# include <openssl/evp.h>
# include <openssl/tls1.h>
#endif

#ifndef OPENSSL_NO_PRF
void tests_hexdump(const char *title, const unsigned char *s, int l)
{
    int i = 0;

    printf("%s", title);

    for (i = 0; i < l; i++) {
        if ((i % 8) == 0)
            printf("\n        ");

        printf("0x%02X, ", s[i]);
    }

    printf("\n\n");
}

static struct test_st {
    unsigned char seed1[32];
    int seed1_len;
    unsigned char seed2[32];
    int seed2_len;
    unsigned char seed3[32];
    int seed3_len;
    unsigned char seed4[32];
    int seed4_len;
    unsigned char seed5[32];
    int seed5_len;
    unsigned char secret[48];
    int secSize;
    size_t masterSecretSize;
    unsigned char expectedMasterSecret[108];
} test[4] = {
    {
        TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE, {
            0x88, 0x3E, 0x61, 0xAE, 0xE3, 0xB6, 0xD8, 0x62, 0x18, 0x86, 0x4A,
            0x7D, 0x4B, 0x0A, 0xA5, 0xF9, 0xE7, 0xE7, 0xAA, 0xD5, 0x8B, 0xB1,
            0xBD, 0x54, 0x1F, 0xF2, 0x47, 0xCC, 0xDA, 0xA8, 0x3F, 0x2D
        }, 32, "", 0, {
            0xEF, 0x14, 0xF7, 0x48, 0x0C, 0x36, 0xB2, 0xF3, 0xFB, 0x4F, 0x9F,
            0xBF, 0xBA, 0x6C, 0x6F, 0x0A, 0x27, 0xAB, 0xF8, 0x16, 0xFF, 0x37,
            0xE9, 0x88, 0x0D, 0x8A, 0x3B, 0x59, 0x57, 0xA6, 0xC1, 0x7E
        }, 32, "", 0, {
            0x03, 0x03, 0x0B, 0x03, 0x07, 0xEF, 0x7A, 0xDC, 0xFB, 0xD1, 0x86,
            0xE3, 0x46, 0xC0, 0x45, 0x36, 0xA2, 0x73, 0x31, 0xE3, 0x7A, 0xC8,
            0x45, 0x3A, 0xB9, 0x58, 0x0A, 0x4E, 0xA1, 0xC0, 0x73, 0x55, 0x57,
            0x92, 0xA5, 0xCD, 0x1A, 0x76, 0xE8, 0xDD, 0xCF, 0xE3, 0x7A, 0x77,
            0x48, 0xEE, 0x16, 0xAE
        }, 48, 48, {
            0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11, 0xE1, 0x51, 0x51,
            0x71, 0x3B, 0xAF, 0xB2, 0xFE, 0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F,
            0x20, 0xB1, 0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B, 0x32,
            0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D, 0x30, 0x53, 0x39, 0x53,
            0xE0, 0x09, 0x7E, 0xE9
        },
    },
    {
        TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE, {
            0xEF, 0x14, 0xF7, 0x48, 0x0C, 0x36, 0xB2, 0xF3, 0xFB, 0x4F, 0x9F,
            0xBF, 0xBA, 0x6C, 0x6F, 0x0A, 0x27, 0xAB, 0xF8, 0x16, 0xFF, 0x37,
            0xE9, 0x88, 0x0D, 0x8A, 0x3B, 0x59, 0x57, 0xA6, 0xC1, 0x7E
        }, 32, {
            0x88, 0x3E, 0x61, 0xAE, 0xE3, 0xB6, 0xD8, 0x62, 0x18, 0x86, 0x4A,
            0x7D, 0x4B, 0x0A, 0xA5, 0xF9, 0xE7, 0xE7, 0xAA, 0xD5, 0x8B, 0xB1,
            0xBD, 0x54, 0x1F, 0xF2, 0x47, 0xCC, 0xDA, 0xA8, 0x3F, 0x2D
        }, 32, "", 0, "", 0, {
            0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11, 0xE1, 0x51, 0x51,
            0x71, 0x3B, 0xAF, 0xB2, 0xFE, 0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F,
            0x20, 0xB1, 0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B, 0x32,
            0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D, 0x30, 0x53, 0x39, 0x53,
            0xE0, 0x09, 0x7E, 0xE9
        }, 48, 104, {
            0x5E, 0xD9, 0x1F, 0x2F, 0x5C, 0x3A, 0x78, 0x82, 0x7C, 0xC3, 0xEA,
            0x22, 0x47, 0x5F, 0x24, 0xD6, 0xEA, 0x8B, 0xCC, 0x40, 0xF5, 0xAD,
            0xC1, 0x39, 0xBE, 0x15, 0x87, 0x85, 0x3A, 0x4C, 0x63, 0xA6, 0xBD,
            0x5C, 0x58, 0x5D, 0xD8, 0xD9, 0x1F, 0x1D, 0xE1, 0x60, 0xD2, 0x2E,
            0x59, 0x31, 0x0E, 0xFC, 0xB7, 0xFB, 0x0D, 0x9A, 0x4E, 0xF8, 0x8D,
            0x72, 0x35, 0x6D, 0x8C, 0xEC, 0x99, 0x6F, 0x08, 0x41, 0xB3, 0xB5,
            0xDA, 0xB6, 0x7F, 0x97, 0xF0, 0xFF, 0xAF, 0xF4, 0x05, 0x26, 0xC2,
            0x05, 0x3D, 0x60, 0x18, 0xAD, 0x01, 0x59, 0xE6, 0x16, 0x06, 0x0C,
            0x90, 0x81, 0x8D, 0x23, 0x08, 0x90, 0x57, 0x73, 0x56, 0xAE, 0xD6,
            0x7F, 0x64, 0x2B, 0x29, 0x72
        },
    },
    {
        TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, {
            0xC2, 0xFA, 0x5E, 0xE1, 0x95, 0xCF, 0x3C, 0xF8, 0x09, 0xC8, 0x37,
            0xC5, 0x80, 0x41, 0xFA, 0xC2, 0xE3, 0x7C, 0x2F, 0xCC, 0xA7, 0x50,
            0x82, 0x6C, 0x9E, 0x5D, 0x87, 0x5F, 0x46, 0xD4, 0xF7, 0x02
        }, 32, "", 0, "", 0, "", 0, {
            0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11, 0xE1, 0x51, 0x51,
            0x71, 0x3B, 0xAF, 0xB2, 0xFE, 0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F,
            0x20, 0xB1, 0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B, 0x32,
            0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D, 0x30, 0x53, 0x39, 0x53,
            0xE0, 0x09, 0x7E, 0xE9
        }, 48, 12, {
            0xC9, 0x86, 0xD8, 0xFE, 0x8D, 0x26, 0xCB, 0x11, 0xC8, 0xB3, 0xF6,
            0xD3
        },
    },
    {
        TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, {
            0xD8, 0xDD, 0x4A, 0xC2, 0x78, 0xD2, 0x2C, 0xE6, 0x22, 0x9C, 0x18,
            0x2C, 0x88, 0x1B, 0x4D, 0x7F, 0xC7, 0xC0, 0x71, 0x46, 0x8C, 0xE8,
            0x86, 0x5B, 0x87, 0x5A, 0x31, 0x2E, 0x53, 0x33, 0xE1, 0x39
        }, 32, "", 0, "", 0, "", 0, {
            0x57, 0x0A, 0xD8, 0x78, 0x67, 0x2B, 0x0B, 0x11, 0xE1, 0x51, 0x51,
            0x71, 0x3B, 0xAF, 0xB2, 0xFE, 0xE4, 0x33, 0x41, 0x67, 0x35, 0x3F,
            0x20, 0xB1, 0x6F, 0x9B, 0xF8, 0x91, 0x2F, 0xD9, 0xF6, 0x3B, 0x32,
            0x7A, 0xAD, 0x77, 0xBD, 0xC2, 0x35, 0x6D, 0x30, 0x53, 0x39, 0x53,
            0xE0, 0x09, 0x7E, 0xE9
        }, 48, 12, {
            0x68, 0xCA, 0xCC, 0xAF, 0x1A, 0x9F, 0xAE, 0xE4, 0xFC, 0x23, 0xD5,
            0xC6
        },
    }
};

int main(int argc, char *argv[])
{
    const EVP_MD *md[1];
    int md_count = 1, ret = 0, err = 0, i = 0;
    unsigned char *masterSecret = NULL;
    OpenSSL_add_all_digests();

    *md = EVP_get_digestbyname(SN_sha256);

    for (i = 0; i < 4; i++) {
        masterSecret = (unsigned char *)malloc(test[i].masterSecretSize);
        ret = EVP_PKEY_derive_PRF(EVP_PKEY_PRF, /* this is a constant */
                                  NULL, /* Engine */
                                  md, md_count, test[i].seed1, test[i].seed1_len, /* seed1:
                                                                                   * master
                                                                                   * secret */
                                  test[i].seed2, test[i].seed2_len, /* seed2:
                                                                     * server
                                                                     * random */
                                  test[i].seed3, test[i].seed3_len, /* seed3:
                                                                     * client
                                                                     * random */
                                  test[i].seed4, test[i].seed4_len, /* seed4:
                                                                     * empty */
                                  test[i].seed5, test[i].seed5_len, /* seed5:
                                                                     * empty */
                                  test[i].secret, test[i].secSize, masterSecret, &test[i].masterSecretSize, /* expected
                                                                                                             * size of
                                                                                                             * the
                                                                                                             * output */
                                  TLS1_2_VERSION, NULL, /* sync -> no
                                                         * callback */
                                  (void *)NULL);

        if (ret) {
            if (memcmp
                (masterSecret, test[i].expectedMasterSecret,
                 test[i].masterSecretSize)) {
                printf("# FAIL verify for PRF\n");
                tests_hexdump("PRF actual  :", masterSecret,
                              test[i].masterSecretSize);
                tests_hexdump("PRF expected:", test[i].expectedMasterSecret,
                              test[i].masterSecretSize);
                err++;
            } else {
                printf("PRF test %s ok\n", test[i].seed1);
            }

        } else
            err++;
        free(masterSecret);
    }
    EXIT(err);
    return (0);
}

#endif
