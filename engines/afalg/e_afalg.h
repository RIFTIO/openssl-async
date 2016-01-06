#ifndef _E_AFALG_H_
# define _E_AFALG_H_

/*
 * If compiling with Unit Tests disable local linkage.
 */
# ifndef AFALG_NO_UNIT_TEST
#  define STATIC static
# else
#  define STATIC
# endif

# ifndef AES_BLOCK_SIZE
#  define AES_BLOCK_SIZE   16
# endif
# define AES_KEY_SIZE_128 16
# define AES_IV_LEN       16

# define MAGIC_INIT_NUM 0x1890671

struct afalg_ctx_st {
    int init_done;
    int sfd;
# ifdef ALG_ZERO_COPY
    int zc_pipe[2];
# endif
    void *aio;
};

typedef struct afalg_ctx_st afalg_ctx;
#endif
