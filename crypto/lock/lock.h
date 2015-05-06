#ifndef HEADER_LOCK_H
# define HEADER_LOCK_H

# ifndef OPENSSL_NO_DEPRECATED
#  include <openssl/crypto.h>
# endif
# include <pthread.h>
# include <stdlib.h>

#ifdef  __cplusplus
extern "C" {
#endif


struct openssl_lock_st {
    pthread_mutex_t mutex_lock;
};

typedef struct openssl_lock_st LOCK;

int LOCK_init(LOCK *lock);
int LOCK_free(LOCK *lock);
int LOCK_lock(LOCK *lock);
int LOCK_unlock(LOCK *lock);


#ifdef  __cplusplus
}
#endif
#endif
