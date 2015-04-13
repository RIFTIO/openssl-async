#include <openssl/crypto.h>

#ifdef PTHREADS
# include <pthread.h>

static pthread_mutex_t *lock_cs;
static long *lock_count;
static int app_lock_id;

static void pthreads_locking_callback(int mode, int type, char *file,
                                      int line)
{
# ifdef LOCK_DEBUG
    fprintf(stderr, "thread=%4d mode=%s%s lock=%s %s:%d\n",
            CRYPTO_thread_id(),
            (mode & CRYPTO_LOCK) ? "l" : "u",
            (mode & CRYPTO_READ) ? "r" : "w",
            CRYPTO_get_lock_name(type), file, line);
# endif
    /*
     * if (CRYPTO_LOCK_SSL_CERT == type) fprintf(stderr,"(t,m,f,l) %ld %d %s
     * %d\n", CRYPTO_thread_id(), mode,file,line);
     */
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

static unsigned long pthreads_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)pthread_self();
    return (ret);
}

void thread_setup(void)
{
    int i, num_locks;

    app_lock_id = CRYPTO_get_new_lockid("APP");
    num_locks = app_lock_id + 1;

    lock_cs = OPENSSL_malloc(num_locks * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(num_locks * sizeof(long));
    for (i = 0; i < num_locks; i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

void thread_cleanup(void)
{
    int i, num_locks;

    num_locks = app_lock_id + 1;

    CRYPTO_set_locking_callback(NULL);
# ifdef LOCK_DEBUG
    fprintf(stderr, "thread lock cleanup\n");
# endif
    for (i = 0; i < num_locks; i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
# ifdef LOCK_DEBUG
        fprintf(stderr, "%8ld:%s\n", lock_count[i], CRYPTO_get_lock_name(i));
# endif
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);

# ifdef LOCK_DEBUG
    fprintf(stderr, "thread lock cleanup done\n");
# endif
}

int thread_app_lock_id(void)
{
    return app_lock_id;
}

#endif
