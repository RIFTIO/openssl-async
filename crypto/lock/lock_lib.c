#include <openssl/lock.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>


int LOCK_init(LOCK *lock)
{
    int sts = 1;

    if (lock != NULL) {
        sts = pthread_mutex_init(&lock->mutex_lock, NULL);
#ifdef LOCK_DEBUG
        if (sts != 0)
            fprintf(stderr, "pthread_mutex_init failed in LOCK_init() - sts = %d.\n", sts);
#endif
    }
#ifdef LOCK_DEBUG
    else
        fprintf(stderr,"NULL pointer passed in LOCK_init()\n");
#endif
    return sts;
}


int LOCK_free(LOCK *lock)
{
    int sts = 1;

    if (lock != NULL) {
        sts = pthread_mutex_destroy(&lock->mutex_lock);
#ifdef LOCK_DEBUG
        if (sts != 0)
            fprintf(stderr, "pthread_mutex_destroy failed in LOCK_free() - sts = %d. Continuing anyway.\n", sts);
#endif
    }
#ifdef LOCK_DEBUG
    else
        fprintf(stderr,"NULL pointer passed in LOCK_free()\n");
#endif
    return sts;
}


int LOCK_lock(LOCK *lock)
{
    int rc = -1;

    if (lock != NULL) {
        rc = pthread_mutex_lock(&lock->mutex_lock);
#ifdef LOCK_DEBUG
        if (rc != 0)
            fprintf(stderr,"pthread_mutex_lock: %s\n", strerror(rc));
#endif
    }
#ifdef LOCK_DEBUG
    else
        fprintf(stderr,"NULL pointer passed in LOCK_lock()\n");
#endif
    return rc;
}

int LOCK_unlock(LOCK *lock)
{
    int rc = -1;

    if (lock != NULL) {
        rc = pthread_mutex_unlock(&lock->mutex_lock);
#ifdef LOCK_DEBUG
        if (rc != 0)
            fprintf(stderr,"pthread_mutex_unlock: %s\n", strerror(rc));
#endif
    }
#ifdef LOCK_DEBUG
    else
        fprintf(stderr,"NULL pointer passed in LOCK_unlock()\n");
#endif
    return rc;
}
