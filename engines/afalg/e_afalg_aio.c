/* Currently under this define until a way is
 * found to selectively compile the file in openssl/engine/Makefile
 * */
# ifdef ALG_USE_AIO

/* AIO headers */
#include <stdio.h>
#include <string.h>
# define _GNU_SOURCE
#include <unistd.h>

#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/async.h>

#define MAX_INFLIGHTS 1

struct afalg_aio_st {
    int efd;
    unsigned int received, retrys, fdnotset, ring_fulls, failed;
    aio_context_t aio_ctx;
    struct io_event events[MAX_INFLIGHTS];
    struct iocb cbt[MAX_INFLIGHTS];
};

typedef struct afalg_aio_st afalg_aio;

static inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static inline int eventfd(int n)
{
    return syscall(__NR_eventfd, n);
}

static inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static inline int io_read(aio_context_t ctx, long n,  struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}


static inline int io_getevents(aio_context_t ctx, long min, long max,
            struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
}


void * afalg_init_aio(void)
{
    int r = -1;
    afalg_aio *aio;

    aio = (afalg_aio *)OPENSSL_malloc(sizeof(afalg_aio));
    if(!aio) {
       fprintf(stderr, "Failed to allocate memory for afalg_aio\n");
       goto err;
    }

    /* Initialise for AIO */
    aio->aio_ctx = 0;
    r = io_setup(MAX_INFLIGHTS, &aio->aio_ctx);
    if (r < 0) {
        perror("io_setup error");
        r = 0;
        goto err;
    }

    aio->efd = eventfd(0);
    aio->received = 0;
    aio->retrys = 0;
    aio->fdnotset = 0;
    aio->ring_fulls = 0;
    aio->failed = 0;
    memset(aio->cbt, 0, sizeof(aio->cbt));
    
    return (void *)aio;

 err:
    if(aio)
        free(aio);
    return NULL;
}

int afalg_fin_cipher_aio(void *ptr, int sfd, unsigned char* buf, size_t len)
{
    int r;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];
    afalg_aio *aio = (afalg_aio *)ptr;
    ASYNC_JOB *job;
    u_int64_t eval = 0;
    
    if(!aio) {
        fprintf(stderr, "%s:ALG AIO CTX Null Pointer\n", __func__);
        return 0;
    }

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    cb = &(aio->cbt[0 % MAX_INFLIGHTS]);
    memset(cb, '\0', sizeof(*cb));
    cb->aio_fildes = sfd;
    cb->aio_lio_opcode = IOCB_CMD_PREAD;
    cb->aio_buf = (unsigned long)buf;
    cb->aio_offset = 0;
    cb->aio_data = 0;
    cb->aio_nbytes = len;
    cb->aio_flags = IOCB_FLAG_RESFD;
    cb->aio_resfd = aio->efd;

    if((job = ASYNC_get_current_job()) != NULL) {
//Not sure of best approach to connect our efd to jobs wait_fd
#if 0
        ASYNC_set_wait_fd(job, aio->efd);
#else
        if (-1 == dup2(aio->efd, ASYNC_get_wake_fd(job))) {
            printf("dup2 error\n");
        }
#endif
    }

    r = io_read(aio->aio_ctx, 1, &cb);
    if (r < 0) {
        perror("io_read failed for cipher operation");
        return 0;
    }
    
    do {
        ASYNC_pause_job();
/* TODO: should this read be made non-blocking? what is best in sync mode? */
        r = read(aio->efd, &eval, sizeof(eval));
        if (r>=0 && eval > 0) {
            r = io_getevents(aio->aio_ctx, 1, 1, events, &timeout);
            if (r > 0) {
                cb = (void*) events[0].obj;
                cb->aio_fildes = 0;
                if (events[0].res == -EBUSY)
                    aio->ring_fulls++;
                else if (events[0].res != 0) {
                    printf("req failed with %lld\n", events[0].res);
                    aio->failed++;
                }
            } else if (r < 0) {
                perror("io_getevents failed");
                return 0;
            } else {
                aio->retrys++;
            }   
        }
    } while (cb->aio_fildes != 0) ;

    return 1;
}

void afalg_cipher_cleanup_aio(void *ptr)
{
    afalg_aio *aio = (afalg_aio *)ptr;
    close(aio->efd);
    //close(aio->bfd);
    io_destroy(aio->aio_ctx); 
    free(aio);
}

#endif /* ALG_USE_AIO */
