/* AIO headers */
#include <linux/aio_abi.h>
#include <sys/syscall.h>

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


static inline int eventfd(int n)
{
    return syscall(__NR_eventfd, n);
}

int afalg_aio(afalg_ctx *actx)
{
    int r=-1;

    /* Initialise for AIO */
    actx->aio_ctx = 0;
    r = io_setup(MAX_INFLIGHTS, &actx->aio_ctx);
    if (r < 0) {
        perror("io_setup error");
        return 0;
    }

    actx->efd = eventfd(0);
    actx->received = 0;
    actx->retrys = 0;
    actx->fdnotset = 0;
    actx->ring_fulls = 0;
    actx->failed = 0;
    memset(actx->cbt, 0, sizeof(actx->cbt));

    return 1;
}

static int afalg_fin_cipher_aio(afalg_ctx *actx, unsigned char* buf, size_t len)
{
    int r;
    struct iocb *cb;
    struct timespec timeout;
    struct io_event events[MAX_INFLIGHTS];

    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    cb = &(actx->cbt[0 % MAX_INFLIGHTS]);
    memset(cb, '\0', sizeof(*cb));
    cb->aio_fildes = actx->sfd;
    cb->aio_lio_opcode = IOCB_CMD_PREAD;
    cb->aio_buf = (unsigned long)buf;
    cb->aio_offset = 0;
    cb->aio_data = 0;
    cb->aio_nbytes = len;
    cb->aio_flags = IOCB_FLAG_RESFD;
    cb->aio_resfd = actx->efd;
    r = io_read(actx->aio_ctx, 1, &cb);
    if (r < 0) {
        perror("io_read failed for cipher operation");
        return 0;
    }
    
    do {
        //ASYNC_pause_job();
        r = io_getevents(actx->aio_ctx, 1, 1, events, &timeout);
        if (r > 0) {
            cb = (void*) events[0].obj;
            cb->aio_fildes = 0;
            if (events[0].res == -EBUSY)
                actx->ring_fulls++;
            else if (events[0].res != 0) {
                printf("req failed with %d\n", events[0].res);
                actx->failed++;
            }
        } else if (r < 0) {
            perror("io_getevents failed");
            return 0;
        } else {
            actx->retrys++;
        }
    } while (cb->aio_fildes != 0) ;
}

int afalg_cipher_cleanup_aio(afalg_aio *aio)
{
    close(aio->efd);
    //close(aio->bfd);
    io_destroy(aio->aio_ctx); 
}
