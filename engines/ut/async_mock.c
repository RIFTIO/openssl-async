#include <openssl/async.h>

ASYNC_JOB *ASYNC_get_current_job(void)
{
    return (void *) 1234;
}

void ASYNC_set_wait_fd(ASYNC_JOB *job, int fd)
{

}

int ASYNC_pause_job(void)
{
    return 1;
}

