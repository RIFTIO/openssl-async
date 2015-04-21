/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*****************************************************************************
 * @file e_qat.c
 *
 * This file provides a OpenSSL engine for the  quick assist API
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

/* Defines */
#ifdef USE_QAT_MEM
# define QAT_DEV "/dev/qat_mem"
#endif
#ifdef USE_QAE_MEM
# define QAT_DEV "/dev/qae_mem"
#endif

#define POLL_PERIOD_IN_NS 10000
/*
 * The number of retries of the nanosleep if it gets interrupted during
 * waiting between polling.
 */
#define QAT_CRYPTO_NUM_POLLING_RETRIES (5)

/*
 * The number of seconds to wait for a response back after submitting a
 * request before raising an error.
 */
#define QAT_CRYPTO_RESPONSE_TIMEOUT (5)

/* Algorithm registration options*/

/* Standard Includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>

/* Local Includes */
#include "qat_ciphers.h"
//#include "qat_digests.h"
#include "qat_rsa.h"
//#include "qat_dsa.h"
//#include "qat_dh.h"
//#include "qat_ecdh.h"
//#include "qat_ecdsa.h"
#include "e_qat.h"
#include "qat_utils.h"
#include "e_qat_err.h"
//#include "qat_rand.h"
//# include "qat_prf.h"

/* OpenSSL Includes */
#include <openssl/err.h>
#include <openssl/async.h>

/* QAT includes */
#ifdef USE_QAT_MEM
# include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
# include "qat_mem_drv_inf.h"
#endif
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_types.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qat_parseconf.h"

#define likely(x)   __builtin_expect (!!(x), 1)
#define unlikely(x) __builtin_expect (!!(x), 0)

/* Forward Declarations */
static CpaPhysicalAddr realVirtualToPhysical(void *virtualAddr);

/* Use the pthread yield version of sendpoll */
/*
 * #define USE_PTHREAD_YIELD
 */

#ifndef USE_PTHREAD_YIELD
int ns_handler(struct timespec *reqTime);
#endif

static int qat_engine_finish(ENGINE *e);

/* Qat engine id declaration */
static const char *engine_qat_id = "qat";
static const char *engine_qat_name =
    "Reference implementation of QAT crypto engine";

/* Globals */
CpaInstanceHandle *qatInstanceHandles = NULL;
static pthread_key_t qatInstanceForThread;
pthread_t *icp_polling_threads;
static int keep_polling = 1;
static int enable_external_polling = 0;
Cpa16U numInstances = 0;
int qatPerformOpRetries = 0;
static int currInst = 0;
static pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;

char *ICPConfigSectionName_libcrypto = "SHIM";

static CpaVirtualToPhysical myVirtualToPhysical = realVirtualToPhysical;
static int zero_copy_memory_mode = 0;
static int qat_inited = 0;
static useconds_t qat_poll_interval = POLL_PERIOD_IN_NS;
static int qat_msg_retry_count = QAT_CRYPTO_NUM_POLLING_RETRIES;

/*
 * Invoked by Client. Used to set the number of retry libcrypto should poll
 * QAT untill it receives success
 */
void setQatMsgRetryCount(int iRetryCount)
{
    if ((iRetryCount >= -1) && (iRetryCount <= 100000)) {
        qat_msg_retry_count = iRetryCount;
    } else {
        fprintf(stderr,
                "The Message retry count value is out of range, using default value %d\n",
                qat_msg_retry_count);
    }

}

int getQatMsgRetryCount()
{
    return qat_msg_retry_count;
}

int getEnableExternalPolling()
{
    return enable_external_polling;
}

/*
 * Invoked by Client. Used to set the interval between each poll retry
 */
void setQatPollInterval(unsigned long int ulPollInterval)
{
    if ((ulPollInterval >= 1) && (ulPollInterval <= 1000000)) {
        qat_poll_interval = (useconds_t) ulPollInterval;
    } else {
        fprintf(stderr,
                "The polling interval value is out of range, using default value %d\n",
                qat_poll_interval);
    }

}

useconds_t getQatPollInterval()
{
    return qat_poll_interval;
}

int isZeroCopy()
{
    return (zero_copy_memory_mode);
}

void enableZeroCopy()
{
    CpaStatus status;

    status =
        CRYPTO_set_mem_ex_functions(qaeCryptoMemAlloc, qaeCryptoMemRealloc,
                                    qaeCryptoMemFree);
    if (CPA_FALSE == status) {
        DEBUG("%s: CRYPTO_set_mem_functions failed\n", __func__);
        /*
         * Don't abort. This may be tried from a few places and will only
         * succeed the first time.
         */
    } else {
        DEBUG("%s: CRYPTO_set_mem_functions succeeded\n", __func__);
    }

    /*
     * If over-riding OPENSSL_malloc then buffers passed will already be
     * pinned memory so we switch to zero copy mode
     */
    zero_copy_memory_mode = 1;
}

/******************************************************************************
* function:
*         incr_curr_inst(void)
*
* description:
*   Increment the logical Cy instance number to use for the next operation.
*
******************************************************************************/
static inline void incr_curr_inst(void)
{
    pthread_mutex_lock(&qat_instance_mutex);
    currInst = (currInst + 1) % numInstances;
    pthread_mutex_unlock(&qat_instance_mutex);
}

/******************************************************************************
* function:
*         get_next_inst(void)
*
* description:
*   Return the next instance handle to use for an operation.
*
******************************************************************************/
CpaInstanceHandle get_next_inst(void)
{
    CpaInstanceHandle instanceHandle;

    //if (1 == enable_external_polling ||
    //    (instanceHandle = pthread_getspecific(qatInstanceForThread)) == NULL)
    //{

        if (qatInstanceHandles) {
            instanceHandle = qatInstanceHandles[currInst];
            incr_curr_inst();
        } else {
            instanceHandle = NULL;
        }
    //}
    return instanceHandle;
}

/******************************************************************************
* function:
*         qat_set_instance_for_thread(long instanceNum)
*
* @param instanceNum [IN] - logical instance number
*
* description:
*   Bind the current thread to a particular logical Cy instance. Note that if
*   instanceNum is greater than the number of configured instances, the
*   modulus operation is used.
*
******************************************************************************/
void qat_set_instance_for_thread(long instanceNum)
{
    int rc;

    if ((rc =
         pthread_setspecific(qatInstanceForThread,
                             qatInstanceHandles[instanceNum %
                                                numInstances])) != 0) {
        fprintf(stderr, "pthread_setspecific: %s\n", strerror(rc));
        return;
    }
}

/******************************************************************************
* function:
*         initOpDone(struct op_done *opDone)
*
* @param opDone [IN] - pointer to op done callback structure
*
* description:
*   Initialise the QAT operation "done" callback structure.
*
******************************************************************************/
void initOpDone(struct op_done *opDone)
{
    int sts = 1;

    if (!opDone) {
        return;
    }

    sts = pthread_mutex_init(&(opDone->mutex), NULL);
    if (sts != 0) {
        fprintf(stderr,
                "pthread_mutex_init failed - sts = %d. Continuing anyway.\n",
                sts);
    }
    sts = pthread_cond_init(&(opDone->cond), NULL);
    if (sts != 0) {
        fprintf(stderr,
                "pthread_cond_init failed - sts = %d. Continuing anyway.\n",
                sts);
    }
    opDone->flag = 0;
    opDone->verifyResult = CPA_FALSE;
}

/******************************************************************************
* function:
*         cleanupOpDone(struct op_done *opDone)
*
* @param opDone [IN] - pointer to op done callback structure
*
* description:
*   Cleanup the thread and mutex used in the QAT operation "done" callback.
*
******************************************************************************/
void cleanupOpDone(struct op_done *opDone)
{
    int sts = 1;

    if (!opDone) {
        return;
    }

    sts = pthread_mutex_destroy(&(opDone->mutex));
    if (sts != 0) {
        fprintf(stderr,
                "pthread_mutex_destroy failed - sts = %d. Continuing anyway.\n",
                sts);
    }
    sts = pthread_cond_destroy(&(opDone->cond));
    if (sts != 0) {
        fprintf(stderr,
                "pthread_cond_destroy failed - sts = %d. Continuing anyway.\n",
                sts);
    }
}

/******************************************************************************
* function:
*         waitForOpToComplete(struct op_done *opDone)
*
* @param opdone [IN] - pointer to op done callback structure
*
* description:
*   Wait on a mutex lock with a timeout for cpaCySymPerformOp to complete.
*
* @retval int - 0 for success, 1 if error or timed out
*
******************************************************************************/
int waitForOpToComplete(struct op_done *opDone)
{
    struct timespec ts;
    int rc = 1;
    int timer_rc = 0;

    if (!opDone) {
        return rc;
    }

    rc = pthread_mutex_lock(&(opDone->mutex));
    if (rc != 0) {
        fprintf(stderr, "pthread_mutex_lock failed - rc = %d.\n", rc);
        QATerr(QAT_F_WAITFOROPTOCOMPLETE, ERR_R_INTERNAL_ERROR);
        return 1;
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += QAT_CRYPTO_RESPONSE_TIMEOUT;
    while (!opDone->flag) {
        timer_rc =
            pthread_cond_timedwait(&(opDone->cond), &(opDone->mutex), &ts);
        if (timer_rc != 0) {
            WARN("pthread_cond_timedwait: %s\n", strerror(timer_rc));
            QATerr(QAT_F_WAITFOROPTOCOMPLETE, QAT_R_PTHREAD_COND_TIMEDWAIT);
            break;
        }
    }
    rc = pthread_mutex_unlock(&(opDone->mutex));
    if (rc != 0) {
        fprintf(stderr, "pthread_mutex_unlock failed - rc = %d\n", rc);
        QATerr(QAT_F_WAITFOROPTOCOMPLETE, ERR_R_INTERNAL_ERROR);
    }
    if (rc || timer_rc)
        return 1;
    return 0;
}

#if 0
/******************************************************************************
* function:
*         qatGetNUMANodeId(CpaInstanceHandle* handle)
*
* @param handle [IN] - pointer to an instance handle
*
* description:
*   Function that maps an Instance Handle to a NUMA Node Id.
*
* @retval Cpa32U - the NUME nodeId the instance is attached to
*
******************************************************************************/
static Cpa32U qatGetNUMANodeId(CpaInstanceHandle handle)
{
    CpaStatus status = CPA_STATUS_FAIL;
    CpaInstanceInfo2 pInstanceInfo2;

    if (NULL == handle) {
        WARN("Invalid Instance Handle\n");
        return 0;
    }

    status = cpaCyInstanceGetInfo2(handle, &pInstanceInfo2);
    if (unlikely(CPA_STATUS_SUCCESS != status)) {
        WARN("Unable to get Node affinity\n");
        return 0;
    }

    return pInstanceInfo2.nodeAffinity;
}
#endif

/******************************************************************************
* function:
*         qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
*                        const CpaCySymOp operationType, void *pOpData,
*                        CpaBufferList * pDstBuffer, CpaBoolean verifyResult)
*

* @param pCallbackTag  [IN] -  Opaque value provided by user while making
*                              individual function call. Cast to op_done.
* @param status        [IN] -  Status of the operation.
* @param operationType [IN] -  Identifies the operation type requested.
* @param pOpData       [IN] -  Pointer to structure with input parameters.
* @param pDstBuffer    [IN] -  Destination buffer to hold the data output.
* @param verifyResult  [IN] -  Used to verify digest result.
*
* description:
*   Callback function used by cpaCySymPerformOp to indicate completion.
*
******************************************************************************/
void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                           const CpaCySymOp operationType, void *pOpData,
                           CpaBufferList * pDstBuffer,
                           CpaBoolean verifyResult)
{
    struct op_done *opDone = (struct op_done *)callbackTag;
    int sts = 1;

    if (!opDone) {
        return;
    }

    DEBUG("e_qat.%s: status %d verifyResult %d\n", __func__, status,
          verifyResult);
    sts = pthread_mutex_lock(&(opDone->mutex));
    if (sts != 0) {
        fprintf(stderr,
                "pthread_mutex_lock failed - sts = %d. Continuing anyway.\n",
                sts);
    }
    opDone->flag = 1;
    opDone->verifyResult = verifyResult;
    //sts = pthread_cond_signal(&(opDone->cond));
    if (sts != 0) {
        fprintf(stderr,
                "pthread_cond_signal failed - sts = %d. Continuing anyway.\n",
                sts);
    }
    sts = pthread_mutex_unlock(&(opDone->mutex));
    if (sts != 0) {
        fprintf(stderr,
                "pthread_mutex_unlock failed - sts = %d. Continuing anyway.\n",
                sts);
    }
}

/******************************************************************************
* function:
*         CpaStatus myPerformOp(const CpaInstanceHandle  instanceHandle,
*                     void *                     pCallbackTag,
*                     const CpaCySymOpData      *pOpData,
*                     const CpaBufferList       *pSrcBuffer,
*                     CpaBufferList             *pDstBuffer,
*                     CpaBoolean                *pVerifyResult)
*
* @param ih [IN] - Instance handle
* @param instanceHandle [IN]  - Instance handle
* @param pCallbackTag   [IN]  - Pointer to op_done struct
* @param pOpData        [IN]  - Operation parameters
* @param pSrcBuffer     [IN]  - Source buffer list
* @param pDstBuffer     [OUT] - Destination buffer list
* @param pVerifyResult  [OUT] - Whether hash verified or not
*
* description:
*   Wrapper around cpaCySymPerformOp which handles retries for us.
*
******************************************************************************/
CpaStatus myPerformOp(const CpaInstanceHandle instanceHandle,
                      void *pCallbackTag,
                      const CpaCySymOpData * pOpData,
                      const CpaBufferList * pSrcBuffer,
                      CpaBufferList * pDstBuffer, CpaBoolean * pVerifyResult)
{
    CpaStatus status;
    useconds_t ulPollInterval = getQatPollInterval();
    int iMsgRetry = getQatMsgRetryCount();
    unsigned int uiRetry = 0;
    do {
        status = cpaCySymPerformOp(instanceHandle,
                                   pCallbackTag,
                                   pOpData,
                                   pSrcBuffer, pDstBuffer, pVerifyResult);
        if (status == CPA_STATUS_RETRY) {
            //qatPerformOpRetries++;
            //pthread_yield();
            //if (uiRetry >= iMsgRetry
            //    && iMsgRetry != QAT_INFINITE_MAX_NUM_RETRIES) {
            //    break;
            //}
            //uiRetry++;
            //usleep(ulPollInterval +
            //       (uiRetry % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            ASYNC_pause_job();
            if (!getEnableExternalPolling())
                poll_instances();
        }
    }
    while (status == CPA_STATUS_RETRY);
    return status;
}

#ifdef USE_PTHREAD_YIELD
/******************************************************************************
* function:
*         void *sendPoll(void *ih)
*
* @param ih [IN] - Instance handle
*
* description:
*   Poll the QAT instances every 2 microseconds.
*
******************************************************************************/
static void *sendPoll(void *ih)
{
    CpaStatus status = 0;
    CpaInstanceHandle instanceHandle;

    instanceHandle = (CpaInstanceHandle) ih;
    if (NULL == instanceHandle) {
        WARN("WARNING sendPoll - instanceHandle is NULL\n");
        return NULL;
    }

    while (keep_polling) {
        /* Poll for 0 means process all packets on the instance */
        status = icp_sal_CyPollInstance(instanceHandle, 0);

        if (likely(CPA_STATUS_SUCCESS == status)) {
            /* Do nothing */
        } else if (CPA_STATUS_RETRY == status) {
            pthread_yield();
        } else {
            WARN("WARNING icp_sal_CyPollInstance returned status %d\n",
                 status);
        }
    }

    return NULL;
}
#else
/******************************************************************************
* function:
*         void *sendPoll_ns(void *ih)
*
* @param ih [IN] - Instance handle
*
* description:
*   Poll the QAT instances (nanosleep version)
*       NB: Delay in this function is set by default at runtime by pulling a value
*       in nsecs from /etc/send_poll_interval. If no such file is available,
*       default falls through to POLL_PERIOD_IN_NS.
*
******************************************************************************/
static void *sendPoll_ns(void *ih)
{
    CpaStatus status = 0;
    CpaInstanceHandle instanceHandle;
    struct timespec reqTime = { 0 };
    struct timespec remTime = { 0 };
    unsigned int retry_count = 0; /* to prevent too much time drift */

    instanceHandle = (CpaInstanceHandle) ih;
    if (NULL == instanceHandle) {
        WARN("WARNING sendPoll_ns - instanceHandle is NULL\n");
        return NULL;
    }

    while (keep_polling) {
        reqTime.tv_nsec = getQatPollInterval();
        /* Poll for 0 means process all packets on the instance */
        status = icp_sal_CyPollInstance(instanceHandle, 0);

        if (likely
            (CPA_STATUS_SUCCESS == status || CPA_STATUS_RETRY == status)) {
            /* Do nothing */
        } else {
            WARN("WARNING icp_sal_CyPollInstance returned status %d\n",
                 status);
        }

        retry_count = 0;
        do {
            retry_count++;
            nanosleep(&reqTime, &remTime);
            reqTime.tv_sec = remTime.tv_sec;
            reqTime.tv_nsec = remTime.tv_nsec;
            if (unlikely((errno < 0) && (EINTR != errno))) {
                WARN("WARNING nanosleep system call failed: errno %i\n",
                     errno);
                break;
            }
        }
        while ((retry_count <= QAT_CRYPTO_NUM_POLLING_RETRIES)
               && (EINTR == errno));
    }

    return NULL;
}

#endif

CpaStatus poll_instances(void)
{
    unsigned int poll_loop;
    CpaStatus internal_status = CPA_STATUS_SUCCESS,
        ret_status = CPA_STATUS_SUCCESS;

    if (qatInstanceHandles != NULL) {
        for (poll_loop = 0; poll_loop < numInstances; poll_loop++) {
            if (qatInstanceHandles[poll_loop] != NULL) {
                internal_status =
                    icp_sal_CyPollInstance(qatInstanceHandles[poll_loop], 0);
                if (CPA_STATUS_SUCCESS == internal_status) {
                    /* Do nothing */
                } else if (CPA_STATUS_RETRY == internal_status) {
                    ret_status = internal_status;
                } else {
                    WARN("WARNING icp_sal_CyPollInstance returned status %d\n", internal_status);
                    ret_status = internal_status;
                    break;
                }
            }
        }
    } else {
        WARN("WARNING qatInstanceHandles == NULL\n");
        ret_status = CPA_STATUS_FAIL;
    }

    return ret_status;
}

/******************************************************************************
* function:
*         realVirtualToPhysical(void *virtualAddr)
*
* @param virtualAddr [IN] - Virtual address.
*
* description:
*   Translates virtual address to hardware physical address. See the qae_mem
*   module for more details. The virtual to physical translator is required
*   by the QAT hardware to map from virtual addresses to physical locations
*   in pinned memory.
*
*   This function is designed to work with the allocator defined in
*   qae_mem_utils.c and qat_mem/qat_mem.c
*
******************************************************************************/
static CpaPhysicalAddr realVirtualToPhysical(void *virtualAddr)
{
    return qaeCryptoMemV2P(virtualAddr);
}

/******************************************************************************
* function:
*         setMyVirtualToPhysical(CpaVirtualToPhysical fp)
*
* @param CpaVirtualToPhysical [IN] - Function pointer to translation function
*
* description:
*   External API to allow users to specify their own virtual to physical
*   address translation function.
*
******************************************************************************/
void setMyVirtualToPhysical(CpaVirtualToPhysical fp)
{
    /*
     * If user specifies a V2P function then the user is taking
     * responsibility for allocating and freeing pinned memory so we switch
     * to zero_copy_memory mode
     */
    if (!qat_inited) {
        myVirtualToPhysical = fp;
        zero_copy_memory_mode = 1;
    } else
        WARN("%s: can't set virtual to physical translation function after initialisation\n", __func__);
}

/******************************************************************************
* function:
*         qat_engine_init(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine init function, associated with Crypto memory setup
*   and cpaStartInstance setups.
******************************************************************************/
static int qat_engine_init(ENGINE *e)
{
    int instNum, err, checkLimitStatus;
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaBoolean limitDevAccess = CPA_FALSE;

    DEBUG("[%s] ---- Engine Initing\n\n", __func__);
    CRYPTO_INIT_QAT_LOG();

    //if (0 == enable_external_polling &&
    //    (err = pthread_key_create(&qatInstanceForThread, NULL)) != 0) {
    //    fprintf(stderr, "pthread_key_create: %s\n", strerror(err));
    //    return 0;
    //}

    checkLimitStatus =
        checkLimitDevAccessValue((int *)&limitDevAccess,
                                 ICPConfigSectionName_libcrypto);
    if (!checkLimitStatus) {
        WARN("Assuming LimitDevAccess = 0\n");
    }

    /* Initialise the QAT hardware */
    if (CPA_STATUS_SUCCESS !=
        icp_sal_userStartMultiProcess(ICPConfigSectionName_libcrypto,
                                      limitDevAccess)) {
        WARN("icp_sal_userStart failed\n");
        return 0;
    }

    /* Get the number of available instances */
    status = cpaCyGetNumInstances(&numInstances);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetNumInstances failed, status=%d\n", status);
        qat_engine_finish(e);
        return 0;
    }
    if (!numInstances) {
        WARN("No crypto instances found\n");
        qat_engine_finish(e);
        return 0;
    }

    DEBUG("%s: %d Cy instances got\n", __func__, numInstances);

    /* Allocate memory for the instance handle array */
    qatInstanceHandles =
        (CpaInstanceHandle *) OPENSSL_malloc(((int)numInstances) *
                                             sizeof(CpaInstanceHandle));
    if (NULL == qatInstanceHandles) {
        WARN("OPENSSL_malloc() failed for instance handles.\n");
        qat_engine_finish(e);
        return 0;
    }

    /* Allocate memory for the polling threads */
    //if (0 == enable_external_polling) {
    //    icp_polling_threads =
    //        (pthread_t *) OPENSSL_malloc(((int)numInstances) *
    //                                     sizeof(pthread_t));
    //    if (NULL == icp_polling_threads) {
    //        WARN("OPENSSL_malloc() failed for icp_polling_threads.\n");
    //        qat_engine_finish(e);
    //        return 0;
    //    }
    //}

    /* Get the Cy instances */
    status = cpaCyGetInstances(numInstances, qatInstanceHandles);
    if (CPA_STATUS_SUCCESS != status) {
        WARN("cpaCyGetInstances failed, status=%d\n", status);
        qat_engine_finish(e);
        return 0;
    }

    /* Set translation function and start each instance */
    for (instNum = 0; instNum < numInstances; instNum++) {
        /* Set the address translation function */
        status = cpaCySetAddressTranslation(qatInstanceHandles[instNum],
                                            myVirtualToPhysical);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCySetAddressTranslation failed, status=%d\n", status);
            qat_engine_finish(e);
            return 0;
        }

        /* Start the instances */
        status = cpaCyStartInstance(qatInstanceHandles[instNum]);
        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCyStartInstance failed, status=%d\n", status);
            qat_engine_finish(e);
            return 0;
        }

        //if (0 == enable_external_polling) {
            /* Create the polling threads */
//#ifdef USE_PTHREAD_YIELD
//            pthread_create(&icp_polling_threads[instNum], NULL, sendPoll,
//                           qatInstanceHandles[instNum]);
//#else
//            pthread_create(&icp_polling_threads[instNum], NULL, sendPoll_ns,
//                           qatInstanceHandles[instNum]);
//#endif
//#ifdef QAT_POLL_CORE_AFFINITY
//            {
//                int coreID = 0;
//                int sts = 1;
//                cpu_set_t cpuset;
//
//                CPU_ZERO(&cpuset);
//
//                CPU_SET(coreID, &cpuset);
//
//                sts =
//                    pthread_setaffinity_np(icp_polling_threads[instNum],
//                                           sizeof(cpu_set_t), &cpuset);
//                if (sts != 0) {
//                    DEBUG("pthread_setaffinity_np error, status = %d \n",
//                          sts);
//                    qat_engine_finish(e);
//                    return 0;
//                }
//                sts =
//                    pthread_getaffinity_np(icp_polling_threads[instNum],
//                                           sizeof(cpu_set_t), &cpuset);
//                if (sts != 0) {
//                    DEBUG("pthread_getaffinity_np error, status = %d \n",
//                          sts);
//                    qat_engine_finish(e);
//                    return 0;
//                }
//
//                if (CPU_ISSET(coreID, &cpuset))
//                    DEBUG("Polling thread assigned on CPU core %d\n", coreID);
//            }
//#endif
//        }
    }

    //status = qat_rand_initialise();
    //if (status != 1) {
    //    WARN("QAT RAND failed to initialise\n");
    //    qat_engine_finish(e);
    //    return 0;
    //}

    /* Reset currInst */
    currInst = 0;
    qat_inited = 1;

    return 1;
}

#define QAT_CMD_ENABLE_POLLING ENGINE_CMD_BASE
#define QAT_CMD_POLL (ENGINE_CMD_BASE + 1)
#define QAT_CMD_SET_INSTANCE_FOR_THREAD (ENGINE_CMD_BASE + 2)
#define QAT_CMD_GET_OP_RETRIES (ENGINE_CMD_BASE + 3)
#define QAT_CMD_SET_V2P (ENGINE_CMD_BASE + 4)
#define QAT_CMD_ENABLE_ZERO_COPY_MODE (ENGINE_CMD_BASE + 5)
#define QAT_CMD_SET_MSG_RETRY_COUNTER (ENGINE_CMD_BASE + 6)
#define QAT_CMD_SET_POLL_INTERVAL (ENGINE_CMD_BASE + 7)

static const ENGINE_CMD_DEFN qat_cmd_defns[] = {
    {
     QAT_CMD_ENABLE_POLLING,
     "ENABLE_POLLING",
     "Enables the polling interface to the engine.",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_POLL,
     "POLL",
     "Polls the engine for any completed requests",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_INSTANCE_FOR_THREAD,
     "SET_INSTANCE_FOR_THREAD",
     "Set instance to be used by this thread",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_GET_OP_RETRIES,
     "GET_OP_RETRIES",
     "Get number of retries",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_V2P,
     "SET_V2P",
     "Set function to be used for V2P translation",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_ENABLE_ZERO_COPY_MODE,
     "ENABLE_ZERO_COPY_MODE",
     "Set zero copy mode",
     ENGINE_CMD_FLAG_NO_INPUT},
    {
     QAT_CMD_SET_MSG_RETRY_COUNTER,
     "SET_MSG_RETRY_COUNT",
     "Set Message retry count",
     ENGINE_CMD_FLAG_NUMERIC},
    {
     QAT_CMD_SET_POLL_INTERVAL,
     "SET_POLL_INTERVAL",
     "Set Poll Interval",
     ENGINE_CMD_FLAG_NUMERIC},
    {0, NULL, NULL, 0}
};

/******************************************************************************
* function:
*         qat_engine_ctrl(ENGINE *e, int cmd, long i,
*                         void *p, void (*f)(void))
*
* @param e   [IN] - OpenSSL engine pointer
* @param cmd [IN] - Control Command
* @param i   [IN] - Unused
* @param p   [IN] - Parameters for the command
* @param f   [IN] - Callback function
*
* description:
*   Qat engine control functions.
*   Note: QAT_CMD_ENABLE_POLLING should be called at the following point
*         during startup:
*         ENGINE_load_qat
*         ENGINE_by_id
*    ---> ENGINE_ctrl_cmd(QAT_CMD_ENABLE_POLLING)
*         ENGINE_init
******************************************************************************/

static int
qat_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    unsigned int retVal = 1;
    CpaStatus *pollRet = (CpaStatus *) p;

    switch (cmd) {
    case QAT_CMD_POLL:
        {
            if (enable_external_polling) {
                if (NULL != p)
                    *pollRet = poll_instances();
                else {
                    WARN("No poll return status passed to engine\n");
                    retVal = 0;
                }
            } else {
                WARN("Polling not enabled on the engine\n");
                retVal = 0;
            }
            break;
        }
    case QAT_CMD_ENABLE_POLLING:
        {
            enable_external_polling = 1;
            break;
        }
    case QAT_CMD_SET_INSTANCE_FOR_THREAD:
        qat_set_instance_for_thread(i);
        break;
    case QAT_CMD_GET_OP_RETRIES:
        *(int *)p = qatPerformOpRetries;
        break;
    case QAT_CMD_SET_V2P:
        setMyVirtualToPhysical((CpaVirtualToPhysical) i);
        break;
    case QAT_CMD_ENABLE_ZERO_COPY_MODE:
        enableZeroCopy();
        break;
    case QAT_CMD_SET_MSG_RETRY_COUNTER:
        setQatMsgRetryCount((int)i);
        break;
    case QAT_CMD_SET_POLL_INTERVAL:
        setQatPollInterval((unsigned long int)i);
        break;
    default:
        {
            WARN("CTRL command not implemented\n");
            retVal = 0;
            break;
        }
    }
    return retVal;
}

/******************************************************************************
* function:
*         qat_engine_finish(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine finish function.
******************************************************************************/

static int qat_engine_finish(ENGINE *e)
{

    int i;
    CpaStatus status = CPA_STATUS_SUCCESS;

    DEBUG("[%s] ---- Engine Finishing...\n\n", __func__);

    keep_polling = 0;

    for (i = 0; i < numInstances; i++) {
        status = cpaCyStopInstance(qatInstanceHandles[i]);

        if (CPA_STATUS_SUCCESS != status) {
            WARN("cpaCyStopInstance failed, status=%d\n", status);
            return 0;
        }

        //if (0 == enable_external_polling)
        //    pthread_join(icp_polling_threads[i], NULL);

    }

    if (qatInstanceHandles)
        OPENSSL_free(qatInstanceHandles);

    //if (0 == enable_external_polling) {
    //    if (icp_polling_threads)
    //        OPENSSL_free(icp_polling_threads);
    //}

    icp_sal_userStop();

    CRYPTO_CLOSE_QAT_LOG();

    return 1;
}

/******************************************************************************
* function:
*         qat_engine_destroy(ENGINE *e)
*
* @param e [IN] - OpenSSL engine pointer
*
* description:
*   Qat engine destroy function, required by Openssl engine API.
*   all the clean up are implemented in qat_engine_finish(), thus we just do
*   nothing here but return 1.
*
******************************************************************************/
static int qat_engine_destroy(ENGINE *e)
{
    DEBUG("[%s] ---- Destroying Engine...\n\n", __func__);
    //qat_prf_cleanup();
    return 1;
}

/******************************************************************************
* function:
*         bind_qat(ENGINE *e,
*                  const char *id)
*
* @param e  [IN] - OpenSSL engine pointer
* @param id [IN] - engine id
*
* description:
*    Connect Qat engine to OpenSSL engine library
******************************************************************************/
static int bind_qat(ENGINE *e, const char *id)
{
    int ret = 0;

    DEBUG("[%s] id=%s\n", __func__, id);

    if (id && (strcmp(id, engine_qat_id) != 0)) {
        WARN("ENGINE_id defined already!\n");
        goto end;
    }

    if (!ENGINE_set_id(e, engine_qat_id)) {
        WARN("ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_qat_name)) {
        WARN("ENGINE_set_name failed\n");
        goto end;
    }

    /* Ensure the QAT error handling is set up */
    ERR_load_QAT_strings();

    DEBUG("%s: About to set mem functions\n", __func__);

    if (!ENGINE_set_RSA(e, get_RSA_methods())) {
        WARN("ENGINE_set_RSA failed\n");
        goto end;
    }

    if (!ENGINE_set_DSA(e, get_DSA_methods())) {
        WARN("ENGINE_set_DSA failed\n");
        goto end;
    }

    if (!ENGINE_set_DH(e, get_DH_methods())) {
        WARN("ENGINE_set_DH failed\n");
        goto end;
    }

    if (!ENGINE_set_ECDH(e, get_ECDH_methods())) {
        WARN("ENGINE_set_ECDH failed\n");
        goto end;
    }

    if (!ENGINE_set_ECDSA(e, get_ECDSA_methods())) {
        WARN("ENGINE_set_ECDSA failed\n");
        goto end;
    }

    if (!ENGINE_set_ciphers(e, qat_ciphers_synch)) {
        WARN("ENGINE_set_ciphers failed\n");
        goto end;
    }

    //if (!ENGINE_set_digests(e, qat_digests_synch)) {
    //    WARN("ENGINE_set_digests failed\n");
    //    goto end;
    //}

    //if (!ENGINE_set_RAND(e, get_RAND_methods())) {
    //    WARN("ENGINE_set_RAND failed\n");
    //    goto end;
    //}

    if (!ENGINE_set_destroy_function(e, qat_engine_destroy)
        || !ENGINE_set_init_function(e, qat_engine_init)
        || !ENGINE_set_finish_function(e, qat_engine_finish)
        || !ENGINE_set_ctrl_function(e, qat_engine_ctrl)
        || !ENGINE_set_cmd_defns(e, qat_cmd_defns)) {
        WARN("[%s] failed reg destroy, init or finish\n", __func__);

        goto end;
    }

    ret = 1;

 end:

    return ret;

}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_qat)
    IMPLEMENT_DYNAMIC_CHECK_FN()
#endif                          /* ndef OPENSSL_NO_DYNAMIC_ENGINE */
/* initialize Qat Engine if OPENSSL_NO_DYNAMIC_ENGINE*/
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_qat(void)
{
    ENGINE *ret = NULL;
    unsigned int devmasks[] = { 0, 0, 0 };
    DEBUG("[%s] engine_qat\n", __func__);

    if (access(QAT_DEV, F_OK) != 0) {
        QATerr(QAT_F_ENGINE_QAT, QAT_R_MEM_DRV_NOT_PRESENT);
        return ret;
    }

    if (!getDevices(devmasks)) {
        QATerr(QAT_F_ENGINE_QAT, QAT_R_QAT_DEV_NOT_PRESENT);
        return ret;
    }
# ifdef QAT_ZERO_COPY_MODE
    enableZeroCopy();
# endif

    ret = ENGINE_new();

    if (!ret)
        return NULL;

    if (!bind_qat(ret, engine_qat_id)) {
        WARN("qat engine bind failed!\n");
        ENGINE_free(ret);
        return NULL;
    }

    return ret;
}

void ENGINE_load_qat(void)
{
    ENGINE *toadd = engine_qat();
    int error = 0;
    char error_string[120] = { 0 };

    DEBUG("[%s] engine_load_qat\n", __func__);

    if (!toadd) {
        error = ERR_get_error();
        ERR_error_string(error, error_string);
        fprintf(stderr, "Error reported by engine load: %s\n", error_string);
        return;
    }

    DEBUG("[%s] engine_load_qat adding\n", __func__);
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
}
#endif
