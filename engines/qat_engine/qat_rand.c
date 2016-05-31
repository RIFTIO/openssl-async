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
 * @file qat_rand.c
 *
 * This file contains the engine implementation for random bit generation
 *
 * The implementation includes a Deterministic Random Bit Generator part (DRBG)
 * and a Non-Deterministic Random Bit Generator part (NRBG). The NRBG is used
 * to ensure high entropy is achieved when requesting random data via DRBG
 *
 * Note: to optimise driver interaction, qat_rand will use a 'cache' of random
 * data, accessible through the qat_rand_bytes interface. The initialisation
 * will generate a synchronous op to the driver to populate the pool with 
 * QAT_RAND_BLOCK_SIZE bytes of data. qat_rand_bytes will perform 
 * a memcpy from the pool. When the pool is all used a synchronous call is made 
 * to replenish the pool.
 *
 *****************************************************************************/

#include <openssl/crypto.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_nrbg.h"
#include "cpa_cy_drbg.h"
#include "icp_sal_drbg_impl.h"

#include "qat_rand.h"
#ifdef USE_QAT_MEM
#include "qae_mem_utils.h"
#endif
#ifdef USE_QAE_MEM
#include "qat_mem_drv_inf.h"
#endif
#include "qat_utils.h"
#include "e_qat.h"

/* Random data pool size */
#define QAT_RAND_BLOCK_SIZE (63 * 1024) /* max DRBG single request */


#ifdef OPENSSL_ENABLE_QAT_OFFLOAD_RAND
#ifdef OPENSSL_DISABLE_QAT_OFFLOAD_RAND
#undef OPENSSL_DISABLE_QAT_OFFLOAD_RAND
#endif
#endif

/* The max number of times we try to remove the session */
#define QAT_RAND_CLEANUP_RETRY_COUNT 10
/* This is the amount of time we wait between remove session re-tries */
#define QAT_RAND_CLEANUP_WAIT_TIME_NS 1000000

typedef struct qat_nrbg_callback_data_s {
    CpaCyNrbgOpData opData;
    /* NRBG client information */
    IcpSalDrbgGetEntropyInputCbFunc pClientCbFunc;
    void *pClientCallbackTag;
    void *pClientOpData;
} qat_nrbg_callback_data_t;

/* NOTE: There is one random data cache of DRBG data per process address space.
 * One instance and one session used for all call requests from all threads
 * in this process */
/* Instance handle */
static CpaInstanceHandle instanceHandle = CPA_INSTANCE_HANDLE_SINGLE;
/* Session handle */
static CpaCyDrbgSessionHandle sessionHandle = NULL;
/* Pointer to cache of random data */
static Cpa8U *pDrbgData = NULL;
/* index to next available random data */
static int indexDrbgData = 0;
static CpaBoolean qat_rand_inited = CPA_FALSE;
static pthread_mutex_t qat_rand_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Previously set GetEntropy function pointer - used to unregister */
static IcpSalDrbgGetEntropyInputFunc pPrevGetEntropyInputFunc = NULL;
/* Previously set GetNonce function pointer - used to unregister */
static IcpSalDrbgGetNonceFunc pPrevGetNonceFunc = NULL;
/* Previously set IsDFReq function pointer - used to unregister */
static IcpSalDrbgIsDFReqFunc pPrevDrbgIsDFReqFunc = NULL;

/* Qat engine rand methods declaration */
static int  qat_rand_bytes(unsigned char *buf, int num);
static void qat_rand_cleanup(void);
static int  qat_pseudorand_bytes(unsigned char *buf, int num);
static int  qat_rand_status(void);

static RAND_METHOD qat_rand_method =
{
    /* "QAT RAND method", */
    NULL, /* seed */
    qat_rand_bytes,
    qat_rand_cleanup,
    NULL, /*add */
    qat_pseudorand_bytes,
    qat_rand_status
};

RAND_METHOD *get_RAND_methods(void)
{
    return &qat_rand_method;
}

/******************************************************************************
* function:
*         qatNrbgCallback(void *pCallbackTag, CpaStatus status, void *pOpdata,
*                                 CpaFlatBuffer *pOut)
*
* @param pCallbackTag[IN]  - pointer to callback data
* @param status      [IN]  - return status of the driver operation perform
* @param pOpdata     [IN]  - pointer to operational data
* @param pOut        [IN]  - pointer containing perform op output
*
*
* description:
*    NRBG callback - following call to nrbgGetEntropy
******************************************************************************/
static void qatNrbgCallback(void *pCallbackTag, CpaStatus status, void *pOpdata,
                            CpaFlatBuffer *pOut)
{
    qat_nrbg_callback_data_t *pNrbgData = NULL;
    IcpSalDrbgGetEntropyInputCbFunc pClientCb = NULL;
    void *pClientCallbackTag = NULL;
    void *pClientOpData = NULL;
    Cpa32U lengthReturned = 0;

    DEBUG("[%s] --- Entry\n", __func__);

    if (NULL == pCallbackTag)
    {
        WARN("[%s] --- pCallbackTag is null", __func__);
        return;
    }

    pNrbgData = (qat_nrbg_callback_data_t *)pCallbackTag;

    if (CPA_STATUS_SUCCESS == status)
    {
        lengthReturned = pNrbgData->opData.lengthInBytes;
    }

    pClientCb = pNrbgData->pClientCbFunc;
    pClientCallbackTag = pNrbgData->pClientCallbackTag;
    pClientOpData = pNrbgData->pClientOpData;

    OPENSSL_free(pNrbgData);

    if (pClientCb)
    {
        pClientCb(pClientCallbackTag, status, pClientOpData, 
                  lengthReturned, pOut);
    }
}

/* Internal function to populate/replenish the random data pool */
static CpaStatus qat_drbgPerformOp(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyDrbgGenOpData *pOpData = NULL;
    struct op_done *opDone = NULL;
    CpaFlatBuffer *pDrbgOut = NULL;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG("[%s]: --- Entry\n", __func__);
    /* pDrbgOut will hold the pool address to populate and the size requested */
    pDrbgOut = OPENSSL_malloc(sizeof(CpaFlatBuffer));
    if (NULL == pDrbgOut)
    {
        WARN("[%s]: --- failed to allocate memory\n", __func__);
        return CPA_STATUS_FAIL;
    }

    pOpData = OPENSSL_malloc(sizeof(CpaCyDrbgGenOpData));
    if (NULL == pOpData)
    {
        WARN("[%s]: --- failed to allocate memory\n", __func__);
        OPENSSL_free(pDrbgOut);
        return CPA_STATUS_FAIL;
    }

    pDrbgOut->pData = pDrbgData;
    pDrbgOut->dataLenInBytes = QAT_RAND_BLOCK_SIZE;

    pOpData->sessionHandle = sessionHandle;
    pOpData->lengthInBytes = QAT_RAND_BLOCK_SIZE;
    pOpData->secStrength = CPA_CY_RBG_SEC_STRENGTH_256;
    pOpData->predictionResistanceRequired = CPA_FALSE;
    pOpData->additionalInput.dataLenInBytes = 0;
    pOpData->additionalInput.pData = NULL;
    do
    {
        status = cpaCyDrbgGen(instanceHandle,
                              (void *)opDone, /* data sent as is to the callback function*/
                              pOpData,        /* operational data struct */
                              pDrbgOut);      /* dst buffer struct */
        if (CPA_STATUS_RETRY == status)
        {
            usleep(ulPollInterval + (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            qatPerformOpRetries++;
        }
    }
    while (CPA_STATUS_RETRY == status &&
              ((qatPerformOpRetries < iMsgRetry) || (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

    if (CPA_STATUS_SUCCESS != status)
    {
        WARN("[%s]: --- failed to generate, status = %d\n", __func__, status);
        OPENSSL_free(pDrbgOut);
        OPENSSL_free(pOpData);
        return CPA_STATUS_FAIL;
    }

    OPENSSL_free(pDrbgOut);
    OPENSSL_free(pOpData);
    
    return status;
}

/******************************************************************************
* function:
*         nrbgGetEntropy(IcpSalDrbgGetEntropyInputCbFunc pCb,
*                         void * pCallbackTag,
*                         icp_sal_drbg_get_entropy_op_data_t *pOpData,
*                         CpaFlatBuffer *pBuffer,
*                         Cpa32U *pLengthReturned)
*
* @param pCb            [IN]  - pointer to client callback function to be executed in this cb
* @param pCallbackTag   [IN]  - callback data passed to the perform
* @param pOpdata        [IN]  - pointer to operational data
* @param pBuffer        [IN]  - pointer to receive perform data
* @param pLengthReturned[IN]  - pointer to len received
*
* @retval CPA_STATUS_INVALID_PARAM - invalid parameter passed  
* @retval CPA_STATUS_FAIL - function failed  
* @retval CPA_STATUS_SUCCESS - function passed  
*
* description:
*   NRBG interface to ensure high entropy when making DRBG calls. 
*   This will be called by the driver on registration and subsequently during 
*   a DRBG request when the seed life defined in the driver expires
******************************************************************************/
static CpaStatus nrbgGetEntropy(IcpSalDrbgGetEntropyInputCbFunc pCb,
                                void * pCallbackTag,
                                icp_sal_drbg_get_entropy_op_data_t *pOpData,
                                CpaFlatBuffer *pBuffer,
                                Cpa32U *pLengthReturned)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyGenFlatBufCbFunc pNrbgCbFunc = NULL;
    qat_nrbg_callback_data_t *pNrbgData = NULL;
    int qatPerformOpRetries = 0;
    int iMsgRetry = getQatMsgRetryCount();
    useconds_t ulPollInterval = getQatPollInterval();

    DEBUG("[%s]: --- Entry\n", __func__);

    if (NULL == pOpData)
    {
        WARN("[%s]: --- Invalid parameter pOpData\n", __func__);
        return CPA_STATUS_INVALID_PARAM;
    }

    if (NULL == pLengthReturned)
    {
        WARN("[%s]: --- Invalid parameter pLengthReturned\n", __func__);
        return CPA_STATUS_INVALID_PARAM;
    }

    pNrbgData = OPENSSL_malloc(sizeof(qat_nrbg_callback_data_t));
    if (NULL == pNrbgData)
    {
        WARN("[%s]: --- Failed to allocate pNrbgData\n", __func__);
        return CPA_STATUS_FAIL;
    }

    /* number of bytes to be generated */
    pNrbgData->opData.lengthInBytes = pOpData->maxLength;

    /* store client information */
    pNrbgData->pClientCbFunc = pCb;
    pNrbgData->pClientCallbackTag = pCallbackTag;
    pNrbgData->pClientOpData = (void *)pOpData;

    /* use local callback function on asynchronous operation */
    if (NULL != pCb) /* want to call this callback in qatNrbgCallback */
    {
        pNrbgCbFunc = qatNrbgCallback;
    }

    do {
        status = cpaCyNrbgGetEntropy(instanceHandle,
                                     pNrbgCbFunc, pNrbgData, 
                                     &(pNrbgData->opData), pBuffer);
        if (CPA_STATUS_RETRY == status)
        {
            usleep(ulPollInterval + (qatPerformOpRetries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
            qatPerformOpRetries++;
        }
    }
    while (CPA_STATUS_RETRY == status &&
              ((qatPerformOpRetries < iMsgRetry) || (iMsgRetry == QAT_INFINITE_MAX_NUM_RETRIES)));

    if (CPA_STATUS_SUCCESS != status)
    {
        status = (CPA_STATUS_INVALID_PARAM == status)? status: CPA_STATUS_FAIL;
        WARN("[%s]: --- cpaCyNrbgGetEntropy failed, status = %d\n", __func__, status);
        OPENSSL_free(pNrbgData);
        return status;
    }

    if (NULL == pCb)
    {
        *pLengthReturned = pNrbgData->opData.lengthInBytes;
        OPENSSL_free(pNrbgData);
    }

    return CPA_STATUS_SUCCESS;
}

/******************************************************************************
* function:
*         nrbgGetNonce(icp_sal_drbg_get_entropy_op_data_t *pOpData,
*                         CpaFlatBuffer *pBuffer,
*                         Cpa32U *pLengthReturned)
*
* @param pOpdata        [IN]  - pointer to operational data
* @param pBuffer        [IN]  - pointer to receive perform data
* @param pLengthReturned[IN]  - pointer to len received
*
* @retval CpaStatus - function return status  
*
* description:
*   NRBG interface to ensure high entropy when making DRBG calls. 
******************************************************************************/
static CpaStatus nrbgGetNonce(icp_sal_drbg_get_entropy_op_data_t *pOpData,
                              CpaFlatBuffer *pBuffer,
                              Cpa32U *pLengthReturned)
{
    CpaStatus status = CPA_STATUS_SUCCESS;

    DEBUG("[%s] --- Entry\n", __func__);

    status = nrbgGetEntropy(NULL, NULL, pOpData, pBuffer, pLengthReturned);
    if (CPA_STATUS_SUCCESS != status)
    {
        WARN("[%s] --- nrbgGetEntropy failed, status = %d\n", __func__, status);
    }

    return status;
}

/******************************************************************************
* function:
*         nrbgIsDFRequired()
*
* @retval CPA_TRUE - is required  
* @retval CPA_FALSE - is not required  
*
* description:
*   NRBG interface to ensure high entropy when making DRBG calls. 
******************************************************************************/
static CpaBoolean nrbgIsDFRequired(void)
{
    DEBUG("[%s] --- Entry\n", __func__);
    return CPA_FALSE;
}

/******************************************************************************
* function:
*         nrbgRegisterDrbgImplFunctions()
*
* description:
*   NRBG interface to register nrbg functions
******************************************************************************/
void nrbgRegisterDrbgImplFunctions(void)
{
    DEBUG("[%s] --- Entry\n", __func__);

    pPrevGetEntropyInputFunc =
        icp_sal_drbgGetEntropyInputFuncRegister(nrbgGetEntropy);
    pPrevGetNonceFunc =
        icp_sal_drbgGetNonceFuncRegister(nrbgGetNonce);
    pPrevDrbgIsDFReqFunc =
        icp_sal_drbgIsDFReqFuncRegister(nrbgIsDFRequired);
}

/******************************************************************************
* function:
*         nrbgRegisterDrbgImplFunctions()
*
* description:
*   NRBG interface to unregister nrbg interfaces
******************************************************************************/
void nrbgUnregisterDrbgImplFunctions(void)
{
    DEBUG("[%s] --- Entry\n", __func__);

    icp_sal_drbgGetEntropyInputFuncRegister(pPrevGetEntropyInputFunc);
    icp_sal_drbgGetNonceFuncRegister(pPrevGetNonceFunc);
    icp_sal_drbgIsDFReqFuncRegister(pPrevDrbgIsDFReqFunc);
}

size_t OPENSSL_ia32_rdrand(void);

/******************************************************************************
* function:
*         rdrand_random_bytes(unsigned char *buf, int num)
* @param buf    [IN]  - pointer to buffer
* @param num    [IN]  - number of bytes to generate
* @retval 1 - success
* @retval 0 - fail
*
* description:
*   Function that generates random bytes using RDRAND cpu instruction
******************************************************************************/
static int rdrand_random_bytes (unsigned char *buf, int num)
{
    size_t rnd;

    while (num>=(int)sizeof(size_t)) {
        if ((rnd = OPENSSL_ia32_rdrand()) == 0) return 0;

        *((size_t *)buf) = rnd;
        buf += sizeof(size_t);
        num -= sizeof(size_t);
    }
    if (num) {
        if ((rnd = OPENSSL_ia32_rdrand()) == 0) return 0;

        memcpy (buf,&rnd,num);
    }

    return 1;
}
#define RDRAND_MASK     0x40000000

/******************************************************************************
 * function:
 *          getCpuidRdrand()
 * @retval 0 - no rdrand support
 * @retval 1 - rdrand support present
 *
 * check the 30th bit of the ecx register after calling cpuid.
 *
  ******************************************************************************/
int getCpuidRdrand()
{
        int reg[4] = {0, 0, 0, 0};

         asm volatile(
#ifndef __x86_64__
                 "mov %%ebx, %%edi;"
                 "cpuid;"
                 "xchgl %%ebx, %%edi;"
                 :"=a"(reg[0]),
                  "=D"(reg[1]),
#else
                  "cpuid"
                  :"=a"(reg[0]),
                   "=b"(reg[1]),
#endif
                  "=c"(reg[2]),
                  "=d"(reg[3]):
                  "a"(1));

         if ((reg[2] & RDRAND_MASK) == RDRAND_MASK)
                 return 1;
         else
                 return 0;
}

/******************************************************************************
* function:
*         qat_rand_initialise(void)
*
* @retval 1 - success 
* @retval 0 - fail 
*
* description:
*   External interface to initialise random number generator.If the CPU supports
*   RDRAND instruction it will be used for random number generation, if not the initialision
*   tries to get an NRBG capable crypto instance, initialises a session and sets up
*   the random number data cache via a synchronous call to the QAT driver. If on NRBG
*   capable instances are found the default openssl software rand inmplementation
*   will be used.
******************************************************************************/
int qat_rand_initialise(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    CpaCyCapabilitiesInfo cap = {0};
    CpaCyDrbgSessionSetupData sessionSetupData = { 0 };
    Cpa32U sessionSize = 0;
    Cpa32U seedLen = 0;
    Cpa16U num_instances = 0;

    RAND_METHOD * rand_meth;

    DEBUG("[%s] --- Entry\n", __func__);


    pthread_mutex_lock(&qat_rand_mutex);
    if (CPA_TRUE == qat_rand_inited)
    {
        WARN("[%s]: --- already initialised\n", __func__);
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }
    
    /* Check if CPU has rdrand, if yes use rdrand */
    if (getCpuidRdrand())
    {
        qat_rand_method.seed = NULL;
        qat_rand_method.bytes = rdrand_random_bytes;
        qat_rand_method.cleanup = NULL;
        qat_rand_method.add = NULL;
        qat_rand_method.pseudorand = rdrand_random_bytes;
        qat_rand_method.status = qat_rand_status;
        pthread_mutex_unlock(&qat_rand_mutex);
        return 1;
    }
#ifdef OPENSSL_DISABLE_QAT_OFFLOAD_RAND
    else
    {
	/* Currently there is an issue with DRBG operations being run
           in the context of the callback thread. As a temporary measure
           we are defaulting DRBG to use software unless the cpu has
           on core rd_rand functionality in which case use that */ 
        WARN("[%s]: Using default SW rand implementation\n", __func__);
        rand_meth = RAND_SSLeay();
        if (rand_meth)
        {
            qat_rand_method.seed = rand_meth->seed;
            qat_rand_method.bytes = rand_meth->bytes;
            qat_rand_method.cleanup = rand_meth->cleanup;
            qat_rand_method.add = rand_meth->add;
            qat_rand_method.pseudorand = rand_meth->pseudorand;
            qat_rand_method.status = rand_meth->status;
            pthread_mutex_unlock(&qat_rand_mutex);
            return 1;
        }
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }
#endif

    status = cpaCyGetNumInstances(&num_instances);
    if(CPA_STATUS_SUCCESS != status)
    {
        WARN("[%s]: --- unable to get number of QAT instances, status = %d\n", 
             __func__, status);
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }

    DEBUG("[%s] --- %d QAT instances detected\n", __func__, num_instances);

    instanceHandle = get_next_inst();
    /* Verify that the instance has NRBG capabilities - not all CY instances do */
    status = cpaCyQueryCapabilities(instanceHandle, &cap);
    if(CPA_STATUS_SUCCESS != status)
    {
        WARN("[%s]: --- unable to get instance capabilities, status = %d\n", 
             __func__, status);
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }

    while(cap.nrbgSupported != CPA_TRUE && --num_instances > 0)
    {
        DEBUG("[%s]: --- QAT instance does not support NRBG, trying another\n", __func__);
        instanceHandle = get_next_inst();
        status = cpaCyQueryCapabilities(instanceHandle, &cap);
        if(CPA_STATUS_SUCCESS != status)
        {
            WARN("[%s]: --- unable to get instance capabilities, status = %d\n", 
                 __func__, status);
            pthread_mutex_unlock(&qat_rand_mutex);
            return 0;
        }
    }
    
    if (0 == num_instances)
    {
        WARN("[%s]: --- unable to get instance with NRBG capabilities\n", __func__);
        WARN("[%s]: Using default SW rand implementation\n", __func__);
        rand_meth = RAND_SSLeay();
        if (rand_meth)
        {
            qat_rand_method.seed = rand_meth->seed;
            qat_rand_method.bytes = rand_meth->bytes;
            qat_rand_method.cleanup = rand_meth->cleanup;
            qat_rand_method.add = rand_meth->add;
            qat_rand_method.pseudorand = rand_meth->pseudorand;
            qat_rand_method.status = rand_meth->status;
            pthread_mutex_unlock(&qat_rand_mutex);
            return 1;
        }
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }

    /* Register get entropy functions - these will be called during InitSession */
    nrbgRegisterDrbgImplFunctions();

    /* initialise session data */
    sessionSetupData.predictionResistanceRequired = CPA_TRUE;
    sessionSetupData.secStrength = CPA_CY_RBG_SEC_STRENGTH_256;
    sessionSetupData.personalizationString.dataLenInBytes = 0;
    sessionSetupData.personalizationString.pData = NULL;
	
    /* Determine size of session to allocate */
    status = cpaCyDrbgSessionGetSize(instanceHandle,
                                     &sessionSetupData, &sessionSize);

    if (CPA_STATUS_SUCCESS != status)
    {
        WARN("[%s]: --- unable to get session size\n", __func__);
        nrbgUnregisterDrbgImplFunctions();
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }
    else
    {
        /* Allocate memory for the session */
        sessionHandle = (CpaCyDrbgSessionHandle) qaeCryptoMemAlloc(sessionSize, __FILE__, __LINE__);
    }

    if (NULL == sessionHandle)
    {
        WARN("[%s]: --- unable to allocate memory for session\n", __func__);
        nrbgUnregisterDrbgImplFunctions();
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }
        
    /* Initialise the session */
    status = cpaCyDrbgInitSession(instanceHandle,
                                  NULL,                /* synchronous */
                                  NULL,                /* callback function for reseed */
                                  &sessionSetupData,   /* session setup data */
                                  sessionHandle,
                                  &seedLen);

    if (status != CPA_STATUS_SUCCESS)
    {
        WARN("[%s]: --- failed to start session\n", __func__);
        nrbgUnregisterDrbgImplFunctions();
        qaeCryptoMemFree(sessionHandle);
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }

    /* request memory for random data cache */
    pDrbgData = (Cpa8U *) qaeCryptoMemAlloc(QAT_RAND_BLOCK_SIZE, __FILE__, __LINE__);
    if (NULL == pDrbgData)
    {
        WARN("[%s]: --- failed to allocate memory\n", __func__);
        pthread_mutex_unlock(&qat_rand_mutex);
        qat_rand_cleanup();
        return 0;
    }

    /* need to initialise the whole cache of random data - synchronously */
    status = qat_drbgPerformOp();
    if (status != CPA_STATUS_SUCCESS)
    {
        pthread_mutex_unlock(&qat_rand_mutex);
        qat_rand_cleanup();
        return 0;
    }

    qat_rand_inited = CPA_TRUE;
    pthread_mutex_unlock(&qat_rand_mutex);

    return 1;
}

/******************************************************************************
* function:
*         qat_rand_bytes(unsigned char *buf, int num)
*
* @param buf  [OUT] - pointer to client allocated buffer to place random bytes in
* @param num  [IN]  - the number of random bytes requested
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function is called via the EVP interface to request random bytes
*
******************************************************************************/
static int qat_rand_bytes(unsigned char *buf, int num)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    
    DEBUG("[%s] --- Entry, buf [%p], num [%d] - index [%d]\n", __func__, 
          buf, num, indexDrbgData);

    if (NULL == buf)
    {
        WARN("[%s]: --- NULL pointer passed\n", __func__);
        return 0; /* fail */
    }
    
    if (num <= 0 || num > QAT_RAND_BLOCK_SIZE)
    {
        WARN("[%s]: --- requested %d bytes, while range is 1 to %d\n",
               __func__, num, QAT_RAND_BLOCK_SIZE);
        return 0; /* fail */
    }

    pthread_mutex_lock(&qat_rand_mutex);

    if (CPA_FALSE == qat_rand_inited)
    {
        WARN("[%s]: --- QAT RAND not initialised\n",__func__);
        pthread_mutex_unlock(&qat_rand_mutex);
        return 0;
    }

    /* check if we are near the end - replenish */
    if ((QAT_RAND_BLOCK_SIZE - indexDrbgData) <= num)
    {
        /* jump to start - perform synchronous replenish */
        indexDrbgData = 0;
        /* replenish pool of random data */
        status = qat_drbgPerformOp();
        if (CPA_STATUS_SUCCESS != status)
        {
            WARN("[%s]: --- failed to PerformOp\n", __func__);
            pthread_mutex_unlock(&qat_rand_mutex);
            return 0;
        }
    }

    /* copy output to client buffer */
    DEBUG("[%s]: --- copying index[%d]\n", __func__, indexDrbgData);
    memcpy (buf, pDrbgData + indexDrbgData, num);

    /* adjust index to random data cache */
    indexDrbgData = indexDrbgData + num;

    pthread_mutex_unlock(&qat_rand_mutex);
    return 1;
}

/******************************************************************************
* function:
*         qat_rand_cleanup(void)
*
* description:
*    This function is called via the EVP interface to clean up
*
******************************************************************************/
static void qat_rand_cleanup(void)
{
    CpaStatus status = CPA_STATUS_SUCCESS;
    unsigned int count = 0;
    struct timespec reqTime = {0};
	struct timespec remTime = {0};

    DEBUG("[%s] --- Entry\n", __func__);

    pthread_mutex_lock(&qat_rand_mutex);
    if (qat_rand_inited && instanceHandle && sessionHandle)
    {
        /* Remove Session - retry if necessary */
        status = cpaCyDrbgRemoveSession(instanceHandle, sessionHandle);
        while ((CPA_STATUS_RETRY == status) && (count < QAT_RAND_CLEANUP_RETRY_COUNT)) 
        {
            /* Wait a while before retry */
            count++;
            reqTime.tv_nsec = QAT_RAND_CLEANUP_WAIT_TIME_NS;
            do 
            {
                nanosleep(&reqTime, &remTime);
				reqTime.tv_sec = remTime.tv_sec;
                reqTime.tv_nsec = remTime.tv_nsec;
                if((errno < 0) && (EINTR != errno))
                {
                    WARN("[%s]: --- nanosleep system call failed: errno %i\n", 
                         __func__, errno);
                    break;
                }
            } while (EINTR == errno);

            status = cpaCyDrbgRemoveSession(instanceHandle, sessionHandle);
        }

        if (CPA_STATUS_SUCCESS != status)
        {
            WARN("[%s]: --- failed to remove session\n", __func__);
        }

        /* Free up memory */
        qaeCryptoMemFree(sessionHandle);
    }

    /* Free up memory */
    if (NULL != pDrbgData)
    {
        qaeCryptoMemFree(pDrbgData);
        pDrbgData = NULL;
    }

    nrbgUnregisterDrbgImplFunctions();

    qat_rand_inited = CPA_FALSE;

    pthread_mutex_unlock(&qat_rand_mutex);
}

/******************************************************************************
* function:
*         qat_pseudorand_bytes(unsigned char *buf, int num)
*
* @param buf  [OUT] - pointer to client allocated buffer to place random bytes in
* @param num  [IN]  - the number of random bytes requested
*
* @retval 1      function succeeded
* @retval 0      function failed
*
* description:
*    This function is called via the EVP interface to request pseudo random bytes
*
******************************************************************************/
static int qat_pseudorand_bytes(unsigned char *buf, int num)
{
    DEBUG("[%s] --- Entry, buf [%p] and num [%d]\n", __func__, buf, num);

    return qat_rand_bytes (buf, num);
}

/******************************************************************************
* function:
*         qat_rand_status(void)
*
* @retval 1      function succeeded
*
* description:
*    This function is called via the EVP interface to request status of entropy
*    Since this is something we manage internally, always return ok
*
******************************************************************************/
static int qat_rand_status(void)
{
    DEBUG("[%s] --- Entry\n", __func__);

    return 1;
}
