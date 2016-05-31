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
 * @file qat_utils.h
 *
 * This file provides an interface to utilities for the QAT engine in OpenSSL
 *
 *****************************************************************************/

#ifndef QAT_UTILS_H
#define QAT_UTILS_H

#include <stdio.h>
#include <pthread.h>
#include "cpa.h"
#include "cpa_cy_sym.h"

#define QAT_BYTE_ALIGNMENT 64
/* For best performance data buffers should be 64-byte aligned */
#define QAT_MEM_ALIGN(x) (void *)(((uintptr_t)(x) + QAT_BYTE_ALIGNMENT - 1) & (~(uintptr_t)(QAT_BYTE_ALIGNMENT-1)))

/* Add -DQAT_TESTS_LOG to ./config to enable
   debug logging to the CRYPTO_QAT_LOG_FILE */

#ifdef QAT_TESTS_LOG

#define CRYPTO_QAT_LOG_FILE "/opt/qat-crypto.log"

extern FILE *cryptoQatLogger;
extern pthread_mutex_t debug_file_mutex;
extern int debug_file_ref_count; 

void crypto_qat_debug_init_log();
void crypto_qat_debug_close_log();

#define CRYPTO_INIT_QAT_LOG() crypto_qat_debug_init_log()

#define CRYPTO_CLOSE_QAT_LOG() crypto_qat_debug_close_log()

#define CRYPTO_QAT_LOG(...)                         \
do {                                                \
    pthread_mutex_lock(&debug_file_mutex);          \
	if (debug_file_ref_count) {                     \
	    if (cryptoQatLogger != NULL) {              \
		    fprintf (cryptoQatLogger, __VA_ARGS__); \
            fflush(cryptoQatLogger);                \
        }                                           \
    }                                               \
	pthread_mutex_unlock(&debug_file_mutex);        \
} while(0)

#else

#define CRYPTO_QAT_LOG(...)
#define CRYPTO_CLOSE_QAT_LOG()
#define CRYPTO_INIT_QAT_LOG()

#endif

/*#define QAT_DEBUG*/
/*#define QAT_WARN*/

#ifdef QAT_DEBUG
void hexDump(const char *func, const char *var, const unsigned char p[], int l);
void dumpRequest(const CpaInstanceHandle instanceHandle,
                        void *pCallbackTag,
                        const CpaCySymOpData * pOpData,
                        const CpaCySymSessionSetupData * sessionData,
                        const CpaBufferList * pSrcBuffer,
                        CpaBufferList * pDstBuffer);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#define DUMPL(var,p,l) hexDump(__func__,var,p,l);
#define DUMPREQ(inst, cb, opD, sess, src, dst) dumpRequest(inst, cb, opD, sess, src, dst);
#else
#define DEBUG(...)
#define DUMPL(...)
#define DUMPREQ(...)
#endif
 
/* warning message for qat engine and cpa function */
#ifdef QAT_WARN
#define WARN(...) fprintf (stderr, __VA_ARGS__)
#else
#define WARN(...)
#endif

#endif /*QAT_UTILS_H*/
