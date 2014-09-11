/*
 * parallels_sdk.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Parallels, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "virerror.h"
#include "viralloc.h"

#include "parallels_sdk.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS
#define JOB_INFINIT_WAIT_TIMEOUT UINT_MAX

PRL_UINT32 defaultJobTimeout = JOB_INFINIT_WAIT_TIMEOUT;

/*
 * Log error description
 */
static void
logPrlErrorHelper(PRL_RESULT err, const char *filename,
                  const char *funcname, size_t linenr)
{
    char *msg1 = NULL, *msg2 = NULL;
    PRL_UINT32 len = 0;

    /* Get required buffer length */
    PrlApi_GetResultDescription(err, PRL_TRUE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg1, len) < 0)
        goto cleanup;

    /* get short error description */
    PrlApi_GetResultDescription(err, PRL_TRUE, PRL_FALSE, msg1, &len);

    PrlApi_GetResultDescription(err, PRL_FALSE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg2, len) < 0)
        goto cleanup;

    /* get long error description */
    PrlApi_GetResultDescription(err, PRL_FALSE, PRL_FALSE, msg2, &len);

    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INTERNAL_ERROR,
                         filename, funcname, linenr,
                         _("%s %s"), msg1, msg2);

 cleanup:
    VIR_FREE(msg1);
    VIR_FREE(msg2);
}

#define logPrlError(code)                          \
    logPrlErrorHelper(code, __FILE__,              \
                         __FUNCTION__, __LINE__)

static PRL_RESULT
logPrlEventErrorHelper(PRL_HANDLE event, const char *filename,
                       const char *funcname, size_t linenr)
{
    PRL_RESULT ret, retCode;
    char *msg1 = NULL, *msg2 = NULL;
    PRL_UINT32 len = 0;
    int err = -1;

    if ((ret = PrlEvent_GetErrCode(event, &retCode))) {
        logPrlError(ret);
        return ret;
    }

    PrlEvent_GetErrString(event, PRL_TRUE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg1, len) < 0)
        goto cleanup;

    PrlEvent_GetErrString(event, PRL_TRUE, PRL_FALSE, msg1, &len);

    PrlEvent_GetErrString(event, PRL_FALSE, PRL_FALSE, NULL, &len);

    if (VIR_ALLOC_N(msg2, len) < 0)
        goto cleanup;

    PrlEvent_GetErrString(event, PRL_FALSE, PRL_FALSE, msg2, &len);

    virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INTERNAL_ERROR,
                         filename, funcname, linenr,
                         _("%s %s"), msg1, msg2);
    err = 0;

 cleanup:
    VIR_FREE(msg1);
    VIR_FREE(msg2);

    return err;
}

#define logPrlEventError(event)                    \
    logPrlEventErrorHelper(event, __FILE__,        \
                         __FUNCTION__, __LINE__)

static PRL_HANDLE
getJobResultHelper(PRL_HANDLE job, unsigned int timeout,
                   const char *filename, const char *funcname,
                   size_t linenr)
{
    PRL_RESULT ret, retCode;
    PRL_HANDLE result = NULL;

    if ((ret = PrlJob_Wait(job, timeout))) {
        logPrlErrorHelper(ret, filename, funcname, linenr);
        goto cleanup;
    }

    if ((ret = PrlJob_GetRetCode(job, &retCode))) {
        logPrlErrorHelper(ret, filename, funcname, linenr);
        goto cleanup;
    }

    if (retCode) {
        PRL_HANDLE err_handle;

        /* Sometimes it's possible to get additional error info. */
        if ((ret = PrlJob_GetError(job, &err_handle))) {
            logPrlErrorHelper(ret, filename, funcname, linenr);
            goto cleanup;
        }

        if (logPrlEventErrorHelper(err_handle, filename, funcname, linenr))
            logPrlErrorHelper(retCode, filename, funcname, linenr);

        PrlHandle_Free(err_handle);
    } else {
        ret = PrlJob_GetResult(job, &result);
        if (PRL_FAILED(ret)) {
            logPrlErrorHelper(ret, filename, funcname, linenr);
            PrlHandle_Free(result);
            result = NULL;
            goto cleanup;
        }
   }

 cleanup:
    PrlHandle_Free(job);
    return result;
}

#define getJobResult(job, timeout)                  \
    getJobResultHelper(job, timeout, __FILE__,      \
                         __FUNCTION__, __LINE__)

static int
waitJobHelper(PRL_HANDLE job, unsigned int timeout,
              const char *filename, const char *funcname,
              size_t linenr)
{
    PRL_HANDLE result = NULL;

    result = getJobResultHelper(job, timeout, filename, funcname, linenr);
    if (result)
        PrlHandle_Free(result);

    return result ? 0 : -1;
}

#define waitJob(job, timeout)                  \
    waitJobHelper(job, timeout, __FILE__,      \
                         __FUNCTION__, __LINE__)

int
prlsdkInit(parallelsConnPtr privconn)
{
    PRL_RESULT ret;

    ret = PrlApi_InitEx(PARALLELS_API_VER, PAM_SERVER, 0, 0);
    if (PRL_FAILED(ret)) {
        logPrlError(ret);
        return -1;
    }

    privconn->jobTimeout = JOB_INFINIT_WAIT_TIMEOUT;

    return 0;
};

void
prlsdkDeinit(void)
{
    PrlApi_Deinit();
};

int
prlsdkConnect(parallelsConnPtr privconn)
{
    PRL_RESULT ret;
    PRL_HANDLE job = PRL_INVALID_HANDLE;

    ret = PrlSrv_Create(&privconn->server);
    if (PRL_FAILED(ret)) {
        logPrlError(ret);
        return -1;
    }

    job = PrlSrv_LoginLocalEx(privconn->server, NULL, 0,
                              PSL_HIGH_SECURITY, PACF_NON_INTERACTIVE_MODE);

    if (waitJob(job, privconn->jobTimeout)) {
        PrlHandle_Free(privconn->server);
        return -1;
    }

    return 0;
}

void
prlsdkDisconnect(parallelsConnPtr privconn)
{
    PRL_HANDLE job;

    job = PrlSrv_Logoff(privconn->server);
    waitJob(job, privconn->jobTimeout);

    PrlHandle_Free(privconn->server);
}
