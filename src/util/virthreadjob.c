/*
 * virthreadjob.c: code for tracking job associated with current thread
 *
 * Copyright (C) 2013-2015 Red Hat, Inc.
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
 */

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "virlog.h"
#include "virthread.h"
#include "virthreadjob.h"

#define VIR_FROM_THIS VIR_FROM_THREAD
VIR_LOG_INIT("util.threadjob");

virThreadLocal virThreadJobWorker;
virThreadLocal virThreadJobName;


static int
virThreadJobOnceInit(void)
{
    if (virThreadLocalInit(&virThreadJobWorker, NULL) < 0 ||
        virThreadLocalInit(&virThreadJobName, NULL) < 0)
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virThreadJob);


const char *
virThreadJobGet(void)
{
    const char *job;

    if (virThreadJobInitialize() < 0)
        return NULL;

    job = virThreadLocalGet(&virThreadJobName);
    if (!job)
        job = virThreadLocalGet(&virThreadJobWorker);

    return job;
}


void
virThreadJobSetWorker(const char *worker)
{
    if (!worker || virThreadJobInitialize() < 0)
        return;

    if (virThreadLocalSet(&virThreadJobWorker, (void *) worker) < 0)
        virReportSystemError(errno,
                             _("cannot set worker name to %1$s"),
                             worker);

    VIR_DEBUG("Thread %llu is running worker %s", virThreadSelfID(), worker);
}


void
virThreadJobSet(const char *caller)
{
    const char *worker;

    if (!caller || virThreadJobInitialize() < 0)
        return;

    if (virThreadLocalSet(&virThreadJobName, (void *) caller) < 0)
        virReportSystemError(errno,
                             _("cannot set current job to %1$s"),
                             caller);

    if ((worker = virThreadLocalGet(&virThreadJobWorker))) {
        VIR_DEBUG("Thread %llu (%s) is now running job %s",
                  virThreadSelfID(), worker, caller);
    } else {
        VIR_DEBUG("Thread %llu is now running job %s",
                  virThreadSelfID(), caller);
    }
}


void
virThreadJobClear(int rv)
{
    const char *old;
    const char *worker;

    if (virThreadJobInitialize() < 0)
        return;

    if (!(old = virThreadLocalGet(&virThreadJobName)))
        return;

    if (virThreadLocalSet(&virThreadJobName, NULL) < 0)
        virReportSystemError(errno, "%s", _("cannot reset current job"));

    if ((worker = virThreadLocalGet(&virThreadJobWorker))) {
        VIR_DEBUG("Thread %llu (%s) finished job %s with ret=%d",
                  virThreadSelfID(), worker, old, rv);
    } else {
        VIR_DEBUG("Thread %llu finished job %s with ret=%d",
                  virThreadSelfID(), old, rv);
    }
}
