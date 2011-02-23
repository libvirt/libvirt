/*
 * threadpool.c: a generic thread pool implementation
 *
 * Copyright (C) 2010 Hu Tao
 * Copyright (C) 2010 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Hu Tao <hutao@cn.fujitsu.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "threadpool.h"
#include "memory.h"
#include "threads.h"
#include "virterror_internal.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _virThreadPoolJob virThreadPoolJob;
typedef virThreadPoolJob *virThreadPoolJobPtr;

struct _virThreadPoolJob {
    virThreadPoolJobPtr next;

    void *data;
};

typedef struct _virThreadPoolJobList virThreadPoolJobList;
typedef virThreadPoolJobList *virThreadPoolJobListPtr;

struct _virThreadPoolJobList {
    virThreadPoolJobPtr head;
    virThreadPoolJobPtr *tail;
};


struct _virThreadPool {
    bool quit;

    virThreadPoolJobFunc jobFunc;
    void *jobOpaque;
    virThreadPoolJobList jobList;

    virMutex mutex;
    virCond cond;
    virCond quit_cond;

    size_t maxWorkers;
    size_t freeWorkers;
    size_t nWorkers;
    virThreadPtr workers;
};

static void virThreadPoolWorker(void *opaque)
{
    virThreadPoolPtr pool = opaque;

    virMutexLock(&pool->mutex);

    while (1) {
        while (!pool->quit &&
               !pool->jobList.head) {
            pool->freeWorkers++;
            if (virCondWait(&pool->cond, &pool->mutex) < 0) {
                pool->freeWorkers--;
                goto out;
            }
            pool->freeWorkers--;
        }

        if (pool->quit)
            break;

        virThreadPoolJobPtr job = pool->jobList.head;
        pool->jobList.head = pool->jobList.head->next;
        job->next = NULL;
        if (pool->jobList.tail == &job->next)
            pool->jobList.tail = &pool->jobList.head;

        virMutexUnlock(&pool->mutex);
        (pool->jobFunc)(job->data, pool->jobOpaque);
        VIR_FREE(job);
        virMutexLock(&pool->mutex);
    }

out:
    pool->nWorkers--;
    if (pool->nWorkers == 0)
        virCondSignal(&pool->quit_cond);
    virMutexUnlock(&pool->mutex);
}

virThreadPoolPtr virThreadPoolNew(size_t minWorkers,
                                  size_t maxWorkers,
                                  virThreadPoolJobFunc func,
                                  void *opaque)
{
    virThreadPoolPtr pool;
    size_t i;

    if (minWorkers > maxWorkers)
        minWorkers = maxWorkers;

    if (VIR_ALLOC(pool) < 0) {
        virReportOOMError();
        return NULL;
    }

    pool->jobList.head = NULL;
    pool->jobList.tail = &pool->jobList.head;

    pool->jobFunc = func;
    pool->jobOpaque = opaque;

    if (virMutexInit(&pool->mutex) < 0)
        goto error;
    if (virCondInit(&pool->cond) < 0)
        goto error;
    if (virCondInit(&pool->quit_cond) < 0)
        goto error;

    if (VIR_ALLOC_N(pool->workers, minWorkers) < 0)
        goto error;

    pool->maxWorkers = maxWorkers;
    for (i = 0; i < minWorkers; i++) {
        if (virThreadCreate(&pool->workers[i],
                            true,
                            virThreadPoolWorker,
                            pool) < 0) {
            goto error;
        }
        pool->nWorkers++;
    }

    return pool;

error:
    virThreadPoolFree(pool);
    return NULL;

}

void virThreadPoolFree(virThreadPoolPtr pool)
{
    virThreadPoolJobPtr job;

    if (!pool)
        return;

    virMutexLock(&pool->mutex);
    pool->quit = true;
    if (pool->nWorkers > 0) {
        virCondBroadcast(&pool->cond);
        ignore_value(virCondWait(&pool->quit_cond, &pool->mutex));
    }

    while ((job = pool->jobList.head)) {
        pool->jobList.head = pool->jobList.head->next;
        VIR_FREE(job);
    }

    VIR_FREE(pool->workers);
    virMutexUnlock(&pool->mutex);
    virMutexDestroy(&pool->mutex);
    ignore_value(virCondDestroy(&pool->quit_cond));
    ignore_value(virCondDestroy(&pool->cond));
    VIR_FREE(pool);
}

int virThreadPoolSendJob(virThreadPoolPtr pool,
                         void *jobData)
{
    virThreadPoolJobPtr job;

    virMutexLock(&pool->mutex);
    if (pool->quit)
        goto error;

    if (pool->freeWorkers == 0 &&
        pool->nWorkers < pool->maxWorkers) {
        if (VIR_EXPAND_N(pool->workers, pool->nWorkers, 1) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virThreadCreate(&pool->workers[pool->nWorkers - 1],
                            true,
                            virThreadPoolWorker,
                            pool) < 0) {
            pool->nWorkers--;
            goto error;
        }
    }

    if (VIR_ALLOC(job) < 0) {
        virReportOOMError();
        goto error;
    }

    job->data = jobData;
    job->next = NULL;
    *pool->jobList.tail = job;
    pool->jobList.tail = &(*pool->jobList.tail)->next;

    virCondSignal(&pool->cond);
    virMutexUnlock(&pool->mutex);

    return 0;

error:
    virMutexUnlock(&pool->mutex);
    return -1;
}
