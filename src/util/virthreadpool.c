/*
 * virthreadpool.c: a generic thread pool implementation
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Hu Tao <hutao@cn.fujitsu.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virthreadpool.h"
#include "viralloc.h"
#include "virthread.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _virThreadPoolJob virThreadPoolJob;
typedef virThreadPoolJob *virThreadPoolJobPtr;

struct _virThreadPoolJob {
    virThreadPoolJobPtr prev;
    virThreadPoolJobPtr next;
    unsigned int priority;

    void *data;
};

typedef struct _virThreadPoolJobList virThreadPoolJobList;
typedef virThreadPoolJobList *virThreadPoolJobListPtr;

struct _virThreadPoolJobList {
    virThreadPoolJobPtr head;
    virThreadPoolJobPtr tail;
    virThreadPoolJobPtr firstPrio;
};


struct _virThreadPool {
    bool quit;

    virThreadPoolJobFunc jobFunc;
    void *jobOpaque;
    virThreadPoolJobList jobList;
    size_t jobQueueDepth;

    virMutex mutex;
    virCond cond;
    virCond quit_cond;

    size_t maxWorkers;
    size_t minWorkers;
    size_t freeWorkers;
    size_t nWorkers;
    virThreadPtr workers;

    size_t nPrioWorkers;
    virThreadPtr prioWorkers;
    virCond prioCond;
};

struct virThreadPoolWorkerData {
    virThreadPoolPtr pool;
    virCondPtr cond;
    bool priority;
};

static void virThreadPoolWorker(void *opaque)
{
    struct virThreadPoolWorkerData *data = opaque;
    virThreadPoolPtr pool = data->pool;
    virCondPtr cond = data->cond;
    bool priority = data->priority;
    virThreadPoolJobPtr job = NULL;

    VIR_FREE(data);

    virMutexLock(&pool->mutex);

    while (1) {
        while (!pool->quit &&
               ((!priority && !pool->jobList.head) ||
                (priority && !pool->jobList.firstPrio))) {
            if (!priority)
                pool->freeWorkers++;
            if (virCondWait(cond, &pool->mutex) < 0) {
                if (!priority)
                    pool->freeWorkers--;
                goto out;
            }
            if (!priority)
                pool->freeWorkers--;
        }

        if (pool->quit)
            break;

        if (priority) {
            job = pool->jobList.firstPrio;
        } else {
            job = pool->jobList.head;
        }

        if (job == pool->jobList.firstPrio) {
            virThreadPoolJobPtr tmp = job->next;
            while (tmp) {
                if (tmp->priority) {
                    break;
                }
                tmp = tmp->next;
            }
            pool->jobList.firstPrio = tmp;
        }

        if (job->prev)
            job->prev->next = job->next;
        else
            pool->jobList.head = job->next;
        if (job->next)
            job->next->prev = job->prev;
        else
            pool->jobList.tail = job->prev;

        pool->jobQueueDepth--;

        virMutexUnlock(&pool->mutex);
        (pool->jobFunc)(job->data, pool->jobOpaque);
        VIR_FREE(job);
        virMutexLock(&pool->mutex);
    }

 out:
    if (priority)
        pool->nPrioWorkers--;
    else
        pool->nWorkers--;
    if (pool->nWorkers == 0 && pool->nPrioWorkers == 0)
        virCondSignal(&pool->quit_cond);
    virMutexUnlock(&pool->mutex);
}

virThreadPoolPtr virThreadPoolNew(size_t minWorkers,
                                  size_t maxWorkers,
                                  size_t prioWorkers,
                                  virThreadPoolJobFunc func,
                                  void *opaque)
{
    virThreadPoolPtr pool;
    size_t i;
    struct virThreadPoolWorkerData *data = NULL;

    if (minWorkers > maxWorkers)
        minWorkers = maxWorkers;

    if (VIR_ALLOC(pool) < 0)
        return NULL;

    pool->jobList.tail = pool->jobList.head = NULL;

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

    pool->minWorkers = minWorkers;
    pool->maxWorkers = maxWorkers;

    for (i = 0; i < minWorkers; i++) {
        if (VIR_ALLOC(data) < 0)
            goto error;
        data->pool = pool;
        data->cond = &pool->cond;

        if (virThreadCreate(&pool->workers[i],
                            true,
                            virThreadPoolWorker,
                            data) < 0) {
            goto error;
        }
        pool->nWorkers++;
    }

    if (prioWorkers) {
        if (virCondInit(&pool->prioCond) < 0)
            goto error;
        if (VIR_ALLOC_N(pool->prioWorkers, prioWorkers) < 0)
            goto error;

        for (i = 0; i < prioWorkers; i++) {
            if (VIR_ALLOC(data) < 0)
                goto error;
            data->pool = pool;
            data->cond = &pool->prioCond;
            data->priority = true;

            if (virThreadCreate(&pool->prioWorkers[i],
                                true,
                                virThreadPoolWorker,
                                data) < 0) {
                goto error;
            }
            pool->nPrioWorkers++;
        }
    }

    return pool;

 error:
    VIR_FREE(data);
    virThreadPoolFree(pool);
    return NULL;

}

void virThreadPoolFree(virThreadPoolPtr pool)
{
    virThreadPoolJobPtr job;
    bool priority = false;
    size_t i;
    size_t nWorkers;
    size_t nPrioWorkers;

    if (!pool)
        return;

    virMutexLock(&pool->mutex);
    nWorkers = pool->nWorkers;
    nPrioWorkers = pool->nPrioWorkers;
    pool->quit = true;
    if (pool->nWorkers > 0)
        virCondBroadcast(&pool->cond);
    if (pool->nPrioWorkers > 0) {
        priority = true;
        virCondBroadcast(&pool->prioCond);
    }

    while (pool->nWorkers > 0 || pool->nPrioWorkers > 0)
        ignore_value(virCondWait(&pool->quit_cond, &pool->mutex));

    while ((job = pool->jobList.head)) {
        pool->jobList.head = pool->jobList.head->next;
        VIR_FREE(job);
    }

    for (i = 0; i < nWorkers; i++)
        virThreadJoin(&pool->workers[i]);

    for (i = 0; i < nPrioWorkers; i++)
        virThreadJoin(&pool->prioWorkers[i]);

    VIR_FREE(pool->workers);
    virMutexUnlock(&pool->mutex);
    virMutexDestroy(&pool->mutex);
    virCondDestroy(&pool->quit_cond);
    virCondDestroy(&pool->cond);
    if (priority) {
        VIR_FREE(pool->prioWorkers);
        virCondDestroy(&pool->prioCond);
    }
    VIR_FREE(pool);
}


size_t virThreadPoolGetMinWorkers(virThreadPoolPtr pool)
{
    return pool->minWorkers;
}

size_t virThreadPoolGetMaxWorkers(virThreadPoolPtr pool)
{
    return pool->maxWorkers;
}

size_t virThreadPoolGetPriorityWorkers(virThreadPoolPtr pool)
{
    return pool->nPrioWorkers;
}

/*
 * @priority - job priority
 * Return: 0 on success, -1 otherwise
 */
int virThreadPoolSendJob(virThreadPoolPtr pool,
                         unsigned int priority,
                         void *jobData)
{
    virThreadPoolJobPtr job;
    struct virThreadPoolWorkerData *data = NULL;

    virMutexLock(&pool->mutex);
    if (pool->quit)
        goto error;

    if (pool->freeWorkers - pool->jobQueueDepth <= 0 &&
        pool->nWorkers < pool->maxWorkers) {
        if (VIR_EXPAND_N(pool->workers, pool->nWorkers, 1) < 0)
            goto error;

        if (VIR_ALLOC(data) < 0) {
            pool->nWorkers--;
            goto error;
        }

        data->pool = pool;
        data->cond = &pool->cond;

        if (virThreadCreate(&pool->workers[pool->nWorkers - 1],
                            true,
                            virThreadPoolWorker,
                            data) < 0) {
            VIR_FREE(data);
            pool->nWorkers--;
            goto error;
        }
    }

    if (VIR_ALLOC(job) < 0)
        goto error;

    job->data = jobData;
    job->priority = priority;

    job->prev = pool->jobList.tail;
    if (pool->jobList.tail)
        pool->jobList.tail->next = job;
    pool->jobList.tail = job;

    if (!pool->jobList.head)
        pool->jobList.head = job;

    if (priority && !pool->jobList.firstPrio)
        pool->jobList.firstPrio = job;

    pool->jobQueueDepth++;

    virCondSignal(&pool->cond);
    if (priority)
        virCondSignal(&pool->prioCond);

    virMutexUnlock(&pool->mutex);
    return 0;

 error:
    virMutexUnlock(&pool->mutex);
    return -1;
}
