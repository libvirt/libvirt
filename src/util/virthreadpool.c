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
 */

#include <config.h>

#include "virthreadpool.h"
#include "viralloc.h"
#include "virthread.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _virThreadPoolJob virThreadPoolJob;
struct _virThreadPoolJob {
    virThreadPoolJob *prev;
    virThreadPoolJob *next;
    unsigned int priority;

    void *data;
};

typedef struct _virThreadPoolJobList virThreadPoolJobList;
struct _virThreadPoolJobList {
    virThreadPoolJob *head;
    virThreadPoolJob *tail;
    virThreadPoolJob *firstPrio;
};


struct _virThreadPool {
    bool quit;

    virThreadPoolJobFunc jobFunc;
    char *jobName;
    void *jobOpaque;
    virThreadPoolJobList jobList;
    size_t jobQueueDepth;

    virIdentity *identity;

    virMutex mutex;
    virCond cond;
    virCond quit_cond;

    size_t maxWorkers;
    size_t minWorkers;
    size_t freeWorkers;
    size_t nWorkers;
    virThread *workers;

    size_t maxPrioWorkers;
    size_t nPrioWorkers;
    virThread *prioWorkers;
    virCond prioCond;
};

struct virThreadPoolWorkerData {
    virThreadPool *pool;
    virCond *cond;
    bool priority;
};

/* Test whether the worker needs to quit if the current number of workers @count
 * is greater than @limit actually allows.
 */
static inline bool virThreadPoolWorkerQuitHelper(size_t count, size_t limit)
{
    return count > limit;
}

static void virThreadPoolWorker(void *opaque)
{
    struct virThreadPoolWorkerData *data = opaque;
    virThreadPool *pool = data->pool;
    virCond *cond = data->cond;
    bool priority = data->priority;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t *maxLimit = priority ? &pool->maxPrioWorkers : &pool->maxWorkers;
    virThreadPoolJob *job = NULL;

    VIR_FREE(data);

    virMutexLock(&pool->mutex);

    if (pool->identity)
        virIdentitySetCurrent(pool->identity);

    while (1) {
        /* In order to support async worker termination, we need ensure that
         * both busy and free workers know if they need to terminated. Thus,
         * busy workers need to check for this fact before they start waiting for
         * another job (and before taking another one from the queue); and
         * free workers need to check for this right after waking up.
         */
        if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
            goto out;
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

            if (virThreadPoolWorkerQuitHelper(*curWorkers, *maxLimit))
                goto out;
        }

        if (pool->quit)
            break;

        if (priority) {
            job = pool->jobList.firstPrio;
        } else {
            job = pool->jobList.head;
        }

        if (job == pool->jobList.firstPrio) {
            virThreadPoolJob *tmp = job->next;
            while (tmp) {
                if (tmp->priority)
                    break;
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

static int
virThreadPoolExpand(virThreadPool *pool, size_t gain, bool priority)
{
    virThread **workers = priority ? &pool->prioWorkers : &pool->workers;
    size_t *curWorkers = priority ? &pool->nPrioWorkers : &pool->nWorkers;
    size_t i = 0;
    struct virThreadPoolWorkerData *data = NULL;

    VIR_EXPAND_N(*workers, *curWorkers, gain);

    for (i = 0; i < gain; i++) {
        g_autofree char *name = NULL;

        data = g_new0(struct virThreadPoolWorkerData, 1);
        data->pool = pool;
        data->cond = priority ? &pool->prioCond : &pool->cond;
        data->priority = priority;

        if (priority)
            name = g_strdup_printf("prio-%s", pool->jobName);
        else
            name = g_strdup(pool->jobName);

        if (virThreadCreateFull(&(*workers)[i],
                                false,
                                virThreadPoolWorker,
                                name,
                                true,
                                data) < 0) {
            VIR_FREE(data);
            virReportSystemError(errno, "%s", _("Failed to create thread"));
            goto error;
        }
    }

    return 0;

 error:
    *curWorkers -= gain - i;
    return -1;
}

virThreadPool *
virThreadPoolNewFull(size_t minWorkers,
                     size_t maxWorkers,
                     size_t prioWorkers,
                     virThreadPoolJobFunc func,
                     const char *name,
                     virIdentity *identity,
                     void *opaque)
{
    virThreadPool *pool;

    if (minWorkers > maxWorkers)
        minWorkers = maxWorkers;

    pool = g_new0(virThreadPool, 1);

    pool->jobList.tail = pool->jobList.head = NULL;

    pool->jobFunc = func;
    pool->jobName = g_strdup(name);
    pool->jobOpaque = opaque;

    if (identity)
        pool->identity = g_object_ref(identity);

    if (virMutexInit(&pool->mutex) < 0)
        goto error;
    if (virCondInit(&pool->cond) < 0)
        goto error;
    if (virCondInit(&pool->prioCond) < 0)
        goto error;
    if (virCondInit(&pool->quit_cond) < 0)
        goto error;

    pool->minWorkers = minWorkers;
    pool->maxWorkers = maxWorkers;
    pool->maxPrioWorkers = prioWorkers;

    if ((minWorkers > 0) && virThreadPoolExpand(pool, minWorkers, false) < 0)
        goto error;

    if ((prioWorkers > 0) && virThreadPoolExpand(pool, prioWorkers, true) < 0)
        goto error;

    return pool;

 error:
    virThreadPoolFree(pool);
    return NULL;

}


static void
virThreadPoolStopLocked(virThreadPool *pool)
{
    if (pool->quit)
        return;

    pool->quit = true;
    if (pool->nWorkers > 0)
        virCondBroadcast(&pool->cond);
    if (pool->nPrioWorkers > 0)
        virCondBroadcast(&pool->prioCond);
}


static void
virThreadPoolDrainLocked(virThreadPool *pool)
{
    virThreadPoolJob *job;

    virThreadPoolStopLocked(pool);

    while (pool->nWorkers > 0 || pool->nPrioWorkers > 0)
        ignore_value(virCondWait(&pool->quit_cond, &pool->mutex));

    while ((job = pool->jobList.head)) {
        pool->jobList.head = pool->jobList.head->next;
        VIR_FREE(job);
    }
}

void virThreadPoolFree(virThreadPool *pool)
{
    if (!pool)
        return;

    virThreadPoolDrain(pool);

    if (pool->identity)
        g_object_unref(pool->identity);

    g_free(pool->jobName);
    g_free(pool->workers);
    virMutexDestroy(&pool->mutex);
    virCondDestroy(&pool->quit_cond);
    virCondDestroy(&pool->cond);
    g_free(pool->prioWorkers);
    virCondDestroy(&pool->prioCond);
    g_free(pool);
}


size_t virThreadPoolGetMinWorkers(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->minWorkers;
}

size_t virThreadPoolGetMaxWorkers(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->maxWorkers;
}

size_t virThreadPoolGetPriorityWorkers(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->nPrioWorkers;
}

size_t virThreadPoolGetCurrentWorkers(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->nWorkers;
}

size_t virThreadPoolGetFreeWorkers(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->freeWorkers;
}

size_t virThreadPoolGetJobQueueDepth(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    return pool->jobQueueDepth;
}

/*
 * @priority - job priority
 * Return: 0 on success, -1 otherwise
 */
int virThreadPoolSendJob(virThreadPool *pool,
                         unsigned int priority,
                         void *jobData)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);
    virThreadPoolJob *job;

    if (pool->quit)
        return -1;

    if (pool->freeWorkers - pool->jobQueueDepth <= 0 &&
        pool->nWorkers < pool->maxWorkers &&
        virThreadPoolExpand(pool, 1, false) < 0)
        return -1;

    job = g_new0(virThreadPoolJob, 1);

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

    return 0;
}

int
virThreadPoolSetParameters(virThreadPool *pool,
                           long long int minWorkers,
                           long long int maxWorkers,
                           long long int prioWorkers)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);
    size_t max;
    size_t min;

    max = maxWorkers >= 0 ? maxWorkers : pool->maxWorkers;
    min = minWorkers >= 0 ? minWorkers : pool->minWorkers;
    if (min > max) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("minWorkers cannot be larger than maxWorkers"));
        return -1;
    }

    if ((maxWorkers == 0 && pool->maxWorkers > 0) ||
        (maxWorkers > 0 && pool->maxWorkers == 0)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("maxWorkers must not be switched from zero to non-zero and vice versa"));
        return -1;
    }

    if (minWorkers >= 0) {
        if ((size_t) minWorkers > pool->nWorkers &&
            virThreadPoolExpand(pool, minWorkers - pool->nWorkers, false) < 0)
            return -1;
        pool->minWorkers = minWorkers;
    }

    if (maxWorkers >= 0) {
        pool->maxWorkers = maxWorkers;
        virCondBroadcast(&pool->cond);
    }

    if (prioWorkers >= 0) {
        if (prioWorkers < pool->nPrioWorkers) {
            virCondBroadcast(&pool->prioCond);
        } else if ((size_t) prioWorkers > pool->nPrioWorkers &&
                   virThreadPoolExpand(pool, prioWorkers - pool->nPrioWorkers,
                                       true) < 0) {
            return -1;
        }
        pool->maxPrioWorkers = prioWorkers;
    }

    return 0;
}

void
virThreadPoolStop(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    virThreadPoolStopLocked(pool);
}

void
virThreadPoolDrain(virThreadPool *pool)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&pool->mutex);

    virThreadPoolDrainLocked(pool);
}
