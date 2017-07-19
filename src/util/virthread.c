/*
 * virthread.c: basic thread synchronization primitives
 *
 * Copyright (C) 2009-2010, 2014 Red Hat, Inc.
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

#include "virthread.h"

#include <unistd.h>
#include <inttypes.h>
#if HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif

#include "viralloc.h"
#include "virthreadjob.h"


/* Nothing special required for pthreads */
int virThreadInitialize(void)
{
    return 0;
}

void virThreadOnExit(void)
{
}

int virOnce(virOnceControlPtr once, virOnceFunc init)
{
    return pthread_once(&once->once, init);
}


int virMutexInit(virMutexPtr m)
{
    int ret;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
    ret = pthread_mutex_init(&m->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

int virMutexInitRecursive(virMutexPtr m)
{
    int ret;
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    ret = pthread_mutex_init(&m->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

void virMutexDestroy(virMutexPtr m)
{
    pthread_mutex_destroy(&m->lock);
}

void virMutexLock(virMutexPtr m)
{
    pthread_mutex_lock(&m->lock);
}

void virMutexUnlock(virMutexPtr m)
{
    pthread_mutex_unlock(&m->lock);
}


/**
 * virRWLockInit:
 * @m: rwlock to init
 *
 * Initializes RW lock using pthread default attributes (which
 * is PTHREAD_RWLOCK_PREFER_READER_NP).
 *
 * Returns 0 on success, -1 otherwise.
 */
int virRWLockInit(virRWLockPtr m)
{
    int ret;
    ret = pthread_rwlock_init(&m->lock, NULL);
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}


/**
 * virRWLockInitPreferWriter:
 * @m: rwlock to init
 *
 * Initializes RW lock which prefers writers over readers.
 *
 * Returns 0 on success, -1 otherwise.
 */
int virRWLockInitPreferWriter(virRWLockPtr m)
{
    int ret;
    pthread_rwlockattr_t attr;

    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    ret = pthread_rwlock_init(&m->lock, &attr);
    pthread_rwlockattr_destroy(&attr);
    if (ret != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}


void virRWLockDestroy(virRWLockPtr m)
{
    pthread_rwlock_destroy(&m->lock);
}


void virRWLockRead(virRWLockPtr m)
{
    pthread_rwlock_rdlock(&m->lock);
}

void virRWLockWrite(virRWLockPtr m)
{
    pthread_rwlock_wrlock(&m->lock);
}


void virRWLockUnlock(virRWLockPtr m)
{
    pthread_rwlock_unlock(&m->lock);
}

int virCondInit(virCondPtr c)
{
    int ret;
    if ((ret = pthread_cond_init(&c->cond, NULL)) != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

int virCondDestroy(virCondPtr c)
{
    int ret;
    if ((ret = pthread_cond_destroy(&c->cond)) != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

int virCondWait(virCondPtr c, virMutexPtr m)
{
    int ret;
    if ((ret = pthread_cond_wait(&c->cond, &m->lock)) != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

int virCondWaitUntil(virCondPtr c, virMutexPtr m, unsigned long long whenms)
{
    int ret;
    struct timespec ts;

    ts.tv_sec = whenms / 1000;
    ts.tv_nsec = (whenms % 1000) * 1000000;

    if ((ret = pthread_cond_timedwait(&c->cond, &m->lock, &ts)) != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

void virCondSignal(virCondPtr c)
{
    pthread_cond_signal(&c->cond);
}

void virCondBroadcast(virCondPtr c)
{
    pthread_cond_broadcast(&c->cond);
}

struct virThreadArgs {
    virThreadFunc func;
    const char *funcName;
    bool worker;
    void *opaque;
};

static void *virThreadHelper(void *data)
{
    struct virThreadArgs *args = data;
    struct virThreadArgs local = *args;

    /* Free args early, rather than tying it up during the entire thread.  */
    VIR_FREE(args);

    if (local.worker)
        virThreadJobSetWorker(local.funcName);
    else
        virThreadJobSet(local.funcName);

    local.func(local.opaque);

    if (!local.worker)
        virThreadJobClear(0);

    return NULL;
}

int virThreadCreateFull(virThreadPtr thread,
                        bool joinable,
                        virThreadFunc func,
                        const char *funcName,
                        bool worker,
                        void *opaque)
{
    struct virThreadArgs *args;
    pthread_attr_t attr;
    int ret = -1;
    int err;

    if ((err = pthread_attr_init(&attr)) != 0)
        goto cleanup;
    if (VIR_ALLOC_QUIET(args) < 0) {
        err = ENOMEM;
        goto cleanup;
    }

    args->func = func;
    args->funcName = funcName;
    args->worker = worker;
    args->opaque = opaque;

    if (!joinable)
        pthread_attr_setdetachstate(&attr, 1);

    err = pthread_create(&thread->thread, &attr, virThreadHelper, args);
    if (err != 0) {
        VIR_FREE(args);
        goto cleanup;
    }
    /* New thread owns 'args' in success case, so don't free */

    ret = 0;
 cleanup:
    pthread_attr_destroy(&attr);
    if (ret < 0)
        errno = err;
    return ret;
}

void virThreadSelf(virThreadPtr thread)
{
    thread->thread = pthread_self();
}

bool virThreadIsSelf(virThreadPtr thread)
{
    return pthread_equal(pthread_self(), thread->thread) ? true : false;
}

/* For debugging use only; this result is not guaranteed unique if
 * pthread_t is larger than a 64-bit pointer, nor does it always match
 * the pthread_self() id on Linux.  */
unsigned long long virThreadSelfID(void)
{
#if defined(HAVE_SYS_SYSCALL_H) && defined(SYS_gettid)
    pid_t tid = syscall(SYS_gettid);
    return tid;
#else
    union {
        unsigned long long l;
        pthread_t t;
    } u;
    u.t = pthread_self();
    return u.l;
#endif
}

/* For debugging use only; this result is not guaranteed unique if
 * pthread_t is larger than a 64-bit pointer, nor does it always match
 * the thread id of virThreadSelfID on Linux.  */
unsigned long long virThreadID(virThreadPtr thread)
{
    union {
        unsigned long long l;
        pthread_t t;
    } u;
    u.t = thread->thread;
    return u.l;
}

void virThreadJoin(virThreadPtr thread)
{
    pthread_join(thread->thread, NULL);
}

void virThreadCancel(virThreadPtr thread)
{
    pthread_cancel(thread->thread);
}

int virThreadLocalInit(virThreadLocalPtr l,
                       virThreadLocalCleanup c)
{
    int ret;
    if ((ret = pthread_key_create(&l->key, c)) != 0) {
        errno = ret;
        return -1;
    }
    return 0;
}

void *virThreadLocalGet(virThreadLocalPtr l)
{
    return pthread_getspecific(l->key);
}

int virThreadLocalSet(virThreadLocalPtr l, void *val)
{
    int err = pthread_setspecific(l->key, val);
    if (err) {
        errno = err;
        return -1;
    }
    return 0;
}
