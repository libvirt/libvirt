/*
 * threads-pthread.c: basic thread synchronization primitives
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 */

#include <config.h>

#include <unistd.h>
#include <inttypes.h>
#if HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif

#include "memory.h"


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

void virMutexLock(virMutexPtr m){
    pthread_mutex_lock(&m->lock);
}

void virMutexUnlock(virMutexPtr m)
{
    pthread_mutex_unlock(&m->lock);
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
    ts.tv_nsec = (whenms % 1000) * 1000;

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
    void *opaque;
};

static void *virThreadHelper(void *data)
{
    struct virThreadArgs *args = data;
    struct virThreadArgs local = *args;

    /* Free args early, rather than tying it up during the entire thread.  */
    VIR_FREE(args);
    local.func(local.opaque);
    return NULL;
}

int virThreadCreate(virThreadPtr thread,
                    bool joinable,
                    virThreadFunc func,
                    void *opaque)
{
    struct virThreadArgs *args;
    pthread_attr_t attr;
    int ret = -1;
    int err;

    if ((err = pthread_attr_init(&attr)) != 0)
        goto cleanup;
    if (VIR_ALLOC(args) < 0) {
        err = ENOMEM;
        goto cleanup;
    }

    args->func = func;
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

/* For debugging use only; this result is not guaranteed unique on BSD
 * systems when pthread_t is a 64-bit pointer.  */
int virThreadSelfID(void)
{
#if defined(HAVE_SYS_SYSCALL_H) && defined(SYS_gettid)
    pid_t tid;
    tid = syscall(SYS_gettid);
    return (int)tid;
#else
    return (int)(intptr_t)(void *)pthread_self();
#endif
}

/* For debugging use only; this result is not guaranteed unique on BSD
 * systems when pthread_t is a 64-bit pointer, nor does it match the
 * thread id of virThreadSelfID on Linux.  */
int virThreadID(virThreadPtr thread)
{
    return (int)(uintptr_t)thread->thread;
}

void virThreadJoin(virThreadPtr thread)
{
    pthread_join(thread->thread, NULL);
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
