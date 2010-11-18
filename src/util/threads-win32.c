/*
 * threads-win32.c: basic thread synchronization primitives
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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

#include <process.h>

#include "memory.h"

struct virThreadLocalData {
    DWORD key;
    virThreadLocalCleanup cleanup;
};
typedef struct virThreadLocalData virThreadLocalData;
typedef virThreadLocalData *virThreadLocalDataPtr;

virMutex virThreadLocalLock;
unsigned int virThreadLocalCount = 0;
virThreadLocalDataPtr virThreadLocalList = NULL;
DWORD selfkey;

virThreadLocal virCondEvent;

void virCondEventCleanup(void *data);

int virThreadInitialize(void)
{
    if (virMutexInit(&virThreadLocalLock) < 0)
        return -1;
    if (virThreadLocalInit(&virCondEvent, virCondEventCleanup) < 0)
        return -1;
    if ((selfkey = TlsAlloc()) == TLS_OUT_OF_INDEXES)
        return -1;
    return 0;
}

void virThreadOnExit(void)
{
    unsigned int i;
    virMutexLock(&virThreadLocalLock);
    for (i = 0 ; i < virThreadLocalCount ; i++) {
        if (virThreadLocalList[i].cleanup) {
            void *data = TlsGetValue(virThreadLocalList[i].key);
            if (data) {
                TlsSetValue(virThreadLocalList[i].key, NULL);

                (virThreadLocalList[i].cleanup)(data);
            }
        }
    }
    virMutexUnlock(&virThreadLocalLock);
}


int virMutexInit(virMutexPtr m)
{
    return virMutexInitRecursive(m);
}

int virMutexInitRecursive(virMutexPtr m)
{
    if (!(m->lock = CreateMutex(NULL, FALSE, NULL))) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

void virMutexDestroy(virMutexPtr m)
{
    CloseHandle(m->lock);
}

void virMutexLock(virMutexPtr m)
{
    WaitForSingleObject(m->lock, INFINITE);
}

void virMutexUnlock(virMutexPtr m)
{
    ReleaseMutex(m->lock);
}



int virCondInit(virCondPtr c)
{
    c->waiters = NULL;
    if (virMutexInit(&c->lock) < 0)
        return -1;
    return 0;
}

int virCondDestroy(virCondPtr c)
{
    if (c->waiters) {
        errno = EINVAL;
        return -1;
    }
    virMutexDestroy(&c->lock);
    return 0;
}

void virCondEventCleanup(void *data)
{
    HANDLE event = data;
    CloseHandle(event);
}

int virCondWait(virCondPtr c, virMutexPtr m)
{
    HANDLE event = virThreadLocalGet(&virCondEvent);

    if (!event) {
        event = CreateEvent(0, FALSE, FALSE, NULL);
        if (!event) {
            return -1;
        }
        virThreadLocalSet(&virCondEvent, event);
    }

    virMutexLock(&c->lock);

    if (VIR_REALLOC_N(c->waiters, c->nwaiters + 1) < 0) {
        virMutexUnlock(&c->lock);
        return -1;
    }
    c->waiters[c->nwaiters] = event;
    c->nwaiters++;

    virMutexUnlock(&c->lock);

    virMutexUnlock(m);

    if (WaitForSingleObject(event, INFINITE) == WAIT_FAILED) {
        virMutexLock(m);
        errno = EINVAL;
        return -1;
    }

    virMutexLock(m);
    return 0;
}

int virCondWaitUntil(virCondPtr c ATTRIBUTE_UNUSED,
                     virMutexPtr m ATTRIBUTE_UNUSED,
                     unsigned long long whenms ATTRIBUTE_UNUSED)
{
    /* FIXME: this function is currently only used by the QEMU driver that
     *        is not compiled on Windows, so it's okay for now to just
     *        miss an implementation */
    return -1;
}

void virCondSignal(virCondPtr c)
{
    virMutexLock(&c->lock);

    if (c->nwaiters) {
        HANDLE event = c->waiters[0];
        if (c->nwaiters > 1)
            memmove(c->waiters,
                    c->waiters + 1,
                    sizeof(c->waiters[0]) * (c->nwaiters-1));
        if (VIR_REALLOC_N(c->waiters, c->nwaiters - 1) < 0) {
            ;
        }
        c->nwaiters--;
        SetEvent(event);
    }

    virMutexUnlock(&c->lock);
}

void virCondBroadcast(virCondPtr c)
{
    virMutexLock(&c->lock);

    if (c->nwaiters) {
        unsigned int i;
        for (i = 0 ; i < c->nwaiters ; i++) {
            HANDLE event = c->waiters[i];
            SetEvent(event);
        }
        VIR_FREE(c->waiters);
        c->nwaiters = 0;
    }

    virMutexUnlock(&c->lock);
}


struct virThreadArgs {
    virThreadFunc func;
    void *opaque;
};

static void virThreadHelperDaemon(void *data)
{
    struct virThreadArgs *args = data;
    virThread self;
    HANDLE handle = GetCurrentThread();
    HANDLE process = GetCurrentProcess();

    self.joinable = false;
    DuplicateHandle(process, handle, process,
                    &self.thread, 0, FALSE,
                    DUPLICATE_SAME_ACCESS);
    TlsSetValue(selfkey, &self);

    args->func(args->opaque);

    TlsSetValue(selfkey, NULL);
    CloseHandle(self.thread);
}

static unsigned int __stdcall virThreadHelperJoinable(void *data)
{
    struct virThreadArgs *args = data;
    virThread self;
    HANDLE handle = GetCurrentThread();
    HANDLE process = GetCurrentProcess();

    self.joinable = true;
    DuplicateHandle(process, handle, process,
                    &self.thread, 0, FALSE,
                    DUPLICATE_SAME_ACCESS);
    TlsSetValue(selfkey, &self);

    args->func(args->opaque);

    TlsSetValue(selfkey, NULL);
    CloseHandle(self.thread);
    return 0;
}

int virThreadCreate(virThreadPtr thread,
                    bool joinable,
                    virThreadFunc func,
                    void *opaque)
{
    struct virThreadArgs args = { func, opaque };
    thread->joinable = joinable;
    if (joinable) {
        thread->thread = (HANDLE)_beginthreadex(NULL, 0,
                                                virThreadHelperJoinable,
                                                &args, 0, NULL);
        if (thread->thread == 0)
            return -1;
    } else {
        thread->thread = (HANDLE)_beginthread(virThreadHelperDaemon,
                                              0, &args);
        if (thread->thread == (HANDLE)-1L)
            return -1;
    }
    return 0;
}

void virThreadSelf(virThreadPtr thread)
{
    virThreadPtr self = TlsGetValue(selfkey);
    thread->thread = self->thread;
    thread->joinable = self->joinable;
}

bool virThreadIsSelf(virThreadPtr thread)
{
    virThread self;
    virThreadSelf(&self);
    return self.thread == thread->thread ? true : false;
}

int virThreadSelfID(void)
{
    return (int)GetCurrentThreadId();
}


void virThreadJoin(virThreadPtr thread)
{
    if (thread->joinable) {
        WaitForSingleObject(thread->thread, INFINITE);
        CloseHandle(thread->thread);
        thread->thread = 0;
        thread->joinable = false;
    }
}


int virThreadLocalInit(virThreadLocalPtr l,
                       virThreadLocalCleanup c)
{
    if ((l->key = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
        errno = ESRCH;
        return -1;
    }
    TlsSetValue(l->key, NULL);

    if (c) {
        virMutexLock(&virThreadLocalLock);
        if (VIR_REALLOC_N(virThreadLocalList,
                          virThreadLocalCount + 1) < 0)
            return -1;
        virThreadLocalList[virThreadLocalCount].key = l->key;
        virThreadLocalList[virThreadLocalCount].cleanup = c;
        virThreadLocalCount++;
        virMutexUnlock(&virThreadLocalLock);
    }

    return 0;
}

void *virThreadLocalGet(virThreadLocalPtr l)
{
    return TlsGetValue(l->key);
}

void virThreadLocalSet(virThreadLocalPtr l, void *val)
{
    TlsSetValue(l->key, val);
}
