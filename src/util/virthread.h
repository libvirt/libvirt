/*
 * virthread.h: basic thread synchronization primitives
 *
 * Copyright (C) 2009-2011, 2013-2014 Red Hat, Inc.
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

#ifndef __THREADS_H_
# define __THREADS_H_

# include "internal.h"
# include "virerror.h"

# include <pthread.h>

typedef struct virMutex virMutex;
typedef virMutex *virMutexPtr;

struct virMutex {
    pthread_mutex_t lock;
};

typedef struct virRWLock virRWLock;
typedef virRWLock *virRWLockPtr;

struct virRWLock {
    pthread_rwlock_t lock;
};


typedef struct virCond virCond;
typedef virCond *virCondPtr;

struct virCond {
    pthread_cond_t cond;
};

typedef struct virThreadLocal virThreadLocal;
typedef virThreadLocal *virThreadLocalPtr;

struct virThreadLocal {
    pthread_key_t key;
};

typedef struct virThread virThread;
typedef virThread *virThreadPtr;

struct virThread {
    pthread_t thread;
};

typedef struct virOnceControl virOnceControl;
typedef virOnceControl *virOnceControlPtr;

struct virOnceControl {
    pthread_once_t once;
};


# define VIR_MUTEX_INITIALIZER            \
    {                                     \
        .lock = PTHREAD_MUTEX_INITIALIZER \
    }

# define VIR_ONCE_CONTROL_INITIALIZER \
    {                                 \
        .once = PTHREAD_ONCE_INIT     \
    }

typedef void (*virOnceFunc)(void);

int virThreadInitialize(void) ATTRIBUTE_RETURN_CHECK;
void virThreadOnExit(void);

typedef void (*virThreadFunc)(void *opaque);

# define virThreadCreate(thread, joinable, func, opaque) \
    virThreadCreateFull(thread, joinable, func, #func, false, opaque)

int virThreadCreateFull(virThreadPtr thread,
                        bool joinable,
                        virThreadFunc func,
                        const char *funcName,
                        bool worker,
                        void *opaque) ATTRIBUTE_RETURN_CHECK;
void virThreadSelf(virThreadPtr thread);
bool virThreadIsSelf(virThreadPtr thread);
void virThreadJoin(virThreadPtr thread);

/* This API is *NOT* for general use. It exists solely as a stub
 * for integration with libselinux AVC callbacks */
void virThreadCancel(virThreadPtr thread);

/* These next two functions are for debugging only, since they are not
 * guaranteed to give unique values for distinct threads on all
 * architectures, nor are the two functions guaranteed to give the same
 * value for the same thread. */
unsigned long long virThreadSelfID(void);
unsigned long long virThreadID(virThreadPtr thread);

/* Static initialization of mutexes is not possible, so we instead
 * provide for guaranteed one-time initialization via a callback
 * function.  Usage:
 * static virOnceControl once = VIR_ONCE_CONTROL_INITIALIZER;
 * static void initializer(void) { ... }
 * void myfunc()
 * {
 *     if (virOnce(&once, initializer) < 0)
 *         goto error;
 *     ...now guaranteed that initializer has completed exactly once
 * }
 */
int virOnce(virOnceControlPtr once, virOnceFunc init)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virMutexInit(virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
int virMutexInitRecursive(virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
void virMutexDestroy(virMutexPtr m);

void virMutexLock(virMutexPtr m);
void virMutexUnlock(virMutexPtr m);


int virRWLockInit(virRWLockPtr m) ATTRIBUTE_RETURN_CHECK;
int virRWLockInitPreferWriter(virRWLockPtr m) ATTRIBUTE_RETURN_CHECK;
void virRWLockDestroy(virRWLockPtr m);

void virRWLockRead(virRWLockPtr m);
void virRWLockWrite(virRWLockPtr m);
void virRWLockUnlock(virRWLockPtr m);


int virCondInit(virCondPtr c) ATTRIBUTE_RETURN_CHECK;
int virCondDestroy(virCondPtr c);

/* virCondWait, virCondWaitUntil:
 * These functions can return without the associated predicate
 * changing value. Therefore in nearly all cases they
 * should be enclosed in a while loop that checks the predicate.
 */
int virCondWait(virCondPtr c, virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
int virCondWaitUntil(virCondPtr c, virMutexPtr m, unsigned long long whenms) ATTRIBUTE_RETURN_CHECK;

void virCondSignal(virCondPtr c);
void virCondBroadcast(virCondPtr c);


typedef void (*virThreadLocalCleanup)(void *);
int virThreadLocalInit(virThreadLocalPtr l,
                       virThreadLocalCleanup c) ATTRIBUTE_RETURN_CHECK;
void *virThreadLocalGet(virThreadLocalPtr l);
int virThreadLocalSet(virThreadLocalPtr l, void*) ATTRIBUTE_RETURN_CHECK;


/**
 * VIR_ONCE_GLOBAL_INIT:
 * classname: base classname
 *
 * This macro simplifies the setup of a one-time only
 * global file initializer.
 *
 * Assuming a class called "virMyObject", and a method
 * implemented like:
 *
 *  int virMyObjectOnceInit(void) {
 *      ...do init tasks...
 *  }
 *
 * Then invoking the macro:
 *
 *  VIR_ONCE_GLOBAL_INIT(virMyObject)
 *
 * Will create a method
 *
 *  int virMyObjectInitialize(void);
 *
 * Which will ensure that 'virMyObjectOnceInit' is
 * guaranteed to be invoked exactly once.
 */
# define VIR_ONCE_GLOBAL_INIT(classname)                                \
    static virOnceControl classname ## OnceControl = VIR_ONCE_CONTROL_INITIALIZER; \
    static virErrorPtr classname ## OnceError;                          \
                                                                        \
    static void classname ## Once(void)                                 \
    {                                                                   \
        if (classname ## OnceInit() < 0)                                \
            classname ## OnceError = virSaveLastError();                \
    }                                                                   \
                                                                        \
    static int classname ## Initialize(void)                            \
    {                                                                   \
        if (virOnce(&classname ## OnceControl, classname ## Once) < 0)  \
            return -1;                                                  \
                                                                        \
        if (classname ## OnceError) {                                   \
            virSetError(classname ## OnceError);                        \
            return -1;                                                  \
        }                                                               \
                                                                        \
        return 0;                                                       \
    }

#endif
