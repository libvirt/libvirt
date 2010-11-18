/*
 * threads.h: basic thread synchronization primitives
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

#ifndef __THREADS_H_
# define __THREADS_H_

# include <stdbool.h>

# include "internal.h"

typedef struct virMutex virMutex;
typedef virMutex *virMutexPtr;

typedef struct virCond virCond;
typedef virCond *virCondPtr;

typedef struct virThreadLocal virThreadLocal;
typedef virThreadLocal *virThreadLocalPtr;

typedef struct virThread virThread;
typedef virThread *virThreadPtr;


int virThreadInitialize(void) ATTRIBUTE_RETURN_CHECK;
void virThreadOnExit(void);

typedef void (*virThreadFunc)(void *opaque);

int virThreadCreate(virThreadPtr thread,
                    bool joinable,
                    virThreadFunc func,
                    void *opaque) ATTRIBUTE_RETURN_CHECK;
void virThreadSelf(virThreadPtr thread);
bool virThreadIsSelf(virThreadPtr thread);
void virThreadJoin(virThreadPtr thread);
int virThreadSelfID(void);

int virMutexInit(virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
int virMutexInitRecursive(virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
void virMutexDestroy(virMutexPtr m);

void virMutexLock(virMutexPtr m);
void virMutexUnlock(virMutexPtr m);



int virCondInit(virCondPtr c) ATTRIBUTE_RETURN_CHECK;
int virCondDestroy(virCondPtr c) ATTRIBUTE_RETURN_CHECK;

int virCondWait(virCondPtr c, virMutexPtr m) ATTRIBUTE_RETURN_CHECK;
int virCondWaitUntil(virCondPtr c, virMutexPtr m, unsigned long long whenms) ATTRIBUTE_RETURN_CHECK;
void virCondSignal(virCondPtr c);
void virCondBroadcast(virCondPtr c);


typedef void (*virThreadLocalCleanup)(void *);
int virThreadLocalInit(virThreadLocalPtr l,
                       virThreadLocalCleanup c) ATTRIBUTE_RETURN_CHECK;
void *virThreadLocalGet(virThreadLocalPtr l);
void virThreadLocalSet(virThreadLocalPtr l, void*);

# ifdef WIN32
#  include "threads-win32.h"
# elif defined HAVE_PTHREAD_MUTEXATTR_INIT
#  include "threads-pthread.h"
# else
#  error "Either pthreads or Win32 threads are required"
# endif

#endif
