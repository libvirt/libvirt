/*
 * viratomic.h: atomic integer operations
 *
 * Copyright (C) 2012 IBM Corporation
 *
 * Authors:
 *     Stefan Berger <stefanb@linux.vnet.ibm.com>
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

#ifndef __VIR_ATOMIC_H__
# define __VIR_ATOMIC_H__

# include "threads.h"

typedef struct _virAtomicInt virAtomicInt;
typedef virAtomicInt *virAtomicIntPtr;

struct _virAtomicInt {
    virMutex lock;
    int value;
};

static inline int
virAtomicIntInit(virAtomicIntPtr vaip)
{
    vaip->value = 0;
    return virMutexInit(&vaip->lock);
}

static inline void
virAtomicIntSet(virAtomicIntPtr vaip, int value)
{
     virMutexLock(&vaip->lock);

     vaip->value = value;

     virMutexUnlock(&vaip->lock);
}

static inline int
virAtomicIntRead(virAtomicIntPtr vaip)
{
     return vaip->value;
}

static inline int
virAtomicIntAdd(virAtomicIntPtr vaip, int add)
{
    int ret;

    virMutexLock(&vaip->lock);

    vaip->value += add;
    ret = vaip->value;

    virMutexUnlock(&vaip->lock);

    return ret;
}

static inline int
virAtomicIntSub(virAtomicIntPtr vaip, int sub)
{
    int ret;

    virMutexLock(&vaip->lock);

    vaip->value -= sub;
    ret = vaip->value;

    virMutexUnlock(&vaip->lock);

    return ret;
}

#endif /* __VIR_ATOMIC_H */
