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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __VIR_ATOMIC_H__
# define __VIR_ATOMIC_H__

# include "threads.h"

typedef struct _virAtomicInt virAtomicInt;
typedef virAtomicInt *virAtomicIntPtr;

# define __VIR_ATOMIC_USES_LOCK

# if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 1)) || (__GNUC__ > 4)
#  undef __VIR_ATOMIC_USES_LOCK
# endif

static inline int virAtomicIntInit(virAtomicIntPtr vaip)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
static inline int virAtomicIntRead(virAtomicIntPtr vaip)
    ATTRIBUTE_NONNULL(1);
static inline void virAtomicIntSet(virAtomicIntPtr vaip, int val)
    ATTRIBUTE_NONNULL(1);
static inline int virAtomicIntAdd(virAtomicIntPtr vaip, int add)
    ATTRIBUTE_NONNULL(1);
static inline int virAtomicIntSub(virAtomicIntPtr vaip, int add)
    ATTRIBUTE_NONNULL(1);
static inline int virAtomicIntInc(virAtomicIntPtr vaip)
    ATTRIBUTE_NONNULL(1);
static inline int virAtomicIntDec(virAtomicIntPtr vaip)
    ATTRIBUTE_NONNULL(1);

# ifdef __VIR_ATOMIC_USES_LOCK

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

# else /* __VIR_ATOMIC_USES_LOCK */

struct _virAtomicInt {
    int value;
};

static inline int
virAtomicIntInit(virAtomicIntPtr vaip)
{
    vaip->value = 0;
    return 0;
}

static inline int
virAtomicIntAdd(virAtomicIntPtr vaip, int add)
{
    return __sync_add_and_fetch(&vaip->value, add);
}

static inline int
virAtomicIntSub(virAtomicIntPtr vaip, int sub)
{
    return __sync_sub_and_fetch(&vaip->value, sub);
}

# endif /* __VIR_ATOMIC_USES_LOCK */



/* common operations that need no locking or build on others */


static inline void
virAtomicIntSet(virAtomicIntPtr vaip, int value)
{
     vaip->value = value;
}

static inline int
virAtomicIntRead(virAtomicIntPtr vaip)
{
     return *(volatile int *)&vaip->value;
}

static inline int
virAtomicIntInc(virAtomicIntPtr vaip)
{
    return virAtomicIntAdd(vaip, 1);
}

static inline int
virAtomicIntDec(virAtomicIntPtr vaip)
{
    return virAtomicIntSub(vaip, 1);
}

#endif /* __VIR_ATOMIC_H */
