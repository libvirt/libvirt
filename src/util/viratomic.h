/*
 * viratomic.h: atomic integer operations
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * Based on code taken from GLib 2.32, under the LGPLv2+
 *
 * Copyright (C) 2011 Ryan Lortie
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

#ifndef __VIR_ATOMIC_H__
# define __VIR_ATOMIC_H__

# include "internal.h"

# ifdef VIR_ATOMIC_OPS_GCC
#  define VIR_STATIC /* Nothing; we just never define the functions */
# else
#  define VIR_STATIC static
# endif

/**
 * virAtomicIntGet:
 * Gets the current value of atomic.
 *
 * This call acts as a full compiler and hardware memory barrier
 * (before the get)
 */
VIR_STATIC int virAtomicIntGet(volatile int *atomic)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntSet:
 * Sets the value of atomic to newval.
 *
 * This call acts as a full compiler and hardware memory barrier
 * (after the set)
 */
VIR_STATIC void virAtomicIntSet(volatile int *atomic,
                                int newval)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntInc:
 * Increments the value of atomic by 1.
 *
 * Think of this operation as an atomic version of
 * { *atomic += 1; return *atomic; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC int virAtomicIntInc(volatile int *atomic)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntDecAndTest:
 * Decrements the value of atomic by 1.
 *
 * Think of this operation as an atomic version of
 * { *atomic -= 1; return *atomic == 0; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC bool virAtomicIntDecAndTest(volatile int *atomic)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntCompareExchange:
 * Compares atomic to oldval and, if equal, sets it to newval. If
 * atomic was not equal to oldval then no change occurs.
 *
 * This compare and exchange is done atomically.
 *
 * Think of this operation as an atomic version of
 * { if (*atomic == oldval) { *atomic = newval; return true; }
 *    else return false; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC bool virAtomicIntCompareExchange(volatile int *atomic,
                                            int oldval,
                                            int newval)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntAdd:
 * Atomically adds val to the value of atomic.
 *
 * Think of this operation as an atomic version of
 * { tmp = *atomic; *atomic += val; return tmp; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC int virAtomicIntAdd(volatile int *atomic,
                               int val)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntAnd:
 * Performs an atomic bitwise 'and' of the value of atomic
 * and val, storing the result back in atomic.
 *
 * This call acts as a full compiler and hardware memory barrier.
 *
 * Think of this operation as an atomic version of
 * { tmp = *atomic; *atomic &= val; return tmp; }
 */
VIR_STATIC unsigned int virAtomicIntAnd(volatile unsigned int *atomic,
                                        unsigned int val)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntOr:
 * Performs an atomic bitwise 'or' of the value of atomic
 * and val, storing the result back in atomic.
 *
 * Think of this operation as an atomic version of
 * { tmp = *atomic; *atomic |= val; return tmp; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC unsigned int virAtomicIntOr(volatile unsigned int *atomic,
                                       unsigned int val)
    ATTRIBUTE_NONNULL(1);

/**
 * virAtomicIntXor:
 * Performs an atomic bitwise 'xor' of the value of atomic
 * and val, storing the result back in atomic.
 *
 * Think of this operation as an atomic version of
 * { tmp = *atomic; *atomic ^= val; return tmp; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
VIR_STATIC unsigned int virAtomicIntXor(volatile unsigned int *atomic,
                                        unsigned int val)
    ATTRIBUTE_NONNULL(1);

# undef VIR_STATIC

# ifdef VIR_ATOMIC_OPS_GCC

#  define virAtomicIntGet(atomic)                                       \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ *(atomic) : 0);                      \
            __sync_synchronize();                                       \
            (int)*(atomic);                                             \
        }))
#  define virAtomicIntSet(atomic, newval)                               \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ (newval) : 0);                       \
            *(atomic) = (newval);                                       \
            __sync_synchronize();                                       \
        }))
#  define virAtomicIntInc(atomic)                                       \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ *(atomic) : 0);                      \
            __sync_add_and_fetch((atomic), 1);                          \
        }))
#  define virAtomicIntDecAndTest(atomic)                                \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ *(atomic) : 0);                      \
            __sync_fetch_and_sub((atomic), 1) == 1;                     \
        }))
#  define virAtomicIntCompareExchange(atomic, oldval, newval)           \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ (newval) ^ (oldval) : 0);            \
            (bool)__sync_bool_compare_and_swap((atomic),                \
                                               (oldval), (newval));     \
        }))
#  define virAtomicIntAdd(atomic, val)                                  \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));        \
            (void)(0 ? *(atomic) ^ (val) : 0);                          \
            (int) __sync_fetch_and_add((atomic), (val));                \
        }))
#  define virAtomicIntAnd(atomic, val)                                  \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));              \
            (void) (0 ? *(atomic) ^ (val) : 0);                         \
            (unsigned int) __sync_fetch_and_and((atomic), (val));       \
        }))
#  define virAtomicIntOr(atomic, val)                                   \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));              \
            (void) (0 ? *(atomic) ^ (val) : 0);                         \
            (unsigned int) __sync_fetch_and_or((atomic), (val));        \
        }))
#  define virAtomicIntXor(atomic, val)                                  \
    (__extension__ ({                                                   \
            (void)verify_true(sizeof(*(atomic)) == sizeof(int));              \
            (void) (0 ? *(atomic) ^ (val) : 0);                         \
            (unsigned int) __sync_fetch_and_xor((atomic), (val));       \
        }))


# else

#  ifdef VIR_ATOMIC_OPS_WIN32

#   include <winsock2.h>
#   include <windows.h>
#   include <intrin.h>
#   if !defined(_M_AMD64) && !defined (_M_IA64) && !defined(_M_X64)
#    define InterlockedAnd _InterlockedAnd
#    define InterlockedOr _InterlockedOr
#    define InterlockedXor _InterlockedXor
#   endif

/*
 * http://msdn.microsoft.com/en-us/library/ms684122(v=vs.85).aspx
 */
static inline int
virAtomicIntGet(volatile int *atomic)
{
    MemoryBarrier();
    return *atomic;
}

static inline void
virAtomicIntSet(volatile int *atomic,
                int newval)
{
    *atomic = newval;
    MemoryBarrier();
}

static inline int
virAtomicIntInc(volatile int *atomic)
{
    return InterlockedIncrement((volatile LONG *)atomic);
}

static inline bool
virAtomicIntDecAndTest(volatile int *atomic)
{
    return InterlockedDecrement((volatile LONG *)atomic) == 0;
}

static inline bool
virAtomicIntCompareExchange(volatile int *atomic,
                            int oldval,
                            int newval)
{
    return InterlockedCompareExchange((volatile LONG *)atomic, newval, oldval) == oldval;
}

static inline int
virAtomicIntAdd(volatile int *atomic,
                int val)
{
    return InterlockedExchangeAdd((volatile LONG *)atomic, val);
}

static inline unsigned int
virAtomicIntAnd(volatile unsigned int *atomic,
                unsigned int val)
{
    return InterlockedAnd((volatile LONG *)atomic, val);
}

static inline unsigned int
virAtomicIntOr(volatile unsigned int *atomic,
               unsigned int val)
{
    return InterlockedOr((volatile LONG *)atomic, val);
}

static inline unsigned int
virAtomicIntXor(volatile unsigned int *atomic,
                unsigned int val)
{
    return InterlockedXor((volatile LONG *)atomic, val);
}


#  else
#   ifdef VIR_ATOMIC_OPS_PTHREAD
#    include <pthread.h>

extern pthread_mutex_t virAtomicLock;

static inline int
virAtomicIntGet(volatile int *atomic)
{
    int value;

    pthread_mutex_lock(&virAtomicLock);
    value = *atomic;
    pthread_mutex_unlock(&virAtomicLock);

    return value;
}

static inline void
virAtomicIntSet(volatile int *atomic,
                int value)
{
    pthread_mutex_lock(&virAtomicLock);
    *atomic = value;
    pthread_mutex_unlock(&virAtomicLock);
}

static inline int
virAtomicIntInc(volatile int *atomic)
{
    int value;

    pthread_mutex_lock(&virAtomicLock);
    value = ++(*atomic);
    pthread_mutex_unlock(&virAtomicLock);

    return value;
}

static inline bool
virAtomicIntDecAndTest(volatile int *atomic)
{
    bool is_zero;

    pthread_mutex_lock(&virAtomicLock);
    is_zero = --(*atomic) == 0;
    pthread_mutex_unlock(&virAtomicLock);

    return is_zero;
}

static inline bool
virAtomicIntCompareExchange(volatile int *atomic,
                            int oldval,
                            int newval)
{
    bool success;

    pthread_mutex_lock(&virAtomicLock);

    if ((success = (*atomic == oldval)))
        *atomic = newval;

    pthread_mutex_unlock(&virAtomicLock);

    return success;
}

static inline int
virAtomicIntAdd(volatile int *atomic,
                int val)
{
    int oldval;

    pthread_mutex_lock(&virAtomicLock);
    oldval = *atomic;
    *atomic = oldval + val;
    pthread_mutex_unlock(&virAtomicLock);

    return oldval;
}

static inline unsigned int
virAtomicIntAnd(volatile unsigned int *atomic,
                unsigned int val)
{
    unsigned int oldval;

    pthread_mutex_lock(&virAtomicLock);
    oldval = *atomic;
    *atomic = oldval & val;
    pthread_mutex_unlock(&virAtomicLock);

    return oldval;
}

static inline unsigned int
virAtomicIntOr(volatile unsigned int *atomic,
               unsigned int val)
{
    unsigned int oldval;

    pthread_mutex_lock(&virAtomicLock);
    oldval = *atomic;
    *atomic = oldval | val;
    pthread_mutex_unlock(&virAtomicLock);

    return oldval;
}

static inline unsigned int
virAtomicIntXor(volatile unsigned int *atomic,
                unsigned int val)
{
    unsigned int oldval;

    pthread_mutex_lock(&virAtomicLock);
    oldval = *atomic;
    *atomic = oldval ^ val;
    pthread_mutex_unlock(&virAtomicLock);

    return oldval;
}


#   else
#    error "No atomic integer impl for this platform"
#   endif
#  endif

/* The int/unsigned int casts here ensure that you can
 * pass either an int or unsigned int to all atomic op
 * functions, in the same way that we can with GCC
 * atomic op helpers.
 */
#  define virAtomicIntGet(atomic)               \
    virAtomicIntGet((int *)atomic)
#  define virAtomicIntSet(atomic, val)          \
    virAtomicIntSet((int *)atomic, val)
#  define virAtomicIntInc(atomic)               \
    virAtomicIntInc((int *)atomic)
#  define virAtomicIntDecAndTest(atomic)        \
    virAtomicIntDecAndTest((int *)atomic)
#  define virAtomicIntCompareExchange(atomic, oldval, newval)   \
    virAtomicIntCompareExchange((int *)atomic, oldval, newval)
#  define virAtomicIntAdd(atomic, val)          \
    virAtomicIntAdd((int *)atomic, val)
#  define virAtomicIntAnd(atomic, val)          \
    virAtomicIntAnd((unsigned int *)atomic, val)
#  define virAtomicIntOr(atomic, val)           \
    virAtomicIntOr((unsigned int *)atomic, val)
#  define virAtomicIntXor(atomic, val)          \
    virAtomicIntXor((unsigned int *)atomic, val)

# endif

#endif /* __VIR_ATOMIC_H */
