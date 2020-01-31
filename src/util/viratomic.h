/*
 * viratomic.h: atomic integer operations
 *
 * Copyright (C) 2012-2020 Red Hat, Inc.
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
 * APIs in this header should no longer be used. Direct
 * use of the g_atomic APIs is preferred & existing code
 * should be converted as needed.
 */

#pragma once

#include "internal.h"

/**
 * virAtomicIntDecAndTest:
 * Decrements the value of atomic by 1.
 *
 * Think of this operation as an atomic version of
 * { *atomic -= 1; return *atomic == 0; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
#define virAtomicIntDecAndTest(i) (!!g_atomic_int_dec_and_test(i))

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
#define virAtomicIntCompareExchange(i, oldi, newi) \
    (!!g_atomic_int_compare_and_exchange(i, oldi, newi))

/**
 * virAtomicIntAdd:
 * Atomically adds val to the value of atomic.
 *
 * Think of this operation as an atomic version of
 * { tmp = *atomic; *atomic += val; return tmp; }
 *
 * This call acts as a full compiler and hardware memory barrier.
 */
#define virAtomicIntAdd(i, v) g_atomic_int_add(i, v)

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
#define virAtomicIntAnd(i, v) g_atomic_int_and(i, v)

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
#define virAtomicIntOr(i, v) g_atomic_int_or(i, v)

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
#define virAtomicIntXor(i, v) g_atomic_int_xor(i, v)
