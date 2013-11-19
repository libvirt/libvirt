/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

#include <time.h>
#include <sched.h>

#include "testutils.h"

#include "viratomic.h"
#include "virrandom.h"
#include "virthread.h"

static int
testTypes(const void *data ATTRIBUTE_UNUSED)
{
    unsigned int u, u2;
    int s, s2;
    bool res;

#define virAssertCmpInt(a, op, b) \
    if (!(a op b)) \
        return -1;
    virAtomicIntSet(&u, 5);
    u2 = virAtomicIntGet(&u);
    virAssertCmpInt(u2, ==, 5);

    res = virAtomicIntCompareExchange(&u, 6, 7);
    if (res)
        return -1;
    virAssertCmpInt(u, ==, 5);

    virAssertCmpInt(virAtomicIntAdd(&u, 1), ==, 5);
    virAssertCmpInt(u, ==, 6);

    virAssertCmpInt(virAtomicIntInc(&u), ==, 7);
    virAssertCmpInt(u, ==, 7);

    res = virAtomicIntDecAndTest(&u);
    if (res)
        return -1;
    virAssertCmpInt(u, ==, 6);

    u2 = virAtomicIntAnd(&u, 5);
    virAssertCmpInt(u2, ==, 6);
    virAssertCmpInt(u, ==, 4);

    u2 = virAtomicIntOr(&u, 8);
    virAssertCmpInt(u2, ==, 4);
    virAssertCmpInt(u, ==, 12);

    u2 = virAtomicIntXor(&u, 4);
    virAssertCmpInt(u2, ==, 12);
    virAssertCmpInt(u, ==, 8);

    virAtomicIntSet(&s, 5);
    s2 = virAtomicIntGet(&s);
    virAssertCmpInt(s2, ==, 5);

    res = virAtomicIntCompareExchange(&s, 6, 7);
    if (res)
        return -1;
    virAssertCmpInt(s, ==, 5);

    virAtomicIntAdd(&s, 1);
    virAssertCmpInt(s, ==, 6);

    virAtomicIntInc(&s);
    virAssertCmpInt(s, ==, 7);

    res = virAtomicIntDecAndTest(&s);
    if (res)
        return -1;
    virAssertCmpInt(s, ==, 6);

    s2 = virAtomicIntAnd(&s, 5);
    virAssertCmpInt(s2, ==, 6);
    virAssertCmpInt(s, ==, 4);

    s2 = virAtomicIntOr(&s, 8);
    virAssertCmpInt(s2, ==, 4);
    virAssertCmpInt(s, ==, 12);

    s2 = virAtomicIntXor(&s, 4);
    virAssertCmpInt(s2, ==, 12);
    virAssertCmpInt(s, ==, 8);

    return 0;
}

#define THREADS 10
#define ROUNDS 10000

volatile int bucket[THREADS];
volatile int atomic;

static void
thread_func(void *data)
{
    int idx = (intptr_t)data;
    size_t i;
    int d;

    for (i = 0; i < ROUNDS; i++) {
        d = virRandomBits(7);
        bucket[idx] += d;
        virAtomicIntAdd(&atomic, d);
#ifdef WIN32
        SleepEx(0, 0);
#else
        sched_yield();
#endif
    }
}

static int
testThreads(const void *data ATTRIBUTE_UNUSED)
{
    int sum;
    size_t i;
    virThread threads[THREADS];

    atomic = 0;
    for (i = 0; i < THREADS; i++)
        bucket[i] = 0;

    for (i = 0; i < THREADS; i++) {
        if (virThreadCreate(&(threads[i]), true, thread_func, (void*)(intptr_t)i) < 0)
            return -1;
    }

    for (i = 0; i < THREADS; i++)
        virThreadJoin(&threads[i]);

    sum = 0;
    for (i = 0; i < THREADS; i++)
        sum += bucket[i];

    if (sum != atomic)
        return -1;

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if (virThreadInitialize() < 0)
        return -1;

    if (virtTestRun("types", testTypes, NULL) < 0)
        ret = -1;
    if (virtTestRun("threads", testThreads, NULL) < 0)
        ret = -1;

    return ret;
}

VIRT_TEST_MAIN(mymain)
