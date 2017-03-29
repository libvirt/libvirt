/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include <stdlib.h>
#include "virfile.h"
#include "testutils.h"

#if HAVE_DLFCN_H
# include <dlfcn.h>
#endif

#if defined(__linux__) && defined(RTLD_NEXT)

# include "virutil.h"
# include "virerror.h"
# include "viralloc.h"
# include "virlog.h"
# include "virportallocator.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.portallocatortest");

static int testAllocAll(const void *args ATTRIBUTE_UNUSED)
{
    virPortAllocatorPtr alloc = virPortAllocatorNew("test", 5900, 5909, 0);
    int ret = -1;
    unsigned short p1, p2, p3, p4, p5, p6, p7;

    if (!alloc)
        return -1;

    if (virPortAllocatorAcquire(alloc, &p1) < 0)
        goto cleanup;
    if (p1 != 5901) {
        VIR_TEST_DEBUG("Expected 5901, got %d", p1);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p2) < 0)
        goto cleanup;
    if (p2 != 5902) {
        VIR_TEST_DEBUG("Expected 5902, got %d", p2);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p3) < 0)
        goto cleanup;
    if (p3 != 5903) {
        VIR_TEST_DEBUG("Expected 5903, got %d", p3);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p4) < 0)
        goto cleanup;
    if (p4 != 5907) {
        VIR_TEST_DEBUG("Expected 5907, got %d", p4);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p5) < 0)
        goto cleanup;
    if (p5 != 5908) {
        VIR_TEST_DEBUG("Expected 5908, got %d", p5);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p6) < 0)
        goto cleanup;
    if (p6 != 5909) {
        VIR_TEST_DEBUG("Expected 5909, got %d", p6);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p7) == 0) {
        VIR_TEST_DEBUG("Expected error, got %d", p7);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(alloc);
    return ret;
}



static int testAllocReuse(const void *args ATTRIBUTE_UNUSED)
{
    virPortAllocatorPtr alloc = virPortAllocatorNew("test", 5900, 5910, 0);
    int ret = -1;
    unsigned short p1, p2, p3, p4;

    if (!alloc)
        return -1;

    if (virPortAllocatorAcquire(alloc, &p1) < 0)
        goto cleanup;
    if (p1 != 5901) {
        VIR_TEST_DEBUG("Expected 5901, got %d", p1);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p2) < 0)
        goto cleanup;
    if (p2 != 5902) {
        VIR_TEST_DEBUG("Expected 5902, got %d", p2);
        goto cleanup;
    }

    if (virPortAllocatorAcquire(alloc, &p3) < 0)
        goto cleanup;
    if (p3 != 5903) {
        VIR_TEST_DEBUG("Expected 5903, got %d", p3);
        goto cleanup;
    }


    if (virPortAllocatorRelease(alloc, p2) < 0)
        goto cleanup;

    if (virPortAllocatorAcquire(alloc, &p4) < 0)
        goto cleanup;
    if (p4 != 5902) {
        VIR_TEST_DEBUG("Expected 5902, got %d", p4);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(alloc);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("Test alloc all", testAllocAll, NULL) < 0)
        ret = -1;

    if (virTestRun("Test alloc reuse", testAllocReuse, NULL) < 0)
        ret = -1;

    setenv("LIBVIRT_TEST_IPV4ONLY", "really", 1);

    if (virTestRun("Test IPv4-only alloc all", testAllocAll, NULL) < 0)
        ret = -1;

    if (virTestRun("Test IPv4-only alloc reuse", testAllocReuse, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virportallocatormock.so")
#else /* defined(__linux__) && defined(RTLD_NEXT) */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
