/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: John Ferlan <jferlan@redhat.com>
 */

#include <config.h>

#include "internal.h"
#include "viralloc.h"
#include "virrandom.h"
#include "testutils.h"

#ifndef WIN32

# define VIR_FROM_THIS VIR_FROM_NONE

static int
testRandomBytes(const void *unused ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    uint8_t *data;
    size_t datalen = 32;

    if (VIR_ALLOC_N(data, datalen) < 0)
        return -1;

    if (virRandomBytes(data, datalen) < 0) {
        fprintf(stderr, "Failed to generate random bytes");
        goto cleanup;
    }

    for (i = 0; i < datalen; i++) {
        if (data[i] != i) {
            fprintf(stderr,
                    "virRandomBytes data[%zu]='%x' not in sequence\n",
                    i, data[i]);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(data);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virtTestRun("RandomBytes", testRandomBytes, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virrandommock.so")

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
