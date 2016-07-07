/*
 * virconftest.c: Test the config file API
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "virconf.h"
#include "viralloc.h"
#include "testutils.h"


#define VIR_FROM_THIS VIR_FROM_NONE

static int testConfRoundTrip(const void *opaque)
{
    const char *name = opaque;
    int ret = -1;
    virConfPtr conf = NULL;
    int len = 10000;
    char *buffer = NULL;
    char *srcfile = NULL;
    char *dstfile = NULL;

    if (virAsprintf(&srcfile, "%s/virconfdata/%s.conf",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&dstfile, "%s/virconfdata/%s.out",
                    abs_srcdir, name) < 0)
        goto cleanup;

    if (VIR_ALLOC_N_QUIET(buffer, len) < 0) {
        fprintf(stderr, "out of memory\n");
        goto cleanup;
    }
    conf = virConfReadFile(srcfile, 0);
    if (conf == NULL) {
        fprintf(stderr, "Failed to process %s\n", srcfile);
        goto cleanup;
    }
    ret = virConfWriteMem(buffer, &len, conf);
    if (ret < 0) {
        fprintf(stderr, "Failed to serialize %s back\n", srcfile);
        goto cleanup;
    }

    if (virTestCompareToFile(buffer, dstfile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(srcfile);
    VIR_FREE(dstfile);
    VIR_FREE(buffer);
    virConfFree(conf);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("fc4", testConfRoundTrip, "fc4") < 0)
        ret = -1;

    if (virTestRun("libvirtd", testConfRoundTrip, "libvirtd") < 0)
        ret = -1;

    if (virTestRun("no-newline", testConfRoundTrip, "no-newline") < 0)
        ret = -1;

    return ret;
}


VIRT_TEST_MAIN(mymain)
