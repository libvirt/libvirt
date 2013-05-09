/*
 * Copyright (C) 2011, 2013 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>

#include "testutils.h"
#include "virutil.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"

#include "virlockspace.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#define LOCKSPACE_DIR abs_builddir "/virlockspacedata"

static int testLockSpaceCreate(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLifecycle(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, "foo") < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLockExcl(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(), 0) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(), 0) == 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") == 0)
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLockExclAuto(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLockShr(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_SHARED) < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(), 0) == 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_SHARED) < 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") == 0)
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") == 0)
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLockShrAuto(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(LOCKSPACE_DIR);

    if (!virFileIsDir(LOCKSPACE_DIR))
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, "foo") < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_SHARED |
                                    VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) == 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, "foo", geteuid(),
                                    VIR_LOCK_SPACE_ACQUIRE_SHARED |
                                    VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, "foo", geteuid()) < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}


static int testLockSpaceResourceLockPath(const void *args ATTRIBUTE_UNUSED)
{
    virLockSpacePtr lockspace;
    int ret = -1;

    rmdir(LOCKSPACE_DIR);

    lockspace = virLockSpaceNew(NULL);

    if (mkdir(LOCKSPACE_DIR, 0700) < 0)
        goto cleanup;

    if (virLockSpaceCreateResource(lockspace, LOCKSPACE_DIR "/foo") < 0)
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, LOCKSPACE_DIR "/foo", geteuid(), 0) < 0)
        goto cleanup;

    if (!virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    if (virLockSpaceAcquireResource(lockspace, LOCKSPACE_DIR "/foo", geteuid(), 0) == 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, LOCKSPACE_DIR "/foo") == 0)
        goto cleanup;

    if (virLockSpaceReleaseResource(lockspace, LOCKSPACE_DIR "/foo", geteuid()) < 0)
        goto cleanup;

    if (virLockSpaceDeleteResource(lockspace, LOCKSPACE_DIR "/foo") < 0)
        goto cleanup;

    if (virFileExists(LOCKSPACE_DIR "/foo"))
        goto cleanup;

    ret = 0;

cleanup:
    virLockSpaceFree(lockspace);
    rmdir(LOCKSPACE_DIR);
    return ret;
}



static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

    if (virtTestRun("Lockspace creation", 1, testLockSpaceCreate, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res lifecycle", 1, testLockSpaceResourceLifecycle, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res lock excl", 1, testLockSpaceResourceLockExcl, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res lock shr", 1, testLockSpaceResourceLockShr, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res lock excl auto", 1, testLockSpaceResourceLockExclAuto, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res lock shr auto", 1, testLockSpaceResourceLockShrAuto, NULL) < 0)
        ret = -1;

    if (virtTestRun("Lockspace res full path", 1, testLockSpaceResourceLockPath, NULL) < 0)
        ret = -1;

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
