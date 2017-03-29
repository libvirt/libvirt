/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.domainconftest");

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

struct testGetFilesystemData {
    const char *filename;
    const char *path;
    bool expectEntry;
};

static int testGetFilesystem(const void *opaque)
{
    int ret = -1;
    virDomainDefPtr def = NULL;
    char *filename = NULL;
    const struct testGetFilesystemData *data = opaque;
    virDomainFSDefPtr fsdef;

    if (virAsprintf(&filename, "%s/domainconfdata/%s.xml",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    if (!(def = virDomainDefParseFile(filename, caps, xmlopt, NULL, 0)))
        goto cleanup;

    fsdef = virDomainGetFilesystemForTarget(def,
                                            data->path);
    if (!fsdef) {
        if (data->expectEntry) {
            fprintf(stderr, "Expected FS for path '%s' in '%s'\n",
                    data->path, filename);
            goto cleanup;
        }
    } else {
        if (!data->expectEntry) {
            fprintf(stderr, "Unexpected FS for path '%s' in '%s'\n",
                    data->path, filename);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virDomainDefFree(def);
    VIR_FREE(filename);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if ((caps = virTestGenericCapsInit()) == NULL)
        goto cleanup;

    if (!(xmlopt = virTestGenericDomainXMLConfInit()))
        goto cleanup;

#define DO_TEST_GET_FS(fspath, expect)                                  \
    do {                                                                \
        struct testGetFilesystemData data = {                           \
            .filename = "getfilesystem",                                \
            .path = fspath,                                             \
            .expectEntry = expect,                                      \
        };                                                              \
        if (virTestRun("Get FS " fspath, testGetFilesystem, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    DO_TEST_GET_FS("/", true);
    DO_TEST_GET_FS("/dev", true);
    DO_TEST_GET_FS("/dev/pts", false);
    DO_TEST_GET_FS("/doesnotexist", false);

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

 cleanup:
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
