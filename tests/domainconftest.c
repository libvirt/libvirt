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
 */

#include <config.h>

#include "testutils.h"
#include "virlog.h"

#include "domain_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.domainconftest");

static virCaps *caps;
static virDomainXMLOption *xmlopt;

struct testGetFilesystemData {
    const char *filename;
    const char *path;
    bool expectEntry;
};

static int testGetFilesystem(const void *opaque)
{
    g_autoptr(virDomainDef) def = NULL;
    g_autofree char *filename = NULL;
    const struct testGetFilesystemData *data = opaque;
    virDomainFSDef *fsdef;

    filename = g_strdup_printf("%s/domainconfdata/%s.xml", abs_srcdir,
                               data->filename);

    if (!(def = virDomainDefParseFile(filename, xmlopt, NULL, 0)))
        return -1;

    fsdef = virDomainGetFilesystemForTarget(def,
                                            data->path);
    if (!fsdef) {
        if (data->expectEntry) {
            fprintf(stderr, "Expected FS for path '%s' in '%s'\n",
                    data->path, filename);
            return -1;
        }
    } else {
        if (!data->expectEntry) {
            fprintf(stderr, "Unexpected FS for path '%s' in '%s'\n",
                    data->path, filename);
            return -1;
        }
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if ((caps = virTestGenericCapsInit()) == NULL)
        return EXIT_FAILURE;

    if (!(xmlopt = virTestGenericDomainXMLConfInit()))
        return EXIT_FAILURE;

#define DO_TEST_GET_FS(fspath, expect) \
    do { \
        struct testGetFilesystemData data = { \
            .filename = "getfilesystem", \
            .path = fspath, \
            .expectEntry = expect, \
        }; \
        if (virTestRun("Get FS " fspath, testGetFilesystem, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_GET_FS("/", true);
    DO_TEST_GET_FS("/dev", true);
    DO_TEST_GET_FS("/dev/pts", false);
    DO_TEST_GET_FS("/doesnotexist", false);

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
