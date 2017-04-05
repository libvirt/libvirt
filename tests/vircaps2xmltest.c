/*
 * Copyright (C) Red Hat, Inc. 2014
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
 * Authors:
 *      Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>
#include <stdlib.h>

#include "testutils.h"
#include "capabilities.h"
#include "virbitmap.h"
#include "virfilewrapper.h"


#define VIR_FROM_THIS VIR_FROM_NONE

struct virCapabilitiesData {
    const char *filename;
    virArch arch;
    bool offlineMigrate;
    bool liveMigrate;
};

static int
test_virCapabilities(const void *opaque)
{
    struct virCapabilitiesData *data = (struct virCapabilitiesData *) opaque;
    const char *archStr = virArchToString(data->arch);
    virCapsPtr caps = NULL;
    char *capsXML = NULL;
    char *path = NULL;
    char *dir = NULL;
    int ret = -1;

    if (virAsprintf(&dir, "%s/vircaps2xmldata/linux-%s",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    virFileWrapperAddPrefix("/sys/devices/system", dir);
    caps = virCapabilitiesNew(data->arch, data->offlineMigrate, data->liveMigrate);

    if (!caps)
        goto cleanup;

    if (virCapabilitiesInitNUMA(caps) < 0)
        goto cleanup;

    virFileWrapperClearPrefixes();

    if (!(capsXML = virCapabilitiesFormatXML(caps)))
        goto cleanup;

    if (virAsprintf(&path, "%s/vircaps2xmldata/vircaps-%s-%s.xml",
                    abs_srcdir, archStr, data->filename) < 0)
        goto cleanup;

    if (virTestCompareToFile(capsXML, path) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(dir);
    VIR_FREE(path);
    VIR_FREE(capsXML);
    virObjectUnref(caps);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(filename, arch, offlineMigrate, liveMigrate)       \
    do {                                                                \
        struct virCapabilitiesData data = {filename, arch,              \
                                           offlineMigrate,              \
                                           liveMigrate};                \
        if (virTestRun(filename, test_virCapabilities, &data) < 0)      \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(filename, arch) DO_TEST_FULL(filename, arch, true, true)

    DO_TEST_FULL("basic", VIR_ARCH_X86_64, false, false);
    DO_TEST_FULL("basic", VIR_ARCH_AARCH64, true, false);

    DO_TEST("caches", VIR_ARCH_X86_64);

    return ret;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnumamock.so")
