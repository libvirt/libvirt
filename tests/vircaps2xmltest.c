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
    bool resctrl; /* Whether both resctrl and system sysfs are used */
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

    /*
     * We want to keep our directory structure clean, so if there's both resctrl
     * and system used, we need to use slightly different path; a subdir.
     */
    if (virAsprintf(&dir, "%s/vircaps2xmldata/linux-%s%s",
                    abs_srcdir, data->filename,
                    data->resctrl ? "/system" : "") < 0)
        goto cleanup;

    virFileWrapperAddPrefix("/sys/devices/system", dir);
    caps = virCapabilitiesNew(data->arch, data->offlineMigrate, data->liveMigrate);

    if (!caps)
        goto cleanup;

    if (virCapabilitiesInitNUMA(caps) < 0 ||
        virCapabilitiesInitCaches(caps) < 0)
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

#define DO_TEST_FULL(filename, arch, offlineMigrate, liveMigrate, resctrl) \
    do {                                                                \
        struct virCapabilitiesData data = {filename, arch,              \
                                           offlineMigrate,              \
                                           liveMigrate, resctrl};       \
        if (virTestRun(filename, test_virCapabilities, &data) < 0)      \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(filename, arch) DO_TEST_FULL(filename, arch, true, true, false)

    DO_TEST_FULL("basic", VIR_ARCH_X86_64, false, false, false);
    DO_TEST_FULL("basic", VIR_ARCH_AARCH64, true, false, false);

    DO_TEST("caches", VIR_ARCH_X86_64);

    DO_TEST_FULL("resctrl", VIR_ARCH_X86_64, true, true, true);

    return ret;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnumamock.so")
