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
 */

#include <config.h>

#include "testutils.h"
#include "capabilities.h"
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
    g_autoptr(virCaps) caps = NULL;
    g_autofree char *capsXML = NULL;
    g_autofree char *path = NULL;
    g_autofree char *system = NULL;
    g_autofree char *resctrl = NULL;

    system = g_strdup_printf("%s/vircaps2xmldata/linux-%s/system", abs_srcdir,
                             data->filename);

    resctrl = g_strdup_printf("%s/vircaps2xmldata/linux-%s/resctrl", abs_srcdir,
                              data->filename);

    virFileWrapperAddPrefix("/sys/devices/system", system);
    virFileWrapperAddPrefix("/sys/fs/resctrl", resctrl);
    caps = virCapabilitiesNew(data->arch, data->offlineMigrate, data->liveMigrate);

    if (!caps)
        return -1;

    if (!(caps->host.numa = virCapabilitiesHostNUMANewHost()))
        return -1;

    if (virCapabilitiesInitCaches(caps) < 0)
        return -1;

    virFileWrapperClearPrefixes();

    if (!(capsXML = virCapabilitiesFormatXML(caps)))
        return -1;

    path = g_strdup_printf("%s/vircaps2xmldata/vircaps-%s-%s.xml", abs_srcdir,
                           archStr, data->filename);

    if (virTestCompareToFile(capsXML, path) < 0)
        return -1;

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(filename, arch, offlineMigrate, liveMigrate) \
    do { \
        struct virCapabilitiesData data = {filename, arch, \
                                           offlineMigrate, \
                                           liveMigrate}; \
        if (virTestRun(filename, test_virCapabilities, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_FULL("basic", VIR_ARCH_X86_64, false, false);
    DO_TEST_FULL("basic", VIR_ARCH_AARCH64, true, false);
    DO_TEST_FULL("basic-dies", VIR_ARCH_X86_64, false, false);

    DO_TEST_FULL("caches", VIR_ARCH_X86_64, true, true);

    DO_TEST_FULL("hmat", VIR_ARCH_X86_64, true, true);

    DO_TEST_FULL("resctrl", VIR_ARCH_X86_64, true, true);
    DO_TEST_FULL("resctrl-cmt", VIR_ARCH_X86_64, true, true);
    DO_TEST_FULL("resctrl-cdp", VIR_ARCH_X86_64, true, true);
    DO_TEST_FULL("resctrl-skx", VIR_ARCH_X86_64, true, true);
    DO_TEST_FULL("resctrl-skx-twocaches", VIR_ARCH_X86_64, true, true);
    DO_TEST_FULL("resctrl-fake-feature", VIR_ARCH_X86_64, true, true);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virnuma"))
