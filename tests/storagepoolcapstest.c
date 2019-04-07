/*
 * Copyright (C) Red Hat, Inc. 2019
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
#include "storage_conf.h"
#include "storage_capabilities.h"


#define VIR_FROM_THIS VIR_FROM_NONE


struct test_virStoragePoolCapsFormatData {
    const char *filename;
    virCapsPtr driverCaps;
};

static void
test_virCapabilitiesAddFullStoragePool(virCapsPtr caps)
{
    size_t i;

    for (i = 0; i < VIR_STORAGE_POOL_LAST; i++)
        virCapabilitiesAddStoragePool(caps, i);
}


static void
test_virCapabilitiesAddFSStoragePool(virCapsPtr caps)
{
    virCapabilitiesAddStoragePool(caps, VIR_STORAGE_POOL_FS);
}


static int
test_virStoragePoolCapsFormat(const void *opaque)
{
    struct test_virStoragePoolCapsFormatData *data =
        (struct test_virStoragePoolCapsFormatData *) opaque;
    virCapsPtr driverCaps = data->driverCaps;
    VIR_AUTOUNREF(virStoragePoolCapsPtr) poolCaps = NULL;
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) poolCapsXML = NULL;


    if (!(poolCaps = virStoragePoolCapsNew(driverCaps)))
        return -1;

    if (virAsprintf(&path, "%s/storagepoolcapsschemadata/poolcaps-%s.xml",
                    abs_srcdir, data->filename) < 0) {
        return -1;
    }

    if (!(poolCapsXML = virStoragePoolCapsFormat(poolCaps)))
        return -1;

    if (virTestCompareToFile(poolCapsXML, path) < 0)
        return -1;

    return 0;
}


static int
mymain(void)
{
    int ret = 0;
    VIR_AUTOUNREF(virCapsPtr) fullCaps = NULL;
    VIR_AUTOUNREF(virCapsPtr) fsCaps = NULL;

#define DO_TEST(Filename, DriverCaps) \
    do { \
        struct test_virStoragePoolCapsFormatData data = \
            {.filename = Filename, .driverCaps = DriverCaps }; \
        if (virTestRun(Filename, test_virStoragePoolCapsFormat, &data) < 0) \
            ret = -1; \
    } while (0)

    if (!(fullCaps = virCapabilitiesNew(VIR_ARCH_NONE, false, false)) ||
        !(fsCaps = virCapabilitiesNew(VIR_ARCH_NONE, false, false))) {
        return -1;
    }

    test_virCapabilitiesAddFullStoragePool(fullCaps);
    test_virCapabilitiesAddFSStoragePool(fsCaps);

    DO_TEST("full", fullCaps);
    DO_TEST("fs", fsCaps);

    return ret;
}

VIR_TEST_MAIN(mymain)
