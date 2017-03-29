/*
 * Copyright (c) 2013. Doug Goldstein <cardoe@cardoe.com>
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

#ifdef WITH_VMWARE

# include <stdio.h>
# include <stdlib.h>

# include "vmware/vmware_conf.h"

//# define VIR_FROM_THIS VIR_FROM_NONE

struct testInfo {
    const char *vmware_type;
    const char *name;
    unsigned long version;
};

static int
testVerStrParse(const void *data)
{
    const struct testInfo *info = data;
    int ret = -1;
    char *path = NULL;
    char *databuf = NULL;
    unsigned long version;
    int vmware_type;

    if (virAsprintf(&path, "%s/vmwareverdata/%s.txt", abs_srcdir,
                    info->name) < 0)
        return -1;

    if (virTestLoadFile(path, &databuf) < 0)
        goto cleanup;

    if ((vmware_type = vmwareDriverTypeFromString(info->vmware_type)) < 0)
        goto cleanup;

    if (vmwareParseVersionStr(vmware_type, databuf, &version) < 0)
        goto cleanup;

    if (version != info->version) {
        fprintf(stderr, "%s: parsed versions do not match: got %lu, "
                "expected %lu\n", info->name, version, info->version);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(databuf);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST(vmware_type, name, version)                            \
    do {                                                                \
        struct testInfo info = {                                        \
            vmware_type, name, version                                  \
        };                                                              \
        if (virTestRun("VMware Version String Parsing " name,           \
                       testVerStrParse, &info) < 0)                     \
            ret = -1;                                                   \
    } while (0)

    DO_TEST("ws", "workstation-7.0.0", 7000000);
    DO_TEST("ws", "workstation-7.0.0-with-garbage", 7000000);
    DO_TEST("fusion", "fusion-5.0.3", 5000003);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_VMWARE */
