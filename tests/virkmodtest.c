/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#ifdef __linux__

# include <stdlib.h>
# define __VIR_COMMAND_PRIV_H_ALLOW__
# include "vircommandpriv.h"
# include "virkmod.h"
# include "virstring.h"

struct testInfo {
    const char *module;
    const char *exp_cmd;
    bool useBlacklist;
};

# define VIR_FROM_THIS VIR_FROM_NONE

static int
testKModConfig(const void *args ATTRIBUTE_UNUSED)
{
    int ret = -1;
    char *outbuf = NULL;

    /* This will return the contents of a 'modprobe -c' which can differ
     * from machine to machine - be happy that we get something.
     */
    outbuf = virKModConfig();
    if (!outbuf) {
        fprintf(stderr, "Failed to get config\n");
        goto cleanup;
    }
    ret = 0;

 cleanup:
    VIR_FREE(outbuf);
    return ret;
}


static int
checkOutput(virBufferPtr buf, const char *exp_cmd)
{
    int ret = -1;
    char *actual_cmd = NULL;

    if (!(actual_cmd = virBufferContentAndReset(buf))) {
        int err = virBufferError(buf);
        if (err)
            fprintf(stderr, "buffer's in error state: %d", err);
        else
            fprintf(stderr, "cannot compare buffer to exp: %s", exp_cmd);
        goto cleanup;
    }

    if (STRNEQ(exp_cmd, actual_cmd)) {
        virTestDifference(stderr, exp_cmd, actual_cmd);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual_cmd);
    return ret;
}


static int
testKModLoad(const void *args)
{
    int ret = -1;
    char *errbuf = NULL;
    const struct testInfo *info = args;
    const char *module = info->module;
    bool useBlacklist = info->useBlacklist;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCommandSetDryRun(&buf, NULL, NULL);

    errbuf = virKModLoad(module, useBlacklist);
    if (errbuf) {
        fprintf(stderr, "Failed to load, error: %s\n", errbuf);
        goto cleanup;
    }

    if (checkOutput(&buf, info->exp_cmd) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    VIR_FREE(errbuf);
    return ret;
}


static int
testKModUnload(const void *args)
{
    int ret = -1;
    char *errbuf = NULL;
    const struct testInfo *info = args;
    const char *module = info->module;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCommandSetDryRun(&buf, NULL, NULL);

    errbuf = virKModUnload(module);
    if (errbuf) {
        fprintf(stderr, "Failed to unload, error: %s\n", errbuf);
        goto cleanup;
    }

    if (checkOutput(&buf, info->exp_cmd) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    VIR_FREE(errbuf);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("config", testKModConfig, NULL) < 0)
        ret = -1;

    /* Although we cannot run the command on the host, we can compare
     * the output of the created command against what we'd expect to be
     * created. So let's at least do that.
     */
# define DO_TEST(_name, _cb, _blkflag, _exp_cmd)              \
    do {                                                      \
        struct testInfo data = {.module = "vfio-pci",         \
                                .exp_cmd = _exp_cmd,          \
                                .useBlacklist = _blkflag};    \
        if (virTestRun(_name, _cb,  &data) < 0)               \
            ret = -1;                                         \
    } while (0)

    DO_TEST("load", testKModLoad, false, MODPROBE " vfio-pci\n");
    DO_TEST("unload", testKModUnload, false, RMMOD " vfio-pci\n");
    DO_TEST("blklist", testKModLoad, true, MODPROBE " -b vfio-pci\n");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

}

VIR_TEST_MAIN(mymain);
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
