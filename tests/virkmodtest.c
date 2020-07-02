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

# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"
# include "virkmod.h"
# include "virstring.h"

# define MODNAME "vfio-pci"

# define VIR_FROM_THIS VIR_FROM_NONE

static int
checkOutput(virBufferPtr buf, const char *exp_cmd)
{
    int ret = -1;
    char *actual_cmd = NULL;

    if (!(actual_cmd = virBufferContentAndReset(buf))) {
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
testKModLoad(const void *args G_GNUC_UNUSED)
{
    int ret = -1;
    char *errbuf = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCommandSetDryRun(&buf, NULL, NULL);

    errbuf = virKModLoad(MODNAME);
    if (errbuf) {
        fprintf(stderr, "Failed to load, error: %s\n", errbuf);
        goto cleanup;
    }

    if (checkOutput(&buf, MODPROBE " -b " MODNAME "\n") < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    VIR_FREE(errbuf);
    return ret;
}


static int
testKModUnload(const void *args G_GNUC_UNUSED)
{
    int ret = -1;
    char *errbuf = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virCommandSetDryRun(&buf, NULL, NULL);

    errbuf = virKModUnload(MODNAME);
    if (errbuf) {
        fprintf(stderr, "Failed to unload, error: %s\n", errbuf);
        goto cleanup;
    }

    if (checkOutput(&buf, RMMOD " " MODNAME "\n") < 0)
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

    if (virTestRun("load", testKModLoad, NULL) < 0)
        ret = -1;
    if (virTestRun("unload", testKModUnload, NULL) < 0)
        ret = -1;

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
