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

# define MODNAME "vfio-pci"

# define VIR_FROM_THIS VIR_FROM_NONE

static int
checkOutput(virBuffer *buf, const char *exp_cmd)
{
    g_autofree char *actual_cmd = NULL;

    if (!(actual_cmd = virBufferContentAndReset(buf))) {
        fprintf(stderr, "cannot compare buffer to exp: %s", exp_cmd);
        return -1;
    }

    if (virTestCompareToString(exp_cmd, actual_cmd) < 0) {
        return -1;
    }

    return 0;
}


static int
testKModLoad(const void *args G_GNUC_UNUSED)
{
    g_autofree char *errbuf = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, false, NULL, NULL);

    errbuf = virKModLoad(MODNAME);
    if (errbuf) {
        fprintf(stderr, "Failed to load, error: %s\n", errbuf);
        return -1;
    }

    if (checkOutput(&buf, MODPROBE " -b " MODNAME "\n") < 0)
        return -1;

    return 0;
}


static int
testKModUnload(const void *args G_GNUC_UNUSED)
{
    g_autofree char *errbuf = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, false, NULL, NULL);

    errbuf = virKModUnload(MODNAME);
    if (errbuf) {
        fprintf(stderr, "Failed to unload, error: %s\n", errbuf);
        return -1;
    }

    if (checkOutput(&buf, RMMOD " " MODNAME "\n") < 0)
        return -1;

    return 0;
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
