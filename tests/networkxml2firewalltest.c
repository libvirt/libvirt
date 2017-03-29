/*
 * networkxml2firewalltest.c: Test iptables rule generation
 *
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
 *
 */

#include <config.h>

#include "testutils.h"

#if defined (__linux__)

# include "network/bridge_driver_platform.h"
# include "virbuffer.h"

# define __VIR_FIREWALL_PRIV_H_ALLOW__
# include "virfirewallpriv.h"

# define __VIR_COMMAND_PRIV_H_ALLOW__
# include "vircommandpriv.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static const char *abs_top_srcdir;

# ifdef __linux__
#  define RULESTYPE "linux"
# else
#  error "test case not ported to this platform"
# endif

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline)
{
    char *expectargv = NULL;
    char *actualargv = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNetworkDefPtr def = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (!(def = virNetworkDefParseFile(xml)))
        goto cleanup;

    if (networkAddFirewallRules(def) < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actualargv = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actualargv);
    virCommandSetDryRun(NULL, NULL, NULL);

    if (virTestCompareToFile(actualargv, cmdline) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&buf);
    VIR_FREE(expectargv);
    VIR_FREE(actualargv);
    virNetworkDefFree(def);
    return ret;
}

struct testInfo {
    const char *name;
};


static int
testCompareXMLToIPTablesHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/networkxml2firewalldata/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/networkxml2firewalldata/%s-%s.args",
                    abs_srcdir, info->name, RULESTYPE) < 0)
        goto cleanup;

    result = testCompareXMLToArgvFiles(xml, args);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}


static int
mymain(void)
{
    int ret = 0;

    abs_top_srcdir = getenv("abs_top_srcdir");
    if (!abs_top_srcdir)
        abs_top_srcdir = abs_srcdir "/..";

# define DO_TEST(name)                                                  \
    do {                                                                \
        static struct testInfo info = {                                 \
            name,                                                       \
        };                                                              \
        if (virTestRun("Network XML-2-iptables " name,                  \
                       testCompareXMLToIPTablesHelper, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

    virFirewallSetLockOverride(true);

    if (virFirewallSetBackend(VIR_FIREWALL_BACKEND_DIRECT) < 0) {
        ret = -1;
        goto cleanup;
    }

    DO_TEST("nat-default");
    DO_TEST("nat-tftp");
    DO_TEST("nat-many-ips");
    DO_TEST("nat-no-dhcp");
    DO_TEST("nat-ipv6");
    DO_TEST("route-default");
    DO_TEST("route-default");

 cleanup:
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined (__linux__) */
