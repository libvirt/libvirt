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
#include "viralloc.h"

#if defined (__linux__)

# include <gio/gio.h>

# include "network/bridge_driver_platform.h"
# include "virbuffer.h"
# include "virmock.h"

# define LIBVIRT_VIRFIREWALLPRIV_H_ALLOW
# include "virfirewallpriv.h"

# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"

# define VIR_FROM_THIS VIR_FROM_NONE

# ifdef __linux__
#  define RULESTYPE "linux"
# else
#  error "test case not ported to this platform"
# endif

VIR_MOCK_WRAP_RET_ARGS(g_dbus_connection_call_sync,
                       GVariant *,
                       GDBusConnection *, connection,
                       const gchar *, bus_name,
                       const gchar *, object_path,
                       const gchar *, interface_name,
                       const gchar *, method_name,
                       GVariant *, parameters,
                       const GVariantType *, reply_type,
                       GDBusCallFlags, flags,
                       gint, timeout_msec,
                       GCancellable *, cancellable,
                       GError **, error)
{
    if (parameters) {
        g_variant_ref_sink(parameters);
        g_variant_unref(parameters);
    }

    VIR_MOCK_REAL_INIT(g_dbus_connection_call_sync);

    *error = g_dbus_error_new_for_dbus_error("org.freedesktop.error",
                                             "dbus is disabled");

    return NULL;
}

static void
testCommandDryRun(const char *const*args G_GNUC_UNUSED,
                  const char *const*env G_GNUC_UNUSED,
                  const char *input G_GNUC_UNUSED,
                  char **output,
                  char **error,
                  int *status,
                  void *opaque G_GNUC_UNUSED)
{
    *status = 0;
    *output = g_strdup("");
    *error = g_strdup("");
}

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     const char *baseargs)
{
    char *actualargv = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virNetworkDefPtr def = NULL;
    int ret = -1;
    char *actual;

    virCommandSetDryRun(&buf, testCommandDryRun, NULL);

    if (!(def = virNetworkDefParseFile(xml, NULL)))
        goto cleanup;

    if (networkAddFirewallRules(def) < 0)
        goto cleanup;

    actual = actualargv = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actualargv);
    virCommandSetDryRun(NULL, NULL, NULL);

    /* The first network to be created populates the
     * libvirt global chains. We must skip args for
     * that if present
     */
    if (STRPREFIX(actual, baseargs))
        actual += strlen(baseargs);

    if (virTestCompareToFile(actual, cmdline) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(actualargv);
    virNetworkDefFree(def);
    return ret;
}

struct testInfo {
    const char *name;
    const char *baseargs;
};


static int
testCompareXMLToIPTablesHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL;

    xml = g_strdup_printf("%s/networkxml2firewalldata/%s.xml",
                          abs_srcdir, info->name);
    args = g_strdup_printf("%s/networkxml2firewalldata/%s-%s.args",
                           abs_srcdir, info->name, RULESTYPE);

    result = testCompareXMLToArgvFiles(xml, args, info->baseargs);

    VIR_FREE(xml);
    VIR_FREE(args);
    return result;
}

static bool
hasNetfilterTools(void)
{
    return virFileIsExecutable(IPTABLES_PATH) &&
        virFileIsExecutable(IP6TABLES_PATH) &&
        virFileIsExecutable(EBTABLES_PATH);
}


static int
mymain(void)
{
    int ret = 0;
    g_autofree char *basefile = NULL;
    g_autofree char *baseargs = NULL;

# define DO_TEST(name) \
    do { \
        struct testInfo info = { \
            name, baseargs, \
        }; \
        if (virTestRun("Network XML-2-iptables " name, \
                       testCompareXMLToIPTablesHelper, &info) < 0) \
            ret = -1; \
    } while (0)

    if (virFirewallSetBackend(VIR_FIREWALL_BACKEND_DIRECT) < 0) {
        if (!hasNetfilterTools()) {
            fprintf(stderr, "iptables/ip6tables/ebtables tools not present");
            return EXIT_AM_SKIP;
        }

        return EXIT_FAILURE;
    }

    basefile = g_strdup_printf("%s/networkxml2firewalldata/base.args", abs_srcdir);

    if (virTestLoadFile(basefile, &baseargs) < 0)
        return EXIT_FAILURE;

    DO_TEST("nat-default");
    DO_TEST("nat-tftp");
    DO_TEST("nat-many-ips");
    DO_TEST("nat-no-dhcp");
    DO_TEST("nat-ipv6");
    DO_TEST("nat-ipv6-masquerade");
    DO_TEST("route-default");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virgdbus"))

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined (__linux__) */
