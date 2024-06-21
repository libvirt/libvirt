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

# include <gio/gio.h>

# include "network/bridge_driver_platform.h"
# include "virbuffer.h"
# include "virmock.h"

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
    /* if arg[1] is -ae then this is an nft command,
     * and the caller requested to get the handle
     * of the newly added object in stdout
     */
    if (STREQ_NULLABLE(args[1], "-ae"))
        *output = g_strdup("# handle 5309");
    else
        *output = g_strdup("");
    *error = g_strdup("");
}

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     const char *baseargs,
                                     virFirewallBackend backend)
{
    g_autofree char *actualargv = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virNetworkDef) def = NULL;
    char *actual;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, true, true, testCommandDryRun, NULL);

    if (!(def = virNetworkDefParse(NULL, xml, NULL, false)))
        return -1;

    if (networkAddFirewallRules(def, backend, NULL) < 0)
        return -1;

    actual = actualargv = virBufferContentAndReset(&buf);

    /* The first network to be created populates the
     * libvirt global chains. We must skip args for
     * that if present
     */
    if (STRPREFIX(actual, baseargs))
        actual += strlen(baseargs);

    if (virTestCompareToFileFull(actual, cmdline, false) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *name;
    const char *baseargs;
    virFirewallBackend backend;
};


static int
testCompareXMLToIPTablesHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *args = NULL;

    xml = g_strdup_printf("%s/networkxml2firewalldata/%s.xml",
                          abs_srcdir, info->name);
    args = g_strdup_printf("%s/networkxml2firewalldata/%s-%s.%s",
                           abs_srcdir, info->name, RULESTYPE,
                           virFirewallBackendTypeToString(info->backend));

    result = testCompareXMLToArgvFiles(xml, args, info->baseargs, info->backend);

    return result;
}


static int
mymain(void)
{
    int ret = 0;
    g_autofree char *basefileIptables = NULL;
    g_autofree char *basefileNftables = NULL;
    g_autofree char *baseargsIptables = NULL;
    g_autofree char *baseargsNftables = NULL;
    const char *baseargs[VIR_FIREWALL_BACKEND_LAST];

# define DO_TEST_FOR_BACKEND(name, backend) \
    do { \
        struct testInfo info = { \
            name, baseargs[backend], backend \
        }; \
        g_autofree char *label = g_strdup_printf("Network XML-2-%s %s", \
                                                 virFirewallBackendTypeToString(backend), \
                                                 name); \
        if (virTestRun(label, testCompareXMLToIPTablesHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FOR_BACKEND(name, VIR_FIREWALL_BACKEND_IPTABLES); \
    DO_TEST_FOR_BACKEND(name, VIR_FIREWALL_BACKEND_NFTABLES);


    basefileIptables = g_strdup_printf("%s/networkxml2firewalldata/base.iptables", abs_srcdir);
    if (virFileReadAll(basefileIptables, INT_MAX, &baseargsIptables) < 0)
        return EXIT_FAILURE;

    baseargs[VIR_FIREWALL_BACKEND_IPTABLES] = baseargsIptables;

    basefileNftables = g_strdup_printf("%s/networkxml2firewalldata/base.nftables", abs_srcdir);
    if (virFileReadAll(basefileNftables, INT_MAX, &baseargsNftables) < 0)
        return EXIT_FAILURE;

    baseargs[VIR_FIREWALL_BACKEND_NFTABLES] = baseargsNftables;


    DO_TEST("nat-default");
    DO_TEST("nat-tftp");
    DO_TEST("nat-many-ips");
    DO_TEST("nat-no-dhcp");
    DO_TEST("nat-ipv6");
    DO_TEST("nat-ipv6-masquerade");
    DO_TEST("route-default");
    DO_TEST("forward-dev");
    DO_TEST("isolated");
    DO_TEST("forward-dev");
    DO_TEST("nat-port-range");
    DO_TEST("nat-port-range-ipv6");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* NB: virgdbus must be mocked because this test calls
 * networkAddFirewallRules(), which will always call
 * virFirewallDIsRegistered(), which calls
 * virGDBusIsServiceRegistered().
 */

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virgdbus"),
                      VIR_TEST_MOCK("virfirewall"))

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined (__linux__) */
