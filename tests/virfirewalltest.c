/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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

#if defined(__linux__)

# include <gio/gio.h>

# include "virbuffer.h"
# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"
# define LIBVIRT_VIRFIREWALLPRIV_H_ALLOW
# include "virfirewallpriv.h"
# define LIBVIRT_VIRFIREWALLDPRIV_H_ALLOW
# include "virfirewalldpriv.h"
# include "virmock.h"

# define VIR_FROM_THIS VIR_FROM_FIREWALL

static bool fwDisabled = true;
static virBuffer *fwBuf;
static bool fwError;

# define TEST_FILTER_TABLE_LIST \
    "Chain INPUT (policy ACCEPT)\n" \
    "target     prot opt source               destination\n" \
    "\n" \
    "Chain FORWARD (policy ACCEPT)\n" \
    "target     prot opt source               destination\n" \
    "\n" \
    "Chain OUTPUT (policy ACCEPT)\n" \
    "target     prot opt source               destination\n"

# define TEST_NAT_TABLE_LIST \
    "Chain PREROUTING (policy ACCEPT)\n" \
    "target     prot opt source               destination\n" \
    "\n" \
    "Chain INPUT (policy ACCEPT)\n" \
    "target     prot opt source               destination\n" \
    "\n" \
    "Chain OUTPUT (policy ACCEPT)\n" \
    "target     prot opt source               destination\n" \
    "\n" \
    "Chain POSTROUTING (policy ACCEPT)\n" \
    "target     prot opt source               destination\n"

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
    GVariant *reply = NULL;
    g_autoptr(GVariant) params = parameters;

    if (params)
        g_variant_ref_sink(params);

    VIR_MOCK_REAL_INIT(g_dbus_connection_call_sync);

    if (STREQ(bus_name, "org.freedesktop.DBus") &&
        STREQ(method_name, "ListNames")) {
        GVariantBuilder builder;

        g_variant_builder_init(&builder, G_VARIANT_TYPE("(as)"));
        g_variant_builder_open(&builder, G_VARIANT_TYPE("as"));

        g_variant_builder_add(&builder, "s", "org.foo.bar.wizz");

        if (!fwDisabled)
            g_variant_builder_add(&builder, "s", VIR_FIREWALL_FIREWALLD_SERVICE);

        g_variant_builder_close(&builder);

        reply = g_variant_builder_end(&builder);
    } else if (STREQ(bus_name, VIR_FIREWALL_FIREWALLD_SERVICE) &&
               STREQ(method_name, "passthrough")) {
        g_autoptr(GVariantIter) iter = NULL;
        static const size_t maxargs = 5;
        g_auto(GStrv) args = NULL;
        size_t nargs = 0;
        char *type = NULL;
        char *item = NULL;
        bool isAdd = false;
        bool doError = false;

        g_variant_get(params, "(&sas)", &type, &iter);

        args = g_new0(char *, maxargs);

        if (fwBuf) {
            if (STREQ(type, "ipv4"))
                virBufferAddLit(fwBuf, IPTABLES_PATH);
            else if (STREQ(type, "ipv6"))
                virBufferAddLit(fwBuf, IP6TABLES_PATH);
            else
                virBufferAddLit(fwBuf, EBTABLES_PATH);
        }

        while (g_variant_iter_loop(iter, "s", &item)) {
            /* Fake failure on the command with this IP addr */
            if (STREQ(item, "-A")) {
                isAdd = true;
            } else if (isAdd && STREQ(item, "192.168.122.255")) {
                doError = true;
            }

            if (nargs < maxargs)
                args[nargs] = g_strdup(item);
            nargs++;

            if (fwBuf) {
                virBufferAddLit(fwBuf, " ");
                virBufferEscapeShell(fwBuf, item);
            }
        }

        if (fwBuf)
            virBufferAddLit(fwBuf, "\n");

        if (doError) {
            if (error)
                *error = g_dbus_error_new_for_dbus_error("org.firewalld.error",
                                                         "something bad happened");
        } else {
            if (nargs == 2 &&
                STREQ(type, "ipv4") &&
                STREQ(args[0], "-w") &&
                STREQ(args[1], "-L")) {
                reply = g_variant_new("(s)", TEST_FILTER_TABLE_LIST);
            } else if (nargs == 4 &&
                       STREQ(type, "ipv4") &&
                       STREQ(args[0], "-w") &&
                       STREQ(args[1], "-t") &&
                       STREQ(args[2], "nat") &&
                       STREQ(args[3], "-L")) {
                reply = g_variant_new("(s)", TEST_NAT_TABLE_LIST);
            } else {
                reply = g_variant_new("(s)", "success");
            }
        }
    } else {
        reply = g_variant_new("()");
    }

    return reply;
}

struct testFirewallData {
    virFirewallBackend tryBackend;
    virFirewallBackend expectBackend;
    bool fwDisabled;
};

static int
testFirewallSingleGroup(const void *opaque)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD)
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static int
testFirewallRemoveRule(const void *opaque)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    virFirewallRule *fwrule;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD)
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                                "-A", "INPUT", NULL);
    virFirewallRuleAddArg(fw, fwrule, "--source");
    virFirewallRemoveRule(fw, fwrule);

    fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                                "-A", "INPUT", NULL);
    virFirewallRuleAddArg(fw, fwrule, "--source");
    virFirewallRuleAddArgFormat(fw, fwrule, "%s", "!192.168.122.1");
    virFirewallRuleAddArgList(fw, fwrule, "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static int
testFirewallManyGroups(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD)
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}

static void
testFirewallRollbackHook(const char *const*args,
                         const char *const*env G_GNUC_UNUSED,
                         const char *input G_GNUC_UNUSED,
                         char **output G_GNUC_UNUSED,
                         char **error G_GNUC_UNUSED,
                         int *status,
                         void *opaque G_GNUC_UNUSED)
{
    bool isAdd = false;
    while (*args) {
        /* Fake failure on the command with this IP addr */
        if (STREQ(*args, "-A")) {
            isAdd = true;
        } else if (isAdd && STREQ(*args, "192.168.122.255")) {
            *status = 127;
            break;
        }
        args++;
    }
}

static int
testFirewallIgnoreFailGroup(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static int
testFirewallIgnoreFailRule(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_IPV4,
                           true, NULL, NULL,
                           "-A", "INPUT",
                           "--source", "192.168.122.255",
                           "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static int
testFirewallNoRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}

static int
testFirewallSingleRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwError = true;
        fwBuf = &cmdbuf;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}

static int
testFirewallManyRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}

static int
testFirewallChainedRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.127",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.127",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, VIR_FIREWALL_ROLLBACK_INHERIT_PREVIOUS);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static const char *expectedLines[] = {
    "Chain INPUT (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain FORWARD (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain OUTPUT (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain PREROUTING (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain INPUT (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain OUTPUT (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
    "Chain POSTROUTING (policy ACCEPT)",
    "target     prot opt source               destination",
    "",
};
static size_t expectedLineNum;
static bool expectedLineError;

static void
testFirewallQueryHook(const char *const*args,
                      const char *const*env G_GNUC_UNUSED,
                      const char *input G_GNUC_UNUSED,
                      char **output,
                      char **error G_GNUC_UNUSED,
                      int *status G_GNUC_UNUSED,
                      void *opaque G_GNUC_UNUSED)
{
    if (STREQ(args[0], IPTABLES_PATH) &&
        STREQ(args[1], "-w") &&
        STREQ(args[2], "-L")) {
        *output = g_strdup(TEST_FILTER_TABLE_LIST);
    } else if (STREQ(args[0], IPTABLES_PATH) &&
               STREQ(args[1], "-w") &&
               STREQ(args[2], "-t") &&
               STREQ(args[3], "nat") &&
               STREQ(args[4], "-L")) {
        *output = g_strdup(TEST_NAT_TABLE_LIST);
    }
}


static int
testFirewallQueryCallback(virFirewall *fw,
                          virFirewallLayer layer,
                          const char *const *lines,
                          void *opaque G_GNUC_UNUSED)
{
    size_t i;
    virFirewallAddRule(fw, layer,
                       "-A", "INPUT",
                       "--source", "!192.168.122.129",
                       "--jump", "REJECT", NULL);

    for (i = 0; lines[i] != NULL; i++) {
        if (expectedLineNum >= G_N_ELEMENTS(expectedLines)) {
            expectedLineError = true;
            break;
        }
        if (STRNEQ(expectedLines[expectedLineNum], lines[i])) {
            fprintf(stderr, "Mismatch '%s' vs '%s' at %zu, %zu\n",
                    expectedLines[expectedLineNum], lines[i],
                    expectedLineNum, i);
            expectedLineError = true;
            break;
        }
        expectedLineNum++;
    }
    return 0;
}

static int
testFirewallQuery(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -w -L\n"
        IPTABLES_PATH " -w -t nat -L\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.130 --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.129' --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.129' --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source 192.168.122.128 --jump REJECT\n"
        IPTABLES_PATH " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    expectedLineNum = 0;
    expectedLineError = false;
    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT ||
        data->expectBackend == VIR_FIREWALL_BACKEND_FIREWALLD) {
        virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallQueryHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.127",
                       "--jump", "REJECT", NULL);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_IPV4,
                           false,
                           testFirewallQueryCallback,
                           NULL,
                           "-L", NULL);
    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_IPV4,
                           false,
                           testFirewallQueryCallback,
                           NULL,
                           "-t", "nat", "-L", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.130",
                       "--jump", "REJECT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "192.168.122.128",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (expectedLineError) {
        fprintf(stderr, "Got some unexpected query data\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexpected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    fwBuf = NULL;
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

# define RUN_TEST_DIRECT(name, method) \
    do { \
        struct testFirewallData data; \
        data.tryBackend = VIR_FIREWALL_BACKEND_AUTOMATIC; \
        data.expectBackend = VIR_FIREWALL_BACKEND_DIRECT; \
        data.fwDisabled = true; \
        if (virTestRun(name " auto direct", method, &data) < 0) \
            ret = -1; \
        data.tryBackend = VIR_FIREWALL_BACKEND_DIRECT; \
        data.expectBackend = VIR_FIREWALL_BACKEND_DIRECT; \
        data.fwDisabled = true; \
        if (virTestRun(name " manual direct", method, &data) < 0) \
            ret = -1; \
    } while (0)

# define RUN_TEST_FIREWALLD(name, method) \
    do { \
        struct testFirewallData data; \
        data.tryBackend = VIR_FIREWALL_BACKEND_AUTOMATIC; \
        data.expectBackend = VIR_FIREWALL_BACKEND_FIREWALLD; \
        data.fwDisabled = false; \
        if (virTestRun(name " auto firewalld", method, &data) < 0) \
            ret = -1; \
        data.tryBackend = VIR_FIREWALL_BACKEND_FIREWALLD; \
        data.expectBackend = VIR_FIREWALL_BACKEND_FIREWALLD; \
        data.fwDisabled = false; \
        if (virTestRun(name " manual firewalld", method, &data) < 0) \
            ret = -1; \
    } while (0)

# define RUN_TEST(name, method) \
    RUN_TEST_DIRECT(name, method); \
    RUN_TEST_FIREWALLD(name, method)

    RUN_TEST("single group", testFirewallSingleGroup);
    RUN_TEST("remove rule", testFirewallRemoveRule);
    RUN_TEST("many groups", testFirewallManyGroups);
    RUN_TEST("ignore fail group", testFirewallIgnoreFailGroup);
    RUN_TEST("ignore fail rule", testFirewallIgnoreFailRule);
    RUN_TEST("no rollback", testFirewallNoRollback);
    RUN_TEST("single rollback", testFirewallSingleRollback);
    RUN_TEST("many rollback", testFirewallManyRollback);
    RUN_TEST("chained rollback", testFirewallChainedRollback);
    RUN_TEST("query transaction", testFirewallQuery);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virgdbus"),
                      VIR_TEST_MOCK("virfirewall"))

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined(__linux__) */
