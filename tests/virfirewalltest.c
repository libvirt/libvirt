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
# include "virfirewall.h"

# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"
# define LIBVIRT_VIRFIREWALLDPRIV_H_ALLOW
# include "virfirewalldpriv.h"

# define VIR_FROM_THIS VIR_FROM_FIREWALL

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


static int
testFirewallSingleGroup(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";

    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}


static int
testFirewallRemoveRule(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";
    virFirewallRule *fwrule;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}


static int
testFirewallManyGroups(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A OUTPUT --jump DROP\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, NULL, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
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
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A OUTPUT --jump DROP\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}


static int
testFirewallIgnoreFailRule(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -A OUTPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A OUTPUT --jump DROP\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}


static int
testFirewallNoRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}

static int
testFirewallSingleRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}

static int
testFirewallManyRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}

static int
testFirewallChainedRollback(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;
    g_autoptr(virFirewall) fw = virFirewallNew();
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n"
        IPTABLES " -w -D INPUT --source 192.168.122.255 --jump REJECT\n"
        IPTABLES " -w -D INPUT --source '!192.168.122.1' --jump REJECT\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallRollbackHook, NULL);

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
        return -1;
    }

    actual = virBufferCurrentContent(&cmdbuf);

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
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
    if (STREQ(args[0], IPTABLES) &&
        STREQ(args[1], "-w") &&
        STREQ(args[2], "-L")) {
        *output = g_strdup(TEST_FILTER_TABLE_LIST);
    } else if (STREQ(args[0], IPTABLES) &&
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
    const char *actual = NULL;
    const char *expected =
        IPTABLES " -w -A INPUT --source 192.168.122.1 --jump ACCEPT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.127 --jump REJECT\n"
        IPTABLES " -w -L\n"
        IPTABLES " -w -t nat -L\n"
        IPTABLES " -w -A INPUT --source 192.168.122.130 --jump REJECT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.129' --jump REJECT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.129' --jump REJECT\n"
        IPTABLES " -w -A INPUT --source 192.168.122.128 --jump REJECT\n"
        IPTABLES " -w -A INPUT --source '!192.168.122.1' --jump REJECT\n";
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    expectedLineNum = 0;
    expectedLineError = false;

    virCommandSetDryRun(dryRunToken, &cmdbuf, false, false, testFirewallQueryHook, NULL);

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
        return -1;

    actual = virBufferCurrentContent(&cmdbuf);

    if (expectedLineError) {
        fprintf(stderr, "Got some unexpected query data\n");
        return -1;
    }

    if (virTestCompareToString(expected, actual) < 0) {
        fprintf(stderr, "Unexpected command execution\n");
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

# define RUN_TEST(name, method) \
    do { \
        if (virTestRun(name, method, NULL) < 0) \
            ret = -1; \
    } while (0)

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

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virfirewall"))

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined(__linux__) */
