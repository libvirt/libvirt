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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#define __VIR_FIREWALL_PRIV_H_ALLOW__
#define __VIR_COMMAND_PRIV_H_ALLOW__

#include "testutils.h"

#if defined(__linux__)

# include "virbuffer.h"
# include "vircommandpriv.h"
# include "virfirewallpriv.h"
# include "virmock.h"
# include "virdbuspriv.h"

# define VIR_FROM_THIS VIR_FROM_FIREWALL

# if WITH_DBUS
#  include <dbus/dbus.h>
# endif

static bool fwDisabled = true;
static virBufferPtr fwBuf;
static bool fwError;

# define TEST_FILTER_TABLE_LIST                                 \
    "Chain INPUT (policy ACCEPT)\n"                             \
    "target     prot opt source               destination\n"    \
    "\n"                                                        \
    "Chain FORWARD (policy ACCEPT)\n"                           \
    "target     prot opt source               destination\n"    \
    "\n"                                                        \
    "Chain OUTPUT (policy ACCEPT)\n"                            \
    "target     prot opt source               destination\n"

# define TEST_NAT_TABLE_LIST                                            \
    "Chain PREROUTING (policy ACCEPT)\n"                                \
    "target     prot opt source               destination\n"            \
    "\n"                                                                \
    "Chain INPUT (policy ACCEPT)\n"                                     \
    "target     prot opt source               destination\n"            \
    "\n"                                                                \
    "Chain OUTPUT (policy ACCEPT)\n"                                    \
    "target     prot opt source               destination\n"            \
    "\n"                                                                \
    "Chain POSTROUTING (policy ACCEPT)\n"                               \
    "target     prot opt source               destination\n"

# if WITH_DBUS
VIR_MOCK_WRAP_RET_ARGS(dbus_connection_send_with_reply_and_block,
                       DBusMessage *,
                       DBusConnection *, connection,
                       DBusMessage *, message,
                       int, timeout_milliseconds,
                       DBusError *, error)
{
    DBusMessage *reply = NULL;
    const char *service = dbus_message_get_destination(message);
    const char *member = dbus_message_get_member(message);
    size_t i;
    size_t nargs = 0;
    char **args = NULL;
    char *type = NULL;

    VIR_MOCK_REAL_INIT(dbus_connection_send_with_reply_and_block);

    if (STREQ(service, "org.freedesktop.DBus") &&
        STREQ(member, "ListNames")) {
        const char *svc1 = "org.foo.bar.wizz";
        const char *svc2 = VIR_FIREWALL_FIREWALLD_SERVICE;
        DBusMessageIter iter;
        DBusMessageIter sub;
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
                                         "s", &sub);

        if (!dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc1))
            goto error;
        if (!fwDisabled &&
            !dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc2))
            goto error;
        dbus_message_iter_close_container(&iter, &sub);
    } else if (STREQ(service, VIR_FIREWALL_FIREWALLD_SERVICE) &&
               STREQ(member, "passthrough")) {
        bool isAdd = false;
        bool doError = false;

        if (virDBusMessageDecode(message,
                                 "sa&s",
                                 &type,
                                 &nargs,
                                 &args) < 0)
            goto error;

        for (i = 0; i < nargs; i++) {
            /* Fake failure on the command with this IP addr */
            if (STREQ(args[i], "-A")) {
                isAdd = true;
            } else if (isAdd && STREQ(args[i], "192.168.122.255")) {
                doError = true;
            }
        }

        if (fwBuf) {
            if (STREQ(type, "ipv4"))
                virBufferAddLit(fwBuf, IPTABLES_PATH);
            else if (STREQ(type, "ipv4"))
                virBufferAddLit(fwBuf, IP6TABLES_PATH);
            else
                virBufferAddLit(fwBuf, EBTABLES_PATH);
        }
        for (i = 0; i < nargs; i++) {
            if (fwBuf) {
                virBufferAddLit(fwBuf, " ");
                virBufferEscapeShell(fwBuf, args[i]);
            }
        }
        if (fwBuf)
            virBufferAddLit(fwBuf, "\n");
        if (doError) {
            dbus_set_error_const(error,
                                 "org.firewalld.error",
                                 "something bad happened");
        } else {
            if (nargs == 1 &&
                STREQ(type, "ipv4") &&
                STREQ(args[0], "-L")) {
                if (virDBusCreateReply(&reply,
                                       "s", TEST_FILTER_TABLE_LIST) < 0)
                    goto error;
            } else if (nargs == 3 &&
                       STREQ(type, "ipv4") &&
                       STREQ(args[0], "-t") &&
                       STREQ(args[1], "nat") &&
                       STREQ(args[2], "-L")) {
                if (virDBusCreateReply(&reply,
                                       "s", TEST_NAT_TABLE_LIST) < 0)
                    goto error;
            } else {
                if (virDBusCreateReply(&reply,
                                       "s", "success") < 0)
                    goto error;
            }
        }
    } else {
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    }

 cleanup:
    VIR_FREE(type);
    for (i = 0; i < nargs; i++)
        VIR_FREE(args[i]);
    VIR_FREE(args);
    return reply;

 error:
    virDBusMessageUnref(reply);
    reply = NULL;
    if (error && !dbus_error_is_set(error))
        dbus_set_error_const(error,
                             "org.firewalld.error",
                             "something unexpected happened");

    goto cleanup;
}
# endif

struct testFirewallData {
    virFirewallBackend tryBackend;
    virFirewallBackend expectBackend;
    bool fwDisabled;
};

static int
testFirewallSingleGroup(const void *opaque)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT)
        virCommandSetDryRun(&cmdbuf, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}


static int
testFirewallRemoveRule(const void *opaque)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;
    virFirewallRulePtr fwrule;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT)
        virCommandSetDryRun(&cmdbuf, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                                "-A", "INPUT", NULL);
    virFirewallRuleAddArg(fw, fwrule, "--source-host");
    virFirewallRemoveRule(fw, fwrule);

    fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                                "-A", "INPUT", NULL);
    virFirewallRuleAddArg(fw, fwrule, "--source-host");
    virFirewallRuleAddArgFormat(fw, fwrule, "%s", "!192.168.122.1");
    virFirewallRuleAddArgList(fw, fwrule, "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}


static int
testFirewallManyGroups(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -A OUTPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT)
        virCommandSetDryRun(&cmdbuf, NULL, NULL);
    else
        fwBuf = &cmdbuf;

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}

static void
testFirewallRollbackHook(const char *const*args,
                         const char *const*env ATTRIBUTE_UNUSED,
                         const char *input ATTRIBUTE_UNUSED,
                         char **output ATTRIBUTE_UNUSED,
                         char **error ATTRIBUTE_UNUSED,
                         int *status,
                         void *opaque ATTRIBUTE_UNUSED)
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
testFirewallIgnoreFailGroup(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -A OUTPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}


static int
testFirewallIgnoreFailRule(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -A OUTPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A OUTPUT --jump DROP\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_IPV4,
                           true, NULL, NULL,
                           "-A", "INPUT",
                           "--source-host", "192.168.122.255",
                           "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "OUTPUT",
                       "--jump", "DROP", NULL);


    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}


static int
testFirewallNoRollback(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    if (virTestOOMActive())
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}

static int
testFirewallSingleRollback(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -D INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwError = true;
        fwBuf = &cmdbuf;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    if (virTestOOMActive())
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}

static int
testFirewallManyRollback(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    if (virTestOOMActive())
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}

static int
testFirewallChainedRollback(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host '!192.168.122.1' --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host 192.168.122.255 --jump REJECT\n"
        IPTABLES_PATH " -D INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallRollbackHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.127",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.127",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    virFirewallStartRollback(fw, VIR_FIREWALL_ROLLBACK_INHERIT_PREVIOUS);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "192.168.122.255",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-D", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) == 0) {
        fprintf(stderr, "Firewall apply unexpectedly worked\n");
        goto cleanup;
    }

    if (virTestOOMActive())
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
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
                      const char *const*env ATTRIBUTE_UNUSED,
                      const char *input ATTRIBUTE_UNUSED,
                      char **output,
                      char **error ATTRIBUTE_UNUSED,
                      int *status,
                      void *opaque ATTRIBUTE_UNUSED)
{
    if (STREQ(args[0], IPTABLES_PATH) &&
        STREQ(args[1], "-L")) {
        if (VIR_STRDUP(*output, TEST_FILTER_TABLE_LIST) < 0)
            *status = 127;
    } else if (STREQ(args[0], IPTABLES_PATH) &&
               STREQ(args[1], "-t") &&
               STREQ(args[2], "nat") &&
               STREQ(args[3], "-L")) {
        if (VIR_STRDUP(*output, TEST_NAT_TABLE_LIST) < 0)
            *status = 127;
    }
}


static int
testFirewallQueryCallback(virFirewallPtr fw,
                          const char *const *lines,
                          void *opaque ATTRIBUTE_UNUSED)
{
    size_t i;
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.129",
                       "--jump", "REJECT", NULL);

    for (i = 0; lines[i] != NULL; i++) {
        if (expectedLineNum >= ARRAY_CARDINALITY(expectedLines)) {
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
testFirewallQuery(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer cmdbuf = VIR_BUFFER_INITIALIZER;
    virFirewallPtr fw = NULL;
    int ret = -1;
    const char *actual = NULL;
    const char *expected =
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.1 --jump ACCEPT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.127 --jump REJECT\n"
        IPTABLES_PATH " -L\n"
        IPTABLES_PATH " -t nat -L\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.130 --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.129' --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.129' --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host 192.168.122.128 --jump REJECT\n"
        IPTABLES_PATH " -A INPUT --source-host '!192.168.122.1' --jump REJECT\n";
    const struct testFirewallData *data = opaque;

    expectedLineNum = 0;
    expectedLineError = false;
    fwDisabled = data->fwDisabled;
    if (virFirewallSetBackend(data->tryBackend) < 0)
        goto cleanup;

    if (data->expectBackend == VIR_FIREWALL_BACKEND_DIRECT) {
        virCommandSetDryRun(&cmdbuf, testFirewallQueryHook, NULL);
    } else {
        fwBuf = &cmdbuf;
        fwError = true;
    }

    fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.1",
                       "--jump", "ACCEPT", NULL);

    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.127",
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
                       "--source-host", "192.168.122.130",
                       "--jump", "REJECT", NULL);


    virFirewallStartTransaction(fw, 0);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "192.168.122.128",
                       "--jump", "REJECT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_IPV4,
                       "-A", "INPUT",
                       "--source-host", "!192.168.122.1",
                       "--jump", "REJECT", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    if (virBufferError(&cmdbuf))
        goto cleanup;

    actual = virBufferCurrentContent(&cmdbuf);

    if (expectedLineError) {
        fprintf(stderr, "Got some unexpected query data\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(expected, actual)) {
        fprintf(stderr, "Unexected command execution\n");
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&cmdbuf);
    fwBuf = NULL;
    virCommandSetDryRun(NULL, NULL, NULL);
    virFirewallFree(fw);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

# define RUN_TEST_DIRECT(name, method)                                  \
    do {                                                                \
        struct testFirewallData data;                                   \
        data.tryBackend = VIR_FIREWALL_BACKEND_AUTOMATIC;               \
        data.expectBackend = VIR_FIREWALL_BACKEND_DIRECT;               \
        data.fwDisabled = true;                                         \
        if (virTestRun(name " auto direct", method, &data) < 0)         \
            ret = -1;                                                   \
        data.tryBackend = VIR_FIREWALL_BACKEND_DIRECT;                  \
        data.expectBackend = VIR_FIREWALL_BACKEND_DIRECT;               \
        data.fwDisabled = true;                                         \
        if (virTestRun(name " manual direct", method, &data) < 0)       \
            ret = -1;                                                   \
    } while (0)

# if WITH_DBUS
#  define RUN_TEST_FIREWALLD(name, method)                              \
    do {                                                                \
        struct testFirewallData data;                                   \
        data.tryBackend = VIR_FIREWALL_BACKEND_AUTOMATIC;               \
        data.expectBackend = VIR_FIREWALL_BACKEND_FIREWALLD;            \
        data.fwDisabled = false;                                        \
        if (virTestRun(name " auto firewalld", method, &data) < 0)      \
            ret = -1;                                                   \
        data.tryBackend = VIR_FIREWALL_BACKEND_FIREWALLD;               \
        data.expectBackend = VIR_FIREWALL_BACKEND_FIREWALLD;            \
        data.fwDisabled = false;                                        \
        if (virTestRun(name " manual firewalld", method, &data) < 0)    \
            ret = -1;                                                   \
    } while (0)

#  define RUN_TEST(name, method)                \
    RUN_TEST_DIRECT(name, method);              \
    RUN_TEST_FIREWALLD(name, method)
# else /* ! WITH_DBUS */
#  define RUN_TEST(name, method)                \
    RUN_TEST_DIRECT(name, method)
# endif /* ! WITH_DBUS */

    virFirewallSetLockOverride(true);

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

# if WITH_DBUS
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virdbusmock.so")
# else
VIR_TEST_MAIN(mymain)
# endif

#else /* ! defined (__linux__) */

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* ! defined(__linux__) */
