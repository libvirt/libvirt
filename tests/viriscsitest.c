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

#ifdef WIN32
int
main(void)
{
    return EXIT_AM_SKIP;
}
#else
# define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
# include "vircommandpriv.h"
# include "viriscsi.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static const char *iscsiadmSessionOutput =
    "tcp: [1] 10.20.30.40:3260,1 iqn.2004-06.example:example1:iscsi.test\n"
    "tcp: [2] 10.20.30.41:3260,1 iqn.2005-05.example:example1:iscsi.hello\n"
    "tcp: [3] 10.20.30.42:3260,1 iqn.2006-04.example:example1:iscsi.world\n"
    "tcp: [5] 10.20.30.43:3260,1 iqn.2007-04.example:example1:iscsi.foo\n"
    "tcp: [6] 10.20.30.44:3260,1 iqn.2008-04.example:example1:iscsi.bar\n"
    "tcp: [7] 10.20.30.45:3260,1 iqn.2009-04.example:example1:iscsi.seven\n";

static const char *iscsiadmSessionOutputNonFlash =
    "tcp: [1] 10.20.30.40:3260,1 iqn.2004-06.example:example1:iscsi.test (non-flash)\n"
    "tcp: [2] 10.20.30.41:3260,1 iqn.2005-05.example:example1:iscsi.hello (non-flash)\n"
    "tcp: [3] 10.20.30.42:3260,1 iqn.2006-04.example:example1:iscsi.world (non-flash)\n"
    "tcp: [5] 10.20.30.43:3260,1 iqn.2007-04.example:example1:iscsi.foo (non-flash)\n"
    "tcp: [6] 10.20.30.44:3260,1 iqn.2008-04.example:example1:iscsi.bar (non-flash)\n"
    "tcp: [7] 10.20.30.45:3260,1 iqn.2009-04.example:example1:iscsi.seven (non-flash)\n";

const char *iscsiadmSendtargetsOutput =
    "10.20.30.40:3260,1 iqn.2004-06.example:example1:iscsi.test\n"
    "10.20.30.40:3260,1 iqn.2005-05.example:example1:iscsi.hello\n"
    "10.20.30.40:3260,1 iqn.2006-04.example:example1:iscsi.world\n"
    "10.20.30.40:3260,1 iqn.2007-04.example:example1:iscsi.foo\n"
    "10.20.30.40:3260,1 iqn.2008-04.example:example1:iscsi.bar\n"
    "10.20.30.40:3260,1 iqn.2009-04.example:example1:iscsi.seven\n";

const char *iscsiadmIfaceDefaultOutput =
    "default tcp,<empty>,<empty>,<empty>,<empty>\n"
    "iser iser,<empty>,<empty>,<empty>,<empty>\n";

const char *iscsiadmIfaceIfaceOutput =
    "default tcp,<empty>,<empty>,<empty>,<empty>\n"
    "iser iser,<empty>,<empty>,<empty>,<empty>\n"
    "libvirt-iface-03020100 tcp,<empty>,<empty>,<empty>,iqn.2004-06.example:example1:initiator\n";


struct testIscsiadmCbData {
    bool output_version;
    bool iface_created;
};

static void testIscsiadmCb(const char *const*args,
                           const char *const*env G_GNUC_UNUSED,
                           const char *input G_GNUC_UNUSED,
                           char **output,
                           char **error G_GNUC_UNUSED,
                           int *status,
                           void *opaque)
{
    struct testIscsiadmCbData *data = opaque;

    if (args[0] && STREQ(args[0], ISCSIADM) &&
        args[1] && STREQ(args[1], "--mode") &&
        args[2] && STREQ(args[2], "session") &&
        args[3] == NULL) {
        if (data->output_version)
            *output = g_strdup(iscsiadmSessionOutputNonFlash);
        else
            *output = g_strdup(iscsiadmSessionOutput);
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "discovery") &&
               args[3] && STREQ(args[3], "--type") &&
               args[4] && STREQ(args[4], "sendtargets") &&
               args[5] && STREQ(args[5], "--portal") &&
               args[6] && STREQ(args[6], "10.20.30.40:3260,1") &&
               args[7] && STREQ(args[7], "--op") &&
               args[8] && STREQ(args[8], "nonpersistent") &&
               args[9] == NULL) {
        *output = g_strdup(iscsiadmSendtargetsOutput);
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "node") &&
               args[3] && STREQ(args[3], "--portal") &&
               args[4] && STREQ(args[4], "10.20.30.40:3260,1") &&
               args[5] && STREQ(args[5], "--targetname") &&
               args[6] && STREQ(args[6], "iqn.2004-06.example:example1:iscsi.test") &&
               args[7] && STREQ(args[7], "--login") &&
               args[8] == NULL) {
        /* Mocking real environment output is not needed for now.
         * Example output from real environment:
         *
         * Logging in to [iface: default, \
         *                target: iqn.2004-06.example:example1:iscsi.test, \
         *                portal: 10.20.30.40:3260,1] (multiple)
         * Login to [iface: default, \
         *           target: iqn.2004-06.example:example1:iscsi.test, \
         *           portal: 10.20.30.40:3260,1] successful.
         */
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "iface") &&
               args[3] == NULL) {
        if (data->iface_created)
            *output = g_strdup(iscsiadmIfaceIfaceOutput);
        else
            *output = g_strdup(iscsiadmIfaceDefaultOutput);
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "iface") &&
               args[3] && STREQ(args[3], "--interface") &&
               args[4] && STREQ(args[4], "libvirt-iface-03020100") &&
               args[5] && STREQ(args[5], "--op") &&
               args[6] && STREQ(args[6], "new") &&
               args[7] == NULL) {
        /* Mocking real environment output is not needed for now.
         * Example output from real environment:
         *
         * New interface libvirt-iface-03020100 added
         */
        data->iface_created = true;
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "iface") &&
               args[3] && STREQ(args[3], "--interface") &&
               args[4] && STREQ(args[4], "libvirt-iface-03020100") &&
               args[5] && STREQ(args[5], "--op") &&
               args[6] && STREQ(args[6], "update") &&
               args[7] && STREQ(args[7], "--name") &&
               args[8] && STREQ(args[8], "iface.initiatorname") &&
               args[9] && STREQ(args[9], "--value") &&
               args[10] && STREQ(args[10], "iqn.2004-06.example:example1:initiator") &&
               args[11] == NULL &&
               data->iface_created) {
        /* Mocking real environment output is not needed for now.
         * Example output from real environment:
         *
         * libvirt-iface-03020100 updated.
         */
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "discovery") &&
               args[3] && STREQ(args[3], "--type") &&
               args[4] && STREQ(args[4], "sendtargets") &&
               args[5] && STREQ(args[5], "--portal") &&
               args[6] && STREQ(args[6], "10.20.30.40:3260,1") &&
               args[7] && STREQ(args[7], "--interface") &&
               args[8] && STREQ(args[8], "libvirt-iface-03020100") &&
               args[9] == NULL &&
               data->iface_created) {
        *output = g_strdup(iscsiadmSendtargetsOutput);
    } else if (args[0] && STREQ(args[0], ISCSIADM) &&
               args[1] && STREQ(args[1], "--mode") &&
               args[2] && STREQ(args[2], "node") &&
               args[3] && STREQ(args[3], "--portal") &&
               args[4] && STREQ(args[4], "10.20.30.40:3260,1") &&
               args[5] && STREQ(args[5], "--targetname") &&
               args[6] && STREQ(args[6], "iqn.2004-06.example:example1:iscsi.test") &&
               args[7] && STREQ(args[7], "--login") &&
               args[8] && STREQ(args[8], "--interface") &&
               args[9] && STREQ(args[9], "libvirt-iface-03020100") &&
               args[10] == NULL &&
               data->iface_created) {
        /* Mocking real environment output is not needed for now.
         * Example output from real environment:
         *
         * Logging in to [iface: libvirt-iface-03020100, \
         *                target: iqn.2004-06.example:example1:iscsi.test, \
         *                portal: 10.20.30.40:3260,1] (multiple)
         * Login to [iface: libvirt-iface-03020100, \
         *           target: iqn.2004-06.example:example1:iscsi.test, \
         *           portal: 10.20.30.40:3260,1] successful.
         */
    } else {
        *status = -1;
    }
}

struct testSessionInfo {
    const char *device_path;
    bool output_version;
    const char *expected_session;
};

static int
testISCSIGetSession(const void *data)
{
    const struct testSessionInfo *info = data;
    struct testIscsiadmCbData cbData = { 0 };
    g_autofree char *actual_session = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    cbData.output_version = info->output_version;

    virCommandSetDryRun(dryRunToken, NULL, false, false, testIscsiadmCb, &cbData);

    actual_session = virISCSIGetSession(info->device_path, true);

    if (STRNEQ_NULLABLE(actual_session, info->expected_session)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected session: '%s' got: '%s'",
                       NULLSTR(info->expected_session),
                       NULLSTR(actual_session));
        return -1;
    }

    return 0;
}

struct testScanTargetsInfo {
    const char *fake_cmd_output;
    const char *portal;
    const char **expected_targets;
    size_t nexpected;
};

static int
testISCSIScanTargets(const void *data)
{
    const struct testScanTargetsInfo *info = data;
    size_t ntargets = 0;
    char **targets = NULL;
    int ret = -1;
    size_t i;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, NULL, false, false, testIscsiadmCb, NULL);

    if (virISCSIScanTargets(info->portal, NULL,
                            false, &ntargets, &targets) < 0)
        goto cleanup;

    if (info->nexpected != ntargets) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected %zu targets, got %zu",
                       info->nexpected, ntargets);
        goto cleanup;
    }

    for (i = 0; i < ntargets; i++) {
        if (STRNEQ(info->expected_targets[i], targets[i])) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Expected target '%s', got '%s'",
                           info->expected_targets[i], targets[i]);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    for (i = 0; i < ntargets; i++)
        VIR_FREE(targets[i]);
    VIR_FREE(targets);
    return ret;
}


struct testConnectionInfoLogin {
    const char *portal;
    const char *initiatoriqn;
    const char *target;
};


static int
testISCSIConnectionLogin(const void *data)
{
    const struct testConnectionInfoLogin *info = data;
    struct testIscsiadmCbData cbData = { 0 };
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, NULL, false, false, testIscsiadmCb, &cbData);

    if (virISCSIConnectionLogin(info->portal, info->initiatoriqn, info->target) < 0)
        return -1;

    return 0;
}


static int
testISCSIScanTargetsTests(void)
{
    const char *targets[] = {
        "iqn.2004-06.example:example1:iscsi.test",
        "iqn.2005-05.example:example1:iscsi.hello",
        "iqn.2006-04.example:example1:iscsi.world",
        "iqn.2007-04.example:example1:iscsi.foo",
        "iqn.2008-04.example:example1:iscsi.bar",
        "iqn.2009-04.example:example1:iscsi.seven"
    };
    struct testScanTargetsInfo infoTargets = {
        .fake_cmd_output = "iscsiadm_sendtargets",
        .portal = "10.20.30.40:3260,1",
        .expected_targets = targets,
        .nexpected = G_N_ELEMENTS(targets),
    };
    if (virTestRun("ISCSI scan targets", testISCSIScanTargets, &infoTargets) < 0)
        return -1;
    return 0;
}


static int
mymain(void)
{
    int rv = 0;

# define DO_SESSION_TEST(name, session) \
    do { \
        struct testSessionInfo info = {name, false, session}; \
        if (virTestRun("ISCSI get session test" name, \
                       testISCSIGetSession, &info) < 0) \
            rv = -1; \
        info.output_version = true; \
        if (virTestRun("ISCSI get (non-flash) session test" name, \
                       testISCSIGetSession, &info) < 0) \
            rv = -1; \
    } while (0)

    DO_SESSION_TEST("iqn.2004-06.example:example1:iscsi.test", "1");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.seven", "7");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.eight", NULL);

    if (testISCSIScanTargetsTests() < 0)
        rv = -1;

# define DO_LOGIN_TEST(portal, iqn, target) \
    do { \
        struct testConnectionInfoLogin info = {portal, iqn, target }; \
        if (virTestRun("ISCSI login " portal, \
                       testISCSIConnectionLogin, &info) < 0) \
        rv = -1; \
    } while (0)

    DO_LOGIN_TEST("10.20.30.40:3260,1", NULL, "iqn.2004-06.example:example1:iscsi.test");
    DO_LOGIN_TEST("10.20.30.40:3260,1", "iqn.2004-06.example:example1:initiator",
                  "iqn.2004-06.example:example1:iscsi.test");

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virrandom"))
#endif /* WIN32 */
