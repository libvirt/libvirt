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
 *
 * Author: Jan Tomko <jtomko@redhat.com>
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
# define __VIR_COMMAND_PRIV_H_ALLOW__

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

struct testSessionInfo {
    const char *device_path;
    int output_version;
    const char *expected_session;
};

static void testIscsiadmCb(const char *const*args,
                           const char *const*env ATTRIBUTE_UNUSED,
                           const char *input ATTRIBUTE_UNUSED,
                           char **output,
                           char **error ATTRIBUTE_UNUSED,
                           int *status,
                           void *opaque)
{
    int *output_version = opaque;
    if (args[0] && STREQ(args[0], ISCSIADM) &&
        args[1] && STREQ(args[1], "--mode") &&
        args[2] && STREQ(args[2], "session") &&
        args[3] == NULL) {
        if (*output_version == 1)
            ignore_value(VIR_STRDUP(*output, iscsiadmSessionOutputNonFlash));
        else
            ignore_value(VIR_STRDUP(*output, iscsiadmSessionOutput));
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
        ignore_value(VIR_STRDUP(*output, iscsiadmSendtargetsOutput));
    } else {
        *status = -1;
    }
}

static int
testISCSIGetSession(const void *data)
{
    const struct testSessionInfo *info = data;
    int ver = info->output_version;
    char *actual_session = NULL;
    int ret = -1;

    virCommandSetDryRun(NULL, testIscsiadmCb, &ver);

    actual_session = virISCSIGetSession(info->device_path, true);

    if (STRNEQ_NULLABLE(actual_session, info->expected_session)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected session: '%s' got: '%s'",
                       NULLSTR(info->expected_session),
                       NULLSTR(actual_session));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    VIR_FREE(actual_session);
    return ret;
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

    virCommandSetDryRun(NULL, testIscsiadmCb, NULL);

    if (virISCSIScanTargets(info->portal, &ntargets, &targets) < 0)
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
    virCommandSetDryRun(NULL, NULL, NULL);
    for (i = 0; i < ntargets; i++)
        VIR_FREE(targets[i]);
    VIR_FREE(targets);
    return ret;
}

static int
mymain(void)
{
    int rv = 0;

# define DO_SESSION_TEST(name, session)                                     \
    do {                                                                    \
        struct testSessionInfo info = {name, 0, session};                   \
        if (virTestRun("ISCSI get session test" name,                       \
                       testISCSIGetSession, &info) < 0)                     \
            rv = -1;                                                        \
        info.output_version = 1;                                            \
        if (virTestRun("ISCSI get (non-flash) session test" name,           \
                       testISCSIGetSession, &info) < 0)                     \
            rv = -1;                                                        \
    } while (0)

    DO_SESSION_TEST("iqn.2004-06.example:example1:iscsi.test", "1");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.seven", "7");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.eight", NULL);

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
        .nexpected = ARRAY_CARDINALITY(targets),
    };
    if (virTestRun("ISCSI scan targets", testISCSIScanTargets, &infoTargets) < 0)
        rv = -1;

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIR_TEST_MAIN(mymain)
#endif /* WIN32 */
