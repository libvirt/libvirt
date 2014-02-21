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

#ifdef WIN32
int
main(void)
{
    return EXIT_AM_SKIP;
}
#else
# define __VIR_COMMAND_PRIV_H_ALLOW__

# include "testutils.h"
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

static int
mymain(void)
{
    int rv = 0;

# define DO_SESSION_TEST(name, session)                                     \
    do {                                                                    \
        struct testSessionInfo info = {name, 0, session};                   \
        if (virtTestRun("ISCSI get session test" name,                      \
                        testISCSIGetSession, &info) < 0)                    \
            rv = -1;                                                        \
        info.output_version = 1;                                            \
        if (virtTestRun("ISCSI get (non-flash) session test" name,          \
                        testISCSIGetSession, &info) < 0)                    \
            rv = -1;                                                        \
    } while (0)

    DO_SESSION_TEST("iqn.2004-06.example:example1:iscsi.test", "1");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.seven", "7");
    DO_SESSION_TEST("iqn.2009-04.example:example1:iscsi.eight", NULL);

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIRT_TEST_MAIN(mymain)
#endif /* WIN32 */
