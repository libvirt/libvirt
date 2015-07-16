/*
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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

#include "testutils.h"

#if defined(WITH_DBUS) && defined(__linux__)

# include <stdlib.h>
# include <dbus/dbus.h>

# include "virsystemd.h"
# include "virlog.h"
# include "virmock.h"
# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.systemdtest");

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

    VIR_MOCK_REAL_INIT(dbus_connection_send_with_reply_and_block);

    if (STREQ(service, "org.freedesktop.machine1")) {
        if (getenv("FAIL_BAD_SERVICE")) {
            dbus_set_error_const(error,
                                 "org.freedesktop.systemd.badthing",
                                 "Something went wrong creating the machine");
        } else {
            reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
        }
    } else if (STREQ(service, "org.freedesktop.login1")) {
        char *supported = getenv("RESULT_SUPPORT");
        DBusMessageIter iter;
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
        dbus_message_iter_init_append(reply, &iter);

        if (!dbus_message_iter_append_basic(&iter,
                                            DBUS_TYPE_STRING,
                                            &supported))
            goto error;
    } else if (STREQ(service, "org.freedesktop.DBus") &&
               STREQ(member, "ListActivatableNames")) {
        const char *svc1 = "org.foo.bar.wizz";
        const char *svc2 = "org.freedesktop.machine1";
        const char *svc3 = "org.freedesktop.login1";
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
        if (!getenv("FAIL_NO_SERVICE") &&
            !dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc2))
            goto error;
        if (!getenv("FAIL_NO_SERVICE") &&
            !dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc3))
            goto error;
        dbus_message_iter_close_container(&iter, &sub);
    } else if (STREQ(service, "org.freedesktop.DBus") &&
               STREQ(member, "ListNames")) {
        const char *svc1 = "org.foo.bar.wizz";
        const char *svc2 = "org.freedesktop.systemd1";
        const char *svc3 = "org.freedesktop.login1";
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
        if ((!getenv("FAIL_NO_SERVICE") && !getenv("FAIL_NOT_REGISTERED")) &&
            !dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc2))
            goto error;
        if ((!getenv("FAIL_NO_SERVICE") && !getenv("FAIL_NOT_REGISTERED")) &&
            !dbus_message_iter_append_basic(&sub,
                                            DBUS_TYPE_STRING,
                                            &svc3))
            goto error;
        dbus_message_iter_close_container(&iter, &sub);
    } else {
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    }

    return reply;

 error:
    dbus_message_unref(reply);
    return NULL;
}


static int testCreateContainer(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    if (virSystemdCreateMachine("demo",
                                "lxc",
                                true,
                                uuid,
                                "/proc/123/root",
                                123,
                                true,
                                0, NULL,
                                "highpriority.slice") < 0) {
        fprintf(stderr, "%s", "Failed to create LXC machine\n");
        return -1;
    }

    return 0;
}

static int testTerminateContainer(const void *opaque ATTRIBUTE_UNUSED)
{
    if (virSystemdTerminateMachine("demo",
                                   "lxc",
                                   true) < 0) {
        fprintf(stderr, "%s", "Failed to terminate LXC machine\n");
        return -1;
    }

    return 0;
}

static int testCreateMachine(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    if (virSystemdCreateMachine("demo",
                                "qemu",
                                false,
                                uuid,
                                NULL,
                                123,
                                false,
                                0, NULL,
                                NULL) < 0) {
        fprintf(stderr, "%s", "Failed to create KVM machine\n");
        return -1;
    }

    return 0;
}

static int testTerminateMachine(const void *opaque ATTRIBUTE_UNUSED)
{
    if (virSystemdTerminateMachine("demo",
                                   "qemu",
                                   false) < 0) {
        fprintf(stderr, "%s", "Failed to terminate KVM machine\n");
        return -1;
    }

    return 0;
}

static int testCreateNoSystemd(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    setenv("FAIL_NO_SERVICE", "1", 1);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      true,
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL)) == 0) {
        unsetenv("FAIL_NO_SERVICE");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    unsetenv("FAIL_NO_SERVICE");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}

static int testCreateSystemdNotRunning(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    setenv("FAIL_NOT_REGISTERED", "1", 1);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      true,
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL)) == 0) {
        unsetenv("FAIL_NOT_REGISTERED");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    unsetenv("FAIL_NOT_REGISTERED");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}

static int testCreateBadSystemd(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    setenv("FAIL_BAD_SERVICE", "1", 1);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      true,
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL)) == 0) {
        unsetenv("FAIL_BAD_SERVICE");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    unsetenv("FAIL_BAD_SERVICE");

    if (rv != -1) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}


static int testCreateNetwork(const void *opaque ATTRIBUTE_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int nicindexes[] = {
        2, 1729, 87539319,
    };
    size_t nnicindexes = ARRAY_CARDINALITY(nicindexes);
    if (virSystemdCreateMachine("demo",
                                "lxc",
                                true,
                                uuid,
                                "/proc/123/root",
                                123,
                                true,
                                nnicindexes, nicindexes,
                                "highpriority.slice") < 0) {
        fprintf(stderr, "%s", "Failed to create LXC machine\n");
        return -1;
    }

    return 0;
}


struct testScopeData {
    const char *name;
    const char *expected;
};

static int
testScopeName(const void *opaque)
{
    const struct testScopeData *data = opaque;
    int ret = -1;
    char *actual = NULL;

    if (!(actual = virSystemdMakeScopeName(data->name, "lxc")))
        goto cleanup;

    if (STRNEQ(actual, data->expected)) {
        fprintf(stderr, "Expected '%s' but got '%s'\n",
                data->expected, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}

typedef int (*virSystemdCanHelper)(bool * result);
struct testPMSupportData {
    virSystemdCanHelper tested;
};

static int testPMSupportHelper(const void *opaque)
{
    int rv;
    bool result;
    size_t i;
    const char *results[4] = {"yes", "no", "na", "challenge"};
    int expected[4] = {1, 0, 0, 1};
    const struct testPMSupportData *data = opaque;

    for (i = 0; i < 4; i++) {
        setenv("RESULT_SUPPORT",  results[i], 1);
        if ((rv = data->tested(&result)) < 0) {
            fprintf(stderr, "%s", "Unexpected canSuspend error\n");
            return -1;
        }

        if (result != expected[i]) {
            fprintf(stderr, "Unexpected result for answer '%s'\n", results[i]);
            goto error;
        }
        unsetenv("RESULT_SUPPORT");
    }

    return 0;
 error:
    unsetenv("RESULT_SUPPORT");
    return -1;
}

static int testPMSupportHelperNoSystemd(const void *opaque)
{
    int rv;
    bool result;
    const struct testPMSupportData *data = opaque;

    setenv("FAIL_NO_SERVICE", "1", 1);

    if ((rv = data->tested(&result)) == 0) {
        unsetenv("FAIL_NO_SERVICE");
        fprintf(stderr, "%s", "Unexpected canSuspend success\n");
        return -1;
    }
    unsetenv("FAIL_NO_SERVICE");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected canSuspend error\n");
        return -1;
    }

    return 0;
}

static int testPMSupportSystemdNotRunning(const void *opaque)
{
    int rv;
    bool result;
    const struct testPMSupportData *data = opaque;

    setenv("FAIL_NOT_REGISTERED", "1", 1);

    if ((rv = data->tested(&result)) == 0) {
        unsetenv("FAIL_NOT_REGISTERED");
        fprintf(stderr, "%s", "Unexpected canSuspend success\n");
        return -1;
    }
    unsetenv("FAIL_NOT_REGISTERED");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected canSuspend error\n");
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if (virtTestRun("Test create container ", testCreateContainer, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test terminate container ", testTerminateContainer, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test create machine ", testCreateMachine, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test terminate machine ", testTerminateMachine, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test create no systemd ", testCreateNoSystemd, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test create systemd not running ",
                    testCreateSystemdNotRunning, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test create bad systemd ", testCreateBadSystemd, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test create with network ", testCreateNetwork, NULL) < 0)
        ret = -1;

# define TEST_SCOPE(name, unitname)                                     \
    do {                                                                \
        struct testScopeData data = {                                   \
            name, unitname                                              \
        };                                                              \
        if (virtTestRun("Test scopename", testScopeName, &data) < 0)    \
            ret = -1;                                                   \
    } while (0)

    TEST_SCOPE("demo", "machine-lxc\\x2ddemo.scope");
    TEST_SCOPE("demo-name", "machine-lxc\\x2ddemo\\x2dname.scope");
    TEST_SCOPE("demo!name", "machine-lxc\\x2ddemo\\x21name.scope");
    TEST_SCOPE(".demo", "machine-lxc\\x2d\\x2edemo.scope");

# define TESTS_PM_SUPPORT_HELPER(name, function)                        \
    do {                                                                \
        struct testPMSupportData data = {                               \
            function                                                    \
        };                                                              \
        if (virtTestRun("Test " name " ", testPMSupportHelper, &data) < 0)  \
            ret = -1;                                                   \
        if (virtTestRun("Test " name " no systemd ",                    \
                        testPMSupportHelperNoSystemd, &data) < 0)       \
            ret = -1;                                                   \
        if (virtTestRun("Test systemd " name " not running ",           \
                        testPMSupportSystemdNotRunning, &data) < 0)     \
            ret = -1;                                                   \
    } while (0)

    TESTS_PM_SUPPORT_HELPER("canSuspend", &virSystemdCanSuspend);
    TESTS_PM_SUPPORT_HELPER("canHibernate", &virSystemdCanHibernate);
    TESTS_PM_SUPPORT_HELPER("canHybridSleep", &virSystemdCanHybridSleep);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virmockdbus.so")

#else /* ! (WITH_DBUS && __linux__) */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* ! WITH_DBUS */
