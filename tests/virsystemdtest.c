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
 */

#include <config.h>

#include "testutils.h"

#if defined(__linux__)

# include <fcntl.h>
# include <unistd.h>

# define LIBVIRT_VIRSYSTEMDPRIV_H_ALLOW
# include "virsystemdpriv.h"

# include "virsystemd.h"
# include "virgdbus.h"
# include "virlog.h"
# include "virmock.h"
# include "rpc/virnetsocket.h"
# include "domain_driver.h"
# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.systemdtest");

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

    if (STREQ(bus_name, "org.freedesktop.machine1")) {
        if (getenv("FAIL_BAD_SERVICE")) {
            *error = g_dbus_error_new_for_dbus_error(
                    "org.freedesktop.systemd.badthing",
                     "Something went wrong creating the machine");
        } else {
            if (STREQ(method_name, "GetMachineByPID")) {
                reply = g_variant_new("(o)",
                                      "/org/freedesktop/machine1/machine/qemu_2ddemo");
            } else if (STREQ(method_name, "Get")) {
                const char *prop;
                g_variant_get(params, "(@s&s)", NULL, &prop);

                if (STREQ(prop, "Name")) {
                    reply = g_variant_new("(v)", g_variant_new_string("qemu-demo"));
                } else if (STREQ(prop, "Unit")) {
                    reply = g_variant_new("(v)",
                                          g_variant_new_string("machine-qemu-demo.scope"));
                } else {
                    *error = g_dbus_error_new_for_dbus_error(
                            "org.freedesktop.systemd.badthing",
                            "Unknown machine property");
                }
            } else {
                reply = g_variant_new("()");
            }
        }
    } else if (STREQ(bus_name, "org.freedesktop.login1")) {
        reply = g_variant_new("(s)", getenv("RESULT_SUPPORT"));
    } else if (STREQ(bus_name, "org.freedesktop.DBus") &&
               STREQ(method_name, "ListActivatableNames")) {
        GVariantBuilder builder;

        g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

        g_variant_builder_add(&builder, "s", "org.foo.bar.wizz");

        if (!getenv("FAIL_NO_SERVICE")) {
            g_variant_builder_add(&builder, "s", "org.freedesktop.machine1");
            g_variant_builder_add(&builder, "s", "org.freedesktop.login1");
        }

        reply = g_variant_new("(@as)", g_variant_builder_end(&builder));
    } else if (STREQ(bus_name, "org.freedesktop.DBus") &&
               STREQ(method_name, "ListNames")) {
        GVariantBuilder builder;

        g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

        g_variant_builder_add(&builder, "s", "org.foo.bar.wizz");

        if (!getenv("FAIL_NO_SERVICE") && !getenv("FAIL_NOT_REGISTERED")) {
            g_variant_builder_add(&builder, "s", "org.freedesktop.systemd1");
            g_variant_builder_add(&builder, "s", "org.freedesktop.login1");
        }

        reply = g_variant_new("(@as)", g_variant_builder_end(&builder));
    } else {
        reply = g_variant_new("()");
    }

    return reply;
}


static int testCreateContainer(const void *opaque G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    if (virSystemdCreateMachine("demo",
                                "lxc",
                                uuid,
                                "/proc/123/root",
                                123,
                                true,
                                0, NULL,
                                "highpriority.slice", 0) < 0) {
        fprintf(stderr, "%s", "Failed to create LXC machine\n");
        return -1;
    }

    return 0;
}

static int testTerminateContainer(const void *opaque G_GNUC_UNUSED)
{
    if (virSystemdTerminateMachine("lxc-demo") < 0) {
        fprintf(stderr, "%s", "Failed to terminate LXC machine\n");
        return -1;
    }

    return 0;
}

static int testCreateMachine(const void *opaque G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    if (virSystemdCreateMachine("demo",
                                "qemu",
                                uuid,
                                NULL,
                                123,
                                false,
                                0, NULL,
                                NULL, 0) < 0) {
        fprintf(stderr, "%s", "Failed to create KVM machine\n");
        return -1;
    }

    return 0;
}

static int testTerminateMachine(const void *opaque G_GNUC_UNUSED)
{
    if (virSystemdTerminateMachine("test-qemu-demo") < 0) {
        fprintf(stderr, "%s", "Failed to terminate KVM machine\n");
        return -1;
    }

    return 0;
}

static int testCreateNoSystemd(const void *opaque G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    g_setenv("FAIL_NO_SERVICE", "1", TRUE);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL, 0)) == 0) {
        g_unsetenv("FAIL_NO_SERVICE");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    g_unsetenv("FAIL_NO_SERVICE");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}

static int testCreateSystemdNotRunning(const void *opaque G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    g_setenv("FAIL_NOT_REGISTERED", "1", TRUE);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL, 0)) == 0) {
        g_unsetenv("FAIL_NOT_REGISTERED");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    g_unsetenv("FAIL_NOT_REGISTERED");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}

static int testCreateBadSystemd(const void *opaque G_GNUC_UNUSED)
{
    unsigned char uuid[VIR_UUID_BUFLEN] = {
        1, 1, 1, 1,
        2, 2, 2, 2,
        3, 3, 3, 3,
        4, 4, 4, 4
    };
    int rv;

    g_setenv("FAIL_BAD_SERVICE", "1", TRUE);

    if ((rv = virSystemdCreateMachine("demo",
                                      "qemu",
                                      uuid,
                                      NULL,
                                      123,
                                      false,
                                      0, NULL,
                                      NULL, 0)) == 0) {
        g_unsetenv("FAIL_BAD_SERVICE");
        fprintf(stderr, "%s", "Unexpected create machine success\n");
        return -1;
    }
    g_unsetenv("FAIL_BAD_SERVICE");

    if (rv != -1) {
        fprintf(stderr, "%s", "Unexpected create machine error\n");
        return -1;
    }

    return 0;
}


static int testCreateNetwork(const void *opaque G_GNUC_UNUSED)
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
    size_t nnicindexes = G_N_ELEMENTS(nicindexes);
    if (virSystemdCreateMachine("demo",
                                "lxc",
                                uuid,
                                "/proc/123/root",
                                123,
                                true,
                                nnicindexes, nicindexes,
                                "highpriority.slice", 2) < 0) {
        fprintf(stderr, "%s", "Failed to create LXC machine\n");
        return -1;
    }

    return 0;
}


static int
testGetMachineName(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *tmp = virSystemdGetMachineNameByPID(1234);
    int ret = -1;

    if (!tmp) {
        fprintf(stderr, "%s", "Failed to create LXC machine\n");
        return ret;
    }

    if (STREQ(tmp, "qemu-demo"))
        ret = 0;

    return ret;
}


static int
testGetMachineUnit(const void *opaque G_GNUC_UNUSED)
{
    g_autofree char *tmp = virSystemdGetMachineUnitByPID(1234);

    if (!tmp) {
        fprintf(stderr, "%s", "Failed to create get machine unit\n");
        return -1;
    }

    if (STREQ(tmp, "machine-qemu-demo.scope"))
        return 0;

    return -1;
}


struct testNameData {
    const char *name;
    const char *expected;
    const char *root;
    int id;
    bool legacy;
};

static int
testScopeName(const void *opaque)
{
    const struct testNameData *data = opaque;
    g_autofree char *actual = NULL;

    if (!(actual = virSystemdMakeScopeName(data->name, "lxc", data->legacy)))
        return -1;

    if (STRNEQ(actual, data->expected)) {
        fprintf(stderr, "Expected '%s' but got '%s'\n",
                data->expected, actual);
        return -1;
    }

    return 0;
}

static int
testMachineName(const void *opaque)
{
    const struct testNameData *data = opaque;
    g_autofree char *actual = NULL;

    if (!(actual = virDomainDriverGenerateMachineName("qemu", data->root,
                                                      data->id, data->name, true)))
        return -1;

    if (STRNEQ(actual, data->expected)) {
        fprintf(stderr, "Expected '%s' but got '%s'\n",
                data->expected, actual);
        return -1;
    }

    return 0;
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
        g_setenv("RESULT_SUPPORT",  results[i], TRUE);
        if ((rv = data->tested(&result)) < 0) {
            fprintf(stderr, "%s", "Unexpected canSuspend error\n");
            return -1;
        }

        if (result != expected[i]) {
            fprintf(stderr, "Unexpected result for answer '%s'\n", results[i]);
            goto error;
        }
        g_unsetenv("RESULT_SUPPORT");
    }

    return 0;
 error:
    g_unsetenv("RESULT_SUPPORT");
    return -1;
}

static int testPMSupportHelperNoSystemd(const void *opaque)
{
    int rv;
    bool result;
    const struct testPMSupportData *data = opaque;

    g_setenv("FAIL_NO_SERVICE", "1", TRUE);

    if ((rv = data->tested(&result)) == 0) {
        g_unsetenv("FAIL_NO_SERVICE");
        fprintf(stderr, "%s", "Unexpected canSuspend success\n");
        return -1;
    }
    g_unsetenv("FAIL_NO_SERVICE");

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

    g_setenv("FAIL_NOT_REGISTERED", "1", TRUE);

    if ((rv = data->tested(&result)) == 0) {
        g_unsetenv("FAIL_NOT_REGISTERED");
        fprintf(stderr, "%s", "Unexpected canSuspend success\n");
        return -1;
    }
    g_unsetenv("FAIL_NOT_REGISTERED");

    if (rv != -2) {
        fprintf(stderr, "%s", "Unexpected canSuspend error\n");
        return -1;
    }

    return 0;
}


static int
testActivationCreateFDs(virNetSocket **sockUNIX,
                        virNetSocket ***sockIP,
                        size_t *nsockIP)
{
    *sockUNIX = NULL;
    *sockIP = NULL;
    *nsockIP = 0;

    if (virNetSocketNewListenUNIX("virsystemdtest.sock",
                                  0777,
                                  0,
                                  0,
                                  sockUNIX) < 0)
        return -1;

    if (virNetSocketNewListenTCP("localhost",
                                 NULL,
                                 AF_UNSPEC,
                                 sockIP,
                                 nsockIP) < 0) {
        virObjectUnref(*sockUNIX);
        return -1;
    }

    return 0;
}


static int
testActivationFDNames(const void *opaque G_GNUC_UNUSED)
{
    virNetSocket *sockUNIX;
    virNetSocket **sockIP;
    size_t nsockIP;
    int ret = -1;
    size_t i;
    char nfdstr[VIR_INT64_STR_BUFLEN];
    char pidstr[VIR_INT64_STR_BUFLEN];
    int *fds = NULL;
    size_t nfds = 0;
    g_autoptr(virSystemdActivation) act = NULL;
    g_auto(virBuffer) names = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&names, "demo-unix.socket");

    if (testActivationCreateFDs(&sockUNIX, &sockIP, &nsockIP) < 0)
        return -1;

    for (i = 0; i < nsockIP; i++)
        virBufferAddLit(&names, ":demo-ip.socket");

    g_snprintf(nfdstr, sizeof(nfdstr), "%zu", 1 + nsockIP);
    g_snprintf(pidstr, sizeof(pidstr), "%lld", (long long)getpid());

    g_setenv("LISTEN_FDS", nfdstr, TRUE);
    g_setenv("LISTEN_PID", pidstr, TRUE);
    g_setenv("LISTEN_FDNAMES", virBufferCurrentContent(&names), TRUE);

    if (virSystemdGetActivation(&act) < 0)
        goto cleanup;

    if (act == NULL) {
        fprintf(stderr, "Activation object was not created: %s", virGetLastErrorMessage());
        goto cleanup;
    }

    if (virSystemdActivationComplete(act) == 0) {
        fprintf(stderr, "Activation did not report unclaimed FDs");
        goto cleanup;
    }

    virSystemdActivationClaimFDs(act, "demo-unix.socket", &fds, &nfds);

    if (nfds != 1) {
        fprintf(stderr, "Expected 1 UNIX fd, but got %zu\n", nfds);
        goto cleanup;
    }
    VIR_FREE(fds);

    virSystemdActivationClaimFDs(act, "demo-ip.socket", &fds, &nfds);

    if (nfds != nsockIP) {
        fprintf(stderr, "Expected %zu IP fd, but got %zu\n", nsockIP, nfds);
        goto cleanup;
    }
    VIR_FREE(fds);

    virSystemdActivationClaimFDs(act, "demo-ip-alt.socket", &fds, &nfds);

    if (nfds != 0) {
        fprintf(stderr, "Expected 0 IP fd, but got %zu\n", nfds);
        goto cleanup;
    }

    if (virSystemdActivationComplete(act) < 0) {
        fprintf(stderr, "Action was not complete: %s\n", virGetLastErrorMessage());
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(sockUNIX);
    for (i = 0; i < nsockIP; i++)
        virObjectUnref(sockIP[i]);
    VIR_FREE(sockIP);
    VIR_FREE(fds);
    return ret;
}


static int
testActivationEmpty(const void *opaque G_GNUC_UNUSED)
{
    virSystemdActivation *act;

    g_unsetenv("LISTEN_FDS");

    if (virSystemdGetActivation(&act) < 0)
        return -1;

    if (act != NULL) {
        fprintf(stderr, "Unexpectedly got activation object");
        virSystemdActivationFree(act);
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    unsigned char uuid[VIR_UUID_BUFLEN];

    /* The one we use in tests quite often */
    if (virUUIDParse("c7a5fdbd-edaf-9455-926a-d65c16db1809", uuid) < 0)
        return EXIT_FAILURE;

# define DO_TEST(_name, func) \
    do { \
        if (virTestRun(_name, func, NULL) < 0) \
            ret = -1; \
        if (virTestRun(_name "again ", func, NULL) < 0) \
            ret = -1; \
        virSystemdHasMachinedResetCachedValue(); \
    } while (0)

    DO_TEST("Test create container ", testCreateContainer);
    DO_TEST("Test terminate container ", testTerminateContainer);
    DO_TEST("Test create machine ", testCreateMachine);
    DO_TEST("Test terminate machine ", testTerminateMachine);
    DO_TEST("Test create no systemd ", testCreateNoSystemd);
    DO_TEST("Test create systemd not running ", testCreateSystemdNotRunning);
    DO_TEST("Test create bad systemd ", testCreateBadSystemd);
    DO_TEST("Test create with network ", testCreateNetwork);
    DO_TEST("Test getting machine name ", testGetMachineName);
    DO_TEST("Test getting machine unit ", testGetMachineUnit);

# define TEST_SCOPE(_name, unitname, _legacy) \
    do { \
        struct testNameData data = { \
            .name = _name, .expected = unitname, .legacy = _legacy, \
        }; \
        if (virTestRun("Test scopename", testScopeName, &data) < 0) \
            ret = -1; \
    } while (0)

# define TEST_SCOPE_OLD(name, unitname) \
    TEST_SCOPE(name, unitname, true)
# define TEST_SCOPE_NEW(name, unitname) \
    TEST_SCOPE(name, unitname, false)

    TEST_SCOPE_OLD("demo", "machine-lxc\\x2ddemo.scope");
    TEST_SCOPE_OLD("demo-name", "machine-lxc\\x2ddemo\\x2dname.scope");
    TEST_SCOPE_OLD("demo!name", "machine-lxc\\x2ddemo\\x21name.scope");
    TEST_SCOPE_OLD(".demo", "machine-lxc\\x2d\\x2edemo.scope");
    TEST_SCOPE_OLD("bull💩", "machine-lxc\\x2dbull\\xf0\\x9f\\x92\\xa9.scope");

    TEST_SCOPE_NEW("qemu-3-demo", "machine-qemu\\x2d3\\x2ddemo.scope");

# define TEST_MACHINE(_name, _root, _id, machinename) \
    do { \
        struct testNameData data = { \
            .name = _name, .expected = machinename, .root = _root, .id = _id, \
        }; \
        if (virTestRun("Test scopename", testMachineName, &data) < 0) \
            ret = -1; \
    } while (0)

    TEST_MACHINE("demo", NULL, 1, "qemu-1-demo");
    TEST_MACHINE("demo-name", NULL, 2, "qemu-2-demo-name");
    TEST_MACHINE("demo!name", NULL, 3, "qemu-3-demoname");
    TEST_MACHINE(".demo", NULL, 4, "qemu-4-demo");
    TEST_MACHINE("bull\U0001f4a9", NULL, 5, "qemu-5-bull");
    TEST_MACHINE("demo..name", NULL, 6, "qemu-6-demo.name");
    TEST_MACHINE("12345678901234567890123456789012345678901234567890123456789", NULL, 7,
                 "qemu-7-123456789012345678901234567890123456789012345678901234567");
    TEST_MACHINE("123456789012345678901234567890123456789012345678901234567890", NULL, 8,
                 "qemu-8-123456789012345678901234567890123456789012345678901234567");
    TEST_MACHINE("kstest-network-device-default-httpks_(c9eed63e-981e-48ec-acdc-56b3f8c5f678)",
                 NULL, 100,
                 "qemu-100-kstest-network-device-default-httpksc9eed63e-981e-48ec");
    TEST_MACHINE("kstest-network-device-default-httpks_(c9eed63e-981e-48ec--cdc-56b3f8c5f678)",
                 NULL, 10,
                 "qemu-10-kstest-network-device-default-httpksc9eed63e-981e-48ec-c");
    TEST_MACHINE("demo.-.test.", NULL, 11, "qemu-11-demo.test");
    TEST_MACHINE("demo", "/tmp/root1", 1, "qemu-embed-0991f456-1-demo");
    TEST_MACHINE("demo", "/tmp/root2", 1, "qemu-embed-95d47ff5-1-demo");
    TEST_MACHINE("|.-m", NULL, 1, "qemu-1-m");
    TEST_MACHINE("Auto-esx7.0-rhel7.9-special-characters~!@#$%^&*_=+,?><:;|.\"[]()`\\-m",
                 NULL, 1, "qemu-1-Auto-esx7.0-rhel7.9-special-characters.m");

# define TESTS_PM_SUPPORT_HELPER(name, function) \
    do { \
        struct testPMSupportData data = { \
            function \
        }; \
        if (virTestRun("Test " name " ", testPMSupportHelper, &data) < 0) \
            ret = -1; \
        virSystemdHasLogindResetCachedValue(); \
        if (virTestRun("Test " name " no systemd ", \
                       testPMSupportHelperNoSystemd, &data) < 0) \
            ret = -1; \
        virSystemdHasLogindResetCachedValue(); \
        if (virTestRun("Test systemd " name " not running ", \
                       testPMSupportSystemdNotRunning, &data) < 0) \
            ret = -1; \
        virSystemdHasLogindResetCachedValue(); \
    } while (0)

    TESTS_PM_SUPPORT_HELPER("canSuspend", &virSystemdCanSuspend);
    TESTS_PM_SUPPORT_HELPER("canHibernate", &virSystemdCanHibernate);
    TESTS_PM_SUPPORT_HELPER("canHybridSleep", &virSystemdCanHybridSleep);

    if (virTestRun("Test activation empty", testActivationEmpty, NULL) < 0)
        ret = -1;

    if (fcntl(STDERR_FILENO + 1, F_GETFL) == -1 && errno == EBADF &&
        fcntl(STDERR_FILENO + 2, F_GETFL) == -1 && errno == EBADF &&
        fcntl(STDERR_FILENO + 3, F_GETFL) == -1 && errno == EBADF) {
        if (virTestRun("Test activation names", testActivationFDNames, NULL) < 0)
            ret = -1;
    } else {
        VIR_INFO("Skipping activation tests as FD 3/4/5 is open");
    }

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virgdbus"))

#else /* ! __linux__ */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* ! __linux__ */
