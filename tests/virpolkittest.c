/*
 * Copyright (C) 2013, 2014, 2016 Red Hat, Inc.
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

#if defined(__ELF__)

# include "virpolkit.h"
# include "virgdbus.h"
# include "virlog.h"
# include "virmock.h"
# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.systemdtest");

/* Some interesting numbers */
# define THE_PID 1458
# define THE_TIME 11011000001
# define THE_UID 1729

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

    if (STREQ(bus_name, "org.freedesktop.PolicyKit1") &&
        STREQ(method_name, "CheckAuthorization")) {
        g_autoptr(GVariantIter) iter = NULL;
        GVariantBuilder builder;
        char *type;
        char *actionid;
        int is_authorized = 1;
        int is_challenge = 0;

        g_variant_get(params, "((&s@a{sv})&sa{ss}@u@s)",
                      &type,
                      NULL,
                      &actionid,
                      &iter,
                      NULL,
                      NULL);

        g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));

        if (STREQ(actionid, "org.libvirt.test.success")) {
            is_authorized = 1;
            is_challenge = 0;
        } else if (STREQ(actionid, "org.libvirt.test.challenge")) {
            is_authorized = 0;
            is_challenge = 1;
        } else if (STREQ(actionid, "org.libvirt.test.cancelled")) {
            is_authorized = 0;
            is_challenge = 0;
            g_variant_builder_add(&builder, "{ss}", "polkit.dismissed", "true");
        } else if (STREQ(actionid, "org.libvirt.test.details")) {
            char *key;
            char *val;
            is_authorized = 0;
            is_challenge = 0;

            while (g_variant_iter_loop(iter, "{ss}", &key, &val)) {
                if (STREQ(key, "org.libvirt.test.person") && STREQ(val, "Fred")) {
                    is_authorized = 1;
                    is_challenge = 0;
                }
            }
        } else {
            is_authorized = 0;
            is_challenge = 0;
        }

        reply = g_variant_new("((bb@a{ss}))", is_authorized, is_challenge,
                              g_variant_builder_end(&builder));
    } else {
        reply = g_variant_new("()");
    }

    return reply;
}



static int testPolkitAuthSuccess(const void *opaque G_GNUC_UNUSED)
{
    if (virPolkitCheckAuth("org.libvirt.test.success",
                           THE_PID,
                           THE_TIME,
                           THE_UID,
                           NULL,
                           true) < 0)
        return -1;

    return 0;
}


static int testPolkitAuthDenied(const void *opaque G_GNUC_UNUSED)
{
    int rv;
    virErrorPtr err;

    rv = virPolkitCheckAuth("org.libvirt.test.deny",
                            THE_PID,
                            THE_TIME,
                            THE_UID,
                            NULL,
                            true);

    if (rv == 0) {
        fprintf(stderr, "Unexpected auth success\n");
        return -1;
    } else if (rv != -2) {
        return -1;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                        _("access denied by policy"))) {
        fprintf(stderr, "Incorrect error response\n");
        return -1;
    }

    return 0;
}


static int testPolkitAuthChallenge(const void *opaque G_GNUC_UNUSED)
{
    int rv;
    virErrorPtr err;

    rv = virPolkitCheckAuth("org.libvirt.test.challenge",
                            THE_PID,
                            THE_TIME,
                            THE_UID,
                            NULL,
                            true);

    if (rv == 0) {
        fprintf(stderr, "Unexpected auth success\n");
        return -1;
    } else if (rv != -2) {
        return -1;
    }

    err = virGetLastError();
    if (!err || err->domain != VIR_FROM_POLKIT ||
        err->code != VIR_ERR_AUTH_UNAVAILABLE ||
        !strstr(err->message, _("no polkit agent available to authenticate"))) {
        fprintf(stderr, "Incorrect error response\n");
        return -1;
    }

    return 0;
}


static int testPolkitAuthCancelled(const void *opaque G_GNUC_UNUSED)
{
    int rv;
    virErrorPtr err;

    rv = virPolkitCheckAuth("org.libvirt.test.cancelled",
                            THE_PID,
                            THE_TIME,
                            THE_UID,
                            NULL,
                            true);

    if (rv == 0) {
        fprintf(stderr, "Unexpected auth success\n");
        return -1;
    } else if (rv != -2) {
        return -1;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                       _("user cancelled authentication process"))) {
        fprintf(stderr, "Incorrect error response\n");
        return -1;
    }

    return 0;
}


static int testPolkitAuthDetailsSuccess(const void *opaque G_GNUC_UNUSED)
{
    const char *details[] = {
        "org.libvirt.test.person", "Fred",
        NULL,
    };

    if (virPolkitCheckAuth("org.libvirt.test.details",
                           THE_PID,
                           THE_TIME,
                           THE_UID,
                           details,
                           true) < 0)
        return -1;

    return 0;
}


static int testPolkitAuthDetailsDenied(const void *opaque G_GNUC_UNUSED)
{
    int rv;
    virErrorPtr err;
    const char *details[] = {
        "org.libvirt.test.person", "Joe",
        NULL,
    };

    rv = virPolkitCheckAuth("org.libvirt.test.details",
                            THE_PID,
                            THE_TIME,
                            THE_UID,
                            details,
                            true);

    if (rv == 0) {
        fprintf(stderr, "Unexpected auth success\n");
        return -1;
    } else if (rv != -2) {
        return -1;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                        _("access denied by policy"))) {
        fprintf(stderr, "Incorrect error response\n");
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("Polkit auth success ", testPolkitAuthSuccess, NULL) < 0)
        ret = -1;
    if (virTestRun("Polkit auth deny ", testPolkitAuthDenied, NULL) < 0)
        ret = -1;
    if (virTestRun("Polkit auth challenge ", testPolkitAuthChallenge, NULL) < 0)
        ret = -1;
    if (virTestRun("Polkit auth cancel ", testPolkitAuthCancelled, NULL) < 0)
        ret = -1;
    if (virTestRun("Polkit auth details success ", testPolkitAuthDetailsSuccess, NULL) < 0)
        ret = -1;
    if (virTestRun("Polkit auth details deny ", testPolkitAuthDetailsDenied, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virgdbus"))

#else /* ! __ELF__ */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* ! __ELF__ */
