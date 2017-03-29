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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "testutils.h"

#if defined(__ELF__)

# include <stdlib.h>
# include <dbus/dbus.h>

# include "virpolkit.h"
# include "virdbus.h"
# include "virlog.h"
# include "virmock.h"
# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.systemdtest");

/* Some interesting numbers */
# define THE_PID 1458
# define THE_TIME 11011000001
# define THE_UID 1729

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

    if (STREQ(service, "org.freedesktop.PolicyKit1") &&
        STREQ(member, "CheckAuthorization")) {
        char *type;
        char *pidkey;
        unsigned int pidval;
        char *timekey;
        unsigned long long timeval;
        char *uidkey;
        int uidval;
        char *actionid;
        char **details;
        size_t detailslen;
        int allowInteraction;
        char *cancellationId;
        const char **retdetails = NULL;
        size_t retdetailslen = 0;
        const char *retdetailscancelled[] = {
            "polkit.dismissed", "true",
        };
        int is_authorized = 1;
        int is_challenge = 0;

        if (virDBusMessageRead(message,
                               "(sa{sv})sa&{ss}us",
                               &type,
                               3,
                               &pidkey, "u", &pidval,
                               &timekey, "t", &timeval,
                               &uidkey, "i", &uidval,
                               &actionid,
                               &detailslen,
                               &details,
                               &allowInteraction,
                               &cancellationId) < 0)
            goto error;

        if (STREQ(actionid, "org.libvirt.test.success")) {
            is_authorized = 1;
            is_challenge = 0;
        } else if (STREQ(actionid, "org.libvirt.test.challenge")) {
            is_authorized = 0;
            is_challenge = 1;
        } else if (STREQ(actionid, "org.libvirt.test.cancelled")) {
            is_authorized = 0;
            is_challenge = 0;
            retdetails = retdetailscancelled;
            retdetailslen = ARRAY_CARDINALITY(retdetailscancelled) / 2;
        } else if (STREQ(actionid, "org.libvirt.test.details")) {
            size_t i;
            is_authorized = 0;
            is_challenge = 0;
            for (i = 0; i < detailslen / 2; i++) {
                if (STREQ(details[i * 2],
                          "org.libvirt.test.person") &&
                    STREQ(details[(i * 2) + 1],
                          "Fred")) {
                    is_authorized = 1;
                    is_challenge = 0;
                }
            }
        } else {
            is_authorized = 0;
            is_challenge = 0;
        }

        VIR_FREE(type);
        VIR_FREE(pidkey);
        VIR_FREE(timekey);
        VIR_FREE(uidkey);
        VIR_FREE(actionid);
        VIR_FREE(cancellationId);
        virStringListFreeCount(details, detailslen);

        if (virDBusCreateReply(&reply,
                               "(bba&{ss})",
                               is_authorized,
                               is_challenge,
                               retdetailslen,
                               retdetails) < 0)
            goto error;
    } else {
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    }

    return reply;

 error:
    virDBusMessageUnref(reply);
    return NULL;
}



static int testPolkitAuthSuccess(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (virPolkitCheckAuth("org.libvirt.test.success",
                           THE_PID,
                           THE_TIME,
                           THE_UID,
                           NULL,
                           true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int testPolkitAuthDenied(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
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
        goto cleanup;
    } else if (rv != -2) {
        goto cleanup;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                        _("access denied by policy"))) {
        fprintf(stderr, "Incorrect error response\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


static int testPolkitAuthChallenge(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
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
        goto cleanup;
    } else if (rv != -2) {
        goto cleanup;
    }

    err = virGetLastError();
    if (!err || err->domain != VIR_FROM_POLKIT ||
        err->code != VIR_ERR_AUTH_UNAVAILABLE ||
        !strstr(err->message, _("no polkit agent available to authenticate"))) {
        fprintf(stderr, "Incorrect error response\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


static int testPolkitAuthCancelled(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
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
        goto cleanup;
    } else if (rv != -2) {
        goto cleanup;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                       _("user cancelled authentication process"))) {
        fprintf(stderr, "Incorrect error response\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


static int testPolkitAuthDetailsSuccess(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
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
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int testPolkitAuthDetailsDenied(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
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
        goto cleanup;
    } else if (rv != -2) {
        goto cleanup;
    }

    err = virGetLastError();
    if (!err || !strstr(err->message,
                        _("access denied by policy"))) {
        fprintf(stderr, "Incorrect error response\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
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

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virdbusmock.so")

#else /* ! __ELF__ */
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif /* ! __ELF__ */
