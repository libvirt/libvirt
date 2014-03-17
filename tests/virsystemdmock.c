/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifdef __linux__
# include "internal.h"

# include <stdlib.h>

# include <dbus/dbus.h>

void dbus_connection_set_change_sigpipe(dbus_bool_t will_modify_sigpipe ATTRIBUTE_UNUSED)
{
}

DBusConnection *dbus_bus_get(DBusBusType type ATTRIBUTE_UNUSED,
                             DBusError *error ATTRIBUTE_UNUSED)
{
    return (DBusConnection *)0x1;
}

void dbus_connection_set_exit_on_disconnect(DBusConnection *connection ATTRIBUTE_UNUSED,
                                            dbus_bool_t exit_on_disconnect ATTRIBUTE_UNUSED)
{
}


dbus_bool_t dbus_connection_set_watch_functions(DBusConnection *connection ATTRIBUTE_UNUSED,
                                                DBusAddWatchFunction add_function ATTRIBUTE_UNUSED,
                                                DBusRemoveWatchFunction remove_function ATTRIBUTE_UNUSED,
                                                DBusWatchToggledFunction toggled_function ATTRIBUTE_UNUSED,
                                                void *data ATTRIBUTE_UNUSED,
                                                DBusFreeFunction free_data_function ATTRIBUTE_UNUSED)
{
    return 1;
}

dbus_bool_t dbus_message_set_reply_serial(DBusMessage *message ATTRIBUTE_UNUSED,
                                          dbus_uint32_t serial ATTRIBUTE_UNUSED)
{
    return 1;
}

DBusMessage *dbus_connection_send_with_reply_and_block(DBusConnection *connection ATTRIBUTE_UNUSED,
                                                       DBusMessage *message,
                                                       int timeout_milliseconds ATTRIBUTE_UNUSED,
                                                       DBusError *error ATTRIBUTE_UNUSED)
{
    DBusMessage *reply = NULL;
    const char *service = dbus_message_get_destination(message);
    const char *member = dbus_message_get_member(message);

    if (STREQ(service, "org.freedesktop.machine1")) {
        if (getenv("FAIL_BAD_SERVICE")) {
            dbus_set_error_const(error,
                                 "org.freedesktop.systemd.badthing",
                                 "Something went wrong creating the machine");
        } else {
            reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
        }
    } else if (STREQ(service, "org.freedesktop.DBus") &&
               STREQ(member, "ListActivatableNames")) {
        const char *svc1 = "org.foo.bar.wizz";
        const char *svc2 = "org.freedesktop.machine1";
        DBusMessageIter iter, sub;
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
        dbus_message_iter_close_container(&iter, &sub);
    } else if (STREQ(service, "org.freedesktop.DBus") &&
               STREQ(member, "ListNames")) {
        const char *svc1 = "org.foo.bar.wizz";
        const char *svc2 = "org.freedesktop.systemd1";
        DBusMessageIter iter, sub;
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
        dbus_message_iter_close_container(&iter, &sub);
    } else {
        reply = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_RETURN);
    }

    return reply;

 error:
    dbus_message_unref(reply);
    return NULL;
}

#else
/* Nothing to override on non-__linux__ platforms */
#endif
