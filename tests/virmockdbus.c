/*
 * virmockdbus.c: mocking of dbus message send/reply
 *
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

#if defined(WITH_DBUS) && !defined(WIN32)
# include "virmock.h"
# include <dbus/dbus.h>

VIR_MOCK_STUB_VOID_ARGS(dbus_connection_set_change_sigpipe,
                        dbus_bool_t, will_modify_sigpipe)


VIR_MOCK_STUB_RET_ARGS(dbus_bus_get,
                       DBusConnection *, (DBusConnection *)0x1,
                       DBusBusType, type,
                       DBusError *, error)

VIR_MOCK_STUB_VOID_ARGS(dbus_connection_set_exit_on_disconnect,
                        DBusConnection *, connection,
                        dbus_bool_t, exit_on_disconnect)

VIR_MOCK_STUB_RET_ARGS(dbus_connection_set_watch_functions,
                       dbus_bool_t, 1,
                       DBusConnection *, connection,
                       DBusAddWatchFunction, add_function,
                       DBusRemoveWatchFunction, remove_function,
                       DBusWatchToggledFunction, toggled_function,
                       void *, data,
                       DBusFreeFunction, free_data_function)

VIR_MOCK_STUB_RET_ARGS(dbus_message_set_reply_serial,
                       dbus_bool_t, 1,
                       DBusMessage *, message,
                       dbus_uint32_t, serial)


VIR_MOCK_LINK_RET_ARGS(dbus_connection_send_with_reply_and_block,
                       DBusMessage *,
                       DBusConnection *, connection,
                       DBusMessage *, message,
                       int, timeout_milliseconds,
                       DBusError *, error)

#endif /* WITH_DBUS && !WIN32 */
