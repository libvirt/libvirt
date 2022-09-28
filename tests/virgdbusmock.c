/*
 * virgdbusmock.c: mocking of dbus message send/reply
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

#include <gio/gio.h>

#include "virmock.h"

VIR_MOCK_STUB_RET_ARGS(g_bus_get_sync,
                       GDBusConnection *, (GDBusConnection *)0x1,
                       GBusType, type,
                       GCancellable, *cancellable,
                       GError, **error)

VIR_MOCK_STUB_RET_ARGS(g_dbus_address_get_for_bus_sync,
                       gchar *, (gchar *)0x1,
                       GBusType, type,
                       GCancellable *, cancellable,
                       GError **, error)

VIR_MOCK_STUB_RET_ARGS(g_dbus_connection_new_for_address_sync,
                       GDBusConnection *, (GDBusConnection *)0x1,
                       const gchar *, address,
                       GDBusConnectionFlags, flags,
                       GDBusAuthObserver *, observer,
                       GCancellable *, cancellable,
                       GError **, error)

VIR_MOCK_STUB_RET_ARGS(g_dbus_connection_flush_sync,
                       gboolean, true,
                       GDBusConnection *, connection,
                       GCancellable *, cancellable,
                       GError **, error)

VIR_MOCK_STUB_RET_ARGS(g_dbus_connection_close_sync,
                       gboolean, true,
                       GDBusConnection *, connection,
                       GCancellable *, cancellable,
                       GError **, error)

VIR_MOCK_LINK_RET_ARGS(g_dbus_connection_call_sync,
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

#ifdef G_OS_UNIX
VIR_MOCK_LINK_RET_ARGS(g_dbus_connection_call_with_unix_fd_list_sync,
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
                       GUnixFDList *, fd_list,
                       GUnixFDList **, out_fd_list,
                       GCancellable *, cancellable,
                       GError **, error)
#endif /* G_OS_UNIX */
