/*
 * virgdbus.c: helper for using GDBus
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
 */

#include <config.h>

#include "virerror.h"
#include "virlog.h"
#include "virgdbus.h"
#include "virthread.h"


#define VIR_FROM_THIS VIR_FROM_DBUS

VIR_LOG_INIT("util.dbus");


static bool sharedBus = true;
static GDBusConnection *systemBus;
static GDBusConnection *sessionBus;
static virOnceControl systemOnce = VIR_ONCE_CONTROL_INITIALIZER;
static virOnceControl sessionOnce = VIR_ONCE_CONTROL_INITIALIZER;
static GError *systemError;
static GError *sessionError;


void
virGDBusSetSharedBus(bool shared)
{
    sharedBus = shared;
}


static GDBusConnection *
virGDBusBusInit(GBusType type, GError **error)
{
    g_autofree char *address = NULL;

    if (sharedBus) {
        return g_bus_get_sync(type, NULL, error);
    } else {
        GDBusConnectionFlags dbusFlags =
                G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION;

        address = g_dbus_address_get_for_bus_sync(type, NULL, error);
        if (*error)
            return NULL;
        return g_dbus_connection_new_for_address_sync(address,
                                                      dbusFlags,
                                                      NULL,
                                                      NULL,
                                                      error);
    }
}


static void
virGDBusSystemBusInit(void)
{
    systemBus = virGDBusBusInit(G_BUS_TYPE_SYSTEM, &systemError);
}


static GDBusConnection *
virGDBusGetSystemBusInternal(void)
{
    if (virOnce(&systemOnce, virGDBusSystemBusInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to run one time GDBus initializer"));
        return NULL;
    }

    return systemBus;
}


GDBusConnection *
virGDBusGetSystemBus(void)
{
    GDBusConnection *bus = virGDBusGetSystemBusInternal();

    if (!bus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to get system bus connection: %1$s"),
                       systemError->message);
        return NULL;
    }

    return bus;
}


static void
virGDBusSessionBusInit(void)
{
    sessionBus = virGDBusBusInit(G_BUS_TYPE_SESSION, &sessionError);
}


GDBusConnection *
virGDBusGetSessionBus(void)
{
    if (virOnce(&sessionOnce, virGDBusSessionBusInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to run one time GDBus initializer"));
        return NULL;
    }

    if (!sessionBus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to get session bus connection: %1$s"),
                       sessionError->message);
        return NULL;
    }

    return sessionBus;
}


/**
 * virGDBusHasSystemBus:
 *
 * Check if DBus system bus is running. This does not imply that we have
 * a connection. DBus might be running and refusing connections due to its
 * client limit. The latter must be treated as a fatal error.
 *
 * Return false if dbus is not available, true if probably available.
 */
bool
virGDBusHasSystemBus(void)
{
    g_autofree char *name = NULL;

    if (virGDBusGetSystemBusInternal())
        return true;

    if (!g_dbus_error_is_remote_error(systemError))
        return false;

    name = g_dbus_error_get_remote_error(systemError);

    if (name &&
        (STREQ(name, "org.freedesktop.DBus.Error.FileNotFound") ||
         STREQ(name, "org.freedesktop.DBus.Error.NoServer"))) {
        VIR_DEBUG("System bus not available: %s", NULLSTR(systemError->message));
        return false;
    }

    return true;
}


void
virGDBusCloseSystemBus(void)
{
    if (!systemBus || sharedBus)
        return;

    g_dbus_connection_flush_sync(systemBus, NULL, NULL);
    g_dbus_connection_close_sync(systemBus, NULL, NULL);
    g_clear_pointer(&systemBus, g_object_unref);
}


#define VIR_DBUS_METHOD_CALL_TIMEOUT_MILIS 30 * 1000

/**
 * virGDBusCallMethod:
 * @conn: a DBus connection
 * @reply: pointer to receive reply message, or NULL
 * @replyType: pointer to GVariantType to validate reply data, or NULL
 * @error: libvirt error pointer or NULL
 * @busName: bus identifier of the target service
 * @objectPath: object path of the target service
 * @ifaceName: the interface of the object
 * @method: the name of the method in the interface
 * @data: pointer to data passed to DBus method
 *
 * If @error is NULL then a libvirt error will be raised when a DBus error
 * is received and the return value will be -1. If @error is non-NULL then
 * any DBus error will be saved into that object and the return value will
 * be 0.
 *
 * Returns 0 on success, or -1 upon error.
 */
int
virGDBusCallMethod(GDBusConnection *conn,
                   GVariant **reply,
                   const GVariantType *replyType,
                   virErrorPtr error,
                   const char *busName,
                   const char *objectPath,
                   const char *ifaceName,
                   const char *method,
                   GVariant *data)
{
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GError) gerror = NULL;

    if (error)
        memset(error, 0, sizeof(*error));

    if (data)
        g_variant_ref_sink(data);

    ret = g_dbus_connection_call_sync(conn,
                                      busName,
                                      objectPath,
                                      ifaceName,
                                      method,
                                      data,
                                      replyType,
                                      G_DBUS_CALL_FLAGS_NONE,
                                      VIR_DBUS_METHOD_CALL_TIMEOUT_MILIS,
                                      NULL,
                                      &gerror);

    if (!ret) {
        if (error && g_dbus_error_is_remote_error(gerror)) {
            error->level = VIR_ERR_ERROR;
            error->code = VIR_ERR_DBUS_SERVICE;
            error->domain = VIR_FROM_DBUS;
            error->str1 = g_dbus_error_get_remote_error(gerror);
            error->message = g_strdup(gerror->message);
        } else {
            virReportError(VIR_ERR_DBUS_SERVICE, "%s", gerror->message);
            return -1;
        }
    }

    if (reply)
        *reply = g_steal_pointer(&ret);

    return 0;
}


#ifdef G_OS_UNIX
int
virGDBusCallMethodWithFD(GDBusConnection *conn,
                         GVariant **reply,
                         const GVariantType *replyType,
                         GUnixFDList **replyFD,
                         virErrorPtr error,
                         const char *busName,
                         const char *objectPath,
                         const char *ifaceName,
                         const char *method,
                         GVariant *data,
                         GUnixFDList *dataFD)
{
    g_autoptr(GVariant) ret = NULL;
    g_autoptr(GError) gerror = NULL;

    if (error)
        memset(error, 0, sizeof(*error));

    if (data)
        g_variant_ref_sink(data);

    ret = g_dbus_connection_call_with_unix_fd_list_sync(conn,
                                                        busName,
                                                        objectPath,
                                                        ifaceName,
                                                        method,
                                                        data,
                                                        replyType,
                                                        G_DBUS_CALL_FLAGS_NONE,
                                                        VIR_DBUS_METHOD_CALL_TIMEOUT_MILIS,
                                                        dataFD,
                                                        replyFD,
                                                        NULL,
                                                        &gerror);

    if (!ret) {
        if (error && g_dbus_error_is_remote_error(gerror)) {
            error->level = VIR_ERR_ERROR;
            error->code = VIR_ERR_DBUS_SERVICE;
            error->domain = VIR_FROM_DBUS;
            error->str1 = g_dbus_error_get_remote_error(gerror);
            error->message = g_strdup(gerror->message);

            if (!error->str1 || !error->message)
                return -1;
        } else {
            virReportError(VIR_ERR_DBUS_SERVICE, "%s", gerror->message);
            return -1;
        }
    }

    if (reply)
        *reply = g_steal_pointer(&ret);

    return 0;
}
#else
int
virGDBusCallMethodWithFD(GDBusConnection *conn G_GNUC_UNUSED,
                         GVariant **reply G_GNUC_UNUSED,
                         const GVariantType *replyType G_GNUC_UNUSED,
                         GUnixFDList **replyFD G_GNUC_UNUSED,
                         virErrorPtr error G_GNUC_UNUSED,
                         const char *busName G_GNUC_UNUSED,
                         const char *objectPath G_GNUC_UNUSED,
                         const char *ifaceName G_GNUC_UNUSED,
                         const char *method G_GNUC_UNUSED,
                         GVariant *data G_GNUC_UNUSED,
                         GUnixFDList *dataFD G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unix file descriptors not supported on this platform"));
    return -1;
}
#endif


static int
virGDBusIsServiceInList(const char *listMethod,
                        const char *name)
{
    GDBusConnection *conn;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariantIter) iter = NULL;
    char *str;
    int rc;

    if (!virGDBusHasSystemBus())
        return -2;

    conn = virGDBusGetSystemBus();
    if (!conn)
        return -1;

    rc = virGDBusCallMethod(conn,
                            &reply,
                            G_VARIANT_TYPE("(as)"),
                            NULL,
                            "org.freedesktop.DBus",
                            "/org/freedesktop/DBus",
                            "org.freedesktop.DBus",
                            listMethod,
                            NULL);

    if (rc < 0)
        return -1;

    g_variant_get(reply, "(as)", &iter);
    while (g_variant_iter_loop(iter, "s", &str)) {
        if (STREQ(str, name)) {
            g_free(str);
            return 0;
        }
    }

    return -2;
}


/**
 * virGDBusIsServiceEnabled:
 * @name: service name
 *
 * Returns 0 if service is available, -1 on fatal error, or -2 if service is not available
 */
int
virGDBusIsServiceEnabled(const char *name)
{
    int ret = virGDBusIsServiceInList("ListActivatableNames", name);

    VIR_DEBUG("Service %s is %s", name, ret ? "unavailable" : "available");

    return ret;
}


/**
 * virGDBusIsServiceRegistered:
 * @name: service name
 *
 * Returns 0 if service is registered, -1 on fatal error, or -2 if service is not registered
 */
int
virGDBusIsServiceRegistered(const char *name)
{
    int ret = virGDBusIsServiceInList("ListNames", name);

    VIR_DEBUG("Service %s is %s", name, ret ? "not registered" : "registered");

    return ret;
}


bool
virGDBusErrorIsUnknownMethod(virErrorPtr err)
{
    return err->domain == VIR_FROM_DBUS &&
        err->code == VIR_ERR_DBUS_SERVICE &&
        err->level == VIR_ERR_ERROR &&
        STREQ_NULLABLE("org.freedesktop.DBus.Error.UnknownMethod",
                       err->str1);
}


bool
virGDBusMessageIsSignal(GDBusMessage *message,
                        const char *iface,
                        const char *signal)
{
    GDBusMessageType type = g_dbus_message_get_message_type(message);

    if (type == G_DBUS_MESSAGE_TYPE_SIGNAL) {
        const char *interface = g_dbus_message_get_interface(message);
        const char *member = g_dbus_message_get_member(message);

        return STREQ(interface, iface) && STREQ(member, signal);
    }

    return false;
}
