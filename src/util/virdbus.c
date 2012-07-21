/*
 * virdbus.c: helper for using DBus
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "virdbus.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"
#include "threads.h"

#define VIR_FROM_THIS VIR_FROM_DBUS

#ifdef HAVE_DBUS

static DBusConnection *systembus = NULL;
static virOnceControl once = VIR_ONCE_CONTROL_INITIALIZER;
static DBusError dbuserr;

static dbus_bool_t virDBusAddWatch(DBusWatch *watch, void *data);
static void virDBusRemoveWatch(DBusWatch *watch, void *data);
static void virDBusToggleWatch(DBusWatch *watch, void *data);

static void virDBusSystemBusInit(void)
{
    /* Allocate and initialize a new HAL context */
    dbus_connection_set_change_sigpipe(FALSE);
    dbus_threads_init_default();

    dbus_error_init(&dbuserr);
    if (!(systembus = dbus_bus_get(DBUS_BUS_SYSTEM, &dbuserr)))
        return;

    dbus_connection_set_exit_on_disconnect(systembus, FALSE);

    /* Register dbus watch callbacks */
    if (!dbus_connection_set_watch_functions(systembus,
                                             virDBusAddWatch,
                                             virDBusRemoveWatch,
                                             virDBusToggleWatch,
                                             NULL, NULL)) {
        systembus = NULL;
        return;
    }
}


DBusConnection *virDBusGetSystemBus(void)
{
    if (virOnce(&once, virDBusSystemBusInit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to run one time DBus initializer"));
        return NULL;
    }

    if (!systembus) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to get DBus system bus connection: %s"),
                       dbuserr.message ? dbuserr.message : "watch setup failed");
        return NULL;
    }

    return systembus;
}


static void virDBusWatchCallback(int fdatch ATTRIBUTE_UNUSED,
                                 int fd ATTRIBUTE_UNUSED,
                                 int events, void *opaque)
{
    DBusWatch *watch = opaque;
    int dbus_flags = 0;

    if (events & VIR_EVENT_HANDLE_READABLE)
        dbus_flags |= DBUS_WATCH_READABLE;
    if (events & VIR_EVENT_HANDLE_WRITABLE)
        dbus_flags |= DBUS_WATCH_WRITABLE;
    if (events & VIR_EVENT_HANDLE_ERROR)
        dbus_flags |= DBUS_WATCH_ERROR;
    if (events & VIR_EVENT_HANDLE_HANGUP)
        dbus_flags |= DBUS_WATCH_HANGUP;

    (void)dbus_watch_handle(watch, dbus_flags);

    while (dbus_connection_dispatch(systembus) == DBUS_DISPATCH_DATA_REMAINS)
        /* keep dispatching while data remains */;
}


static int virDBusTranslateWatchFlags(int dbus_flags)
{
    unsigned int flags = 0;
    if (dbus_flags & DBUS_WATCH_READABLE)
        flags |= VIR_EVENT_HANDLE_READABLE;
    if (dbus_flags & DBUS_WATCH_WRITABLE)
        flags |= VIR_EVENT_HANDLE_WRITABLE;
    if (dbus_flags & DBUS_WATCH_ERROR)
        flags |= VIR_EVENT_HANDLE_ERROR;
    if (dbus_flags & DBUS_WATCH_HANGUP)
        flags |= VIR_EVENT_HANDLE_HANGUP;
    return flags;
}


struct virDBusWatch
{
    int watch;
};

static void virDBusWatchFree(void *data) {
    struct virDBusWatch *info = data;
    VIR_FREE(info);
}

static dbus_bool_t virDBusAddWatch(DBusWatch *watch,
                                  void *data ATTRIBUTE_UNUSED)
{
    int flags = 0;
    int fd;
    struct virDBusWatch *info;

    if (VIR_ALLOC(info) < 0)
        return 0;

    if (dbus_watch_get_enabled(watch))
        flags = virDBusTranslateWatchFlags(dbus_watch_get_flags(watch));

# if HAVE_DBUS_WATCH_GET_UNIX_FD
    fd = dbus_watch_get_unix_fd(watch);
# else
    fd = dbus_watch_get_fd(watch);
# endif
    info->watch = virEventAddHandle(fd, flags,
                                    virDBusWatchCallback,
                                    watch, NULL);
    if (info->watch < 0) {
        VIR_FREE(info);
        return 0;
    }
    dbus_watch_set_data(watch, info, virDBusWatchFree);

    return 1;
}


static void virDBusRemoveWatch(DBusWatch *watch,
                               void *data ATTRIBUTE_UNUSED)
{
    struct virDBusWatch *info;

    info = dbus_watch_get_data(watch);

    (void)virEventRemoveHandle(info->watch);
}


static void virDBusToggleWatch(DBusWatch *watch,
                               void *data ATTRIBUTE_UNUSED)
{
    int flags = 0;
    struct virDBusWatch *info;

    if (dbus_watch_get_enabled(watch))
        flags = virDBusTranslateWatchFlags(dbus_watch_get_flags(watch));

    info = dbus_watch_get_data(watch);

    (void)virEventUpdateHandle(info->watch, flags);
}

#else /* ! HAVE_DBUS */
DBusConnection *virDBusGetSystemBus(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("DBus support not compiled into this binary"));
    return NULL;
}

#endif /* ! HAVE_DBUS */
