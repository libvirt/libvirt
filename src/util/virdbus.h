/*
 * virdbus.h: helper for using DBus
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRDBUS_H
# define LIBVIRT_VIRDBUS_H

# ifdef WITH_DBUS
#  undef interface /* Work around namespace pollution in mingw's rpc.h */
#  include <dbus/dbus.h>
# else
#  define DBusConnection void
#  define DBusMessage void
# endif
# include "internal.h"

# include <stdarg.h>

void virDBusSetSharedBus(bool shared);

DBusConnection *virDBusGetSystemBus(void);
bool virDBusHasSystemBus(void);
void virDBusCloseSystemBus(void);
DBusConnection *virDBusGetSessionBus(void);

int virDBusCreateMethod(DBusMessage **call,
                        const char *destination,
                        const char *path,
                        const char *iface,
                        const char *member,
                        const char *types, ...);
int virDBusCreateMethodV(DBusMessage **call,
                         const char *destination,
                         const char *path,
                         const char *iface,
                         const char *member,
                         const char *types,
                         va_list args);
int virDBusCreateReply(DBusMessage **reply,
                       const char *types, ...);
int virDBusCreateReplyV(DBusMessage **reply,
                        const char *types,
                        va_list args);

int virDBusCallMethod(DBusConnection *conn,
                      DBusMessage **reply,
                      virErrorPtr error,
                      const char *destination,
                      const char *path,
                      const char *iface,
                      const char *member,
                      const char *types, ...);
int virDBusMessageRead(DBusMessage *msg,
                       const char *types, ...);
void virDBusMessageUnref(DBusMessage *msg);

int virDBusIsServiceEnabled(const char *name);
int virDBusIsServiceRegistered(const char *name);

bool virDBusErrorIsUnknownMethod(virErrorPtr err);
#endif /* LIBVIRT_VIRDBUS_H */
