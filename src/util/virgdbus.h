/*
 * virgdbus.h: helper for using GDBus
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

#pragma once

#include <gio/gio.h>

#ifdef G_OS_UNIX
# include <gio/gunixfdlist.h>
#endif

#include "internal.h"

void
virGDBusSetSharedBus(bool shared);

GDBusConnection *
virGDBusGetSystemBus(void);

GDBusConnection *
virGDBusGetSessionBus(void);

bool
virGDBusHasSystemBus(void);

void
virGDBusCloseSystemBus(void);

int
virGDBusCallMethod(GDBusConnection *conn,
                   GVariant **reply,
                   const GVariantType *replyType,
                   virErrorPtr error,
                   const char *busName,
                   const char *objectPath,
                   const char *ifaceName,
                   const char *method,
                   GVariant *data);

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
                         GUnixFDList *dataFD);

int
virGDBusIsServiceEnabled(const char *name);

int
virGDBusIsServiceRegistered(const char *name);

bool
virGDBusErrorIsUnknownMethod(virErrorPtr err);

bool
virGDBusMessageIsSignal(GDBusMessage *message,
                        const char *iface,
                        const char *signal);
