/*
 * libvirt-admin.h: Admin interface for libvirt
 * Summary: Interfaces for handling server-related tasks
 * Description: Provides the interfaces of the libvirt library to operate
 *              with the server itself, not any hypervisors.
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

#ifndef __VIR_ADMIN_H__
# define __VIR_ADMIN_H__

# ifdef __cplusplus
extern "C" {
# endif

# define __VIR_ADMIN_H_INCLUDES__
# include <libvirt/libvirt-common.h>
# undef __VIR_ADMIN_H_INCLUDES__

/**
 * virAdmDaemon:
 *
 * a virAdmDaemon is a private structure representing a remote daemon.
 */
typedef struct _virAdmDaemon virAdmDaemon;

/**
 * virAdmDaemonPtr:
 *
 * a virAdmDaemonPtr is pointer to a virAdmDaemon private structure,
 * this is the type used to reference a daemon in the API.
 */
typedef virAdmDaemon *virAdmDaemonPtr;

virAdmDaemonPtr virAdmDaemonOpen(const char *name, unsigned int flags);
int virAdmDaemonClose(virAdmDaemonPtr dmn);

int virAdmDaemonRef(virAdmDaemonPtr dmn);
int virAdmDaemonIsAlive(virAdmDaemonPtr dmn);

int virAdmGetVersion(unsigned long long *libVer);

char *virAdmDaemonGetURI(virAdmDaemonPtr dmn);

int virAdmDaemonGetVersion(virAdmDaemonPtr dmn,
                           unsigned long long *libVer);

/**
 * virAdmDaemonCloseFunc:
 * @dmn: virAdmDaemon connection
 * @reason: reason why the connection was closed (see virConnectCloseReason)
 * @opaque: opaque client data
 *
 * A callback to be registered, in case a connection was closed.
 */
typedef void (*virAdmDaemonCloseFunc)(virAdmDaemonPtr dmn,
                                       int reason,
                                       void *opaque);

int virAdmDaemonRegisterCloseCallback(virAdmDaemonPtr dmn,
                                      virAdmDaemonCloseFunc cb,
                                      void *opaque,
                                      virFreeCallback freecb);
int virAdmDaemonUnregisterCloseCallback(virAdmDaemonPtr dmn,
                                        virAdmDaemonCloseFunc cb);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_ADMIN_H__ */
