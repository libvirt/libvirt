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
 * virAdmConnect:
 *
 * a virAdmConnect is a private structure representing a connection to
 * libvirt daemon.
 */
typedef struct _virAdmConnect virAdmConnect;

/**
 * virAdmServer:
 *
 * a virAdmServer is a private structure and client-side representation of
 * a remote server object
 */
typedef struct _virAdmServer virAdmServer;

/**
 * virAdmConnectPtr:
 *
 * a virAdmConnectPtr is pointer to a virAdmConnect private structure,
 * this is the type used to reference a connection to the daemon
 * in the API.
 */
typedef virAdmConnect *virAdmConnectPtr;

/**
 * virAdmServerPtr:
 *
 * a virAdmServerPtr is a pointer to a virAdmServer structure,
 * this is the type used to reference client-side representation of a
 * remote server object throughout all the APIs.
 */
typedef virAdmServer *virAdmServerPtr;

virAdmConnectPtr virAdmConnectOpen(const char *name, unsigned int flags);
int virAdmConnectClose(virAdmConnectPtr conn);
int virAdmConnectRef(virAdmConnectPtr conn);
int virAdmConnectIsAlive(virAdmConnectPtr conn);
int virAdmServerFree(virAdmServerPtr srv);

int virAdmConnectListServers(virAdmConnectPtr dmn,
                             virAdmServerPtr **servers,
                             unsigned int flags);

int virAdmGetVersion(unsigned long long *libVer);

char *virAdmConnectGetURI(virAdmConnectPtr conn);

int virAdmConnectGetLibVersion(virAdmConnectPtr conn,
                               unsigned long long *libVer);

/**
 * virAdmConnectCloseFunc:
 * @conn: virAdmConnect connection
 * @reason: reason why the connection was closed (see virConnectCloseReason)
 * @opaque: opaque client data
 *
 * A callback to be registered, in case a connection was closed.
 */
typedef void (*virAdmConnectCloseFunc)(virAdmConnectPtr conn,
                                       int reason,
                                       void *opaque);

int virAdmConnectRegisterCloseCallback(virAdmConnectPtr conn,
                                       virAdmConnectCloseFunc cb,
                                       void *opaque,
                                       virFreeCallback freecb);
int virAdmConnectUnregisterCloseCallback(virAdmConnectPtr conn,
                                         virAdmConnectCloseFunc cb);

const char *virAdmServerGetName(virAdmServerPtr srv);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_ADMIN_H__ */
