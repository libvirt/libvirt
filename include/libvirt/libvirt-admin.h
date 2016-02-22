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

virAdmServerPtr virAdmConnectLookupServer(virAdmConnectPtr conn,
                                          const char *name,
                                          unsigned int flags);

/* Manage threadpool attributes */

/**
 * VIR_THREADPOOL_WORKERS_MIN:
 * Macro for the threadpool minWorkers limit: represents the bottom limit to
 * number of active workers in threadpool, as VIR_TYPED_PARAM_UINT.
 */

# define VIR_THREADPOOL_WORKERS_MIN "minWorkers"

/**
 * VIR_THREADPOOL_WORKERS_MAX:
 * Macro for the threadpool maxWorkers limit: represents the upper limit to
 * number of active workers in threadpool, as VIR_TYPED_PARAM_UINT.
 * The value of this limit has to be greater than VIR_THREADPOOL_WORKERS_MIN
 * at all times.
 */

# define VIR_THREADPOOL_WORKERS_MAX "maxWorkers"

/**
 * VIR_THREADPOOL_WORKERS_PRIORITY:
 * Macro for the threadpool nPrioWorkers attribute: represents the current number
 * of active priority workers in threadpool, as VIR_TYPED_PARAM_UINT.
 */

# define VIR_THREADPOOL_WORKERS_PRIORITY "prioWorkers"

/**
 * VIR_THREADPOOL_WORKERS_FREE:
 * Macro for the threadpool freeWorkers attribute: represents the current number
 * of free workers available to accomplish a job, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 */

# define VIR_THREADPOOL_WORKERS_FREE "freeWorkers"

/**
 * VIR_THREADPOOL_WORKERS_CURRENT:
 * Macro for the threadpool nWorkers attribute: represents the current number
 * of active ordinary workers in threadpool, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 */

# define VIR_THREADPOOL_WORKERS_CURRENT "nWorkers"

/**
 * VIR_THREADPOOL_JOB_QUEUE_DEPTH:
 * Macro for the threadpool jobQueueDepth attribute: represents the current
 * number of jobs waiting in a queue to be processed, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 */

# define VIR_THREADPOOL_JOB_QUEUE_DEPTH "jobQueueDepth"

/* Tunables for a server workerpool */
int virAdmServerGetThreadPoolParameters(virAdmServerPtr srv,
                                        virTypedParameterPtr *params,
                                        int *nparams,
                                        unsigned int flags);

int virAdmServerSetThreadPoolParameters(virAdmServerPtr srv,
                                        virTypedParameterPtr params,
                                        int nparams,
                                        unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_ADMIN_H__ */
