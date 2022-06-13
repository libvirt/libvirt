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
 */

#ifndef LIBVIRT_ADMIN_H
# define LIBVIRT_ADMIN_H

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
 *
 * Since: 2.0.0
 */
typedef struct _virAdmConnect virAdmConnect;

/**
 * virAdmServer:
 *
 * a virAdmServer is a private structure and client-side representation of
 * a remote server object
 *
 * Since: 2.0.0
 */
typedef struct _virAdmServer virAdmServer;

/**
 * virAdmClient:
 *
 * a virAdmClient is a private structure and client-side representation of
 * a remote server's client object (as server sees clients connected to it)
 *
 * Since: 2.0.0
 */
typedef struct _virAdmClient virAdmClient;

/**
 * virAdmConnectPtr:
 *
 * a virAdmConnectPtr is pointer to a virAdmConnect private structure,
 * this is the type used to reference a connection to the daemon
 * in the API.
 *
 * Since: 2.0.0
 */
typedef virAdmConnect *virAdmConnectPtr;

/**
 * virAdmServerPtr:
 *
 * a virAdmServerPtr is a pointer to a virAdmServer structure,
 * this is the type used to reference client-side representation of a
 * remote server object throughout all the APIs.
 *
 * Since: 2.0.0
 */
typedef virAdmServer *virAdmServerPtr;

/**
 * virAdmClientPtr:
 *
 * a virAdmClientPtr is a pointer to a virAdmClient structure,
 * this is the type used to reference client-side representation of a
 * client object throughout all the APIs.
 *
 * Since: 2.0.0
 */
typedef virAdmClient *virAdmClientPtr;

int virAdmInitialize(void);
virAdmConnectPtr virAdmConnectOpen(const char *name, unsigned int flags);
int virAdmConnectClose(virAdmConnectPtr conn);
int virAdmConnectRef(virAdmConnectPtr conn);
int virAdmConnectIsAlive(virAdmConnectPtr conn);
int virAdmServerFree(virAdmServerPtr srv);

int virAdmConnectListServers(virAdmConnectPtr conn,
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
 *
 * Since: 2.0.0
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
 *
 * Since: 2.0.0
 */

# define VIR_THREADPOOL_WORKERS_MIN "minWorkers"

/**
 * VIR_THREADPOOL_WORKERS_MAX:
 * Macro for the threadpool maxWorkers limit: represents the upper limit to
 * number of active workers in threadpool, as VIR_TYPED_PARAM_UINT.
 * The value of this limit has to be greater than VIR_THREADPOOL_WORKERS_MIN
 * at all times.
 *
 * Since: 2.0.0
 */

# define VIR_THREADPOOL_WORKERS_MAX "maxWorkers"

/**
 * VIR_THREADPOOL_WORKERS_PRIORITY:
 * Macro for the threadpool nPrioWorkers attribute: represents the current number
 * of active priority workers in threadpool, as VIR_TYPED_PARAM_UINT.
 *
 * Since: 2.0.0
 */

# define VIR_THREADPOOL_WORKERS_PRIORITY "prioWorkers"

/**
 * VIR_THREADPOOL_WORKERS_FREE:
 * Macro for the threadpool freeWorkers attribute: represents the current number
 * of free workers available to accomplish a job, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_THREADPOOL_WORKERS_FREE "freeWorkers"

/**
 * VIR_THREADPOOL_WORKERS_CURRENT:
 * Macro for the threadpool nWorkers attribute: represents the current number
 * of active ordinary workers in threadpool, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_THREADPOOL_WORKERS_CURRENT "nWorkers"

/**
 * VIR_THREADPOOL_JOB_QUEUE_DEPTH:
 * Macro for the threadpool jobQueueDepth attribute: represents the current
 * number of jobs waiting in a queue to be processed, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
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

/* virAdmClient object accessors */
unsigned long long virAdmClientGetID(virAdmClientPtr client);
long long virAdmClientGetTimestamp(virAdmClientPtr client);
int virAdmClientGetTransport(virAdmClientPtr client);
int virAdmClientFree(virAdmClientPtr client);

/**
 * virClientTransport:
 *
 * Since: 2.0.0
 */
typedef enum {
    VIR_CLIENT_TRANS_UNIX = 0, /* connection via UNIX socket (Since: 2.0.0) */
    VIR_CLIENT_TRANS_TCP,      /* connection via unencrypted TCP socket (Since: 2.0.0) */
    VIR_CLIENT_TRANS_TLS,      /* connection via encrypted TCP socket (Since: 2.0.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_CLIENT_TRANS_LAST /* (Since: 2.0.0) */
# endif
} virClientTransport;

int virAdmServerListClients(virAdmServerPtr srv,
                            virAdmClientPtr **clients,
                            unsigned int flags);

virAdmClientPtr
virAdmServerLookupClient(virAdmServerPtr srv,
                         unsigned long long id,
                         unsigned int flags);

/* Client identity info */

/**
 * VIR_CLIENT_INFO_READONLY:
 * Macro represents client's connection permission, whether the client is
 * connected in read-only mode or just the opposite - read-write,
 * as VIR_TYPED_PARAM_BOOLEAN.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_READONLY "readonly"

/**
 * VIR_CLIENT_INFO_SOCKET_ADDR:
 * Macro represents clients network socket address in a standard URI format:
 * (IPv4|[IPv6]):port, as VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_SOCKET_ADDR "sock_addr"

/**
 * VIR_CLIENT_INFO_SASL_USER_NAME:
 * Macro represents client's SASL user name, if SASL authentication is enabled
 * on the remote host, as VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_SASL_USER_NAME "sasl_user_name"

/**
 * VIR_CLIENT_INFO_X509_DISTINGUISHED_NAME:
 * Macro represents the 'distinguished name' field in X509 certificate the
 * client used to establish a TLS session with remote host, as
 * VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_X509_DISTINGUISHED_NAME "tls_x509_dname"

/**
 * VIR_CLIENT_INFO_UNIX_USER_ID:
 * Macro represents UNIX UID the client process is running with. Only relevant
 * for clients connected locally, i.e. via a UNIX socket,
 * as VIR_TYPED_PARAM_INT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_UNIX_USER_ID "unix_user_id"

/**
 * VIR_CLIENT_INFO_UNIX_USER_NAME:
 * Macro represents the user name that is bound to the client process's UID it
 * is running with. Only relevant for clients connected locally, i.e. via a
 * UNIX socket, as VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_UNIX_USER_NAME "unix_user_name"

/**
 * VIR_CLIENT_INFO_UNIX_GROUP_ID:
 * Macro represents UNIX GID the client process is running with. Only relevant
 * for clients connected locally, i.e. via a UNIX socket,
 * as VIR_TYPED_PARAM_INT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_UNIX_GROUP_ID "unix_group_id"

/**
 * VIR_CLIENT_INFO_UNIX_GROUP_NAME:
 * Macro represents the group name that is bound to the client process's GID it
 * is running with. Only relevant for clients connected locally, i.e. via a
 * UNIX socket, as VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_UNIX_GROUP_NAME "unix_group_name"

/**
 * VIR_CLIENT_INFO_UNIX_PROCESS_ID:
 * Macro represents the client process's pid it is running with. Only relevant
 * for clients connected locally, i.e. via a UNIX socket,
 * as VIR_TYPED_PARAM_INT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_UNIX_PROCESS_ID "unix_process_id"

/**
 * VIR_CLIENT_INFO_SELINUX_CONTEXT:
 * Macro represents the client's (peer's) SELinux context and this can either
 * be at socket layer or at transport layer, depending on the connection type,
 * as VIR_TYPED_PARAM_STRING.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_CLIENT_INFO_SELINUX_CONTEXT "selinux_context"

int virAdmClientGetInfo(virAdmClientPtr client,
                        virTypedParameterPtr *params,
                        int *nparams,
                        unsigned int flags);

int virAdmClientClose(virAdmClientPtr client, unsigned int flags);

/* Manage per-server client limits */

/**
 * VIR_SERVER_CLIENTS_MAX:
 * Macro for per-server nclients_max limit: represents the upper limit to
 * number of clients connected to the server, as uint.
 *
 * Since: 2.0.0
 */

# define VIR_SERVER_CLIENTS_MAX "nclients_max"

/**
 * VIR_SERVER_CLIENTS_CURRENT:
 * Macro for per-server nclients attribute: represents the current number of
 * clients connected to the server, as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_SERVER_CLIENTS_CURRENT "nclients"

/**
 * VIR_SERVER_CLIENTS_UNAUTH_MAX:
 * Macro for per-server nclients_unauth_max limit: represents the upper limit
 * to number of clients connected to the server, but not authenticated yet,
 * as VIR_TYPED_PARAM_UINT.
 *
 * Since: 2.0.0
 */

# define VIR_SERVER_CLIENTS_UNAUTH_MAX "nclients_unauth_max"

/**
 * VIR_SERVER_CLIENTS_UNAUTH_CURRENT:
 * Macro for per-server nclients_unauth attribute: represents the current
 * number of clients connected to the server, but not authenticated yet,
 * as VIR_TYPED_PARAM_UINT.
 *
 * NOTE: This attribute is read-only and any attempt to set it will be denied
 * by daemon
 *
 * Since: 2.0.0
 */

# define VIR_SERVER_CLIENTS_UNAUTH_CURRENT "nclients_unauth"

int virAdmServerGetClientLimits(virAdmServerPtr srv,
                                virTypedParameterPtr *params,
                                int *nparams,
                                unsigned int flags);

int virAdmServerSetClientLimits(virAdmServerPtr srv,
                                virTypedParameterPtr params,
                                int nparams,
                                unsigned int flags);

int virAdmServerUpdateTlsFiles(virAdmServerPtr srv,
                               unsigned int flags);

int virAdmConnectGetLoggingOutputs(virAdmConnectPtr conn,
                                   char **outputs,
                                   unsigned int flags);

int virAdmConnectGetLoggingFilters(virAdmConnectPtr conn,
                                   char **filters,
                                   unsigned int flags);

int virAdmConnectSetLoggingOutputs(virAdmConnectPtr conn,
                                   const char *outputs,
                                   unsigned int flags);

int virAdmConnectSetLoggingFilters(virAdmConnectPtr conn,
                                   const char *filters,
                                   unsigned int flags);

int virAdmConnectSetDaemonTimeout(virAdmConnectPtr conn,
                                  unsigned int timeout,
                                  unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* LIBVIRT_ADMIN_H */
