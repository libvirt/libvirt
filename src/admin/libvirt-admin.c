/*
 * libvirt-admin.c
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

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "configmake.h"

#include "viralloc.h"
#include "virconf.h"
#include "virlog.h"
#include "virnetclient.h"
#include "virobject.h"
#include "viruri.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN


VIR_LOG_INIT("libvirt-admin");

#include "admin_remote.c"

static bool virAdmGlobalError;
static virOnceControl virAdmGlobalOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
virAdmGlobalInit(void)
{
    /* It would be nice if we could trace the use of this call, to
     * help diagnose in log files if a user calls something other than
     * virAdmConnectOpen first.  But we can't rely on VIR_DEBUG working
     * until after initialization is complete, and since this is
     * one-shot, we never get here again.  */
    if (virErrorInitialize() < 0)
        goto error;

    if (virLogSetFromEnv() < 0)
        goto error;

#ifdef WITH_LIBINTL_H
    if (!bindtextdomain(PACKAGE, LOCALEDIR))
        goto error;
#endif /* WITH_LIBINTL_H */

    if (!VIR_CLASS_NEW(remoteAdminPriv, virClassForObjectLockable()))
        goto error;

    return;
 error:
    virAdmGlobalError = true;
}

/**
 * virAdmInitialize:
 *
 * Initialize the library.
 *
 * This method is automatically invoked by virAdmConnectOpen() API. Therefore,
 * in most cases it is unnecessary to call this method manually, unless an
 * event loop should be set up by calling virEventRegisterImpl() or the error
 * reporting of the first connection attempt with virSetErrorFunc() should be
 * altered prior to setting up connections. If the latter is the case, it is
 * necessary for the application to call virAdmInitialize.
 *
 * Returns 0 in case of success, -1 in case of error
 *
 * Since: 2.0.0
 */
int
virAdmInitialize(void)
{
    if (virOnce(&virAdmGlobalOnce, virAdmGlobalInit) < 0)
        return -1;

    if (virAdmGlobalError)
        return -1;

    return 0;
}

static char *
getSocketPath(virURI *uri)
{
    g_autofree char *rundir = virGetUserRuntimeDirectory();
    g_autofree char *sock_path = NULL;
    size_t i = 0;

    if (!uri)
        return NULL;


    for (i = 0; i < uri->paramsCount; i++) {
        virURIParam *param = &uri->params[i];

        if (STREQ(param->name, "socket")) {
            g_free(sock_path);
            sock_path = g_strdup(param->value);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown URI parameter '%1$s'"), param->name);
            return NULL;
        }
    }

    if (!sock_path) {
        g_autofree char *sockbase = NULL;
        bool legacy = false;

        if (!uri->scheme) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("No URI scheme specified"));
            return NULL;
        }
        if (STREQ(uri->scheme, "libvirtd")) {
            legacy = true;
        } else if (!STRPREFIX(uri->scheme, "virt")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported URI scheme '%1$s'"),
                           uri->scheme);
            return NULL;
        }

        if (legacy) {
            sockbase = g_strdup("libvirt-admin-sock");
        } else {
            sockbase = g_strdup_printf("%s-admin-sock", uri->scheme);
        }

        if (STREQ_NULLABLE(uri->path, "/system")) {
            sock_path = g_strdup_printf(RUNSTATEDIR "/libvirt/%s", sockbase);
        } else if (STREQ_NULLABLE(uri->path, "/session")) {
            sock_path = g_strdup_printf("%s/%s", rundir, sockbase);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid URI path '%1$s', try '/system'"),
                           NULLSTR_EMPTY(uri->path));
            return NULL;
        }
    }

    return g_steal_pointer(&sock_path);
}

static int
virAdmGetDefaultURI(virConf *conf, char **uristr)
{
    const char *defname = getenv("LIBVIRT_ADMIN_DEFAULT_URI");
    if (defname && *defname) {
        *uristr = g_strdup(defname);
        VIR_DEBUG("Using LIBVIRT_ADMIN_DEFAULT_URI '%s'", *uristr);
    } else {
        if (virConfGetValueString(conf, "uri_default", uristr) < 0)
            return -1;

        if (*uristr) {
            VIR_DEBUG("Using config file uri '%s'", *uristr);
        } else {
            /* Since we can't probe connecting via any hypervisor driver as libvirt
             * does, if no explicit URI was given and neither the environment
             * variable, nor the configuration parameter had previously been set,
             * we set the default admin server URI to 'libvirtd:///system' or
             * 'libvirtd:///session' depending on the process's EUID.
             */
            if (geteuid() == 0) {
                *uristr = g_strdup("libvirtd:///system");
            } else {
                *uristr = g_strdup("libvirtd:///session");
            }
        }
    }

    return 0;
}

/**
 * virAdmConnectOpen:
 * @name: uri of the daemon to connect to, NULL for default
 * @flags: bitwise-OR of virConnectFlags; so far the only supported flag is
 *         VIR_CONNECT_NO_ALIASES
 *
 * Opens connection to admin interface of the daemon.
 *
 * Returns @virAdmConnectPtr object or NULL on error
 *
 * Since: 2.0.0
 */
virAdmConnectPtr
virAdmConnectOpen(const char *name, unsigned int flags)
{
    g_autofree char *sock_path = NULL;
    char *alias = NULL;
    virAdmConnectPtr conn = NULL;
    g_autoptr(virConf) conf = NULL;
    g_autofree char *uristr = NULL;

    if (virAdmInitialize() < 0)
        goto error;

    VIR_DEBUG("name=%s flags=0x%x", NULLSTR(name), flags);
    virResetLastError();

    if (!(conn = virAdmConnectNew()))
        goto error;

    if (virConfLoadConfig(&conf, "libvirt-admin.conf") < 0)
        goto error;

    if (name) {
        uristr = g_strdup(name);
    } else {
        if (virAdmGetDefaultURI(conf, &uristr) < 0)
            goto error;
    }

    if ((!(flags & VIR_CONNECT_NO_ALIASES) &&
         virURIResolveAlias(conf, uristr, &alias) < 0))
        goto error;

    if (alias) {
        g_free(uristr);
        uristr = alias;
    }

    if (!(conn->uri = virURIParse(uristr)))
        goto error;

    if (!(sock_path = getSocketPath(conn->uri)))
        goto error;

    if (!(conn->privateData = remoteAdminPrivNew(sock_path)))
        goto error;

    conn->privateDataFreeFunc = remoteAdminPrivFree;

    if (remoteAdminConnectOpen(conn, flags) < 0)
        goto error;

    return conn;

 error:
    virDispatchError(NULL);
    virObjectUnref(conn);
    return NULL;
}

/**
 * virAdmConnectClose:
 * @conn: pointer to admin connection to close
 *
 * This function closes the admin connection to the Hypervisor. This should not
 * be called if further interaction with the Hypervisor are needed especially if
 * there is running domain which need further monitoring by the application.
 *
 * Connections are reference counted; the count is explicitly increased by the
 * initial virAdmConnectOpen, as well as virAdmConnectRef; it is also temporarily
 * increased by other API that depend on the connection remaining alive.  The
 * open and every virAdmConnectRef call should have a matching
 * virAdmConnectClose, and all other references will be released after the
 * corresponding operation completes.
 *
 * Returns a positive number if at least 1 reference remains on success. The
 * returned value should not be assumed to be the total reference count. A
 * return of 0 implies no references remain and the connection is closed and
 * memory has been freed. A return of -1 implies a failure.
 *
 * It is possible for the last virAdmConnectClose to return a positive value if
 * some other object still has a temporary reference to the connection, but the
 * application should not try to further use a connection after the
 * virAdmConnectClose that matches the initial open.
 *
 * Since: 2.0.0
 */
int
virAdmConnectClose(virAdmConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();
    if (!conn)
        return 0;

    virCheckAdmConnectReturn(conn, -1);

    virAdmConnectWatchDispose();
    virObjectUnref(conn);
    if (virAdmConnectWasDisposed())
        return 0;
    return 1;
}


/**
 * virAdmConnectRef:
 * @conn: the connection to hold a reference on
 *
 * Increment the reference count on the connection. For each additional call to
 * this method, there shall be a corresponding call to virAdmConnectClose to
 * release the reference count, once the caller no longer needs the reference to
 * this object.
 *
 * This method is typically useful for applications where multiple threads are
 * using a connection, and it is required that the connection remain open until
 * all threads have finished using it. I.e., each new thread using a connection
 * would increment the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure
 *
 * Since: 2.0.0
 */
int
virAdmConnectRef(virAdmConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    virObjectRef(conn);

    return 0;
}

/**
 * virAdmGetVersion:
 * @libVer: where to store the library version
 *
 * Provides version information. @libVer is the version of the library and will
 * always be set unless an error occurs in which case an error code and a
 * generic message will be returned. @libVer format is as follows:
 * major * 1,000,000 + minor * 1,000 + release.
 *
 * NOTE: To get the remote side library version use virAdmConnectGetLibVersion
 * instead.
 *
 * Returns 0 on success, -1 in case of an error.
 *
 * Since: 2.0.0
 */
int
virAdmGetVersion(unsigned long long *libVer)
{
    if (virAdmInitialize() < 0)
        goto error;

    VIR_DEBUG("libVer=%p", libVer);

    virResetLastError();
    if (!libVer)
        goto error;
    *libVer = LIBVIR_VERSION_NUMBER;

    return 0;

 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectIsAlive:
 * @conn: connection to admin server
 *
 * Decide whether the connection to the admin server is alive or not.
 * Connection is considered alive if the channel it is running over is not
 * closed.
 *
 * Returns 1, if the connection is alive, 0 if there isn't an existing
 * connection at all or the channel has already been closed, or -1 on error.
 *
 * Since: 2.0.0
 */
int
virAdmConnectIsAlive(virAdmConnectPtr conn)
{
    bool ret;
    remoteAdminPriv *priv = NULL;

    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    if (!conn)
        return 0;

    virCheckAdmConnectReturn(conn, -1);

    priv = conn->privateData;
    virObjectLock(priv);
    ret = virNetClientIsOpen(priv->client);
    virObjectUnlock(priv);

    return ret;
}

/**
 * virAdmConnectGetURI:
 * @conn: pointer to an admin connection
 *
 * String returned by this method is normally the same as the string passed
 * to the virAdmConnectOpen. Even if NULL was passed to virAdmConnectOpen,
 * this method returns a non-null URI string.
 *
 * Returns an URI string related to the connection or NULL in case of an error.
 * Caller is responsible for freeing the string.
 *
 * Since: 2.0.0
 */
char *
virAdmConnectGetURI(virAdmConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckAdmConnectReturn(conn, NULL);

    return virURIFormat(conn->uri);
}

/**
 * virAdmConnectRegisterCloseCallback:
 * @conn: connection to admin server
 * @cb: callback to be invoked upon connection close
 * @opaque: user data to pass to @cb
 * @freecb: callback to free @opaque
 *
 * Registers a callback to be invoked when the connection
 * is closed. This callback is invoked when there is any
 * condition that causes the socket connection to the
 * hypervisor to be closed.
 *
 * The @freecb must not invoke any other libvirt public
 * APIs, since it is not called from a re-entrant safe
 * context.
 *
 * Returns 0 on success, -1 on error
 *
 * Since: 2.0.0
 */
int virAdmConnectRegisterCloseCallback(virAdmConnectPtr conn,
                                       virAdmConnectCloseFunc cb,
                                       void *opaque,
                                       virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckAdmConnectReturn(conn, -1);

    virObjectRef(conn);

    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A close callback is already registered"));
        goto error;
    }

    conn->closeCallback->conn = conn;
    conn->closeCallback->callback = cb;
    conn->closeCallback->opaque = opaque;
    conn->closeCallback->freeCallback = freecb;

    virObjectUnlock(conn->closeCallback);

    return 0;

 error:
    virObjectUnlock(conn->closeCallback);
    virDispatchError(NULL);
    virObjectUnref(conn);
    return -1;

}

/**
 * virAdmConnectUnregisterCloseCallback:
 * @conn: pointer to connection object
 * @cb: pointer to the current registered callback
 *
 * Unregisters the callback previously set with the
 * virAdmConnectRegisterCloseCallback method. The callback
 * will no longer receive notifications when the connection
 * closes. If a virFreeCallback was provided at time of
 * registration, it will be invoked.
 *
 * Returns 0 on success, -1 on error
 *
 * Since: 2.0.0
 */
int virAdmConnectUnregisterCloseCallback(virAdmConnectPtr conn,
                                         virAdmConnectCloseFunc cb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckAdmConnectReturn(conn, -1);
    virCheckNonNullArgGoto(cb, error);

    if (virAdmConnectCloseCallbackDataUnregister(conn->closeCallback, cb) < 0)
        goto error;

    return 0;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectGetLibVersion:
 * @conn: pointer to an active admin connection
 * @libVer: stores the current remote libvirt version number
 *
 * Retrieves the remote side libvirt version used by the daemon. Format
 * returned in @libVer is of a following pattern:
 * major * 1,000,000 + minor * 1,000 + release.
 *
 * Returns 0 on success, -1 on failure and @libVer follows this format:
 *
 * Since: 2.0.0
 */
int virAdmConnectGetLibVersion(virAdmConnectPtr conn,
                               unsigned long long *libVer)
{
    VIR_DEBUG("conn=%p, libVir=%p", conn, libVer);

    virResetLastError();

    virCheckAdmConnectReturn(conn, -1);
    virCheckNonNullArgReturn(libVer, -1);

    if (remoteAdminConnectGetLibVersion(conn, libVer) < 0)
        goto error;

    return 0;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerGetName:
 * @srv: a server object
 *
 *  Get the public name for specified server
 *
 * Returns a pointer to the name or NULL. The string doesn't need to be
 * deallocated since its lifetime will be the same as the server object.
 *
 * Since: 2.0.0
 */
const char *
virAdmServerGetName(virAdmServerPtr srv)
{
    VIR_DEBUG("server=%p", srv);

    virResetLastError();
    virCheckAdmServerReturn(srv, NULL);

    return srv->name;
}

/**
 * virAdmServerFree:
 * @srv: server object
 *
 * Release the server object. The running instance is kept alive.
 * The data structure is freed and should not be used thereafter.
 *
 * Returns 0 on success, -1 on failure.
 *
 * Since: 2.0.0
 */
int virAdmServerFree(virAdmServerPtr srv)
{
    VIR_DEBUG("server=%p", srv);

    virResetLastError();

    if (!srv)
        return 0;

    virCheckAdmServerReturn(srv, -1);

    virObjectUnref(srv);
    return 0;
}

/**
 * virAdmClientGetID:
 * @client: a client object
 *
 * Get client's unique numeric ID.
 *
 * Returns numeric value used for client's ID or -1 in case of an error.
 *
 * Since: 2.0.0
 */
unsigned long long
virAdmClientGetID(virAdmClientPtr client)
{
    VIR_DEBUG("client=%p", client);

    virResetLastError();
    virCheckAdmClientReturn(client, -1);
    return client->id;
}

/**
 * virAdmClientGetTimestamp:
 * @client: a client object
 *
 * Get client's connection time.
 * A situation may happen, that some clients had connected prior to the update
 * to admin API, thus, libvirt assigns these clients epoch time to express that
 * it doesn't know when the client connected.
 *
 * Returns client's connection timestamp (seconds from epoch in UTC) or 0
 * (epoch time) if libvirt doesn't have any information about client's
 * connection time, or -1 in case of an error.
 *
 * Since: 2.0.0
 */
long long
virAdmClientGetTimestamp(virAdmClientPtr client)
{
    VIR_DEBUG("client=%p", client);

    virResetLastError();
    virCheckAdmClientReturn(client, -1);
    return client->timestamp;
}

/**
 * virAdmClientGetTransport:
 * @client: a client object
 *
 * Get client's connection transport type. This information can be helpful to
 * differentiate between clients connected locally or remotely. An exception to
 * this would be SSH which is one of libvirt's supported transports.
 * Although SSH creates a channel between two (preferably) remote endpoints,
 * the client process libvirt spawns automatically on the remote side will
 * still connect to a UNIX socket, thus becoming indistinguishable from any
 * other locally connected clients.
 *
 * Returns integer representation of the connection transport used by @client
 * (this will be one of virClientTransport) or -1 in case of an error.
 *
 * Since: 2.0.0
 */
int
virAdmClientGetTransport(virAdmClientPtr client)
{
    VIR_DEBUG("client=%p", client);

    virResetLastError();
    virCheckAdmClientReturn(client, -1);
    return client->transport;
}

/**
 * virAdmClientFree:
 * @client: a client object
 *
 * Release the client object. The running instance is kept alive. The data
 * structure is freed and should not be used thereafter.
 *
 * Returns 0 in success, -1 on failure.
 *
 * Since: 2.0.0
 */
int virAdmClientFree(virAdmClientPtr client)
{
    VIR_DEBUG("client=%p", client);

    virResetLastError();

    if (!client)
        return 0;

    virCheckAdmClientReturn(client, -1);

    virObjectUnref(client);
    return 0;
}

/**
 * virAdmConnectListServers:
 * @conn: daemon connection reference
 * @servers: Pointer to a list to store an array containing objects or NULL
 *           if the list is not required (number of servers only)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect list of all servers provided by daemon the client is connected to.
 *
 * Returns the number of servers available on daemon side or -1 in case of a
 * failure, setting @servers to NULL. There is a guaranteed extra element set
 * to NULL in the @servers list returned to make the iteration easier, excluding
 * this extra element from the final count.
 * Caller is responsible to call virAdmServerFree() on each list element,
 * followed by freeing @servers.
 *
 * Since: 2.0.0
 */
int
virAdmConnectListServers(virAdmConnectPtr conn,
                         virAdmServerPtr **servers,
                         unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, servers=%p, flags=0x%x", conn, servers, flags);

    virResetLastError();

    if (servers)
        *servers = NULL;

    virCheckAdmConnectReturn(conn, -1);
    if ((ret = remoteAdminConnectListServers(conn, servers, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectLookupServer:
 * @conn: daemon connection reference
 * @name: name of the server too lookup
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Try to lookup a server on the given daemon based on @name.
 *
 * virAdmServerFree() should be used to free the resources after the
 * server object is no longer needed.
 *
 * Returns the requested server or NULL in case of failure.  If the
 * server cannot be found, then VIR_ERR_NO_SERVER error is raised.
 *
 * Since: 2.0.0
 */
virAdmServerPtr
virAdmConnectLookupServer(virAdmConnectPtr conn,
                          const char *name,
                          unsigned int flags)
{
    virAdmServerPtr ret = NULL;

    VIR_DEBUG("conn=%p, name=%s, flags=0x%x", conn, NULLSTR(name), flags);
    virResetLastError();

    virCheckAdmConnectGoto(conn, cleanup);
    virCheckNonNullArgGoto(name, cleanup);

    ret = remoteAdminConnectLookupServer(conn, name, flags);
 cleanup:
    if (!ret)
        virDispatchError(NULL);
    return ret;
}

/**
 * virAdmServerGetThreadPoolParameters:
 * @srv: a valid server object reference
 * @params: pointer to a list of typed parameters which will be allocated
 *          to store all returned parameters
 * @nparams: pointer which will hold the number of params returned in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Retrieves threadpool parameters from @srv. Upon successful completion,
 * @params will be allocated automatically to hold all returned data, setting
 * @nparams accordingly.
 * When extracting parameters from @params, following search keys are
 * supported:
 *      VIR_THREADPOOL_WORKERS_MIN
 *      VIR_THREADPOOL_WORKERS_MAX
 *      VIR_THREADPOOL_WORKERS_PRIORITY
 *      VIR_THREADPOOL_WORKERS_FREE
 *      VIR_THREADPOOL_WORKERS_CURRENT
 *
 * Returns 0 on success, -1 in case of an error.
 *
 * Since: 2.0.0
 */
int
virAdmServerGetThreadPoolParameters(virAdmServerPtr srv,
                                    virTypedParameterPtr *params,
                                    int *nparams,
                                    unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("srv=%p, params=%p, nparams=%p, flags=0x%x",
              srv, params, nparams, flags);

    virResetLastError();

    virCheckAdmServerReturn(srv, -1);
    virCheckNonNullArgGoto(params, error);

    if ((ret = remoteAdminServerGetThreadPoolParameters(srv, params, nparams,
                                                        flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerSetThreadPoolParameters:
 * @srv: a valid server object reference
 * @params: pointer to threadpool typed parameter objects
 * @nparams: number of parameters in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Change server threadpool parameters according to @params. Note that some
 * tunables are read-only, thus any attempt to set them will result in a
 * failure.
 *
 * Returns 0 on success, -1 in case of an error.
 *
 * Since: 2.0.0
 */
int
virAdmServerSetThreadPoolParameters(virAdmServerPtr srv,
                                    virTypedParameterPtr params,
                                    int nparams,
                                    unsigned int flags)
{
    VIR_DEBUG("srv=%p, params=%p, nparams=%d, flags=0x%x",
              srv, params, nparams, flags);

    virResetLastError();

    virCheckAdmServerReturn(srv, -1);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if (remoteAdminServerSetThreadPoolParameters(srv, params,
                                                 nparams, flags) < 0)
        goto error;

    return 0;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerListClients:
 * @srv: a valid server object reference
 * @clients: pointer to a list to store an array containing objects or NULL
 *           if the list is not required (number of clients only)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect list of all clients connected to daemon on server @srv.
 *
 * Returns the number of clients connected to daemon on server @srv -1 in case
 * of a failure, setting @clients to NULL. There is a guaranteed extra element
 * set to NULL in the @clients list returned to make the iteration easier,
 * excluding this extra element from the final count.
 * Caller is responsible to call virAdmClientFree() on each list element,
 * followed by freeing @clients.
 *
 * Since: 2.0.0
 */
int
virAdmServerListClients(virAdmServerPtr srv,
                        virAdmClientPtr **clients,
                        unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("srv=%p, clients=%p, flags=0x%x", srv, clients, flags);

    virResetLastError();

    if (clients)
        *clients = NULL;

    virCheckAdmServerReturn(srv, -1);
    if ((ret = remoteAdminServerListClients(srv, clients, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerLookupClient:
 * @srv: a valid server object reference
 * @id: ID of the client to lookup on server @srv
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Try to lookup a client on the given server based on @id.
 *
 * virAdmClientFree() should be used to free the resources after the
 * client object is no longer needed.
 *
 * Returns the requested client or NULL in case of failure.  If the
 * client could not be found, then VIR_ERR_NO_CLIENT error is raised.
 *
 * Since: 2.0.0
 */
virAdmClientPtr
virAdmServerLookupClient(virAdmServerPtr srv,
                         unsigned long long id,
                         unsigned int flags)
{
    virAdmClientPtr ret = NULL;

    VIR_DEBUG("srv=%p, id=%llu, flags=0x%x", srv, id, flags);
    virResetLastError();

    virCheckAdmServerGoto(srv, error);

    if (!(ret = remoteAdminServerLookupClient(srv, id, flags)))
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return NULL;
}

/**
 * virAdmClientGetInfo:
 * @client: a client object reference
 * @params: pointer to a list of typed parameters which will be allocated
 *          to store all returned parameters
 * @nparams: pointer which will hold the number of params returned in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Extract identity information about a client. Attributes returned in @params
 * are mostly transport-dependent, i.e. some attributes including client
 * process's pid, gid, uid, or remote side's socket address are only available
 * for a specific connection type - local vs remote.
 * Other identity attributes like authentication method used
 * (if authentication is enabled on the remote host), SELinux context, or
 * an indicator whether client is connected via a read-only connection are
 * independent of the connection transport.
 *
 * Note that the read-only connection indicator returns false for TCP/TLS
 * clients because libvirt treats such connections as read-write by default,
 * even though a TCP client is able to restrict access to certain APIs for
 * itself.
 *
 * Returns 0 if the information has been successfully retrieved or -1 in case
 * of an error.
 *
 * Since: 2.0.0
 */
int
virAdmClientGetInfo(virAdmClientPtr client,
                    virTypedParameterPtr *params,
                    int *nparams,
                    unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("client=%p, params=%p, nparams=%p, flags=0x%x",
              client, params, nparams, flags);

    virResetLastError();
    virCheckAdmClientReturn(client, -1);
    virCheckNonNullArgGoto(params, error);

    if ((ret = remoteAdminClientGetInfo(client, params, nparams, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmClientClose:
 * @client: a valid client object reference
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Close @client's connection to daemon forcefully.
 *
 * Returns 0 if the daemon's connection with @client was closed successfully
 * or -1 in case of an error.
 *
 * Since: 2.0.0
 */
int virAdmClientClose(virAdmClientPtr client,
                      unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("client=%p, flags=0x%x", client, flags);
    virResetLastError();

    virCheckAdmClientGoto(client, error);

    if ((ret = remoteAdminClientClose(client, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerGetClientLimits:
 * @srv: a valid server object reference
 * @params: pointer to client limits object
 *          (return value, allocated automatically)
 * @nparams: pointer to number of parameters returned in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Retrieve client limits from server @srv. These include:
 *  - current number of clients connected to @srv,
 *  - maximum number of clients connected to @srv,
 *  - current number of clients connected to @srv waiting for authentication,
 *  - maximum number of clients connected to @srv that can be wainting for
 *  authentication.
 *
 * Returns 0 on success, allocating @params to size returned in @nparams, or
 * -1 in case of an error. Caller is responsible for deallocating @params.
 *
 * Since: 2.0.0
 */
int
virAdmServerGetClientLimits(virAdmServerPtr srv,
                            virTypedParameterPtr *params,
                            int *nparams,
                            unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("srv=%p, params=%p, nparams=%p, flags=0x%x",
              srv, params, nparams, flags);
    virResetLastError();

    virCheckAdmServerGoto(srv, error);

    if ((ret = remoteAdminServerGetClientLimits(srv, params,
                                                nparams, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmServerSetClientLimits:
 * @srv: a valid server object reference
 * @params: pointer to client limits object
 * @nparams: number of parameters in @params
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Change client limits configuration on server @srv.
 *
 * Caller is responsible for allocating @params prior to calling this function.
 * See 'Manage per-server client limits' in libvirt-admin.h for
 * supported parameters in @params.
 *
 * Returns 0 if the limits have been changed successfully or -1 in case of an
 * error.
 *
 * Since: 2.0.0
 */
int
virAdmServerSetClientLimits(virAdmServerPtr srv,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("srv=%p, params=%p, nparams=%d, flags=0x%x", srv, params, nparams,
              flags);
    VIR_TYPED_PARAMS_DEBUG(params, nparams);

    virResetLastError();

    virCheckAdmServerGoto(srv, error);
    virCheckNonNullArgGoto(params, error);
    virCheckNonNegativeArgGoto(nparams, error);

    if ((ret = remoteAdminServerSetClientLimits(srv, params, nparams,
                                                flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return ret;
}

/**
 * virAdmServerUpdateTlsFiles:
 * @srv: a valid server object reference
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Notify server to update tls file, such as cacert, cacrl, server cert / key.
 *
 * Returns 0 if the TLS files have been updated successfully or -1 in case of an
 * error.
 *
 * Since: 6.2.0
 */
int
virAdmServerUpdateTlsFiles(virAdmServerPtr srv,
                           unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("srv=%p, flags=0x%x", srv, flags);
    virResetLastError();

    virCheckAdmServerGoto(srv, error);

    if ((ret = remoteAdminServerUpdateTlsFiles(srv, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return ret;
}

/**
 * virAdmConnectGetLoggingOutputs:
 * @conn: pointer to an active admin connection
 * @outputs: pointer to a variable to store a string containing all currently
 *           defined logging outputs on daemon (allocated automatically) or
 *           NULL if just the number of defined outputs is required
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Retrieves a list of currently installed logging outputs. Outputs returned
 * are contained within an automatically allocated string and delimited by
 * spaces. The format of each output conforms to the format described in
 * daemon's configuration file (e.g. libvirtd.conf).
 *
 * To retrieve individual outputs, additional parsing needs to be done by the
 * caller. Caller is also responsible for freeing @outputs correctly.
 *
 * Returns the count of outputs in @outputs, or -1 in case of an error.
 *
 * Since: 3.0.0
 */
int
virAdmConnectGetLoggingOutputs(virAdmConnectPtr conn,
                               char **outputs,
                               unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, flags=0x%x", conn, flags);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    if ((ret = remoteAdminConnectGetLoggingOutputs(conn, outputs,
                                                   flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectGetLoggingFilters:
 * @conn: pointer to an active admin connection
 * @filters: pointer to a variable to store a string containing all currently
 *           defined logging filters on daemon (allocated automatically) or
 *           NULL if just the number of defined outputs is required
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Retrieves a list of currently installed logging filters. Filters returned
 * are contained within an automatically allocated string and delimited by
 * spaces. The format of each filter conforms to the format described in
 * daemon's configuration file (e.g. libvirtd.conf).
 *
 * To retrieve individual filters, additional parsing needs to be done by the
 * caller. Caller is also responsible for freeing @filters correctly.
 *
 * Returns the number of filters returned in @filters, or -1 in case of
 * an error.
 *
 * Since: 3.0.0
 */
int
virAdmConnectGetLoggingFilters(virAdmConnectPtr conn,
                               char **filters,
                               unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, filters=%p, flags=0x%x",
              conn, filters, flags);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    if ((ret = remoteAdminConnectGetLoggingFilters(conn, filters,
                                                   flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectSetLoggingOutputs:
 * @conn: pointer to an active admin connection
 * @outputs: pointer to a string containing a list of outputs to be defined
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Redefine the existing (set of) outputs(s) with a new one specified in
 * @outputs. If multiple outputs are specified, they need to be delimited by
 * spaces. The format of each output must conform to the format described in
 * daemon's configuration file (e.g. libvirtd.conf).
 *
 * To reset the existing (set of) output(s) to libvirt's defaults, an empty
 * string ("") or NULL should be passed in @outputs.
 *
 * Returns 0 if the new output or the set of outputs has been defined
 * successfully, or -1 in case of an error.
 *
 * Since: 3.0.0
 */
int
virAdmConnectSetLoggingOutputs(virAdmConnectPtr conn,
                               const char *outputs,
                               unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, outputs=%s, flags=0x%x", conn, outputs, flags);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    if ((ret = remoteAdminConnectSetLoggingOutputs(conn, outputs, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}

/**
 * virAdmConnectSetLoggingFilters:
 * @conn: pointer to an active admin connection
 * @filters: pointer to a string containing a list of filters to be defined
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Redefine the existing (set of) filter(s) with a new one specified in
 * @filters. If multiple filters are specified, they need to be delimited by
 * spaces. The format of each filter must conform to the format described in
 * daemon's configuration file (e.g. libvirtd.conf).
 *
 * To clear the currently defined (set of) filter(s), pass either an empty
 * string ("") or NULL in @filters.
 *
 * Returns 0 if the new filter or the set of filters has been defined
 * successfully, or -1 in case of an error.
 *
 * Since: 3.0.0
 */
int
virAdmConnectSetLoggingFilters(virAdmConnectPtr conn,
                               const char *filters,
                               unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, filters=%s, flags=0x%x", conn, filters, flags);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    if ((ret = remoteAdminConnectSetLoggingFilters(conn, filters, flags)) < 0)
        goto error;

    return ret;
 error:
    virDispatchError(NULL);
    return -1;
}


/**
 * virAdmConnectSetDaemonTimeout:
 * @conn: pointer to an active admin connection
 * @timeout: timeout to set in seconds (0 disables timeout)
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Reconfigure the existing timeout of the daemon to @timeout. Setting timeout
 * to 0 disables the daemon timeout.
 *
 * Returns 0 on success, -1 on error.
 *
 * Since: 8.6.0
 */
int
virAdmConnectSetDaemonTimeout(virAdmConnectPtr conn,
                              unsigned int timeout,
                              unsigned int flags)
{
    int ret;

    VIR_DEBUG("conn=%p, timeout=%u, flags=0x%x", conn, timeout, flags);

    virResetLastError();
    virCheckAdmConnectReturn(conn, -1);

    if ((ret = remoteAdminConnectSetDaemonTimeout(conn, timeout, flags)) < 0) {
        virDispatchError(NULL);
        return -1;
    }

    return ret;
}
