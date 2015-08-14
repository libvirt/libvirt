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
 *
 * Author: Martin Kletzander <mkletzan@redhat.com>
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
#include "virstring.h"
#include "viruri.h"
#include "virutil.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

#define LIBVIRTD_ADMIN_SOCK_NAME "/libvirt-admin-sock"
#define LIBVIRTD_ADMIN_UNIX_SOCKET LOCALSTATEDIR "/run/libvirt" LIBVIRTD_ADMIN_SOCK_NAME

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
    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0)
        goto error;

    virLogSetFromEnv();

    if (!bindtextdomain(PACKAGE, LOCALEDIR))
        goto error;

    if (!(remoteAdminPrivClass = virClassNew(virClassForObjectLockable(),
                                             "remoteAdminPriv",
                                             sizeof(remoteAdminPriv),
                                             remoteAdminPrivDispose)))
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
 * Returns 0 in case of success, -1 in case of error
 */
static int
virAdmInitialize(void)
{
    if (virOnce(&virAdmGlobalOnce, virAdmGlobalInit) < 0)
        return -1;

    if (virAdmGlobalError)
        return -1;

    return 0;
}

static char *
getSocketPath(virURIPtr uri)
{
    char *rundir = virGetUserRuntimeDirectory();
    char *sock_path = NULL;
    size_t i = 0;

    if (!uri)
        goto cleanup;


    for (i = 0; i < uri->paramsCount; i++) {
        virURIParamPtr param = &uri->params[i];

        if (STREQ(param->name, "socket")) {
            VIR_FREE(sock_path);
            if (VIR_STRDUP(sock_path, param->value) < 0)
                goto error;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown URI parameter '%s'"), param->name);
            goto error;
        }
    }

    if (!sock_path) {
        if (STRNEQ(uri->scheme, "libvirtd")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported URI scheme '%s'"),
                           uri->scheme);
            goto error;
        }
        if (STREQ_NULLABLE(uri->path, "/system")) {
            if (VIR_STRDUP(sock_path, LIBVIRTD_ADMIN_UNIX_SOCKET) < 0)
                goto error;
        } else if (STREQ_NULLABLE(uri->path, "/session")) {
            if (!rundir || virAsprintf(&sock_path, "%s%s", rundir,
                                       LIBVIRTD_ADMIN_SOCK_NAME) < 0)
                goto error;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid URI path '%s', try '/system'"),
                           uri->path ? uri->path : "");
            goto error;
        }
    }

 cleanup:
    VIR_FREE(rundir);
    return sock_path;

 error:
    VIR_FREE(sock_path);
    goto cleanup;
}

static const char *
virAdmGetDefaultURI(virConfPtr conf)
{
    virConfValuePtr value = NULL;
    const char *uristr = NULL;

    uristr = virGetEnvAllowSUID("LIBVIRT_ADMIN_DEFAULT_URI");
    if (uristr && *uristr) {
        VIR_DEBUG("Using LIBVIRT_ADMIN_DEFAULT_URI '%s'", uristr);
    } else if ((value = virConfGetValue(conf, "admin_uri_default"))) {
        if (value->type != VIR_CONF_STRING) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Expected a string for 'admin_uri_default' config "
                             "parameter"));
            return NULL;
        }

        VIR_DEBUG("Using config file uri '%s'", value->str);
        uristr = value->str;
    } else {
        /* Since we can't probe connecting via any hypervisor driver as libvirt
         * does, if no explicit URI was given and neither the environment
         * variable, nor the configuration parameter had previously been set,
         * we set the default admin server URI to 'libvirtd://system'.
         */
        uristr = "libvirtd:///system";
    }

    return uristr;
}

/**
 * virAdmConnectOpen:
 * @name: uri of the daemon to connect to, NULL for default
 * @flags: unused, must be 0
 *
 * Opens connection to admin interface of the daemon.
 *
 * Returns @virAdmConnectPtr object or NULL on error
 */
virAdmConnectPtr
virAdmConnectOpen(const char *name, unsigned int flags)
{
    char *sock_path = NULL;
    char *alias = NULL;
    virAdmConnectPtr conn = NULL;
    virConfPtr conf = NULL;

    if (virAdmInitialize() < 0)
        goto error;

    VIR_DEBUG("flags=%x", flags);
    virResetLastError();
    virCheckFlags(VIR_CONNECT_NO_ALIASES, NULL);

    if (!(conn = virAdmConnectNew()))
        goto error;

    if (virConfLoadConfig(&conf, "libvirt-admin.conf") < 0)
        goto error;

    if (!name && !(name = virAdmGetDefaultURI(conf)))
        goto error;

    if ((!(flags & VIR_CONNECT_NO_ALIASES) &&
         virURIResolveAlias(conf, name, &alias) < 0))
        goto error;

    if (!(conn->uri = virURIParse(alias ? alias : name)))
        goto error;

    if (!(sock_path = getSocketPath(conn->uri)))
        goto error;

    if (!(conn->privateData = remoteAdminPrivNew(sock_path)))
        goto error;

    conn->privateDataFreeFunc = remoteAdminPrivFree;

    if (remoteAdminConnectOpen(conn, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(sock_path);
    VIR_FREE(alias);
    virConfFree(conf);
    return conn;

 error:
    virDispatchError(NULL);
    virObjectUnref(conn);
    conn = NULL;
    goto cleanup;
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
 */
int
virAdmConnectClose(virAdmConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();
    if (!conn)
        return 0;

    virCheckAdmConnectReturn(conn, -1);

    if (!virObjectUnref(conn))
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
 */
int
virAdmConnectRef(virAdmConnectPtr conn)
{
    VIR_DEBUG("conn=%p refs=%d", conn,
              conn ? conn->object.parent.u.s.refs : 0);

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
 * allways be set unless an error occurs in which case an error code and a
 * generic message will be returned. @libVer format is as follows:
 * major * 1,000,000 + minor * 1,000 + release.
 *
 * NOTE: To get the remote side library version use virAdmConnectGetLibVersion
 * instead.
 *
 * Returns 0 on success, -1 in case of an error.
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
 */
int
virAdmConnectIsAlive(virAdmConnectPtr conn)
{
    bool ret;
    remoteAdminPrivPtr priv = NULL;

    VIR_DEBUG("conn=%p", conn);

    if (!conn)
        return 0;

    virCheckAdmConnectReturn(conn, -1);
    virResetLastError();

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
 */
char *
virAdmConnectGetURI(virAdmConnectPtr conn)
{
    char *uri = NULL;
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckAdmConnectReturn(conn, NULL);

    if (!(uri = virURIFormat(conn->uri)))
        virDispatchError(NULL);

    return uri;
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

    virObjectLock(conn);
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
    virObjectUnlock(conn);

    return 0;

 error:
    virObjectUnlock(conn->closeCallback);
    virObjectUnlock(conn);
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
 */
int virAdmConnectUnregisterCloseCallback(virAdmConnectPtr conn,
                                         virAdmConnectCloseFunc cb)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckAdmConnectReturn(conn, -1);

    virObjectLock(conn);
    virObjectLock(conn->closeCallback);

    virCheckNonNullArgGoto(cb, error);

    if (conn->closeCallback->callback != cb) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A different callback was requested"));
        goto error;
    }

    conn->closeCallback->callback = NULL;
    if (conn->closeCallback->freeCallback)
        conn->closeCallback->freeCallback(conn->closeCallback->opaque);
    conn->closeCallback->freeCallback = NULL;

    virObjectUnlock(conn->closeCallback);
    virObjectUnlock(conn);
    virObjectUnref(conn);

    return 0;

 error:
    virObjectUnlock(conn->closeCallback);
    virObjectUnlock(conn);
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
 */
int virAdmServerFree(virAdmServerPtr srv)
{
    VIR_DEBUG("server=%p", srv);

    virResetLastError();
    virCheckAdmServerReturn(srv, -1);

    virObjectUnref(srv);
    return 0;
}

/**
 * virAdmConnectListServers:
 * @conn: daemon connection reference
 * @servers: Pointer to a list to store an array containing objects or NULL
 *           if the list is not required (number of servers only)
 * @flags: bitwise-OR of virAdmConnectListServersFlags
 *
 * Collect list of all servers provided by daemon the client is connected to.
 *
 * Returns the number of servers available on daemon side or -1 in case of a
 * failure, setting @servers to NULL. There is a guaranteed extra element set
 * to NULL in the @servers list returned to make the iteration easier, excluding
 * this extra element from the final count.
 * Caller is responsible to call virAdmServerFree() on each list element,
 * followed by freeing @servers.
 */
int
virAdmConnectListServers(virAdmConnectPtr conn,
                         virAdmServerPtr **servers,
                         unsigned int flags)
{
    int ret = -1;

    VIR_DEBUG("conn=%p, servers=%p, flags=%x", conn, servers, flags);

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
