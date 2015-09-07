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

#include <rpc/rpc.h>

#include "internal.h"
#include "datatypes.h"
#include "configmake.h"

#include "viralloc.h"
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


typedef struct _remoteAdminPriv remoteAdminPriv;
typedef remoteAdminPriv *remoteAdminPrivPtr;

struct _remoteAdminPriv {
    virObjectLockable parent;

    int counter;
    virNetClientPtr client;
    virNetClientProgramPtr program;
};

static virClassPtr remoteAdminPrivClass;

static void
remoteAdminPrivDispose(void *opaque)
{
    remoteAdminPrivPtr priv = opaque;

    virObjectUnref(priv->program);
    virObjectUnref(priv->client);
}


static int
callFull(virAdmConnectPtr conn ATTRIBUTE_UNUSED,
         remoteAdminPrivPtr priv,
         int *fdin,
         size_t fdinlen,
         int **fdout,
         size_t *fdoutlen,
         int proc_nr,
         xdrproc_t args_filter, char *args,
         xdrproc_t ret_filter, char *ret)
{
    int rv;
    virNetClientProgramPtr prog = priv->program;
    int counter = priv->counter++;
    virNetClientPtr client = priv->client;

    /* Unlock, so that if we get any async events/stream data
     * while processing the RPC, we don't deadlock when our
     * callbacks for those are invoked
     */
    virObjectRef(priv);
    virObjectUnlock(priv);

    rv = virNetClientProgramCall(prog,
                                 client,
                                 counter,
                                 proc_nr,
                                 fdinlen, fdin,
                                 fdoutlen, fdout,
                                 args_filter, args,
                                 ret_filter, ret);

    virObjectLock(priv);
    virObjectUnref(priv);

    return rv;
}

static int
call(virAdmConnectPtr conn,
     unsigned int flags,
     int proc_nr,
     xdrproc_t args_filter, char *args,
     xdrproc_t ret_filter, char *ret)
{
    virCheckFlags(0, -1);

    return callFull(conn, conn->privateData,
                    NULL, 0, NULL, NULL, proc_nr,
                    args_filter, args, ret_filter, ret);
}

#include "admin_protocol.h"
#include "admin_client.h"

static bool virAdmGlobalError;
static virOnceControl virAdmGlobalOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
remoteAdminPrivFree(void *opaque)
{
    virAdmConnectPtr conn = opaque;

    remoteAdminConnectClose(conn);
    virObjectUnref(conn->privateData);
}

static remoteAdminPrivPtr
remoteAdminPrivNew(const char *sock_path)
{
    remoteAdminPrivPtr priv = NULL;

    if (!(priv = virObjectLockableNew(remoteAdminPrivClass)))
        goto error;

    if (!(priv->client = virNetClientNewUNIX(sock_path, false, NULL)))
        goto error;

    if (!(priv->program = virNetClientProgramNew(ADMIN_PROGRAM,
                                                 ADMIN_PROTOCOL_VERSION,
                                                 NULL, 0, NULL)))
        goto error;

    if (virNetClientAddProgram(priv->client, priv->program) < 0)
        goto error;

    return priv;
 error:
    virObjectUnref(priv);
    return NULL;
}

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
getSocketPath(const char *name)
{
    char *rundir = virGetUserRuntimeDirectory();
    char *sock_path = NULL;
    size_t i = 0;
    virURIPtr uri = NULL;

    if (name) {
        if (!(uri = virURIParse(name)))
            goto error;

        if (STRNEQ(uri->scheme, "admin") ||
            uri->server || uri->user || uri->fragment) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid connection name '%s'"), name);
            goto error;
        }

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
    }

    if (!sock_path) {
        if (!uri || !uri->path || STREQ(uri->path, "/system")) {
            if (VIR_STRDUP(sock_path, LIBVIRTD_ADMIN_UNIX_SOCKET) < 0)
                goto error;
        } else if (STREQ_NULLABLE(uri->path, "/session")) {
            if (!rundir)
                goto error;

            if (virAsprintf(&sock_path,
                            "%s%s", rundir, LIBVIRTD_ADMIN_SOCK_NAME) < 0)
                goto error;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid URI path '%s'"), uri->path);
            goto error;
        }
    }

 cleanup:
    VIR_FREE(rundir);
    virURIFree(uri);
    return sock_path;

 error:
    VIR_FREE(sock_path);
    goto cleanup;
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
    virAdmConnectPtr conn = NULL;

    if (virAdmInitialize() < 0)
        goto error;

    VIR_DEBUG("flags=%x", flags);
    virResetLastError();

    if (!(conn = virAdmConnectNew()))
        goto error;

    if (!(sock_path = getSocketPath(name)))
        goto error;

    if (!(conn->privateData = remoteAdminPrivNew(sock_path)))
        goto error;

    conn->privateDataFreeFunc = remoteAdminPrivFree;

    if (remoteAdminConnectOpen(conn, flags) < 0)
        goto error;

 cleanup:
    VIR_FREE(sock_path);
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
