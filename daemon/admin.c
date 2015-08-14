/*
 * admin.c: handlers for admin RPC method calls
 *
 * Copyright (C) 2014-2016 Red Hat, Inc.
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
#include "libvirtd.h"
#include "libvirt_internal.h"

#include "admin_protocol.h"
#include "admin.h"
#include "admin_server.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetdaemon.h"
#include "virnetserver.h"
#include "virstring.h"
#include "virthreadjob.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin");


void
remoteAdmClientFreeFunc(void *data)
{
    struct daemonAdmClientPrivate *priv = data;

    virMutexDestroy(&priv->lock);
    virObjectUnref(priv->dmn);
    VIR_FREE(priv);
}

void *
remoteAdmClientInitHook(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                        void *opaque)
{
    struct daemonAdmClientPrivate *priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virMutexInit(&priv->lock) < 0) {
        VIR_FREE(priv);
        virReportSystemError(errno, "%s", _("unable to init mutex"));
        return NULL;
    }

    /*
     * We don't necessarily need to ref this object right now as there
     * must be one ref being held throughout the life of the daemon,
     * but let's just be safe for future.
     */
    priv->dmn = virObjectRef(opaque);

    return priv;
}

/* Helpers */

static void
make_nonnull_server(admin_nonnull_server *srv_dst,
                    virAdmServerPtr srv_src)
{
    ignore_value(VIR_STRDUP_QUIET(srv_dst->name, srv_src->name));
}

/* Functions */
static int
adminDispatchConnectOpen(virNetServerPtr server ATTRIBUTE_UNUSED,
                         virNetServerClientPtr client,
                         virNetMessagePtr msg ATTRIBUTE_UNUSED,
                         virNetMessageErrorPtr rerr,
                         struct admin_connect_open_args *args)
{
    unsigned int flags;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    int ret = -1;

    VIR_DEBUG("priv=%p dmn=%p", priv, priv->dmn);
    virMutexLock(&priv->lock);

    flags = args->flags;
    virCheckFlagsGoto(0, cleanup);

    ret = 0;
 cleanup:
    if (ret < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return ret;
}

static int
adminDispatchConnectClose(virNetServerPtr server ATTRIBUTE_UNUSED,
                          virNetServerClientPtr client,
                          virNetMessagePtr msg ATTRIBUTE_UNUSED,
                          virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED)
{
    virNetServerClientDelayedClose(client);
    return 0;
}

static int
adminConnectGetLibVersion(virNetDaemonPtr dmn ATTRIBUTE_UNUSED,
                          unsigned long long *libVer)
{
    if (libVer)
        *libVer = LIBVIR_VERSION_NUMBER;
    return 0;
}

static int
adminDispatchConnectListServers(virNetServerPtr server ATTRIBUTE_UNUSED,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                admin_connect_list_servers_args *args,
                                admin_connect_list_servers_ret *ret)
{
    virAdmServerPtr *servers = NULL;
    int nservers = 0;
    int rv = -1;
    size_t i;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if ((nservers =
            adminDaemonListServers(priv->dmn,
                                   args->need_results ? &servers : NULL,
                                   args->flags)) < 0)
        goto cleanup;

    if (servers && nservers) {
        if (VIR_ALLOC_N(ret->servers.servers_val, nservers) < 0)
            goto cleanup;

        ret->servers.servers_len = nservers;
        for (i = 0; i < nservers; i++)
            make_nonnull_server(ret->servers.servers_val + i, servers[i]);
    } else {
        ret->servers.servers_len = 0;
        ret->servers.servers_val = NULL;
    }

    ret->ret = nservers;
    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    if (servers && nservers > 0)
        for (i = 0; i < nservers; i++)
            virObjectUnref(servers[i]);
    VIR_FREE(servers);
    return rv;
}
#include "admin_dispatch.h"
