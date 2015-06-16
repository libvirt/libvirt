/*
 * admin_server.c:
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
#include "libvirtd.h"
#include "libvirt_internal.h"

#include "admin_protocol.h"
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

#include "admin_dispatch.h"
