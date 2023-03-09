/*
 * lock_daemon_dispatch.c: lock management daemon dispatch
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "rpc/virnetdaemon.h"
#include "rpc/virnetserverclient.h"
#include "virlog.h"
#include "lock_daemon.h"
#include "lock_protocol.h"
#include "virerror.h"
#include "virthreadjob.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("locking.lock_daemon_dispatch");

#include "lock_daemon_dispatch_stubs.h"

static int
virLockSpaceProtocolDispatchAcquireResource(virNetServer *server G_GNUC_UNUSED,
                                            virNetServerClient *client,
                                            virNetMessage *msg G_GNUC_UNUSED,
                                            struct virNetMessageError *rerr,
                                            virLockSpaceProtocolAcquireResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;
    unsigned int newFlags;

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED |
                      VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %1$s does not exist"),
                       args->path);
        goto cleanup;
    }

    newFlags = 0;
    if (flags & VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED)
        newFlags |= VIR_LOCK_SPACE_ACQUIRE_SHARED;
    if (flags & VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE)
        newFlags |= VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE;

    if (virLockSpaceAcquireResource(lockspace,
                                    args->name,
                                    priv->ownerPid,
                                    newFlags) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchCreateResource(virNetServer *server G_GNUC_UNUSED,
                                           virNetServerClient *client,
                                           virNetMessage *msg G_GNUC_UNUSED,
                                           struct virNetMessageError *rerr,
                                           virLockSpaceProtocolCreateResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %1$s does not exist"),
                       args->path);
        goto cleanup;
    }

    if (virLockSpaceCreateResource(lockspace, args->name) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchDeleteResource(virNetServer *server G_GNUC_UNUSED,
                                           virNetServerClient *client,
                                           virNetMessage *msg G_GNUC_UNUSED,
                                           struct virNetMessageError *rerr,
                                           virLockSpaceProtocolDeleteResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %1$s does not exist"),
                       args->path);
        goto cleanup;
    }

    if (virLockSpaceDeleteResource(lockspace, args->name) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchNew(virNetServer *server G_GNUC_UNUSED,
                                virNetServerClient *client,
                                virNetMessage *msg G_GNUC_UNUSED,
                                struct virNetMessageError *rerr,
                                virLockSpaceProtocolNewArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!args->path || STREQ(args->path, "")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("the default lockspace already exists"));
        goto cleanup;
    }

    if (virLockDaemonFindLockSpace(lockDaemon, args->path) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %1$s already exists"),
                       args->path);
        goto cleanup;
    }
    virResetLastError();

    lockspace = virLockSpaceNew(args->path);
    virLockDaemonAddLockSpace(lockDaemon, args->path, lockspace);

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchRegister(virNetServer *server G_GNUC_UNUSED,
                                     virNetServerClient *client,
                                     virNetMessage *msg G_GNUC_UNUSED,
                                     struct virNetMessageError *rerr,
                                     virLockSpaceProtocolRegisterArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!args->owner.id) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    priv->ownerName = g_strdup(args->owner.name);
    memcpy(priv->ownerUUID, args->owner.uuid, VIR_UUID_BUFLEN);
    priv->ownerId = args->owner.id;
    priv->ownerPid = args->owner.pid;
    VIR_DEBUG("ownerName=%s ownerId=%d ownerPid=%lld",
              priv->ownerName, priv->ownerId, (unsigned long long)priv->ownerPid);

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchReleaseResource(virNetServer *server G_GNUC_UNUSED,
                                            virNetServerClient *client,
                                            virNetMessage *msg G_GNUC_UNUSED,
                                            struct virNetMessageError *rerr,
                                            virLockSpaceProtocolReleaseResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %1$s does not exist"),
                       args->path);
        goto cleanup;
    }

    if (virLockSpaceReleaseResource(lockspace,
                                    args->name,
                                    priv->ownerPid) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchRestrict(virNetServer *server G_GNUC_UNUSED,
                                     virNetServerClient *client,
                                     virNetMessage *msg G_GNUC_UNUSED,
                                     struct virNetMessageError *rerr,
                                     virLockSpaceProtocolRestrictArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);

    g_mutex_lock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerId) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    priv->restricted = true;
    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchCreateLockSpace(virNetServer *server G_GNUC_UNUSED,
                                            virNetServerClient *client,
                                            virNetMessage *msg G_GNUC_UNUSED,
                                            struct virNetMessageError *rerr,
                                            virLockSpaceProtocolCreateLockSpaceArgs *args)
{
    int rv = -1;
    virLockDaemonClient *priv =
        virNetServerClientGetPrivateData(client);
    virLockSpace *lockspace;

    g_mutex_lock(&priv->lock);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (virLockDaemonFindLockSpace(lockDaemon, args->path) != NULL) {
        VIR_DEBUG("Lockspace for path %s already exists", args->path);
        rv = 0;
        goto cleanup;
    }

    if (!(lockspace = virLockSpaceNew(args->path)))
        goto cleanup;

    if (virLockDaemonAddLockSpace(lockDaemon, args->path, lockspace) < 0) {
        virLockSpaceFree(lockspace);
        goto cleanup;
    }

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    g_mutex_unlock(&priv->lock);
    return rv;
}
