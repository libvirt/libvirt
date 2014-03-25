/*
 * lock_daemon_dispatch.c: lock management daemon dispatch
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "rpc/virnetserver.h"
#include "rpc/virnetserverclient.h"
#include "virlog.h"
#include "virstring.h"
#include "lock_daemon.h"
#include "lock_protocol.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("locking.lock_daemon_dispatch");

#include "lock_daemon_dispatch_stubs.h"

static int
virLockSpaceProtocolDispatchAcquireResource(virNetServerPtr server ATTRIBUTE_UNUSED,
                                            virNetServerClientPtr client,
                                            virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                            virNetMessageErrorPtr rerr,
                                            virLockSpaceProtocolAcquireResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;
    unsigned int newFlags;

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED |
                      VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %s does not exist"),
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
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchCreateResource(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           virLockSpaceProtocolCreateResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %s does not exist"),
                       args->path);
        goto cleanup;
    }

    if (virLockSpaceCreateResource(lockspace, args->name) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchDeleteResource(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           virLockSpaceProtocolDeleteResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %s does not exist"),
                       args->path);
        goto cleanup;
    }

    if (virLockSpaceDeleteResource(lockspace, args->name) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchNew(virNetServerPtr server ATTRIBUTE_UNUSED,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                virNetMessageErrorPtr rerr,
                                virLockSpaceProtocolNewArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
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
                       _("Lockspace for path %s already exists"),
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
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchRegister(virNetServerPtr server ATTRIBUTE_UNUSED,
                                     virNetServerClientPtr client,
                                     virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                     virNetMessageErrorPtr rerr,
                                     virLockSpaceProtocolRegisterArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have already been registered"));
        goto cleanup;
    }

    if (VIR_STRDUP(priv->ownerName, args->owner.name) < 0)
        goto cleanup;
    memcpy(priv->ownerUUID, args->owner.uuid, VIR_UUID_BUFLEN);
    priv->ownerId = args->owner.id;
    priv->ownerPid = args->owner.pid;
    VIR_DEBUG("ownerName=%s ownerId=%d ownerPid=%lld",
              priv->ownerName, priv->ownerId, (unsigned long long)priv->ownerPid);

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchReleaseResource(virNetServerPtr server ATTRIBUTE_UNUSED,
                                            virNetServerClientPtr client,
                                            virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                            virNetMessageErrorPtr rerr,
                                            virLockSpaceProtocolReleaseResourceArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    if (!(lockspace = virLockDaemonFindLockSpace(lockDaemon, args->path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace for path %s does not exist"),
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
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchRestrict(virNetServerPtr server ATTRIBUTE_UNUSED,
                                     virNetServerClientPtr client,
                                     virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                     virNetMessageErrorPtr rerr,
                                     virLockSpaceProtocolRestrictArgs *args)
{
    int rv = -1;
    unsigned int flags = args->flags;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);

    virMutexLock(&priv->lock);

    virCheckFlagsGoto(0, cleanup);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (!priv->ownerPid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("lock owner details have not been registered"));
        goto cleanup;
    }

    priv->restricted = true;
    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return rv;
}


static int
virLockSpaceProtocolDispatchCreateLockSpace(virNetServerPtr server ATTRIBUTE_UNUSED,
                                            virNetServerClientPtr client,
                                            virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                            virNetMessageErrorPtr rerr,
                                            virLockSpaceProtocolCreateLockSpaceArgs *args)
{
    int rv = -1;
    virLockDaemonClientPtr priv =
        virNetServerClientGetPrivateData(client);
    virLockSpacePtr lockspace;

    virMutexLock(&priv->lock);

    if (priv->restricted) {
        virReportError(VIR_ERR_OPERATION_DENIED, "%s",
                       _("lock manager connection has been restricted"));
        goto cleanup;
    }

    if (virLockDaemonFindLockSpace(lockDaemon, args->path) != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Lockspace for path %s already exists"),
                       args->path);
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
    virMutexUnlock(&priv->lock);
    return rv;
}
