/*
 * log_daemon_dispatch.c: log management daemon dispatch
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

#include "rpc/virnetserver.h"
#include "rpc/virnetserverclient.h"
#include "virlog.h"
#include "log_daemon.h"
#include "log_protocol.h"
#include "virerror.h"
#include "virthreadjob.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("logging.log_daemon_dispatch");

#include "log_daemon_dispatch_stubs.h"

static int
virLogManagerProtocolDispatchDomainOpenLogFile(virNetServer *server G_GNUC_UNUSED,
                                               virNetServerClient *client G_GNUC_UNUSED,
                                               virNetMessage *msg,
                                               struct virNetMessageError *rerr,
                                               virLogManagerProtocolDomainOpenLogFileArgs *args,
                                               virLogManagerProtocolDomainOpenLogFileRet *ret)
{
    int fd = -1;
    int rv = -1;
    off_t offset;
    ino_t inode;
    bool trunc = args->flags & VIR_LOG_MANAGER_PROTOCOL_DOMAIN_OPEN_LOG_FILE_TRUNCATE;

    if ((fd = virLogHandlerDomainOpenLogFile(virLogDaemonGetHandler(logDaemon),
                                             args->driver,
                                             (unsigned char *)args->dom.uuid,
                                             args->dom.name,
                                             args->path,
                                             trunc,
                                             &inode, &offset)) < 0)
        goto cleanup;

    ret->pos.inode = inode;
    ret->pos.offset = offset;

    if (virNetMessageAddFD(msg, fd) < 0)
        goto cleanup;

    rv = 1; /* '1' tells caller we added some FDs */

 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}


static int
virLogManagerProtocolDispatchDomainGetLogFilePosition(virNetServer *server G_GNUC_UNUSED,
                                                      virNetServerClient *client G_GNUC_UNUSED,
                                                      virNetMessage *msg G_GNUC_UNUSED,
                                                      struct virNetMessageError *rerr,
                                                      virLogManagerProtocolDomainGetLogFilePositionArgs *args,
                                                      virLogManagerProtocolDomainGetLogFilePositionRet *ret)
{
    int rv = -1;
    off_t offset;
    ino_t inode;

    if (virLogHandlerDomainGetLogFilePosition(virLogDaemonGetHandler(logDaemon),
                                              args->path,
                                              args->flags,
                                              &inode, &offset) < 0)
        goto cleanup;

    ret->pos.inode = inode;
    ret->pos.offset = offset;

    rv = 0;
 cleanup:

    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}


static int
virLogManagerProtocolDispatchDomainReadLogFile(virNetServer *server G_GNUC_UNUSED,
                                               virNetServerClient *client G_GNUC_UNUSED,
                                               virNetMessage *msg G_GNUC_UNUSED,
                                               struct virNetMessageError *rerr,
                                               virLogManagerProtocolDomainReadLogFileArgs *args,
                                               virLogManagerProtocolDomainReadLogFileRet *ret)
{
    int rv = -1;
    char *data;

    if (args->maxlen > VIR_LOG_MANAGER_PROTOCOL_STRING_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Requested data len %1$llu is larger than maximum %2$d"),
                       (unsigned long long)args->maxlen,
                       VIR_LOG_MANAGER_PROTOCOL_STRING_MAX);
        goto cleanup;
    }

    if ((data = virLogHandlerDomainReadLogFile(virLogDaemonGetHandler(logDaemon),
                                               args->path,
                                               args->pos.inode,
                                               args->pos.offset,
                                               args->maxlen,
                                               args->flags)) == NULL)
        goto cleanup;

    ret->data = data;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    return rv;
}


static int
virLogManagerProtocolDispatchDomainAppendLogFile(virNetServer *server G_GNUC_UNUSED,
                                                 virNetServerClient *client G_GNUC_UNUSED,
                                                 virNetMessage *msg G_GNUC_UNUSED,
                                                 struct virNetMessageError *rerr,
                                                 virLogManagerProtocolDomainAppendLogFileArgs *args,
                                                 virLogManagerProtocolDomainAppendLogFileRet *ret)
{
    int rv;

    if ((rv = virLogHandlerDomainAppendLogFile(virLogDaemonGetHandler(logDaemon),
                                               args->driver,
                                               (unsigned char *)args->dom.uuid,
                                               args->dom.name,
                                               args->path,
                                               args->message,
                                               args->flags)) < 0) {
        virNetMessageSaveError(rerr);
        return -1;
    }

    ret->ret = rv;
    return 0;
}
