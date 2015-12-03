/*
 * log_manager.c: log management client
 *
 * Copyright (C) 2015 Red Hat, Inc.
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

#include "log_manager.h"
#include "log_protocol.h"
#include "viralloc.h"
#include "virutil.h"
#include "virstring.h"
#include "virerror.h"
#include "virfile.h"

#include "rpc/virnetclient.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOGGING

struct _virLogManager {
    virNetClientPtr client;
    virNetClientProgramPtr program;
    unsigned int serial;
};


static char *
virLogManagerDaemonPath(bool privileged)
{
    char *path;
    if (privileged) {
        if (VIR_STRDUP(path, LOCALSTATEDIR "/run/libvirt/virtlogd-sock") < 0)
            return NULL;
    } else {
        char *rundir = NULL;

        if (!(rundir = virGetUserRuntimeDirectory()))
            return NULL;

        if (virAsprintf(&path, "%s/virtlogd-sock", rundir) < 0) {
            VIR_FREE(rundir);
            return NULL;
        }

        VIR_FREE(rundir);
    }
    return path;
}


static virNetClientPtr
virLogManagerConnect(bool privileged,
                     virNetClientProgramPtr *prog)
{
    virNetClientPtr client = NULL;
    char *logdpath;
    char *daemonPath = NULL;

    *prog = NULL;

    if (!(logdpath = virLogManagerDaemonPath(privileged)))
        goto error;

    if (!privileged &&
        !(daemonPath = virFileFindResourceFull("virtlogd",
                                               NULL, NULL,
                                               abs_topbuilddir "/src",
                                               SBINDIR,
                                               "VIRTLOGD_PATH")))
        goto error;

    if (!(client = virNetClientNewUNIX(logdpath,
                                       daemonPath != NULL,
                                       daemonPath)))
        goto error;

    if (!(*prog = virNetClientProgramNew(VIR_LOG_MANAGER_PROTOCOL_PROGRAM,
                                         VIR_LOG_MANAGER_PROTOCOL_PROGRAM_VERSION,
                                         NULL,
                                         0,
                                         NULL)))
        goto error;

    if (virNetClientAddProgram(client, *prog) < 0)
        goto error;

    VIR_FREE(daemonPath);
    VIR_FREE(logdpath);

    return client;

 error:
    VIR_FREE(daemonPath);
    VIR_FREE(logdpath);
    virNetClientClose(client);
    virObjectUnref(client);
    virObjectUnref(*prog);
    return NULL;
}


virLogManagerPtr
virLogManagerNew(bool privileged)
{
    virLogManagerPtr mgr;

    if (VIR_ALLOC(mgr) < 0)
        goto error;

    if (!(mgr->client = virLogManagerConnect(privileged, &mgr->program)))
        goto error;

    return mgr;

 error:
    virLogManagerFree(mgr);
    return NULL;
}


void
virLogManagerFree(virLogManagerPtr mgr)
{
    if (!mgr)
        return;

    if (mgr->client)
        virNetClientClose(mgr->client);
    virObjectUnref(mgr->program);
    virObjectUnref(mgr->client);

    VIR_FREE(mgr);
}


int
virLogManagerDomainOpenLogFile(virLogManagerPtr mgr,
                               const char *driver,
                               const unsigned char *domuuid,
                               const char *domname,
                               const char *path,
                               unsigned int flags,
                               ino_t *inode,
                               off_t *offset)
{
    struct virLogManagerProtocolDomainOpenLogFileArgs args;
    struct virLogManagerProtocolDomainOpenLogFileRet ret;
    int *fdout = NULL;
    size_t fdoutlen = 0;
    int rv = -1;

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    args.driver = (char *)driver;
    memcpy(args.dom.uuid, domuuid, VIR_UUID_BUFLEN);
    args.dom.name = (char *)domname;
    args.path = (char *)path;
    args.flags = flags;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_OPEN_LOG_FILE,
                                0, NULL, &fdoutlen, &fdout,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainOpenLogFileArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainOpenLogFileRet, &ret) < 0)
        goto cleanup;

    if (fdoutlen != 1) {
        if (fdoutlen) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("too many file descriptors received"));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("no file descriptor received"));
        }
        goto cleanup;
    }

    *inode = ret.pos.inode;
    *offset = ret.pos.offset;

    rv = fdout[0];
 cleanup:
    if (rv < 0) {
        while (fdoutlen)
            VIR_FORCE_CLOSE(fdout[--fdoutlen]);
    }
    VIR_FREE(fdout);

    return rv;
}


int
virLogManagerDomainGetLogFilePosition(virLogManagerPtr mgr,
                                      const char *path,
                                      unsigned int flags,
                                      ino_t *inode,
                                      off_t *offset)
{
    struct virLogManagerProtocolDomainGetLogFilePositionArgs args;
    struct virLogManagerProtocolDomainGetLogFilePositionRet ret;
    int rv = -1;

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    args.path = (char *)path;
    args.flags = flags;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_GET_LOG_FILE_POSITION,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainGetLogFilePositionArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainGetLogFilePositionRet, &ret) < 0)
        goto cleanup;

    *inode = ret.pos.inode;
    *offset = ret.pos.offset;

    rv = 0;
 cleanup:
    return rv;
}


char *
virLogManagerDomainReadLogFile(virLogManagerPtr mgr,
                               const char *path,
                               ino_t inode,
                               off_t offset,
                               size_t maxlen,
                               unsigned int flags)
{
    struct virLogManagerProtocolDomainReadLogFileArgs args;
    struct virLogManagerProtocolDomainReadLogFileRet ret;
    int *fdout = NULL;
    size_t fdoutlen = 0;
    char *rv = NULL;

    memset(&args, 0, sizeof(args));
    memset(&ret, 0, sizeof(ret));

    args.path = (char *)path;
    args.flags = flags;
    args.pos.inode = inode;
    args.pos.offset = offset;
    args.maxlen = maxlen;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_READ_LOG_FILE,
                                0, NULL, &fdoutlen, &fdout,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainReadLogFileArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainReadLogFileRet, &ret) < 0)
        goto cleanup;

    rv = ret.data;
 cleanup:
    return rv;
}
