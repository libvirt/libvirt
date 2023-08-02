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
 */

#include <config.h>

#include "log_manager.h"
#include "log_protocol.h"
#include "viralloc.h"
#include "virutil.h"
#include "virerror.h"
#include "virfile.h"

#include "rpc/virnetclient.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOGGING

struct _virLogManager {
    virNetClient *client;
    virNetClientProgram *program;
    unsigned int serial;
};


static char *
virLogManagerDaemonPath(bool privileged)
{
    char *path;
    if (privileged) {
        path = g_strdup(RUNSTATEDIR "/libvirt/virtlogd-sock");
    } else {
        g_autofree char *rundir = NULL;

        rundir = virGetUserRuntimeDirectory();

        path = g_strdup_printf("%s/virtlogd-sock", rundir);
    }
    return path;
}


static virNetClient *
virLogManagerConnect(bool privileged,
                     virNetClientProgram **prog)
{
    virNetClient *client = NULL;
    char *logdpath;
    char *daemonPath = NULL;

    *prog = NULL;

    if (!(logdpath = virLogManagerDaemonPath(privileged)))
        goto error;

    if (!privileged &&
        !(daemonPath = virFileFindResourceFull("virtlogd",
                                               NULL, NULL,
                                               abs_top_builddir "/src",
                                               SBINDIR,
                                               "VIRTLOGD_PATH")))
        goto error;

    if (!(client = virNetClientNewUNIX(logdpath,
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


virLogManager *
virLogManagerNew(bool privileged)
{
    virLogManager *mgr;

    mgr = g_new0(virLogManager, 1);

    if (!(mgr->client = virLogManagerConnect(privileged, &mgr->program)))
        goto error;

    return mgr;

 error:
    virLogManagerFree(mgr);
    return NULL;
}


void
virLogManagerFree(virLogManager *mgr)
{
    if (!mgr)
        return;

    if (mgr->client)
        virNetClientClose(mgr->client);
    virObjectUnref(mgr->program);
    virObjectUnref(mgr->client);

    g_free(mgr);
}


int
virLogManagerDomainOpenLogFile(virLogManager *mgr,
                               const char *driver,
                               const unsigned char *domuuid,
                               const char *domname,
                               const char *path,
                               unsigned int flags,
                               ino_t *inode,
                               off_t *offset)
{
    struct virLogManagerProtocolDomainOpenLogFileArgs args = { 0 };
    struct virLogManagerProtocolDomainOpenLogFileRet ret = { 0 };
    int *fdout = NULL;
    size_t fdoutlen = 0;
    int rv = -1;

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

    if (inode)
        *inode = ret.pos.inode;
    if (offset)
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
virLogManagerDomainGetLogFilePosition(virLogManager *mgr,
                                      const char *path,
                                      unsigned int flags,
                                      ino_t *inode,
                                      off_t *offset)
{
    struct virLogManagerProtocolDomainGetLogFilePositionArgs args = { 0 };
    struct virLogManagerProtocolDomainGetLogFilePositionRet ret = { 0 };

    args.path = (char *)path;
    args.flags = flags;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_GET_LOG_FILE_POSITION,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainGetLogFilePositionArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainGetLogFilePositionRet, &ret) < 0)
        return -1;

    *inode = ret.pos.inode;
    *offset = ret.pos.offset;

    return 0;
}


char *
virLogManagerDomainReadLogFile(virLogManager *mgr,
                               const char *path,
                               ino_t inode,
                               off_t offset,
                               size_t maxlen,
                               unsigned int flags)
{
    struct virLogManagerProtocolDomainReadLogFileArgs args = { 0 };
    struct virLogManagerProtocolDomainReadLogFileRet ret = { 0 };

    args.path = (char *)path;
    args.flags = flags;
    args.pos.inode = inode;
    args.pos.offset = offset;
    args.maxlen = maxlen;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_READ_LOG_FILE,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainReadLogFileArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainReadLogFileRet, &ret) < 0)
        return NULL;

    return ret.data;
}


int
virLogManagerDomainAppendMessage(virLogManager *mgr,
                                 const char *driver,
                                 const unsigned char *domuuid,
                                 const char *domname,
                                 const char *path,
                                 const char *message,
                                 unsigned int flags)
{
    struct virLogManagerProtocolDomainAppendLogFileArgs args = { 0 };
    struct virLogManagerProtocolDomainAppendLogFileRet ret;

    args.driver = (char *)driver;
    memcpy(args.dom.uuid, domuuid, VIR_UUID_BUFLEN);
    args.dom.name = (char *)domname;
    args.path = (char *)path;
    args.message = (char *)message;
    args.flags = flags;

    if (virNetClientProgramCall(mgr->program,
                                mgr->client,
                                mgr->serial++,
                                VIR_LOG_MANAGER_PROTOCOL_PROC_DOMAIN_APPEND_LOG_FILE,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainAppendLogFileArgs, &args,
                                (xdrproc_t)xdr_virLogManagerProtocolDomainAppendLogFileRet, &ret) < 0)
        return -1;

    return ret.ret;
}
