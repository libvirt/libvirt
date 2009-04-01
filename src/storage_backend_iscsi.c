/*
 * storage_backend_iscsi.c: storage backend for iSCSI handling
 *
 * Copyright (C) 2007-2008 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/socket.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include "virterror_internal.h"
#include "storage_backend_scsi.h"
#include "storage_backend_iscsi.h"
#include "util.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE


static int
virStorageBackendISCSITargetIP(virConnectPtr conn,
                               const char *hostname,
                               char *ipaddr,
                               size_t ipaddrlen)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int ret;

    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("host lookup failed %s"),
                              gai_strerror(ret));
        return -1;
    }

    if (result == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("no IP address for target %s"),
                              hostname);
        return -1;
    }

    if (getnameinfo(result->ai_addr, result->ai_addrlen,
                    ipaddr, ipaddrlen, NULL, 0,
                    NI_NUMERICHOST) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot format ip addr for %s"),
                              hostname);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

static int
virStorageBackendISCSIExtractSession(virConnectPtr conn,
                                     virStoragePoolObjPtr pool,
                                     char **const groups,
                                     void *data)
{
    char **session = data;

    if (STREQ(groups[1], pool->def->source.devices[0].path)) {
        if ((*session = strdup(groups[0])) == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }

    return 0;
}

static char *
virStorageBackendISCSISession(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
                              int probe)
{
    /*
     * # iscsiadm --mode session
     * tcp: [1] 192.168.122.170:3260,1 demo-tgt-b
     * tcp: [2] 192.168.122.170:3260,1 demo-tgt-a
     *
     * Pull out 2nd and 4th fields
     */
    const char *regexes[] = {
        "^tcp:\\s+\\[(\\S+)\\]\\s+\\S+\\s+(\\S+)\\s*$"
    };
    int vars[] = {
        2,
    };
    const char *const prog[] = {
        ISCSIADM, "--mode", "session", NULL
    };
    char *session = NULL;

    /* Note that we ignore the exitstatus.  Older versions of iscsiadm tools
     * returned an exit status of > 0, even if they succeeded.  We will just
     * rely on whether session got filled in properly.
     */
    if (virStorageBackendRunProgRegex(conn, pool,
                                      prog,
                                      1,
                                      regexes,
                                      vars,
                                      virStorageBackendISCSIExtractSession,
                                      &session,
                                      NULL) < 0)
        return NULL;

    if (session == NULL &&
        !probe) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot find session"));
        return NULL;
    }

    return session;
}

static int
virStorageBackendISCSIConnection(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 const char *portal,
                                 const char *action)
{
    const char *const cmdargv[] = {
        ISCSIADM, "--mode", "node", "--portal", portal,
        "--targetname", pool->def->source.devices[0].path, action, NULL
    };

    if (virRun(conn, cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSIFindLUs(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
                              const char *session)
{
    char sysfs_path[PATH_MAX];
    int retval = 0;
    uint32_t host;

    snprintf(sysfs_path, PATH_MAX,
             "/sys/class/iscsi_session/session%s/device", session);

    if (virStorageBackendSCSIGetHostNumber(conn, sysfs_path, &host) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to get host number for iSCSI session "
                               "with path '%s'"),
                             sysfs_path);
        retval = -1;
    }

    if (virStorageBackendSCSIFindLUs(conn, pool, host) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to find LUs on host %u"), host);
        retval = -1;
    }

    return retval;
}

static int
virStorageBackendISCSIRescanLUNs(virConnectPtr conn,
                                 virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 const char *session)
{
    const char *const cmdargv[] = {
        ISCSIADM, "--mode", "session", "-r", session, "-R", NULL,
    };

    if (virRun(conn, cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSILogin(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            const char *portal)
{
    const char *const cmdsendtarget[] = {
        ISCSIADM, "--mode", "discovery", "--type", "sendtargets",
        "--portal", portal, NULL
    };

    if (virRun(conn, cmdsendtarget, NULL) < 0)
        return -1;

    return virStorageBackendISCSIConnection(conn, pool, portal, "--login");
}

static int
virStorageBackendISCSILogout(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             const char *portal)
{
    return virStorageBackendISCSIConnection(conn, pool, portal, "--logout");
}

static char *
virStorageBackendISCSIPortal(virConnectPtr conn,
                             virStoragePoolObjPtr pool)
{
    char ipaddr[NI_MAXHOST];
    char *portal;

    if (virStorageBackendISCSITargetIP(conn,
                                       pool->def->source.host.name,
                                       ipaddr, sizeof(ipaddr)) < 0)
        return NULL;

    if (VIR_ALLOC_N(portal, strlen(ipaddr) + 1 + 4 + 2 + 1) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    strcpy(portal, ipaddr);
    strcat(portal, ":3260,1");

    return portal;
}


static int
virStorageBackendISCSIStartPool(virConnectPtr conn,
                                virStoragePoolObjPtr pool)
{
    char *portal = NULL;
    char *session;

    if (pool->def->source.host.name == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing source host"));
        return -1;
    }

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(conn, pool, 1)) == NULL) {
        if ((portal = virStorageBackendISCSIPortal(conn, pool)) == NULL)
            return -1;
        if (virStorageBackendISCSILogin(conn, pool, portal) < 0) {
            VIR_FREE(portal);
            return -1;
        }
        VIR_FREE(portal);
    } else {
        VIR_FREE(session);
    }
    return 0;
}

static int
virStorageBackendISCSIRefreshPool(virConnectPtr conn,
                                  virStoragePoolObjPtr pool)
{
    char *session = NULL;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if ((session = virStorageBackendISCSISession(conn, pool, 0)) == NULL)
        goto cleanup;
    if (virStorageBackendISCSIRescanLUNs(conn, pool, session) < 0)
        goto cleanup;
    if (virStorageBackendISCSIFindLUs(conn, pool, session) < 0)
        goto cleanup;
    VIR_FREE(session);

    return 0;

 cleanup:
    VIR_FREE(session);
    return -1;
}


static int
virStorageBackendISCSIStopPool(virConnectPtr conn,
                               virStoragePoolObjPtr pool)
{
    char *portal;

    if ((portal = virStorageBackendISCSIPortal(conn, pool)) == NULL)
        return -1;

    if (virStorageBackendISCSILogout(conn, pool, portal) < 0) {
        VIR_FREE(portal);
        return -1;
    }
    VIR_FREE(portal);

    return 0;
}

virStorageBackend virStorageBackendISCSI = {
    .type = VIR_STORAGE_POOL_ISCSI,

    .startPool = virStorageBackendISCSIStartPool,
    .refreshPool = virStorageBackendISCSIRefreshPool,
    .stopPool = virStorageBackendISCSIStopPool,
};
