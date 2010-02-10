/*
 * storage_backend_iscsi.c: storage backend for iSCSI handling
 *
 * Copyright (C) 2007-2008, 2010 Red Hat, Inc.
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
#include <sys/stat.h>

#include "virterror_internal.h"
#include "storage_backend_scsi.h"
#include "storage_backend_iscsi.h"
#include "util.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int
virStorageBackendISCSITargetIP(const char *hostname,
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("host lookup failed %s"),
                              gai_strerror(ret));
        return -1;
    }

    if (result == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("no IP address for target %s"),
                              hostname);
        return -1;
    }

    if (getnameinfo(result->ai_addr, result->ai_addrlen,
                    ipaddr, ipaddrlen, NULL, 0,
                    NI_NUMERICHOST) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("cannot format ip addr for %s"),
                              hostname);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

static int
virStorageBackendISCSIExtractSession(virStoragePoolObjPtr pool,
                                     char **const groups,
                                     void *data)
{
    char **session = data;

    if (STREQ(groups[1], pool->def->source.devices[0].path)) {
        if ((*session = strdup(groups[0])) == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    return 0;
}

static char *
virStorageBackendISCSISession(virStoragePoolObjPtr pool,
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
    if (virStorageBackendRunProgRegex(pool,
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot find session"));
        return NULL;
    }

    return session;
}


#define LINE_SIZE 4096

static int
virStorageBackendIQNFound(virStoragePoolObjPtr pool,
                          char **ifacename)
{
    int ret = IQN_MISSING, fd = -1;
    char ebuf[64];
    FILE *fp = NULL;
    pid_t child = 0;
    char *line = NULL, *newline = NULL, *iqn = NULL, *token = NULL,
        *saveptr = NULL;
    const char *const prog[] = {
        ISCSIADM, "--mode", "iface", NULL
    };

    if (VIR_ALLOC_N(line, LINE_SIZE) != 0) {
        ret = IQN_ERROR;
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Could not allocate memory for output of '%s'"),
                              prog[0]);
        goto out;
    }

    memset(line, 0, LINE_SIZE);

    if (virExec(prog, NULL, NULL, &child, -1, &fd, NULL, VIR_EXEC_NONE) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to run '%s' when looking for existing interface with IQN '%s'"),
                              prog[0], pool->def->source.initiator.iqn);

        ret = IQN_ERROR;
        goto out;
    }

    if ((fp = fdopen(fd, "r")) == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to open stream for file descriptor "
                                "when reading output from '%s': '%s'"),
                              prog[0], virStrerror(errno, ebuf, sizeof ebuf));
        ret = IQN_ERROR;
        goto out;
    }

    while (fgets(line, LINE_SIZE, fp) != NULL) {
        newline = strrchr(line, '\n');
        if (newline == NULL) {
            ret = IQN_ERROR;
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unexpected line > %d characters "
                                    "when parsing output of '%s'"),
                                  LINE_SIZE, prog[0]);
            goto out;
        }
        *newline = '\0';

        iqn = strrchr(line, ',');
        if (iqn == NULL) {
            continue;
        }
        iqn++;

        if (STREQ(iqn, pool->def->source.initiator.iqn)) {
            token = strtok_r(line, " ", &saveptr);
            *ifacename = strdup(token);
            if (*ifacename == NULL) {
                ret = IQN_ERROR;
                virReportOOMError();
                goto out;
            }
            VIR_DEBUG("Found interface '%s' with IQN '%s'", *ifacename, iqn);
            ret = IQN_FOUND;
            break;
        }
    }

out:
    if (ret == IQN_MISSING) {
        VIR_DEBUG("Could not find interface witn IQN '%s'", iqn);
    }

    VIR_FREE(line);
    if (fp != NULL) {
        fclose(fp);
    } else {
        if (fd != -1) {
            close(fd);
        }
    }

    return ret;
}


static int
virStorageBackendCreateIfaceIQN(virStoragePoolObjPtr pool,
                                char **ifacename)
{
    int ret = -1, exitstatus = -1;
    char temp_ifacename[32];

    if (virRandomInitialize(time(NULL) ^ getpid()) == -1) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                              _("Failed to initialize random generator "
                                "when creating iscsi interface"));
        goto out;
    }

    snprintf(temp_ifacename, sizeof(temp_ifacename), "libvirt-iface-%08x", virRandom(1024 * 1024 * 1024));

    const char *const cmdargv1[] = {
        ISCSIADM, "--mode", "iface", "--interface",
        &temp_ifacename[0], "--op", "new", NULL
    };

    VIR_DEBUG("Attempting to create interface '%s' with IQN '%s'",
              &temp_ifacename[0], pool->def->source.initiator.iqn);

    /* Note that we ignore the exitstatus.  Older versions of iscsiadm
     * tools returned an exit status of > 0, even if they succeeded.
     * We will just rely on whether the interface got created
     * properly. */
    if (virRun(cmdargv1, &exitstatus) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to run command '%s' to create new iscsi interface"),
                              cmdargv1[0]);
        goto out;
    }

    const char *const cmdargv2[] = {
        ISCSIADM, "--mode", "iface", "--interface", &temp_ifacename[0],
        "--op", "update", "--name", "iface.initiatorname", "--value",
        pool->def->source.initiator.iqn, NULL
    };

    /* Note that we ignore the exitstatus.  Older versions of iscsiadm tools
     * returned an exit status of > 0, even if they succeeded.  We will just
     * rely on whether iface file got updated properly. */
    if (virRun(cmdargv2, &exitstatus) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to run command '%s' to update iscsi interface with IQN '%s'"),
                              cmdargv1[0], pool->def->source.initiator.iqn);
        goto out;
    }

    /* Check again to make sure the interface was created. */
    if (virStorageBackendIQNFound(pool, ifacename) != IQN_FOUND) {
        VIR_DEBUG("Failed to find interface '%s' with IQN '%s' "
                  "after attempting to create it",
                  &temp_ifacename[0], pool->def->source.initiator.iqn);
        goto out;
    } else {
        VIR_DEBUG("Interface '%s' with IQN '%s' was created successfully",
                  *ifacename, pool->def->source.initiator.iqn);
    }

    ret = 0;

out:
    if (ret != 0)
        VIR_FREE(*ifacename);
    return ret;
}


static int
virStorageBackendISCSIConnectionIQN(virStoragePoolObjPtr pool,
                                    const char *portal,
                                    const char *action)
{
    int ret = -1;
    char *ifacename = NULL;

    switch (virStorageBackendIQNFound(pool, &ifacename)) {
    case IQN_FOUND:
        VIR_DEBUG("ifacename: '%s'", ifacename);
        break;
    case IQN_MISSING:
        if (virStorageBackendCreateIfaceIQN(pool, &ifacename) != 0) {
            goto out;
        }
        break;
    case IQN_ERROR:
    default:
        goto out;
    }

    const char *const sendtargets[] = {
        ISCSIADM, "--mode", "discovery", "--type", "sendtargets", "--portal", portal, NULL
    };
    if (virRun(sendtargets, NULL) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to run %s to get target list"),
                              sendtargets[0]);
        goto out;
    }

    const char *const cmdargv[] = {
        ISCSIADM, "--mode", "node", "--portal", portal,
        "--targetname", pool->def->source.devices[0].path, "--interface",
        ifacename, action, NULL
    };

    if (virRun(cmdargv, NULL) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to run command '%s' with action '%s'"),
                              cmdargv[0], action);
        goto out;
    }

    ret = 0;

out:
    VIR_FREE(ifacename);
    return ret;
}


static int
virStorageBackendISCSIConnection(virStoragePoolObjPtr pool,
                                 const char *portal,
                                 const char *action)
{
    int ret = 0;

    if (pool->def->source.initiator.iqn != NULL) {

        ret = virStorageBackendISCSIConnectionIQN(pool, portal, action);

    } else {

        const char *const cmdargv[] = {
            ISCSIADM, "--mode", "node", "--portal", portal,
            "--targetname", pool->def->source.devices[0].path, action, NULL
        };

        if (virRun(cmdargv, NULL) < 0) {
            ret = -1;
        }

    }

    return ret;
}


static int
virStorageBackendISCSIFindLUs(virStoragePoolObjPtr pool,
                              const char *session)
{
    char sysfs_path[PATH_MAX];
    int retval = 0;
    uint32_t host;

    snprintf(sysfs_path, PATH_MAX,
             "/sys/class/iscsi_session/session%s/device", session);

    if (virStorageBackendSCSIGetHostNumber(sysfs_path, &host) < 0) {
        virReportSystemError(errno,
                             _("Failed to get host number for iSCSI session "
                               "with path '%s'"),
                             sysfs_path);
        retval = -1;
    }

    if (virStorageBackendSCSIFindLUs(pool, host) < 0) {
        virReportSystemError(errno,
                             _("Failed to find LUs on host %u"), host);
        retval = -1;
    }

    return retval;
}

static int
virStorageBackendISCSIRescanLUNs(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 const char *session)
{
    const char *const cmdargv[] = {
        ISCSIADM, "--mode", "session", "-r", session, "-R", NULL,
    };

    if (virRun(cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSILogin(virStoragePoolObjPtr pool,
                            const char *portal)
{
    const char *const cmdsendtarget[] = {
        ISCSIADM, "--mode", "discovery", "--type", "sendtargets",
        "--portal", portal, NULL
    };

    if (virRun(cmdsendtarget, NULL) < 0)
        return -1;

    return virStorageBackendISCSIConnection(pool, portal, "--login");
}

static int
virStorageBackendISCSILogout(virStoragePoolObjPtr pool,
                             const char *portal)
{
    return virStorageBackendISCSIConnection(pool, portal, "--logout");
}

static char *
virStorageBackendISCSIPortal(virStoragePoolObjPtr pool)
{
    char ipaddr[NI_MAXHOST];
    char *portal;

    if (virStorageBackendISCSITargetIP(pool->def->source.host.name,
                                       ipaddr, sizeof(ipaddr)) < 0)
        return NULL;

    if (VIR_ALLOC_N(portal, strlen(ipaddr) + 1 + 4 + 2 + 1) < 0) {
        virReportOOMError();
        return NULL;
    }

    strcpy(portal, ipaddr);
    strcat(portal, ":3260,1");

    return portal;
}


static int
virStorageBackendISCSIStartPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool)
{
    char *portal = NULL;
    char *session;

    if (pool->def->source.host.name == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing source host"));
        return -1;
    }

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, 1)) == NULL) {
        if ((portal = virStorageBackendISCSIPortal(pool)) == NULL)
            return -1;
        if (virStorageBackendISCSILogin(pool, portal) < 0) {
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
virStorageBackendISCSIRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool)
{
    char *session = NULL;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if ((session = virStorageBackendISCSISession(pool, 0)) == NULL)
        goto cleanup;
    if (virStorageBackendISCSIRescanLUNs(pool, session) < 0)
        goto cleanup;
    if (virStorageBackendISCSIFindLUs(pool, session) < 0)
        goto cleanup;
    VIR_FREE(session);

    return 0;

 cleanup:
    VIR_FREE(session);
    return -1;
}


static int
virStorageBackendISCSIStopPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool)
{
    char *portal;

    if ((portal = virStorageBackendISCSIPortal(pool)) == NULL)
        return -1;

    if (virStorageBackendISCSILogout(pool, portal) < 0) {
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
