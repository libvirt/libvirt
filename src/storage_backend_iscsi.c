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

#include "storage_backend_iscsi.h"
#include "util.h"

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
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("session"));
            return -1;
        }
    }

    return 0;
}

static char *
virStorageBackendISCSISession(virConnectPtr conn,
                              virStoragePoolObjPtr pool)
{
    /*
     * # iscsiadm --mode session  -P 0
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
    const char *prog[] = {
        ISCSIADM, "--mode", "session", "-P", "0", NULL
    };
    char *session = NULL;

    if (virStorageBackendRunProgRegex(conn, pool,
                                      prog,
                                      1,
                                      regexes,
                                      vars,
                                      virStorageBackendISCSIExtractSession,
                                      &session) < 0)
        return NULL;

    if (session == NULL) {
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
    const char *cmdargv[] = {
        ISCSIADM, "--mode", "node", "--portal", portal,
        "--targetname", pool->def->source.devices[0].path, action, NULL
    };

    const char *cmdsendtarget[] = {
        ISCSIADM, "--mode", "discovery", "--type", "sendtargets",
        "--portal", portal, NULL
    };

    if (virRun(conn, (char **)cmdsendtarget, NULL) < 0)
        return -1;

    if (virRun(conn, (char **)cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSIMakeLUN(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
                              char **const groups,
                              void *data)
{
    virStorageVolDefPtr vol;
    int fd = -1;
    unsigned int target, channel, id, lun;
    char lunid[100];
    int opentries = 0;
    char *devpath = NULL;
    char *session = data;
    char sysfs_path[PATH_MAX];
    char *dev = NULL;
    DIR *sysdir;
    struct dirent *block_dirent;
    struct stat sbuf;
    int len;

    if ((virStrToLong_ui(groups[0], NULL, 10, &target) < 0) ||
        (virStrToLong_ui(groups[1], NULL, 10, &channel) < 0) ||
        (virStrToLong_ui(groups[2], NULL, 10, &id) < 0) ||
        (virStrToLong_ui(groups[3], NULL, 10, &lun) < 0)) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                              _("Failed parsing iscsiadm commands"));
        return -1;
    }

    if (lun == 0) {
        /* the 0'th LUN isn't a real LUN, it's just a control LUN; skip it */
        return 0;
    }

    snprintf(sysfs_path, PATH_MAX,
             "/sys/class/iscsi_session/session%s/device/"
             "target%d:%d:%d/%d:%d:%d:%d/block",
             session, target, channel, id, target, channel, id, lun);

    if (stat(sysfs_path, &sbuf) < 0) {
        /* block path in subdir didn't exist; this is unexpected, so fail */
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to find the sysfs path for %d:%d:%d:%d: %s"),
                              target, channel, id, lun, strerror(errno));
        return -1;
    }

    sysdir = opendir(sysfs_path);
    if (sysdir == NULL) {
        /* we failed for some reason; return an error */
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to opendir sysfs path %s: %s"),
                              sysfs_path, strerror(errno));
        return -1;
    }

    while ((block_dirent = readdir(sysdir)) != NULL) {
        len = strlen(block_dirent->d_name);
        if ((len == 1 && block_dirent->d_name[0] == '.') ||
            (len == 2 && block_dirent->d_name[0] == '.' && block_dirent->d_name[1] == '.')) {
            /* the . and .. directories; just skip them */
            continue;
        }

        /* OK, not . or ..; let's see if it is a SCSI device */
        if (len > 2 &&
            block_dirent->d_name[0] == 's' &&
            block_dirent->d_name[1] == 'd') {
            /* looks like a scsi device, smells like scsi device; it must be
               a scsi device */
            dev = strdup(block_dirent->d_name);
            break;
        }
    }
    closedir(sysdir);

    if (dev == NULL) {
        /* we didn't find the sd? device we were looking for; fail */
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to find SCSI device for %d:%d:%d:%d: %s"),
                              target, channel, id, lun, strerror(errno));
        return -1;
    }

    snprintf(lunid, sizeof(lunid)-1, "lun-%s", groups[3]);

    if ((vol = calloc(1, sizeof(virStorageVolDef))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
        goto cleanup;
    }

    if ((vol->name = strdup(lunid)) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("name"));
        goto cleanup;
    }

    if ((devpath = malloc(5 + strlen(dev) + 1)) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("devpath"));
        goto cleanup;
    }
    strcpy(devpath, "/dev/");
    strcat(devpath, dev);
    free(dev);
    dev = NULL;
    /* It can take a little while between logging into the ISCSI
     * server and udev creating the /dev nodes, so if we get ENOENT
     * we must retry a few times - they should eventually appear.
     * We currently wait for upto 5 seconds. Is this good enough ?
     * Perhaps not on a very heavily loaded system Any other
     * options... ?
     */
 reopen:
    if ((fd = open(devpath, O_RDONLY)) < 0) {
        opentries++;
        if (errno == ENOENT && opentries < 50) {
            usleep(100 * 1000);
            goto reopen;
        }
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot open %s: %s"),
                              devpath, strerror(errno));
        goto cleanup;
    }

    /* Now figure out the stable path
     *
     * XXX this method is O(N) because it scans the pool target
     * dir every time its run. Should figure out a more efficient
     * way of doing this...
     */
    if ((vol->target.path = virStorageBackendStablePath(conn,
                                                        pool,
                                                        devpath)) == NULL)
        goto cleanup;

    if (devpath != vol->target.path)
        free(devpath);
    devpath = NULL;

    if (virStorageBackendUpdateVolInfoFD(conn, vol, fd, 1) < 0)
        goto cleanup;

    /* XXX use unique iSCSI id instead */
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("key"));
        goto cleanup;
    }


    pool->def->capacity += vol->capacity;
    pool->def->allocation += vol->allocation;

    vol->next = pool->volumes;
    pool->volumes = vol;
    pool->nvolumes++;

    close(fd);

    return 0;

 cleanup:
    if (fd != -1) close(fd);
    free(devpath);
    virStorageVolDefFree(vol);
    free(dev);
    return -1;
}

static int
virStorageBackendISCSIFindLUNs(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               const char *session)
{
    /*
     * # iscsiadm --mode session -r $session -P 3
     *
     *           scsi1 Channel 00 Id 0 Lun: 0
     *           scsi1 Channel 00 Id 0 Lun: 1
     *                   Attached scsi disk sdc          State: running
     *           scsi1 Channel 00 Id 0 Lun: 2
     *                   Attached scsi disk sdd          State: running
     *           scsi1 Channel 00 Id 0 Lun: 3
     *                   Attached scsi disk sde          State: running
     *           scsi1 Channel 00 Id 0 Lun: 4
     *                   Attached scsi disk sdf          State: running
     *           scsi1 Channel 00 Id 0 Lun: 5
     *                   Attached scsi disk sdg          State: running
     *
     * Need a regex to match the Channel:Id:Lun lines
     */
    const char *regexes[] = {
        "^\\s*scsi(\\S+)\\s+Channel\\s+(\\S+)\\s+Id\\s+(\\S+)\\s+Lun:\\s+(\\S+)\\s*$"
    };
    int vars[] = {
        4
    };
    const char *prog[] = {
        ISCSIADM, "--mode", "session", "-r", session, "-P", "3", NULL,
    };

    return virStorageBackendRunProgRegex(conn, pool,
                                         prog,
                                         1,
                                         regexes,
                                         vars,
                                         virStorageBackendISCSIMakeLUN,
                                         (void *)session);
}


static int
virStorageBackendISCSIRescanLUNs(virConnectPtr conn,
                                 virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                 const char *session)
{
    const char *cmdargv[] = {
        ISCSIADM, "--mode", "session", "-r", session, "-R", NULL,
    };

    if (virRun(conn, (char **)cmdargv, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSILogin(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            const char *portal)
{
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

    portal = malloc(strlen(ipaddr) + 1 + 4 + 2 + 1);
    if (portal == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("portal"));
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

    if ((portal = virStorageBackendISCSIPortal(conn, pool)) == NULL)
        return -1;
    if (virStorageBackendISCSILogin(conn, pool, portal) < 0) {
        free(portal);
        return -1;
    }
    free(portal);
    return 0;
}

static int
virStorageBackendISCSIRefreshPool(virConnectPtr conn,
                                  virStoragePoolObjPtr pool)
{
    char *session = NULL;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if ((session = virStorageBackendISCSISession(conn, pool)) == NULL)
        goto cleanup;
    if (virStorageBackendISCSIRescanLUNs(conn, pool, session) < 0)
        goto cleanup;
    if (virStorageBackendISCSIFindLUNs(conn, pool, session) < 0)
        goto cleanup;
    free(session);

    return 0;

 cleanup:
    free(session);
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
        free(portal);
        return -1;
    }
    free(portal);

    return 0;
}


virStorageBackend virStorageBackendISCSI = {
  .type = VIR_STORAGE_POOL_ISCSI,

  .startPool = virStorageBackendISCSIStartPool,
  .refreshPool = virStorageBackendISCSIRefreshPool,
  .stopPool = virStorageBackendISCSIStopPool,

  .poolOptions = {
        .flags = (VIR_STORAGE_BACKEND_POOL_SOURCE_HOST |
                  VIR_STORAGE_BACKEND_POOL_SOURCE_DEVICE)
    },

  .volType = VIR_STORAGE_VOL_BLOCK,
};

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
