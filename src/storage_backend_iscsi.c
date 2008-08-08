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

#include "internal.h"
#include "storage_backend_iscsi.h"
#include "util.h"
#include "memory.h"

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
    const char *const cmdargv[] = {
        ISCSIADM, "--mode", "node", "--portal", portal,
        "--targetname", pool->def->source.devices[0].path, action, NULL
    };

    if (virRun(conn, cmdargv, NULL) < 0)
        return -1;

    return 0;
}

static int
virStorageBackendISCSINewLun(virConnectPtr conn, virStoragePoolObjPtr pool,
                             unsigned int lun, const char *dev)
{
    virStorageVolDefPtr vol;
    int fd = -1;
    char *devpath = NULL;
    int opentries = 0;

    if (VIR_ALLOC(vol) < 0) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("volume"));
        goto cleanup;
    }

    if (asprintf(&(vol->name), "lun-%d", lun) < 0) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("name"));
        goto cleanup;
    }

    if (asprintf(&devpath, "/dev/%s", dev) < 0) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("devpath"));
        goto cleanup;
    }

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
        VIR_FREE(devpath);

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
    VIR_FREE(devpath);
    virStorageVolDefFree(vol);
    return -1;
}

static int notdotdir(const struct dirent *dir)
{
    return !(STREQLEN(dir->d_name, ".", 1) || STREQLEN(dir->d_name, "..", 2));
}

/* Function to check if the type file in the given sysfs_path is a
 * Direct-Access device (i.e. type 0).  Return -1 on failure, 0 if not
 * a Direct-Access device, and 1 if a Direct-Access device
 */
static int directAccessDevice(const char *sysfs_path)
{
    char typestr[3];
    char *gottype, *p;
    FILE *typefile;
    int type;

    typefile = fopen(sysfs_path, "r");
    if (typefile == NULL) {
        /* there was no type file; that doesn't seem right */
        return -1;
    }
    gottype = fgets(typestr, 3, typefile);
    fclose(typefile);

    if (gottype == NULL) {
        /* we couldn't read the type file; have to give up */
        return -1;
    }

    /* we don't actually care about p, but if you pass NULL and the last
     * character is not \0, virStrToLong_i complains
     */
    if (virStrToLong_i(typestr, &p, 10, &type) < 0) {
        /* Hm, type wasn't an integer; seems strange */
        return -1;
    }

    if (type != 0) {
        /* saw a device other than Direct-Access */
        return 0;
    }

    return 1;
}

static int
virStorageBackendISCSIFindLUNs(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               const char *session)
{
    char sysfs_path[PATH_MAX];
    uint32_t host, bus, target, lun;
    DIR *sysdir;
    struct dirent *sys_dirent;
    struct dirent **namelist;
    int i, n, tries, retval, directaccess;
    char *block, *scsidev, *block2;

    retval = 0;
    block = NULL;
    scsidev = NULL;

    snprintf(sysfs_path, PATH_MAX,
             "/sys/class/iscsi_session/session%s/device", session);

    sysdir = opendir(sysfs_path);
    if (sysdir == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to opendir sysfs path %s: %s"),
                              sysfs_path, strerror(errno));
        return -1;
    }
    while ((sys_dirent = readdir(sysdir))) {
        /* double-negative, so we can use the same function for scandir below */
        if (!notdotdir(sys_dirent))
            continue;

        if (STREQLEN(sys_dirent->d_name, "target", 6)) {
            if (sscanf(sys_dirent->d_name, "target%u:%u:%u",
                       &host, &bus, &target) != 3) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Failed to parse target from sysfs path %s/%s"),
                                      sysfs_path, sys_dirent->d_name);
                closedir(sysdir);
                return -1;
            }
            break;
        }
    }
    closedir(sysdir);

    /* we now have the host, bus, and target; let's scan for LUNs */
    snprintf(sysfs_path, PATH_MAX,
             "/sys/class/iscsi_session/session%s/device/target%u:%u:%u",
             session, host, bus, target);

    n = scandir(sysfs_path, &namelist, notdotdir, versionsort);
    if (n <= 0) {
        /* we didn't find any reasonable entries; return failure */
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to find any LUNs for session %s: %s"),
                              session, strerror(errno));

        return -1;
    }

    for (i=0; i<n; i++) {
        block = NULL;
        scsidev = NULL;

        if (sscanf(namelist[i]->d_name, "%u:%u:%u:%u\n",
                   &host, &bus, &target, &lun) != 4)
            continue;

        /* we found a LUN */
        /* Note, however, that just finding a LUN doesn't mean it is
         * actually useful to us.  There are a few different types of
         * LUNs, enumerated in the linux kernel in
         * drivers/scsi/scsi.c:scsi_device_types[].  Luckily, these device
         * types form part of the ABI between the kernel and userland, so
         * are unlikely to change.  For now, we ignore everything that isn't
         * type 0; that is, a Direct-Access device
         */
        snprintf(sysfs_path, PATH_MAX,
                 "/sys/bus/scsi/devices/%u:%u:%u:%u/type",
                 host, bus, target, lun);

        directaccess = directAccessDevice(sysfs_path);
        if (directaccess < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to determine if %u:%u:%u:%u is a Direct-Access LUN"),
                                  host, bus, target, lun);
            retval = -1;
            goto namelist_cleanup;
        }
        else if (directaccess == 0) {
            /* not a direct-access device; skip */
            continue;
        }
        /* implicit else if (access == 1); Direct-Access device */

        /* It might take some time for the
         * /sys/bus/scsi/devices/host:bus:target:lun/block{:sda,/sda}
         * link to show up; wait up to 5 seconds for it, then give up
         */
        tries = 0;
        while (block == NULL && tries < 50) {
            snprintf(sysfs_path, PATH_MAX, "/sys/bus/scsi/devices/%u:%u:%u:%u",
                     host, bus, target, lun);

            sysdir = opendir(sysfs_path);
            if (sysdir == NULL) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Failed to opendir sysfs path %s: %s"),
                                      sysfs_path, strerror(errno));
                retval = -1;
                goto namelist_cleanup;
            }
            while ((sys_dirent = readdir(sysdir))) {
                if (!notdotdir(sys_dirent))
                    continue;
                if (STREQLEN(sys_dirent->d_name, "block", 5)) {
                    block = strdup(sys_dirent->d_name);
                    break;
                }
            }
            closedir(sysdir);
            tries++;
            if (block == NULL)
                 usleep(100 * 1000);
        }

        if (block == NULL) {
            /* we couldn't find the device link for this device; fail */
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to find device link for lun %d"),
                                  lun);
            retval = -1;
            goto namelist_cleanup;
        }

        if (strlen(block) == 5) {
            /* OK, this is exactly "block"; must be new-style */
            snprintf(sysfs_path, PATH_MAX,
                     "/sys/bus/scsi/devices/%u:%u:%u:%u/block",
                     host, bus, target, lun);
            sysdir = opendir(sysfs_path);
            if (sysdir == NULL) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Failed to opendir sysfs path %s: %s"),
                                      sysfs_path, strerror(errno));
                retval = -1;
                goto namelist_cleanup;
            }
            while ((sys_dirent = readdir(sysdir))) {
                if (!notdotdir(sys_dirent))
                    continue;

                scsidev = strdup(sys_dirent->d_name);
                break;
            }
            closedir(sysdir);
        }
        else {
            /* old-style; just parse out the sd */
            block2 = strrchr(block, ':');
            if (block2 == NULL) {
                /* Hm, wasn't what we were expecting; have to give up */
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("Failed to parse block path %s"),
                                      block);
                retval = -1;
                goto namelist_cleanup;
            }
            block2++;
            scsidev = strdup(block2);
        }
        if (scsidev == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s",
                                  _("Failed allocating memory for scsidev"));
            retval = -1;
            goto namelist_cleanup;
        }

        retval = virStorageBackendISCSINewLun(conn, pool, lun, scsidev);
        if (retval < 0)
            break;
        VIR_FREE(scsidev);
        VIR_FREE(block);
    }

namelist_cleanup:
    /* we call these VIR_FREE here to make sure we don't leak memory on
     * error cases; in the success case, these are already freed but NULL,
     * which should be fine
     */
    VIR_FREE(scsidev);
    VIR_FREE(block);

    for (i=0; i<n; i++)
        VIR_FREE(namelist[i]);

    VIR_FREE(namelist);

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
        VIR_FREE(portal);
        return -1;
    }
    VIR_FREE(portal);
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

  .poolOptions = {
        .flags = (VIR_STORAGE_BACKEND_POOL_SOURCE_HOST |
                  VIR_STORAGE_BACKEND_POOL_SOURCE_DEVICE)
    },

  .volType = VIR_STORAGE_VOL_BLOCK,
};
