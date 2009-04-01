/*
 * storage_backend_disk.c: storage backend for disk handling
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
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "virterror_internal.h"
#include "logging.h"
#include "storage_backend_disk.h"
#include "util.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define PARTHELPER BINDIR "/libvirt_parthelper"

static int
virStorageBackendDiskMakeDataVol(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 char **const groups,
                                 virStorageVolDefPtr vol)
{
    char *tmp, *devpath;

    if (vol == NULL) {
        if (VIR_ALLOC(vol) < 0) {
            virReportOOMError(conn);
            return -1;
        }

        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0) {
            virReportOOMError(conn);
            virStorageVolDefFree(vol);
            return -1;
        }
        pool->volumes.objs[pool->volumes.count++] = vol;

        /* Prepended path will be same for all partitions, so we can
         * strip the path to form a reasonable pool-unique name
         */
        tmp = strrchr(groups[0], '/');
        if ((vol->name = strdup(tmp ? tmp + 1 : groups[0])) == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }

    if (vol->target.path == NULL) {
        if ((devpath = strdup(groups[0])) == NULL) {
            virReportOOMError(conn);
            return -1;
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
            return -1;

        VIR_FREE(devpath);
    }

    if (vol->key == NULL) {
        /* XXX base off a unique key of the underlying disk */
        if ((vol->key = strdup(vol->target.path)) == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }

    if (vol->source.extents == NULL) {
        if (VIR_ALLOC(vol->source.extents) < 0) {
            virReportOOMError(conn);
            return -1;
        }
        vol->source.nextent = 1;

        if (virStrToLong_ull(groups[3], NULL, 10,
                             &vol->source.extents[0].start) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot parse device start location"));
            return -1;
        }

        if (virStrToLong_ull(groups[4], NULL, 10,
                             &vol->source.extents[0].end) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot parse device end location"));
            return -1;
        }

        if ((vol->source.extents[0].path =
             strdup(pool->def->source.devices[0].path)) == NULL) {
            virReportOOMError(conn);
            return -1;
        }
    }

    /* Refresh allocation/capacity/perms */
    if (virStorageBackendUpdateVolInfo(conn, vol, 1) < 0)
        return -1;

    vol->type = VIR_STORAGE_VOL_BLOCK;

    /* The above gets allocation wrong for
     * extended partitions, so overwrite it */
    vol->allocation = vol->capacity =
        (vol->source.extents[0].end - vol->source.extents[0].start);

    if (STRNEQ(groups[2], "metadata"))
        pool->def->allocation += vol->allocation;
    if (vol->source.extents[0].end > pool->def->capacity)
        pool->def->capacity = vol->source.extents[0].end;

    return 0;
}

static int
virStorageBackendDiskMakeFreeExtent(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virStoragePoolObjPtr pool,
                                    char **const groups)
{
    virStoragePoolSourceDevicePtr dev = &pool->def->source.devices[0];

    if (VIR_REALLOC_N(dev->freeExtents,
                      dev->nfreeExtent + 1) < 0)
        return -1;

    memset(dev->freeExtents +
           dev->nfreeExtent, 0,
           sizeof(dev->freeExtents[0]));

    if (virStrToLong_ull(groups[3], NULL, 10,
                         &dev->freeExtents[dev->nfreeExtent].start) < 0)
        return -1; /* Don't bother to re-alloc freeExtents - it'll be free'd shortly */

    if (virStrToLong_ull(groups[4], NULL, 10,
                         &dev->freeExtents[dev->nfreeExtent].end) < 0)
        return -1; /* Don't bother to re-alloc freeExtents - it'll be free'd shortly */

    pool->def->available +=
        (dev->freeExtents[dev->nfreeExtent].end -
         dev->freeExtents[dev->nfreeExtent].start);
    if (dev->freeExtents[dev->nfreeExtent].end > pool->def->capacity)
        pool->def->capacity = dev->freeExtents[dev->nfreeExtent].end;

    dev->nfreeExtent++;

    return 0;
}


static int
virStorageBackendDiskMakeVol(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             size_t ntok ATTRIBUTE_UNUSED,
                             char **const groups,
                             void *data)
{
    /*
     * Ignore normal+metadata, and logical+metadata partitions
     * since they're basically internal book-keeping regions
     * we have no control over. Do keep extended+metadata though
     * because that's the MS-DOS extended partition region we
     * need to be able to view/create/delete
     */
    if ((STREQ(groups[1], "normal") ||
         STREQ(groups[1], "logical")) &&
        STREQ(groups[2], "metadata"))
        return 0;

    /* Remaining data / metadata parts get turn into volumes... */
    if (STREQ(groups[2], "metadata") ||
        STREQ(groups[2], "data")) {
        virStorageVolDefPtr vol = data;
        /* We're searching for a specific vol only, so ignore others */
        if (vol &&
            STRNEQ(vol->name, groups[0]))
            return 0;

        return virStorageBackendDiskMakeDataVol(conn, pool, groups, vol);
    } else if (STREQ(groups[2], "free")) {
        /* ....or free space extents */
        return virStorageBackendDiskMakeFreeExtent(conn, pool, groups);
    } else {
        /* This code path should never happen unless someone changed
         * libvirt_parthelper forgot to change this code */
        return -1;
    }
}


/* To get a list of partitions we run an external helper
 * tool which then uses parted APIs. This is because
 * parted's API is not compatible with libvirt's license
 * but we really really want to use parted because the
 * other options all suck :-)
 *
 * All the other storage backends run an external tool for
 * listing volumes so this really isn't too much of a pain,
 * and we can even ensure the output is friendly.
 */
static int
virStorageBackendDiskReadPartitions(virConnectPtr conn,
                                    virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol)
{

    /*
     *  # libvirt_parthelper DEVICE
     * /dev/sda1      normal       data        32256    106928128    106896384
     * /dev/sda2      normal       data    106928640 100027629568  99920701440
     * -              normal   metadata 100027630080 100030242304      2612736
     *
     */
    const char *prog[] = {
        PARTHELPER, pool->def->source.devices[0].path, NULL,
    };

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    return virStorageBackendRunProgNul(conn,
                                       pool,
                                       prog,
                                       6,
                                       virStorageBackendDiskMakeVol,
                                       vol);
}


static int
virStorageBackendDiskRefreshPool(virConnectPtr conn,
                                 virStoragePoolObjPtr pool)
{
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    virStorageBackendWaitForDevices(conn);

    return virStorageBackendDiskReadPartitions(conn, pool, NULL);
}


/**
 * Write a new partition table header
 */
static int
virStorageBackendDiskBuildPool(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    /* eg parted /dev/sda mklabel msdos */
    const char *prog[] = {
        PARTED,
        pool->def->source.devices[0].path,
        "mklabel",
        "--script",
        ((pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) ? "msdos" :
          virStoragePoolFormatDiskTypeToString(pool->def->source.format)),
        NULL,
    };

    if (virRun(conn, prog, NULL) < 0)
        return -1;

    return 0;
}

static int
virStorageBackendDiskCreateVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol)
{
    int i;
    char start[100], end[100];
    unsigned long long startOffset, endOffset, smallestSize = 0;
    int smallestExtent = -1;
    virStoragePoolSourceDevicePtr dev = &pool->def->source.devices[0];
    /* XXX customizable partition types */
    const char *cmdargv[] = {
        PARTED,
        pool->def->source.devices[0].path,
        "mkpart",
        "--script",
        "ext2",
        start,
        end,
        NULL
    };

    for (i = 0 ; i < dev->nfreeExtent ; i++) {
        unsigned long long size =
            dev->freeExtents[i].end -
            dev->freeExtents[i].start;
        if (size > vol->allocation &&
            (smallestSize == 0 ||
             size < smallestSize)) {
            smallestSize = size;
            smallestExtent = i;
        }
    }
    if (smallestExtent == -1) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("no large enough free extent"));
        return -1;
    }
    startOffset = dev->freeExtents[smallestExtent].start;
    endOffset = startOffset + vol->allocation;

    snprintf(start, sizeof(start)-1, "%lluB", startOffset);
    start[sizeof(start)-1] = '\0';
    snprintf(end, sizeof(end)-1, "%lluB", endOffset);
    end[sizeof(end)-1] = '\0';

    if (virRun(conn, cmdargv, NULL) < 0)
        return -1;

    /* Blow away free extent info, as we're about to re-populate it */
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    /* Fetch actual extent info */
    if (virStorageBackendDiskReadPartitions(conn, pool, vol) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendDiskDeleteVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    char *part_num = NULL;
    int err;
    char *devpath = NULL;
    char *devname, *srcname;
    int rc = -1;

    if ((err = virFileResolveLink(vol->target.path, &devpath)) < 0) {
        virReportSystemError(conn, err,
                             _("Couldn't read volume target path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    devname = basename(devpath);
    srcname = basename(pool->def->source.devices[0].path);
    DEBUG("devname=%s, srcname=%s", devname, srcname);

    if (!STRPREFIX(devname, srcname)) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Volume path '%s' did not start with parent "
                                "pool source device name."), devname);
        goto cleanup;
    }

    part_num = devname + strlen(srcname);

    if (!part_num) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot parse partition number from target "
                                "'%s'"), devname);
        goto cleanup;
    }

    /* eg parted /dev/sda rm 2 */
    const char *prog[] = {
        PARTED,
        pool->def->source.devices[0].path,
        "rm",
        "--script",
        part_num,
        NULL,
    };

    if (virRun(conn, prog, NULL) < 0)
        goto cleanup;

    rc = 0;
cleanup:
    VIR_FREE(devpath);
    return rc;
}


virStorageBackend virStorageBackendDisk = {
    .type = VIR_STORAGE_POOL_DISK,

    .buildPool = virStorageBackendDiskBuildPool,
    .refreshPool = virStorageBackendDiskRefreshPool,

    .createVol = virStorageBackendDiskCreateVol,
    .deleteVol = virStorageBackendDiskDeleteVol,
};
