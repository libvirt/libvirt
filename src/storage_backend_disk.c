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

#include "internal.h"
#include "storage_backend_disk.h"
#include "util.h"
#include "memory.h"

enum {
    VIR_STORAGE_POOL_DISK_DOS = 0,
    VIR_STORAGE_POOL_DISK_DVH,
    VIR_STORAGE_POOL_DISK_GPT,
    VIR_STORAGE_POOL_DISK_MAC,
    VIR_STORAGE_POOL_DISK_BSD,
    VIR_STORAGE_POOL_DISK_PC98,
    VIR_STORAGE_POOL_DISK_SUN,
};

/*
 * XXX these are basically partition types.
 *
 * fdisk has a bazillion partition ID types
 * parted has practically none, and splits the
 * info across 3 different attributes.
 *
 * So this is a semi-generic set
 */
enum {
    VIR_STORAGE_VOL_DISK_NONE = 0,
    VIR_STORAGE_VOL_DISK_LINUX,
    VIR_STORAGE_VOL_DISK_FAT16,
    VIR_STORAGE_VOL_DISK_FAT32,
    VIR_STORAGE_VOL_DISK_LINUX_SWAP,
    VIR_STORAGE_VOL_DISK_LINUX_LVM,
    VIR_STORAGE_VOL_DISK_LINUX_RAID,
    VIR_STORAGE_VOL_DISK_EXTENDED,
};

#define PARTHELPER BINDIR "/libvirt_parthelper"

static int
virStorageBackendDiskPoolFormatFromString(virConnectPtr conn,
                                          const char *format) {
    if (format == NULL)
        return VIR_STORAGE_POOL_DISK_DOS;

    if (STREQ(format, "dos"))
        return VIR_STORAGE_POOL_DISK_DOS;
    if (STREQ(format, "dvh"))
        return VIR_STORAGE_POOL_DISK_DVH;
    if (STREQ(format, "gpt"))
        return VIR_STORAGE_POOL_DISK_GPT;
    if (STREQ(format, "mac"))
        return VIR_STORAGE_POOL_DISK_MAC;
    if (STREQ(format, "bsd"))
        return VIR_STORAGE_POOL_DISK_BSD;
    if (STREQ(format, "pc98"))
        return VIR_STORAGE_POOL_DISK_PC98;
    if (STREQ(format, "sun"))
        return VIR_STORAGE_POOL_DISK_SUN;

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported pool format %s"), format);
    return -1;
}

static const char *
virStorageBackendDiskPoolFormatToString(virConnectPtr conn,
                                        int format) {
    switch (format) {
    case VIR_STORAGE_POOL_DISK_DOS:
        return "dos";
    case VIR_STORAGE_POOL_DISK_DVH:
        return "dvh";
    case VIR_STORAGE_POOL_DISK_GPT:
        return "gpt";
    case VIR_STORAGE_POOL_DISK_MAC:
        return "mac";
    case VIR_STORAGE_POOL_DISK_BSD:
        return "bsd";
    case VIR_STORAGE_POOL_DISK_PC98:
        return "pc98";
    case VIR_STORAGE_POOL_DISK_SUN:
        return "sun";
    }

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported pool format %d"), format);
    return NULL;
}

static int
virStorageBackendDiskVolFormatFromString(virConnectPtr conn,
                                         const char *format) {
    if (format == NULL)
        return VIR_STORAGE_VOL_DISK_NONE;

    if (STREQ(format, "none"))
        return VIR_STORAGE_VOL_DISK_NONE;
    if (STREQ(format, "linux"))
        return VIR_STORAGE_VOL_DISK_LINUX;
    if (STREQ(format, "fat16"))
        return VIR_STORAGE_VOL_DISK_FAT16;
    if (STREQ(format, "fat32"))
        return VIR_STORAGE_VOL_DISK_FAT32;
    if (STREQ(format, "linux-swap"))
        return VIR_STORAGE_VOL_DISK_LINUX_SWAP;
    if (STREQ(format, "linux-lvm"))
        return VIR_STORAGE_VOL_DISK_LINUX_LVM;
    if (STREQ(format, "linux-raid"))
        return VIR_STORAGE_VOL_DISK_LINUX_RAID;
    if (STREQ(format, "extended"))
        return VIR_STORAGE_VOL_DISK_EXTENDED;

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported volume format %s"), format);
    return -1;
}

static const char *
virStorageBackendDiskVolFormatToString(virConnectPtr conn,
                                       int format) {
    switch (format) {
    case VIR_STORAGE_VOL_DISK_NONE:
        return "none";
    case VIR_STORAGE_VOL_DISK_LINUX:
        return "linux";
    case VIR_STORAGE_VOL_DISK_FAT16:
        return "fat16";
    case VIR_STORAGE_VOL_DISK_FAT32:
        return "fat32";
    case VIR_STORAGE_VOL_DISK_LINUX_SWAP:
        return "linux-swap";
    case VIR_STORAGE_VOL_DISK_LINUX_LVM:
        return "linux-lvm";
    case VIR_STORAGE_VOL_DISK_LINUX_RAID:
        return "linux-raid";
    case VIR_STORAGE_VOL_DISK_EXTENDED:
        return "extended";
    }

    virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          _("unsupported volume format %d"), format);
    return NULL;
}

static int
virStorageBackendDiskMakeDataVol(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 char **const groups,
                                 virStorageVolDefPtr vol)
{
    char *tmp, *devpath;

    if (vol == NULL) {
        if (VIR_ALLOC(vol) < 0) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, _("volume"));
            return -1;
        }

        vol->next = pool->volumes;
        pool->volumes = vol;
        pool->nvolumes++;

        /* Prepended path will be same for all partitions, so we can
         * strip the path to form a reasonable pool-unique name
         */
        tmp = strrchr(groups[0], '/');
        if ((vol->name = strdup(tmp ? tmp + 1 : groups[0])) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, _("volume"));
            return -1;
        }
    }

    if (vol->target.path == NULL) {
        if ((devpath = strdup(groups[0])) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, _("volume"));
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

        if (devpath != vol->target.path)
            VIR_FREE(devpath);
    }

    if (vol->key == NULL) {
        /* XXX base off a unique key of the underlying disk */
        if ((vol->key = strdup(vol->target.path)) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, _("volume"));
            return -1;
        }
    }

    if (vol->source.extents == NULL) {
        if (VIR_ALLOC(vol->source.extents) < 0) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                  _("volume extents"));
            return -1;
        }
        vol->source.nextent = 1;

        if (virStrToLong_ull(groups[3], NULL, 10,
                             &vol->source.extents[0].start) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse device start location"));
            return -1;
        }

        if (virStrToLong_ull(groups[4], NULL, 10,
                             &vol->source.extents[0].end) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse device end location"));
            return -1;
        }

        if ((vol->source.extents[0].path =
             strdup(pool->def->source.devices[0].path)) == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, _("extents"));
            return -1;
        }
    }

    /* Refresh allocation/capacity/perms */
    if (virStorageBackendUpdateVolInfo(conn, vol, 1) < 0)
        return -1;

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
        virStorageBackendDiskPoolFormatToString(conn, pool->def->source.format),
        NULL,
    };

    if (virRun(conn, (char**)prog, NULL) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendDiskDeleteVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               unsigned int flags);

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
                              _("no large enough free extent"));
        return -1;
    }
    startOffset = dev->freeExtents[smallestExtent].start;
    endOffset = startOffset + vol->allocation;

    snprintf(start, sizeof(start)-1, "%lluB", startOffset);
    start[sizeof(start)-1] = '\0';
    snprintf(end, sizeof(end)-1, "%lluB", endOffset);
    end[sizeof(end)-1] = '\0';

    if (virRun(conn, (char**)cmdargv, NULL) < 0)
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
                               virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                               virStorageVolDefPtr vol ATTRIBUTE_UNUSED,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    /* delete a partition */
    virStorageReportError(conn, VIR_ERR_NO_SUPPORT,
                          _("Disk pools are not yet supported"));
    return -1;
}


virStorageBackend virStorageBackendDisk = {
    .type = VIR_STORAGE_POOL_DISK,

    .buildPool = virStorageBackendDiskBuildPool,
    .refreshPool = virStorageBackendDiskRefreshPool,

    .createVol = virStorageBackendDiskCreateVol,
    .deleteVol = virStorageBackendDiskDeleteVol,

    .poolOptions = {
        .flags = (VIR_STORAGE_BACKEND_POOL_SOURCE_DEVICE),
        .formatFromString = virStorageBackendDiskPoolFormatFromString,
        .formatToString = virStorageBackendDiskPoolFormatToString,
    },
    .volOptions = {
        .formatFromString = virStorageBackendDiskVolFormatFromString,
        .formatToString = virStorageBackendDiskVolFormatToString,
    },

    .volType = VIR_STORAGE_VOL_BLOCK,
};
