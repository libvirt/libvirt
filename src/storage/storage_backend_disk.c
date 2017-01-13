/*
 * storage_backend_disk.c: storage backend for disk handling
 *
 * Copyright (C) 2007-2016 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "dirname.h"
#include "virerror.h"
#include "virlog.h"
#include "storage_backend_disk.h"
#include "storage_util.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "configmake.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_disk");

#define SECTOR_SIZE 512

static int
virStorageBackendDiskMakeDataVol(virStoragePoolObjPtr pool,
                                 char **const groups,
                                 virStorageVolDefPtr vol)
{
    char *tmp, *devpath, *partname;

    /* Prepended path will be same for all partitions, so we can
     * strip the path to form a reasonable pool-unique name
     */
    if ((tmp = strrchr(groups[0], '/')))
        partname = tmp + 1;
    else
        partname = groups[0];

    if (vol == NULL) {
        /* This is typically a reload/restart/refresh path where
         * we're discovering the existing partitions for the pool
         */
        if (VIR_ALLOC(vol) < 0)
            return -1;
        if (VIR_STRDUP(vol->name, partname) < 0 ||
            VIR_APPEND_ELEMENT_COPY(pool->volumes.objs,
                                    pool->volumes.count, vol) < 0) {
            virStorageVolDefFree(vol);
            return -1;
        }
    }

    if (vol->target.path == NULL) {
        if (VIR_STRDUP(devpath, groups[0]) < 0)
            return -1;

        /* Now figure out the stable path
         *
         * XXX this method is O(N) because it scans the pool target
         * dir every time its run. Should figure out a more efficient
         * way of doing this...
         */
        vol->target.path = virStorageBackendStablePath(pool, devpath, true);
        VIR_FREE(devpath);
        if (vol->target.path == NULL)
            return -1;
    }

    /* Enforce provided vol->name is the same as what parted created.
     * We do this after filling target.path so that we have a chance at
     * deleting the partition with this failure from CreateVol path
     */
    if (STRNEQ(vol->name, partname)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid partition name '%s', expected '%s'"),
                       vol->name, partname);

        /* Let's see if by chance parthelper created a name that won't be
         * found later when we try to delete. We tell parthelper to add a 'p'
         * to the output via the part_separator flag, but if devmapper has
         * user_friendly_names set, the creation won't happen that way, thus
         * our deletion will fail because the name we generated is wrong.
         * Check for our conditions and see if the generated name is the
         * same as StablePath returns and has the 'p' in it */
        if (pool->def->source.devices[0].part_separator ==
            VIR_TRISTATE_BOOL_YES &&
            !virIsDevMapperDevice(vol->target.path) &&
            STREQ(groups[0], vol->target.path) &&
            (tmp = strrchr(groups[0], 'p'))) {

            /* If we remove the 'p' from groups[0] and the resulting
             * device is a devmapper device, then we know parthelper
             * was told to create the wrong name based on the results.
             * So just remove the 'p' from the vol->target.path too. */
            memmove(tmp, tmp + 1, strlen(tmp));
            if (virIsDevMapperDevice(groups[0]) &&
                (tmp = strrchr(vol->target.path, 'p')))
                memmove(tmp, tmp + 1, strlen(tmp));
        }
        return -1;
    }

    if (vol->key == NULL) {
        /* XXX base off a unique key of the underlying disk */
        if (VIR_STRDUP(vol->key, vol->target.path) < 0)
            return -1;
    }

    if (vol->source.extents == NULL) {
        if (VIR_ALLOC(vol->source.extents) < 0)
            return -1;
        vol->source.nextent = 1;

        if (virStrToLong_ull(groups[3], NULL, 10,
                             &vol->source.extents[0].start) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot parse device start location"));
            return -1;
        }

        if (virStrToLong_ull(groups[4], NULL, 10,
                             &vol->source.extents[0].end) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot parse device end location"));
            return -1;
        }

        if (VIR_STRDUP(vol->source.extents[0].path,
                       pool->def->source.devices[0].path) < 0)
            return -1;
    }

    /* set partition type */
    if (STREQ(groups[1], "normal"))
       vol->source.partType = VIR_STORAGE_VOL_DISK_TYPE_PRIMARY;
    else if (STREQ(groups[1], "logical"))
       vol->source.partType = VIR_STORAGE_VOL_DISK_TYPE_LOGICAL;
    else if (STREQ(groups[1], "extended"))
       vol->source.partType = VIR_STORAGE_VOL_DISK_TYPE_EXTENDED;
    else
       vol->source.partType = VIR_STORAGE_VOL_DISK_TYPE_NONE;

    vol->type = VIR_STORAGE_VOL_BLOCK;

    /* Refresh allocation/capacity/perms
     *
     * For an extended partition, virStorageBackendUpdateVolInfo will
     * return incorrect values for allocation and capacity, so use the
     * extent information captured above instead.
     *
     * Also once a logical partition exists or another primary partition
     * after an extended partition is created an open on the extended
     * partition will fail, so pass the NOERROR flag and only error if a
     * -1 was returned indicating some other error than an open error.
     */
    if (vol->source.partType == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
        if (virStorageBackendUpdateVolInfo(vol, false,
                                           VIR_STORAGE_VOL_OPEN_DEFAULT |
                                           VIR_STORAGE_VOL_OPEN_NOERROR,
                                           0) == -1)
            return -1;
        vol->target.allocation = 0;
        vol->target.capacity =
            (vol->source.extents[0].end - vol->source.extents[0].start);
    } else {
        if (virStorageBackendUpdateVolInfo(vol, false,
                                           VIR_STORAGE_VOL_OPEN_DEFAULT, 0) < 0)
            return -1;
    }

    /* Find the extended partition and increase the allocation value */
    if (vol->source.partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL) {
        size_t i;

        for (i = 0; i < pool->volumes.count; i++) {
            if (pool->volumes.objs[i]->source.partType ==
                VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
                pool->volumes.objs[i]->target.allocation +=
                    vol->target.allocation;
                break;
            }
        }
    }

    if (STRNEQ(groups[2], "metadata"))
        pool->def->allocation += vol->target.allocation;
    if (vol->source.extents[0].end > pool->def->capacity)
        pool->def->capacity = vol->source.extents[0].end;

    return 0;
}

static int
virStorageBackendDiskMakeFreeExtent(virStoragePoolObjPtr pool,
                                    char **const groups)
{
    virStoragePoolSourceDevicePtr dev = &pool->def->source.devices[0];

    if (VIR_REALLOC_N(dev->freeExtents,
                      dev->nfreeExtent + 1) < 0)
        return -1;

    memset(dev->freeExtents +
           dev->nfreeExtent, 0,
           sizeof(dev->freeExtents[0]));

    /* set type of free area */
    if (STREQ(groups[1], "logical")) {
        dev->freeExtents[dev->nfreeExtent].type = VIR_STORAGE_FREE_LOGICAL;
    } else {
        dev->freeExtents[dev->nfreeExtent].type = VIR_STORAGE_FREE_NORMAL;
    }


    if (virStrToLong_ull(groups[3], NULL, 10,
                         &dev->freeExtents[dev->nfreeExtent].start) < 0)
        return -1; /* Don't bother to re-alloc freeExtents - it'll be free'd shortly */

    if (virStrToLong_ull(groups[4], NULL, 10,
                         &dev->freeExtents[dev->nfreeExtent].end) < 0)
        return -1; /* Don't bother to re-alloc freeExtents - it'll be free'd shortly */

    /* first block reported as free, even if it is not */
    if (dev->freeExtents[dev->nfreeExtent].start == 0)
        dev->freeExtents[dev->nfreeExtent].start = SECTOR_SIZE;

    pool->def->available +=
        (dev->freeExtents[dev->nfreeExtent].end -
         dev->freeExtents[dev->nfreeExtent].start);
    if (dev->freeExtents[dev->nfreeExtent].end > pool->def->capacity)
        pool->def->capacity = dev->freeExtents[dev->nfreeExtent].end;

    dev->nfreeExtent++;

    return 0;
}


struct virStorageBackendDiskPoolVolData {
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
};

static int
virStorageBackendDiskMakeVol(size_t ntok ATTRIBUTE_UNUSED,
                             char **const groups,
                             void *opaque)
{
    struct virStorageBackendDiskPoolVolData *data = opaque;
    virStoragePoolObjPtr pool = data->pool;
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
        virStorageVolDefPtr vol = data->vol;

        if (vol) {
            /* We're searching for a specific vol only */
            if (vol->key) {
                if (STRNEQ(vol->key, groups[0]))
                    return 0;
            } else if (virStorageVolDefFindByKey(pool, groups[0]) != NULL) {
                /* If no key, the volume must be newly created. If groups[0]
                 * isn't already a volume, assume it's the path we want */
                return 0;
            }
        }

        return virStorageBackendDiskMakeDataVol(pool, groups, vol);
    } else if (STREQ(groups[2], "free")) {
        /* ....or free space extents */
        return virStorageBackendDiskMakeFreeExtent(pool, groups);
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
virStorageBackendDiskReadPartitions(virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol)
{
    /*
     *  # libvirt_parthelper DEVICE
     * /dev/sda1      normal       data        32256    106928128    106896384
     * /dev/sda2      normal       data    106928640 100027629568  99920701440
     * -              normal   metadata 100027630080 100030242304      2612736
     *
     */

    char *parthelper_path;
    virCommandPtr cmd;
    struct virStorageBackendDiskPoolVolData cbdata = {
        .pool = pool,
        .vol = vol,
    };
    int ret;

    if (!(parthelper_path = virFileFindResource("libvirt_parthelper",
                                                abs_topbuilddir "/src",
                                                LIBEXECDIR)))
        return -1;

    cmd = virCommandNewArgList(parthelper_path,
                               pool->def->source.devices[0].path,
                               NULL);

    /* Check for the presence of the part_separator='yes'. Pass this
     * along to the libvirt_parthelper as option '-p'. This will cause
     * libvirt_parthelper to append the "p" partition separator to
     * the generated device name for a source device which ends with
     * a non-numeric value (e.g. mpatha would generate mpathap#).
     */
    if (pool->def->source.devices[0].part_separator ==
        VIR_TRISTATE_BOOL_YES)
        virCommandAddArg(cmd, "-p");

    /* If a volume is passed, virStorageBackendDiskMakeVol only updates the
     * pool allocation for that single volume.
     */
    if (!vol)
        pool->def->allocation = 0;
    pool->def->capacity = pool->def->available = 0;

    ret = virCommandRunNul(cmd,
                           6,
                           virStorageBackendDiskMakeVol,
                           &cbdata);
    virCommandFree(cmd);
    VIR_FREE(parthelper_path);
    return ret;
}

static int
virStorageBackendDiskMakePoolGeometry(size_t ntok ATTRIBUTE_UNUSED,
                                      char **const groups,
                                      void *data)
{
    virStoragePoolObjPtr pool = data;
    virStoragePoolSourceDevicePtr device = &(pool->def->source.devices[0]);
    if (virStrToLong_i(groups[0], NULL, 0, &device->geometry.cylinders) < 0 ||
        virStrToLong_i(groups[1], NULL, 0, &device->geometry.heads) < 0 ||
        virStrToLong_i(groups[2], NULL, 0, &device->geometry.sectors) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to create disk pool geometry"));
        return -1;
    }

    return 0;
}

static int
virStorageBackendDiskReadGeometry(virStoragePoolObjPtr pool)
{
    char *parthelper_path;
    virCommandPtr cmd;
    int ret;

    if (!(parthelper_path = virFileFindResource("libvirt_parthelper",
                                                abs_topbuilddir "/src",
                                                LIBEXECDIR)))
        return -1;

    cmd = virCommandNewArgList(parthelper_path,
                                             pool->def->source.devices[0].path,
                                             "-g",
                                             NULL);

    ret = virCommandRunNul(cmd,
                           3,
                           virStorageBackendDiskMakePoolGeometry,
                           pool);
    virCommandFree(cmd);
    VIR_FREE(parthelper_path);
    return ret;
}

static int
virStorageBackendDiskRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    virFileWaitForDevices();

    if (!virFileExists(pool->def->source.devices[0].path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device path '%s' doesn't exist"),
                       pool->def->source.devices[0].path);
        return -1;
    }

    if (virStorageBackendDiskReadGeometry(pool) != 0)
        return -1;

    return virStorageBackendDiskReadPartitions(pool, NULL);
}


static int
virStorageBackendDiskStartPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool)
{
    const char *format =
        virStoragePoolFormatDiskTypeToString(pool->def->source.format);
    const char *path = pool->def->source.devices[0].path;

    virFileWaitForDevices();

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device path '%s' doesn't exist"), path);
        return -1;
    }

    if (!virStorageBackendDeviceIsEmpty(path, format, false))
        return -1;

    return 0;
}


/**
 * Write a new partition table header
 */
static int
virStorageBackendDiskBuildPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool,
                               unsigned int flags)
{
    int format = pool->def->source.format;
    const char *fmt;
    bool ok_to_mklabel = false;
    int ret = -1;
    virCommandPtr cmd = NULL;

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, ret);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                             VIR_STORAGE_POOL_BUILD_NO_OVERWRITE,
                             error);

    fmt = virStoragePoolFormatDiskTypeToString(format);
    if (flags & VIR_STORAGE_POOL_BUILD_OVERWRITE) {
        ok_to_mklabel = true;
    } else {
        if (virStorageBackendDeviceIsEmpty(pool->def->source.devices[0].path,
                                              fmt, true))
            ok_to_mklabel = true;
    }

    if (ok_to_mklabel) {
        /* eg parted /dev/sda mklabel --script msdos */
        if (format == VIR_STORAGE_POOL_DISK_UNKNOWN)
            format = pool->def->source.format = VIR_STORAGE_POOL_DISK_DOS;
        if (format == VIR_STORAGE_POOL_DISK_DOS)
            fmt = "msdos";
        else
            fmt = virStoragePoolFormatDiskTypeToString(format);

        cmd = virCommandNewArgList(PARTED,
                                   pool->def->source.devices[0].path,
                                   "mklabel",
                                   "--script",
                                   fmt,
                                   NULL);
        ret = virCommandRun(cmd, NULL);
    }

 error:
    virCommandFree(cmd);
    return ret;
}

/**
 * Decides what kind of partition type that should be created.
 * Important when the partition table is of msdos type
 */
static int
virStorageBackendDiskPartTypeToCreate(virStoragePoolObjPtr pool)
{
    if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        /* count primary and extended partitions,
           can't be more than 3 to create a new primary partition */
        size_t i;
        int count = 0;
        for (i = 0; i < pool->volumes.count; i++) {
            int partType = pool->volumes.objs[i]->source.partType;
            if (partType == VIR_STORAGE_VOL_DISK_TYPE_PRIMARY ||
                partType == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED)
                count++;
        }
        if (count >= 4)
            return VIR_STORAGE_VOL_DISK_TYPE_LOGICAL;
    }

    /* for all other cases, all partitions are primary */
    return VIR_STORAGE_VOL_DISK_TYPE_PRIMARY;
}

static int
virStorageBackendDiskPartFormat(virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol,
                                char** partFormat)
{
    size_t i;
    if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        const char *partedFormat;
        partedFormat = virStoragePartedFsTypeToString(vol->target.format);
        if (partedFormat == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Invalid partition type"));
            return -1;
        }
        if (vol->target.format == VIR_STORAGE_VOL_DISK_EXTENDED) {
            /* make sure we don't have an extended partition already */
            for (i = 0; i < pool->volumes.count; i++) {
                if (pool->volumes.objs[i]->source.partType ==
                    VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("extended partition already exists"));
                    return -1;
                }
            }
            if (VIR_STRDUP(*partFormat, partedFormat) < 0)
                return -1;
        } else {
            /* create primary partition as long as it is possible
               and after that check if an extended partition exists
               to create logical partitions. */
            /* XXX Only support one extended partition */
            switch (virStorageBackendDiskPartTypeToCreate(pool)) {
            case VIR_STORAGE_VOL_DISK_TYPE_PRIMARY:
                if (virAsprintf(partFormat, "primary %s", partedFormat) < 0)
                    return -1;
                break;
            case VIR_STORAGE_VOL_DISK_TYPE_LOGICAL:
                /* make sure we have an extended partition */
                for (i = 0; i < pool->volumes.count; i++) {
                    if (pool->volumes.objs[i]->source.partType ==
                        VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
                        if (virAsprintf(partFormat, "logical %s",
                                        partedFormat) < 0)
                            return -1;
                        break;
                    }
                }
                if (i == pool->volumes.count) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("no extended partition found and no primary partition available"));
                    return -1;
                }
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("unknown partition type"));
                return -1;
            }
        }
    } else {
        if (VIR_STRDUP(*partFormat, "primary") < 0)
            return -1;
    }
    return 0;
}

/**
 * Aligns a new partition to nearest cylinder boundary
 * when having a msdos partition table type
 * to avoid any problem with already existing
 * partitions
 */
static int
virStorageBackendDiskPartBoundaries(virStoragePoolObjPtr pool,
                                    unsigned long long *start,
                                    unsigned long long *end,
                                    unsigned long long allocation)
{
    size_t i;
    int smallestExtent = -1;
    unsigned long long smallestSize = 0;
    unsigned long long extraBytes = 0;
    unsigned long long alignedAllocation = allocation;
    virStoragePoolSourceDevicePtr dev = &pool->def->source.devices[0];
    unsigned long long cylinderSize = (unsigned long long)dev->geometry.heads *
                                      dev->geometry.sectors * SECTOR_SIZE;

    VIR_DEBUG("find free area: allocation %llu, cyl size %llu", allocation,
          cylinderSize);
    int partType = virStorageBackendDiskPartTypeToCreate(pool);

    /* how many extra bytes we have since we allocate
       aligned to the cylinder boundary */
    extraBytes = cylinderSize - (allocation % cylinderSize);

    for (i = 0; i < dev->nfreeExtent; i++) {
         unsigned long long size =
             dev->freeExtents[i].end -
             dev->freeExtents[i].start;
         unsigned long long neededSize = allocation;

         if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
             /* align to cylinder boundary */
             neededSize += extraBytes;
             if ((*start % cylinderSize) > extraBytes) {
                 /* add an extra cylinder if the offset can't fit within
                    the extra bytes we have */
                 neededSize += cylinderSize;
             }
             /* if we are creating a logical partition, we need one extra
                block between partitions (or actually move start one block) */
             if (partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL)
                 size -= SECTOR_SIZE;
         }
         if (size > neededSize &&
             (smallestSize == 0 ||
             size < smallestSize)) {
             /* for logical partition, the free extent
                must be within a logical free area */
             if (partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL &&
                 dev->freeExtents[i].type != VIR_STORAGE_FREE_LOGICAL) {
                 continue;
                 /* for primary partition, the free extent
                    must not be within a logical free area */
             } else if (partType == VIR_STORAGE_VOL_DISK_TYPE_PRIMARY &&
                        dev->freeExtents[i].type != VIR_STORAGE_FREE_NORMAL) {
                 continue;
             }
             smallestSize = size;
             smallestExtent = i;
             alignedAllocation = neededSize;
         }
    }

    if (smallestExtent == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no large enough free extent"));
        return -1;
    }

    VIR_DEBUG("aligned alloc %llu", alignedAllocation);
    *start = dev->freeExtents[smallestExtent].start;

    if (partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL) {
        /* for logical partition, skip one block */
        *start += SECTOR_SIZE;
    }

    *end = *start + alignedAllocation;
    if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        /* adjust our allocation if start is not at a cylinder boundary */
        *end -= (*start % cylinderSize);
    }

    /* counting in bytes, we want the last byte of the current sector */
    *end -= 1;
    VIR_DEBUG("final aligned start %llu, end %llu", *start, *end);
    return 0;
}


/* virStorageBackendDiskDeleteVol
 * @conn: Pointer to a libvirt connection
 * @pool: Pointer to the storage pool
 * @vol: Pointer to the volume definition
 * @flags: flags (unused for now)
 *
 * This API will remove the disk volume partition either from direct
 * API call or as an error path during creation when the partition
 * name provided during create doesn't match the name read from
 * virStorageBackendDiskReadPartitions.
 *
 * For a device mapper device, device respresentation is dependant upon
 * device mapper configuration, but the general rule of thumb is that at
 * creation if a device name ends with a number, then a partition separator
 * "p" is added to the created name; otherwise, if the device name doesn't
 * end with a number, then there is no partition separator. This name is
 * what ends up in the vol->target.path. This ends up being a link to a
 * /dev/mapper/dm-# device which cannot be used in the algorithm to determine
 * which partition to remove, but a properly handled target.path can be.
 *
 * For non device mapper devices, just need to resolve the link of the
 * vol->target.path in order to get the path.
 *
 * Returns 0 on success, -1 on failure with error message set.
 */
static int
virStorageBackendDiskDeleteVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               unsigned int flags)
{
    char *part_num = NULL;
    char *devpath = NULL;
    char *dev_name;
    char *src_path = pool->def->source.devices[0].path;
    char *srcname = last_component(src_path);
    virCommandPtr cmd = NULL;
    bool isDevMapperDevice;
    int rc = -1;

    virCheckFlags(0, -1);

    if (!vol->target.path) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("volume target path empty for source path '%s'"),
                      src_path);
        return -1;
    }

    /* NB: This is the corollary to the algorithm in libvirt_parthelper
     *     (parthelper.c) that is used to generate the target.path name
     *     for use by libvirt. Changes to either, need to be reflected
     *     in both places */
    isDevMapperDevice = virIsDevMapperDevice(vol->target.path);
    if (isDevMapperDevice) {
        dev_name = last_component(vol->target.path);
    } else {
        if (virFileResolveLink(vol->target.path, &devpath) < 0) {
            virReportSystemError(errno,
                                 _("Couldn't read volume target path '%s'"),
                                 vol->target.path);
            goto cleanup;
        }
        dev_name = last_component(devpath);
    }

    VIR_DEBUG("dev_name=%s, srcname=%s", dev_name, srcname);

    if (!STRPREFIX(dev_name, srcname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume path '%s' did not start with parent "
                         "pool source device name."), dev_name);
        goto cleanup;
    }

    part_num = dev_name + strlen(srcname);

    /* For device mapper and we have a partition character 'p' as the
     * current character, let's move beyond that before checking part_num */
    if (isDevMapperDevice && *part_num == 'p')
        part_num++;

    if (*part_num == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse partition number from target "
                         "'%s'"), dev_name);
        goto cleanup;
    }

    /* eg parted /dev/sda rm 2 or /dev/mapper/mpathc rm 2 */
    cmd = virCommandNewArgList(PARTED,
                               src_path,
                               "rm",
                               "--script",
                               part_num,
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    /* Refreshing the pool is the easiest option as LOGICAL and EXTENDED
     * partition allocation/capacity management is handled within
     * virStorageBackendDiskMakeDataVol and trying to redo that logic
     * here is pointless
     */
    virStoragePoolObjClearVols(pool);
    if (virStorageBackendDiskRefreshPool(conn, pool) < 0)
        goto cleanup;

    rc = 0;
 cleanup:
    VIR_FREE(devpath);
    virCommandFree(cmd);
    return rc;
}


static int
virStorageBackendDiskCreateVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol)
{
    int res = -1;
    char *partFormat = NULL;
    unsigned long long startOffset = 0, endOffset = 0;
    virCommandPtr cmd = virCommandNewArgList(PARTED,
                                             pool->def->source.devices[0].path,
                                             "mkpart",
                                             "--script",
                                             NULL);

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("storage pool does not support encrypted "
                               "volumes"));
        goto cleanup;
    }

    if (virStorageBackendDiskPartFormat(pool, vol, &partFormat) != 0)
        goto cleanup;
    virCommandAddArg(cmd, partFormat);

    if (virStorageBackendDiskPartBoundaries(pool, &startOffset,
                                            &endOffset,
                                            vol->target.capacity) != 0) {
        goto cleanup;
    }

    virCommandAddArgFormat(cmd, "%lluB", startOffset);
    virCommandAddArgFormat(cmd, "%lluB", endOffset);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    /* wait for device node to show up */
    virFileWaitForDevices();

    /* Blow away free extent info, as we're about to re-populate it */
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    /* Specifying a target path is meaningless */
    VIR_FREE(vol->target.path);

    /* Fetch actual extent info, generate key */
    if (virStorageBackendDiskReadPartitions(pool, vol) < 0) {
        /* Best effort to remove the partition. Ignore any errors
         * since we could be calling this with vol->target.path == NULL
         */
        virErrorPtr save_err = virSaveLastError();
        ignore_value(virStorageBackendDiskDeleteVol(conn, pool, vol, 0));
        virSetError(save_err);
        virFreeError(save_err);
        goto cleanup;
    }

    res = 0;

 cleanup:
    VIR_FREE(partFormat);
    virCommandFree(cmd);
    return res;
}

static int
virStorageBackendDiskBuildVolFrom(virConnectPtr conn,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  virStorageVolDefPtr inputvol,
                                  unsigned int flags)
{
    virStorageBackendBuildVolFrom build_func;

    build_func = virStorageBackendGetBuildVolFromFunction(vol, inputvol);
    if (!build_func)
        return -1;

    return build_func(conn, pool, vol, inputvol, flags);
}


static int
virStorageBackendDiskVolWipe(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             virStorageVolDefPtr vol,
                             unsigned int algorithm,
                             unsigned int flags)
{
    if (vol->source.partType != VIR_STORAGE_VOL_DISK_TYPE_EXTENDED)
        return virStorageBackendVolWipeLocal(conn, pool, vol, algorithm, flags);

    /* Wiping an extended partition is not support */
    virReportError(VIR_ERR_NO_SUPPORT,
                   _("cannot wipe extended partition '%s'"),
                   vol->target.path);
    return -1;
}


virStorageBackend virStorageBackendDisk = {
    .type = VIR_STORAGE_POOL_DISK,

    .startPool = virStorageBackendDiskStartPool,
    .buildPool = virStorageBackendDiskBuildPool,
    .refreshPool = virStorageBackendDiskRefreshPool,

    .createVol = virStorageBackendDiskCreateVol,
    .deleteVol = virStorageBackendDiskDeleteVol,
    .buildVolFrom = virStorageBackendDiskBuildVolFrom,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendDiskVolWipe,
};


int
virStorageBackendDiskRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendDisk);
}
