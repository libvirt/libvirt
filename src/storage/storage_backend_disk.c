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
 */

#include <config.h>
#include <unistd.h>

#include "virerror.h"
#include "virlog.h"
#include "storage_backend_disk.h"
#include "storage_util.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virfile.h"
#include "virutil.h"
#include "configmake.h"
#include "virstring.h"
#include "virdevmapper.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_disk");

#define SECTOR_SIZE 512

#define PARTED "parted"

static bool
virStorageVolPartFindExtended(virStorageVolDef *def,
                              const void *opaque G_GNUC_UNUSED)
{
    if (def->source.partType == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED)
        return true;

    return false;
}


static int
virStorageBackendDiskMakeDataVol(virStoragePoolObj *pool,
                                 char **const groups,
                                 virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    char *tmp, *partname;
    bool addVol = false;
    g_autofree char *devpath = NULL;

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
        addVol = true;
        vol = g_new0(virStorageVolDef, 1);
        vol->name = g_strdup(partname);
    }

    if (vol->target.path == NULL) {
        devpath = g_strdup(groups[0]);

        /* Now figure out the stable path
         *
         * XXX this method is O(N) because it scans the pool target
         * dir every time its run. Should figure out a more efficient
         * way of doing this...
         */
        vol->target.path = virStorageBackendStablePath(pool, devpath, true);
        if (vol->target.path == NULL)
            goto error;
    }

    /* Enforce provided vol->name is the same as what parted created.
     * We do this after filling target.path so that we have a chance at
     * deleting the partition with this failure from CreateVol path
     */
    if (STRNEQ(vol->name, partname)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("invalid partition name '%1$s', expected '%2$s'"),
                       vol->name, partname);

        /* Let's see if by chance parthelper created a name that won't be
         * found later when we try to delete. We tell parthelper to add a 'p'
         * to the output via the part_separator flag, but if devmapper has
         * user_friendly_names set, the creation won't happen that way, thus
         * our deletion will fail because the name we generated is wrong.
         * Check for our conditions and see if the generated name is the
         * same as StablePath returns and has the 'p' in it */
        if (def->source.devices[0].part_separator == VIR_TRISTATE_BOOL_YES &&
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
        goto error;
    }

    if (vol->key == NULL) {
        /* XXX base off a unique key of the underlying disk */
        vol->key = g_strdup(vol->target.path);
    }

    if (vol->source.extents == NULL) {
        vol->source.extents = g_new0(virStorageVolSourceExtent, 1);
        vol->source.nextent = 1;

        if (virStrToLong_ull(groups[3], NULL, 10,
                             &vol->source.extents[0].start) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot parse device start location"));
            goto error;
        }

        if (virStrToLong_ull(groups[4], NULL, 10,
                             &vol->source.extents[0].end) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot parse device end location"));
            goto error;
        }

        vol->source.extents[0].path = g_strdup(def->source.devices[0].path);
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
     *
     * NB: A small window exists in some cases where the just created
     * partition disappears, but then reappears. Since we were given
     * vol->target.path from parthelper, let's just be sure that any
     * kernel magic that occurs as a result of parthelper doesn't cause
     * us to fail with some sort of ENOENT failure since that would be
     * quite "unexpected". So rather than just fail, let's use the
     * virWaitForDevices to ensure everything has settled properly.
     */
    virWaitForDevices();
    if (vol->source.partType == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
        if (virStorageBackendUpdateVolInfo(vol, false,
                                           VIR_STORAGE_VOL_OPEN_DEFAULT |
                                           VIR_STORAGE_VOL_OPEN_NOERROR,
                                           0) == -1)
            goto error;
        vol->target.allocation = 0;
        vol->target.capacity =
            (vol->source.extents[0].end - vol->source.extents[0].start);
    } else {
        if (virStorageBackendUpdateVolInfo(vol, false,
                                           VIR_STORAGE_VOL_OPEN_DEFAULT, 0) < 0)
            goto error;
    }

    /* Now that we've updated @vol enough, let's add it to the pool
     * if it's not already there so that the subsequent pool search
     * pool def adjustments will work properly */
    if (addVol && virStoragePoolObjAddVol(pool, vol) < 0)
        goto error;

    /* Find the extended partition and increase the allocation value */
    if (vol->source.partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL) {
        virStorageVolDef *voldef;

        voldef = virStoragePoolObjSearchVolume(pool,
                                               virStorageVolPartFindExtended,
                                               NULL);
        if (voldef)
            voldef->target.allocation += vol->target.allocation;
    }

    if (STRNEQ(groups[2], "metadata"))
        def->allocation += vol->target.allocation;
    if (vol->source.extents[0].end > def->capacity)
        def->capacity = vol->source.extents[0].end;

    return 0;

 error:
    if (addVol)
        virStorageVolDefFree(vol);
    return -1;
}

static int
virStorageBackendDiskMakeFreeExtent(virStoragePoolObj *pool,
                                    char **const groups)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStoragePoolSourceDevice *dev = &def->source.devices[0];

    VIR_REALLOC_N(dev->freeExtents, dev->nfreeExtent + 1);

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

    def->available += (dev->freeExtents[dev->nfreeExtent].end -
                       dev->freeExtents[dev->nfreeExtent].start);
    if (dev->freeExtents[dev->nfreeExtent].end > def->capacity)
        def->capacity = dev->freeExtents[dev->nfreeExtent].end;

    dev->nfreeExtent++;

    return 0;
}


struct virStorageBackendDiskPoolVolData {
    virStoragePoolObj *pool;
    virStorageVolDef *vol;
};

static int
virStorageBackendDiskMakeVol(size_t ntok G_GNUC_UNUSED,
                             char **const groups,
                             void *opaque)
{
    struct virStorageBackendDiskPoolVolData *data = opaque;
    virStoragePoolObj *pool = data->pool;
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
        virStorageVolDef *vol = data->vol;

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
virStorageBackendDiskReadPartitions(virStoragePoolObj *pool,
                                    virStorageVolDef *vol)
{
    /*
     *  # libvirt_parthelper DEVICE
     * /dev/sda1      normal       data        32256    106928128    106896384
     * /dev/sda2      normal       data    106928640 100027629568  99920701440
     * -              normal   metadata 100027630080 100030242304      2612736
     *
     */

    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    struct virStorageBackendDiskPoolVolData cbdata = {
        .pool = pool,
        .vol = vol,
    };
    g_autofree char *parthelper_path = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (!(parthelper_path = virFileFindResource("libvirt_parthelper",
                                                abs_top_builddir "/src",
                                                LIBEXECDIR)))
        return -1;

    cmd = virCommandNewArgList(parthelper_path,
                               def->source.devices[0].path,
                               NULL);

    /* Check for the presence of the part_separator='yes'. Pass this
     * along to the libvirt_parthelper as option '-p'. This will cause
     * libvirt_parthelper to append the "p" partition separator to
     * the generated device name for a source device which ends with
     * a non-numeric value (e.g. mpatha would generate mpathap#).
     */
    if (def->source.devices[0].part_separator == VIR_TRISTATE_BOOL_YES)
        virCommandAddArg(cmd, "-p");

    /* If a volume is passed, virStorageBackendDiskMakeVol only updates the
     * pool allocation for that single volume.
     */
    if (!vol)
        def->allocation = 0;
    def->capacity = def->available = 0;

    return virCommandRunNul(cmd, 6, virStorageBackendDiskMakeVol, &cbdata);
}

static int
virStorageBackendDiskMakePoolGeometry(size_t ntok G_GNUC_UNUSED,
                                      char **const groups,
                                      void *data)
{
    virStoragePoolObj *pool = data;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStoragePoolSourceDevice *device = &(def->source.devices[0]);
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
virStorageBackendDiskReadGeometry(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *parthelper_path = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (!(parthelper_path = virFileFindResource("libvirt_parthelper",
                                                abs_top_builddir "/src",
                                                LIBEXECDIR)))
        return -1;

    cmd = virCommandNewArgList(parthelper_path,
                               def->source.devices[0].path,
                               "-g",
                               NULL);

    return virCommandRunNul(cmd, 3, virStorageBackendDiskMakePoolGeometry,
                            pool);
}

static int
virStorageBackendDiskRefreshPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    VIR_FREE(def->source.devices[0].freeExtents);
    def->source.devices[0].nfreeExtent = 0;

    virWaitForDevices();

    if (!virFileExists(def->source.devices[0].path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device path '%1$s' doesn't exist"),
                       def->source.devices[0].path);
        return -1;
    }

    if (virStorageBackendDiskReadGeometry(pool) != 0)
        return -1;

    return virStorageBackendDiskReadPartitions(pool, NULL);
}


static int
virStorageBackendDiskStartPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    const char *format;
    const char *path = def->source.devices[0].path;

    /* This can take a significant amount of time. */
    virObjectUnlock(pool);
    virWaitForDevices();
    virObjectLock(pool);

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("device path '%1$s' doesn't exist"), path);
        return -1;
    }

    if (def->source.format == VIR_STORAGE_POOL_DISK_UNKNOWN)
        def->source.format = VIR_STORAGE_POOL_DISK_DOS;
    format = virStoragePoolFormatDiskTypeToString(def->source.format);
    if (!virStorageBackendDeviceIsEmpty(path, format, false))
        return -1;

    return 0;
}


static int
virStorageBackendDiskCheckPool(virStoragePoolObj *pool,
                               bool *isActive)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    const char *path = def->source.devices[0].path;

    *isActive = false;

    if (!virFileExists(path))
        return 0;

    if (def->source.format == VIR_STORAGE_POOL_DISK_UNKNOWN)
        def->source.format = VIR_STORAGE_POOL_DISK_DOS;

    if (!virStorageBackendDeviceIsEmpty(path,
                                        virStoragePoolFormatDiskTypeToString(def->source.format),
                                        false))
        return -1;

    *isActive = true;

    return 0;
}


/**
 * Write a new partition table header
 */
static int
virStorageBackendDiskBuildPool(virStoragePoolObj *pool,
                               unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    int format = def->source.format;
    const char *fmt;
    g_autoptr(virCommand) cmd = NULL;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, -1);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE,
                            -1);

    fmt = virStoragePoolFormatDiskTypeToString(format);

    if (!(flags & VIR_STORAGE_POOL_BUILD_OVERWRITE) &&
        !(virStorageBackendDeviceIsEmpty(def->source.devices[0].path,
                                         fmt, true)))
        return -1;

    if (virStorageBackendZeroPartitionTable(def->source.devices[0].path,
                                            1024 * 1024) < 0)
        return -1;

    /* eg parted /dev/sda mklabel --script msdos */
    if (format == VIR_STORAGE_POOL_DISK_UNKNOWN)
        format = def->source.format = VIR_STORAGE_POOL_DISK_DOS;
    if (format == VIR_STORAGE_POOL_DISK_DOS)
        fmt = "msdos";
    else
        fmt = virStoragePoolFormatDiskTypeToString(format);

    cmd = virCommandNewArgList(PARTED,
                               def->source.devices[0].path,
                               "mklabel",
                               "--script",
                               fmt,
                               NULL);

    virObjectUnlock(pool);
    ret = virCommandRun(cmd, NULL);
    virObjectLock(pool);

    return ret;
}


/**
 * Wipe the existing partition table
 */
static int
virStorageBackendDiskDeletePool(virStoragePoolObj *pool,
                                unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    virCheckFlags(0, -1);

    if (virStorageBackendZeroPartitionTable(def->source.devices[0].path,
                                            1024 * 1024) < 0)
        return -1;

    return 0;
}


struct virStorageVolNumData {
    int count;
};

static int
virStorageVolNumOfPartTypes(virStorageVolDef *def,
                            const void *opaque)
{
    struct virStorageVolNumData *data = (struct virStorageVolNumData *)opaque;

    if (def->source.partType == VIR_STORAGE_VOL_DISK_TYPE_PRIMARY ||
        def->source.partType == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED)
        data->count++;

    return 0;
}


/**
 * Decides what kind of partition type that should be created.
 * Important when the partition table is of msdos type
 */
static int
virStorageBackendDiskPartTypeToCreate(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    struct virStorageVolNumData data = { .count = 0 };

    if (def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        /* count primary and extended partitions,
           can't be more than 3 to create a new primary partition */
        if (virStoragePoolObjForEachVolume(pool, virStorageVolNumOfPartTypes,
                                           &data) == 0) {
            if (data.count >= 4)
                return VIR_STORAGE_VOL_DISK_TYPE_LOGICAL;
        }
    }

    /* for all other cases, all partitions are primary */
    return VIR_STORAGE_VOL_DISK_TYPE_PRIMARY;
}

static int
virStorageBackendDiskPartFormat(virStoragePoolObj *pool,
                                virStorageVolDef *vol,
                                char** partFormat)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    if (def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        const char *partedFormat;
        partedFormat = virStoragePartedFsTypeToString(vol->target.format);
        if (partedFormat == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Invalid partition type"));
            return -1;
        }
        if (vol->target.format == VIR_STORAGE_VOL_DISK_EXTENDED) {
            /* make sure we don't have an extended partition already */
            if (virStoragePoolObjSearchVolume(pool,
                                              virStorageVolPartFindExtended,
                                              NULL)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("extended partition already exists"));
                    return -1;
            }
            *partFormat = g_strdup(partedFormat);
        } else {
            /* create primary partition as long as it is possible
               and after that check if an extended partition exists
               to create logical partitions. */
            /* XXX Only support one extended partition */
            switch (virStorageBackendDiskPartTypeToCreate(pool)) {
            case VIR_STORAGE_VOL_DISK_TYPE_PRIMARY:
                *partFormat = g_strdup_printf("primary %s", partedFormat);
                break;
            case VIR_STORAGE_VOL_DISK_TYPE_LOGICAL:
                /* make sure we have an extended partition */
                if (virStoragePoolObjSearchVolume(pool,
                                                  virStorageVolPartFindExtended,
                                                  NULL)) {
                    *partFormat = g_strdup_printf("logical %s", partedFormat);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("no extended partition found and no primary partition available"));
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
        *partFormat = g_strdup("primary");
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
virStorageBackendDiskPartBoundaries(virStoragePoolObj *pool,
                                    unsigned long long *start,
                                    unsigned long long *end,
                                    unsigned long long allocation)
{
    size_t i;
    int smallestExtent = -1;
    unsigned long long smallestSize = 0;
    unsigned long long extraBytes = 0;
    unsigned long long alignedAllocation = allocation;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStoragePoolSourceDevice *dev = &def->source.devices[0];
    unsigned long long cylinderSize = (unsigned long long)dev->geometry.heads *
                                      dev->geometry.sectors * SECTOR_SIZE;
    int partType = virStorageBackendDiskPartTypeToCreate(pool);

    VIR_DEBUG("find free area: allocation %llu, cyl size %llu", allocation,
          cylinderSize);

    /* how many extra bytes we have since we allocate
       aligned to the cylinder boundary */
    extraBytes = cylinderSize - (allocation % cylinderSize);

    for (i = 0; i < dev->nfreeExtent; i++) {
         unsigned long long size =
             dev->freeExtents[i].end -
             dev->freeExtents[i].start;
         unsigned long long neededSize = allocation;

         if (def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
             /* align to cylinder boundary */
             neededSize += extraBytes;
             if ((dev->freeExtents[i].start % cylinderSize) > extraBytes) {
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
    if (def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        /* adjust our allocation if start is not at a cylinder boundary */
        *end -= (*start % cylinderSize);
    }

    /* counting in bytes, we want the last byte of the current sector */
    *end -= 1;
    VIR_DEBUG("final aligned start %llu, end %llu", *start, *end);
    return 0;
}


/* virStorageBackendDiskDeleteVol
 * @pool: Pointer to the storage pool
 * @vol: Pointer to the volume definition
 * @flags: flags (unused for now)
 *
 * This API will remove the disk volume partition either from direct
 * API call or as an error path during creation when the partition
 * name provided during create doesn't match the name read from
 * virStorageBackendDiskReadPartitions.
 *
 * For a device mapper device, device representation is dependent upon
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
virStorageBackendDiskDeleteVol(virStoragePoolObj *pool,
                               virStorageVolDef *vol,
                               unsigned int flags)
{
    char *part_num = NULL;
    g_autofree char *dev_name = NULL;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    char *src_path = def->source.devices[0].path;
    g_autofree char *srcname = g_path_get_basename(src_path);
    bool isDevMapperDevice;
    g_autofree char *devpath = NULL;
    g_autoptr(virCommand) cmd = NULL;

    virCheckFlags(0, -1);

    if (!vol->target.path) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("volume target path empty for source path '%1$s'"),
                      src_path);
        return -1;
    }

    /* NB: This is the corollary to the algorithm in libvirt_parthelper
     *     (parthelper.c) that is used to generate the target.path name
     *     for use by libvirt. Changes to either, need to be reflected
     *     in both places */
    isDevMapperDevice = virIsDevMapperDevice(vol->target.path);
    if (isDevMapperDevice) {
        dev_name = g_path_get_basename(vol->target.path);
    } else {
        if (virFileResolveLink(vol->target.path, &devpath) < 0) {
            virReportSystemError(errno,
                                 _("Couldn't read volume target path '%1$s'"),
                                 vol->target.path);
            return -1;
        }
        dev_name = g_path_get_basename(devpath);
    }

    VIR_DEBUG("dev_name=%s, srcname=%s", dev_name, srcname);

    if (!STRPREFIX(dev_name, srcname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume path '%1$s' did not start with parent pool source device name."),
                       dev_name);
        return -1;
    }

    part_num = dev_name + strlen(srcname);

    /* For device mapper and we have a partition character 'p' as the
     * current character, let's move beyond that before checking part_num */
    if (isDevMapperDevice && *part_num == 'p')
        part_num++;

    if (*part_num == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse partition number from target '%1$s'"),
                       dev_name);
        return -1;
    }

    /* eg parted /dev/sda rm 2 or /dev/mapper/mpathc rm 2 */
    cmd = virCommandNewArgList(PARTED,
                               src_path,
                               "rm",
                               "--script",
                               part_num,
                               NULL);
    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    /* Refreshing the pool is the easiest option as LOGICAL and EXTENDED
     * partition allocation/capacity management is handled within
     * virStorageBackendDiskMakeDataVol and trying to redo that logic
     * here is pointless
     */
    virStoragePoolObjClearVols(pool);
    if (virStorageBackendDiskRefreshPool(pool) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendDiskCreateVol(virStoragePoolObj *pool,
                               virStorageVolDef *vol)
{
    unsigned long long startOffset = 0, endOffset = 0;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virErrorPtr save_err;
    g_autofree char *partFormat = NULL;
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(PARTED,
                               def->source.devices[0].path,
                               "mkpart",
                               "--script",
                               NULL);

    if (vol->target.encryption &&
        vol->target.encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool only supports LUKS encrypted volumes"));
        return -1;
    }

    if (virStorageBackendDiskPartFormat(pool, vol, &partFormat) != 0)
        return -1;
    virCommandAddArg(cmd, partFormat);

    /* If we're going to encrypt using LUKS, then we could need up to
     * an extra 2MB for the LUKS header - so account for that now */
    if (vol->target.encryption)
        vol->target.capacity += 2 * 1024 * 1024;

    if (virStorageBackendDiskPartBoundaries(pool, &startOffset, &endOffset,
                                            vol->target.capacity) < 0)
        return -1;

    virCommandAddArgFormat(cmd, "%lluB", startOffset);
    virCommandAddArgFormat(cmd, "%lluB", endOffset);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    /* wait for device node to show up */
    virWaitForDevices();

    /* Blow away free extent info, as we're about to re-populate it */
    VIR_FREE(def->source.devices[0].freeExtents);
    def->source.devices[0].nfreeExtent = 0;

    /* Specifying a target path is meaningless */
    VIR_FREE(vol->target.path);

    /* Fetch actual extent info, generate key */
    if (virStorageBackendDiskReadPartitions(pool, vol) < 0)
        goto error;

    if (vol->target.encryption) {
        /* Adjust the sizes to account for the LUKS header */
        vol->target.capacity -= 2 * 1024 * 1024;
        vol->target.allocation -= 2 * 1024 * 1024;
        if (virStorageBackendCreateVolUsingQemuImg(pool, vol, NULL, 0) < 0)
            goto error;
    }

    return 0;

 error:
    /* Best effort to remove the partition. Ignore any errors
     * since we could be calling this with vol->target.path == NULL
     */
    virErrorPreserveLast(&save_err);
    ignore_value(virStorageBackendDiskDeleteVol(pool, vol, 0));
    virErrorRestore(&save_err);
    return -1;
}


static int
virStorageBackendDiskBuildVolFrom(virStoragePoolObj *pool,
                                  virStorageVolDef *vol,
                                  virStorageVolDef *inputvol,
                                  unsigned int flags)
{
    virStorageBackendBuildVolFrom build_func;

    build_func = virStorageBackendGetBuildVolFromFunction(vol, inputvol);
    if (!build_func)
        return -1;

    return build_func(pool, vol, inputvol, flags);
}


static int
virStorageBackendDiskVolWipe(virStoragePoolObj *pool,
                             virStorageVolDef *vol,
                             unsigned int algorithm,
                             unsigned int flags)
{
    if (vol->source.partType != VIR_STORAGE_VOL_DISK_TYPE_EXTENDED)
        return virStorageBackendVolWipeLocal(pool, vol, algorithm, flags);

    /* Wiping an extended partition is not support */
    virReportError(VIR_ERR_NO_SUPPORT,
                   _("cannot wipe extended partition '%1$s'"),
                   vol->target.path);
    return -1;
}


virStorageBackend virStorageBackendDisk = {
    .type = VIR_STORAGE_POOL_DISK,

    .startPool = virStorageBackendDiskStartPool,
    .buildPool = virStorageBackendDiskBuildPool,
    .refreshPool = virStorageBackendDiskRefreshPool,
    .deletePool = virStorageBackendDiskDeletePool,
    .checkPool = virStorageBackendDiskCheckPool,

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
