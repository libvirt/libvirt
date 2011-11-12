/*
 * storage_backend_disk.c: storage backend for disk handling
 *
 * Copyright (C) 2007-2008, 2010-2011 Red Hat, Inc.
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
#include "command.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define PARTHELPER LIBEXECDIR "/libvirt_parthelper"

#define SECTOR_SIZE 512

static int
virStorageBackendDiskMakeDataVol(virStoragePoolObjPtr pool,
                                 char **const groups,
                                 virStorageVolDefPtr vol)
{
    char *tmp, *devpath;

    if (vol == NULL) {
        if (VIR_ALLOC(vol) < 0) {
            virReportOOMError();
            return -1;
        }

        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0) {
            virReportOOMError();
            virStorageVolDefFree(vol);
            return -1;
        }
        pool->volumes.objs[pool->volumes.count++] = vol;

        /* Prepended path will be same for all partitions, so we can
         * strip the path to form a reasonable pool-unique name
         */
        tmp = strrchr(groups[0], '/');
        if ((vol->name = strdup(tmp ? tmp + 1 : groups[0])) == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    if (vol->target.path == NULL) {
        if ((devpath = strdup(groups[0])) == NULL) {
            virReportOOMError();
            return -1;
        }

        /* Now figure out the stable path
         *
         * XXX this method is O(N) because it scans the pool target
         * dir every time its run. Should figure out a more efficient
         * way of doing this...
         */
        vol->target.path = virStorageBackendStablePath(pool, devpath);
        VIR_FREE(devpath);
        if (vol->target.path == NULL)
            return -1;
    }

    if (vol->key == NULL) {
        /* XXX base off a unique key of the underlying disk */
        if ((vol->key = strdup(vol->target.path)) == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    if (vol->source.extents == NULL) {
        if (VIR_ALLOC(vol->source.extents) < 0) {
            virReportOOMError();
            return -1;
        }
        vol->source.nextent = 1;

        if (virStrToLong_ull(groups[3], NULL, 10,
                             &vol->source.extents[0].start) < 0) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot parse device start location"));
            return -1;
        }

        if (virStrToLong_ull(groups[4], NULL, 10,
                             &vol->source.extents[0].end) < 0) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot parse device end location"));
            return -1;
        }

        if ((vol->source.extents[0].path =
             strdup(pool->def->source.devices[0].path)) == NULL) {
            virReportOOMError();
            return -1;
        }
    }

    /* Refresh allocation/capacity/perms */
    if (virStorageBackendUpdateVolInfo(vol, 1) < 0)
        return -1;

    /* set partition type */
    if (STREQ(groups[1], "normal"))
       vol->target.type = VIR_STORAGE_VOL_DISK_TYPE_PRIMARY;
    else if (STREQ(groups[1], "logical"))
       vol->target.type = VIR_STORAGE_VOL_DISK_TYPE_LOGICAL;
    else if (STREQ(groups[1], "extended"))
       vol->target.type = VIR_STORAGE_VOL_DISK_TYPE_EXTENDED;
    else
       vol->target.type = VIR_STORAGE_VOL_DISK_TYPE_NONE;

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
    if (dev->freeExtents[dev->nfreeExtent].start == 0) {
        dev->freeExtents[dev->nfreeExtent].start = SECTOR_SIZE;
    }

    pool->def->available +=
        (dev->freeExtents[dev->nfreeExtent].end -
         dev->freeExtents[dev->nfreeExtent].start);
    if (dev->freeExtents[dev->nfreeExtent].end > pool->def->capacity)
        pool->def->capacity = dev->freeExtents[dev->nfreeExtent].end;

    dev->nfreeExtent++;

    return 0;
}


static int
virStorageBackendDiskMakeVol(virStoragePoolObjPtr pool,
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
    const char *prog[] = {
        PARTHELPER, pool->def->source.devices[0].path, NULL,
    };

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    return virStorageBackendRunProgNul(pool,
                                       prog,
                                       6,
                                       virStorageBackendDiskMakeVol,
                                       vol);
}

static int
virStorageBackendDiskMakePoolGeometry(virStoragePoolObjPtr pool,
                                      size_t ntok ATTRIBUTE_UNUSED,
                                      char **const groups,
                                      void *data ATTRIBUTE_UNUSED)
{

       pool->def->source.devices[0].geometry.cyliders = atoi(groups[0]);
       pool->def->source.devices[0].geometry.heads = atoi(groups[1]);
       pool->def->source.devices[0].geometry.sectors = atoi(groups[2]);

       return 0;
}

static int
virStorageBackendDiskReadGeometry(virStoragePoolObjPtr pool)
{
    const char *prog[] = {
        PARTHELPER, pool->def->source.devices[0].path, "-g", NULL,
    };

    return virStorageBackendRunProgNul(pool,
                                       prog,
                                       3,
                                       virStorageBackendDiskMakePoolGeometry,
                                       NULL);
}

static int
virStorageBackendDiskRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    virFileWaitForDevices();

    if (!virFileExists(pool->def->source.devices[0].path)) {
        virStorageReportError(VIR_ERR_INVALID_ARG,
                              _("device path '%s' doesn't exist"),
                              pool->def->source.devices[0].path);
        return -1;
    }

    if (virStorageBackendDiskReadGeometry(pool) != 0) {
        return -1;
    }

    return virStorageBackendDiskReadPartitions(pool, NULL);
}


/**
 * Check for a valid disk label (partition table) on device
 *
 * return: 0 - valid disk label found
 *        >0 - no or unrecognized disk label
 *        <0 - error finding the disk label
 */
static int
virStorageBackendDiskFindLabel(const char* device)
{
    const char *const args[] = {
        device, "print", "--script", NULL,
    };
    virCommandPtr cmd = virCommandNew(PARTED);
    char *output = NULL;
    int ret = -1;

    virCommandAddArgSet(cmd, args);
    virCommandAddEnvString(cmd, "LC_ALL=C");
    virCommandSetOutputBuffer(cmd, &output);

    /* if parted succeeds we have a valid partition table */
    ret = virCommandRun(cmd, NULL);
    if (ret < 0) {
        if (strstr (output, "unrecognised disk label"))
            ret = 1;
    }

    virCommandFree(cmd);
    VIR_FREE(output);
    return ret;
}


/**
 * Write a new partition table header
 */
static int
virStorageBackendDiskBuildPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool,
                               unsigned int flags)
{
    bool ok_to_mklabel = false;
    int ret = -1;
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

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, ret);

    if (flags == (VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE)) {
        virStorageReportError(VIR_ERR_OPERATION_INVALID,
                              _("Overwrite and no overwrite flags"
                                " are mutually exclusive"));
        goto error;
    }

    if (flags & VIR_STORAGE_POOL_BUILD_OVERWRITE)
        ok_to_mklabel = true;
    else {
        int check;

        check = virStorageBackendDiskFindLabel (
                    pool->def->source.devices[0].path);
        if (check > 0) {
            ok_to_mklabel = true;
        } else if (check < 0) {
            virStorageReportError(VIR_ERR_OPERATION_FAILED,
                                  _("Error checking for disk label"));
        } else {
            virStorageReportError(VIR_ERR_OPERATION_INVALID,
                                  _("Disk label already present"));
        }
    }

    if (ok_to_mklabel)
        ret = virRun(prog, NULL);

error:
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
        /* count primary and extended paritions,
           can't be more than 3 to create a new primary partition */
        int i;
        int count = 0;
        for (i = 0; i < pool->volumes.count; i++) {
             if (pool->volumes.objs[i]->target.type == VIR_STORAGE_VOL_DISK_TYPE_PRIMARY ||
                 pool->volumes.objs[i]->target.type == VIR_STORAGE_VOL_DISK_TYPE_EXTENDED) {
                     count++;
             }
        }
        if (count >= 4) {
            return VIR_STORAGE_VOL_DISK_TYPE_LOGICAL;
        }
    }

    /* for all other cases, all partitions are primary */
    return VIR_STORAGE_VOL_DISK_TYPE_PRIMARY;
}

static int
virStorageBackendDiskPartFormat(virStoragePoolObjPtr pool,
                                virStorageVolDefPtr vol,
                                char** partFormat)
{
    int i;
    if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
        const char *partedFormat;
        partedFormat = virStoragePartedFsTypeTypeToString(vol->target.format);
        if (partedFormat == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("Invalid partition type"));
            return -1;
        }
        if (vol->target.format == VIR_STORAGE_VOL_DISK_EXTENDED) {
            /* make sure we don't have a extended partition already */
            for (i = 0; i < pool->volumes.count; i++) {
                if (pool->volumes.objs[i]->target.format ==
                    VIR_STORAGE_VOL_DISK_EXTENDED) {
                    virStorageReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                          _("extended partition already exists"));
                    return -1;
                }
            }
            if ((*partFormat = strdup(partedFormat)) == NULL) {
                virReportOOMError();
                return -1;
            }
        } else {
            /* create primary partition as long as it is possible
               and after that check if an extended partition exists
               to create logical partitions. */
            /* XXX Only support one extended partition */
            switch (virStorageBackendDiskPartTypeToCreate(pool)) {
            case VIR_STORAGE_VOL_DISK_TYPE_PRIMARY:
                if (virAsprintf(partFormat, "primary %s", partedFormat) < 0) {
                    virReportOOMError();
                    return -1;
                }
                break;
            case VIR_STORAGE_VOL_DISK_TYPE_LOGICAL:
                /* make sure we have a extended partition */
                for (i = 0; i < pool->volumes.count; i++) {
                    if (pool->volumes.objs[i]->target.format ==
                        VIR_STORAGE_VOL_DISK_EXTENDED) {
                        if (virAsprintf(partFormat, "logical %s",
                                        partedFormat) < 0) {
                            virReportOOMError();
                            return -1;
                        }
                        break;
                    }
                }
                if (i == pool->volumes.count) {
                    virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                          "%s", _("no extended partition found and no primary partition available"));
                    return -1;
                }
                break;
            default:
                virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                      "%s", _("unknown partition type"));
                return -1;
            }
        }
    } else {
        if ((*partFormat = strdup("primary")) == NULL) {
            virReportOOMError();
            return -1;
        }
    }
    return 0;
}

/**
 * Aligns a new partition to nearest cylinder boundry
 * when having a msdos partition table type
 * to avoid any problem with all ready existing
 * partitions
 */
static int
virStorageBackendDiskPartBoundries(virStoragePoolObjPtr pool,
                                   unsigned long long *start,
                                   unsigned long long *end,
                                   unsigned long long allocation)
{
    int i;
    int smallestExtent = -1;
    unsigned long long smallestSize = 0;
    unsigned long long extraBytes = 0;
    unsigned long long alignedAllocation = allocation;
    virStoragePoolSourceDevicePtr dev = &pool->def->source.devices[0];
    unsigned long long cylinderSize = dev->geometry.heads *
                                      dev->geometry.sectors * SECTOR_SIZE;

    VIR_DEBUG("find free area: allocation %llu, cyl size %llu", allocation,
          cylinderSize);
    int partType = virStorageBackendDiskPartTypeToCreate(pool);

    /* how many extra bytes we have since we allocate
       aligned to the cylinder boundry */
    extraBytes = cylinderSize - (allocation % cylinderSize);

    for (i = 0 ; i < dev->nfreeExtent ; i++) {
         unsigned long long size =
             dev->freeExtents[i].end -
             dev->freeExtents[i].start;
         unsigned long long neededSize = allocation;

         if (pool->def->source.format == VIR_STORAGE_POOL_DISK_DOS) {
             /* align to cylinder boundry */
             neededSize += extraBytes;
             if ((*start % cylinderSize) > extraBytes) {
                 /* add an extra cylinder if the offset can't fit within
                    the extra bytes we have */
                 neededSize += cylinderSize;
             }
             /* if we are creating a logical patition, we need one extra
                block between partitions (or actually move start one block) */
             if (partType == VIR_STORAGE_VOL_DISK_TYPE_LOGICAL) {
                 size -= SECTOR_SIZE;
             }
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
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
        /* adjust our allocation if start is not at a cylinder boundry */
        *end -= (*start % cylinderSize);
    }

    /* counting in byte, we want the last byte of the current sector */
    *end -= 1;
    VIR_DEBUG("final aligned start %llu, end %llu", *start, *end);
    return 0;
}


static int
virStorageBackendDiskCreateVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol)
{
    int res = -1;
    char *start = NULL;
    char *end = NULL;
    char *partFormat;
    unsigned long long startOffset = 0, endOffset = 0;
    const char *cmdargv[] = {
        PARTED,
        pool->def->source.devices[0].path,
        "mkpart",
        "--script",
        NULL /*partFormat*/,
        NULL /*start*/,
        NULL /*end*/,
        NULL
    };

    if (vol->target.encryption != NULL) {
        virStorageReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                              "%s", _("storage pool does not support encrypted "
                                      "volumes"));
        return -1;
    }

    if (virStorageBackendDiskPartFormat(pool, vol, &partFormat) != 0) {
        return -1;
    }
    cmdargv[4] = partFormat;

    if (virStorageBackendDiskPartBoundries(pool, &startOffset,
                                           &endOffset,
                                           vol->capacity) != 0) {
        goto cleanup;
    }

    if (virAsprintf(&start, "%lluB", startOffset) < 0 ||
        virAsprintf(&end, "%lluB", endOffset) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    cmdargv[5] = start;
    cmdargv[6] = end;

    if (virRun(cmdargv, NULL) < 0)
        goto cleanup;

    /* wait for device node to show up */
    virFileWaitForDevices();

    /* Blow away free extent info, as we're about to re-populate it */
    VIR_FREE(pool->def->source.devices[0].freeExtents);
    pool->def->source.devices[0].nfreeExtent = 0;

    /* Specifying a target path is meaningless */
    VIR_FREE(vol->target.path);

    /* Fetch actual extent info, generate key */
    if (virStorageBackendDiskReadPartitions(pool, vol) < 0)
        goto cleanup;

    res = 0;

cleanup:
    VIR_FREE(partFormat);
    VIR_FREE(start);
    VIR_FREE(end);
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
virStorageBackendDiskDeleteVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool,
                               virStorageVolDefPtr vol,
                               unsigned int flags)
{
    char *part_num = NULL;
    char *devpath = NULL;
    char *dev_name, *srcname;
    virCommandPtr cmd = NULL;
    bool isDevMapperDevice;
    int rc = -1;

    virCheckFlags(0, -1);

    if (virFileResolveLink(vol->target.path, &devpath) < 0) {
        virReportSystemError(errno,
                             _("Couldn't read volume target path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    dev_name = basename(devpath);
    srcname = basename(pool->def->source.devices[0].path);
    VIR_DEBUG("dev_name=%s, srcname=%s", dev_name, srcname);

    isDevMapperDevice = virIsDevMapperDevice(devpath);

    if (!isDevMapperDevice && !STRPREFIX(dev_name, srcname)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Volume path '%s' did not start with parent "
                                "pool source device name."), dev_name);
        goto cleanup;
    }

    if (!isDevMapperDevice) {
        part_num = dev_name + strlen(srcname);

        if (*part_num == 0) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse partition number from target "
                                    "'%s'"), dev_name);
            goto cleanup;
        }

        /* eg parted /dev/sda rm 2 */
        cmd = virCommandNewArgList(PARTED,
                                   pool->def->source.devices[0].path,
                                   "rm",
                                   "--script",
                                   part_num,
                                   NULL);
        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    } else {
        cmd = virCommandNewArgList(DMSETUP, "remove", "--force", devpath, NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;
    }

    rc = 0;
cleanup:
    VIR_FREE(devpath);
    virCommandFree(cmd);
    return rc;
}


virStorageBackend virStorageBackendDisk = {
    .type = VIR_STORAGE_POOL_DISK,

    .buildPool = virStorageBackendDiskBuildPool,
    .refreshPool = virStorageBackendDiskRefreshPool,

    .createVol = virStorageBackendDiskCreateVol,
    .deleteVol = virStorageBackendDiskDeleteVol,
    .buildVolFrom = virStorageBackendDiskBuildVolFrom,
};
