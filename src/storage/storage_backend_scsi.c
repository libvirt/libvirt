/*
 * storage_backend_scsi.c: storage backend for SCSI handling
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
 * Author: Daniel P. Berrange <berrange redhat com>
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>

#include "virterror_internal.h"
#include "storage_backend_scsi.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"
#include "command.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

/* Function to check if the type file in the given sysfs_path is a
 * Direct-Access device (i.e. type 0).  Return -1 on failure, type of
 * the device otherwise.
 */
static int
getDeviceType(uint32_t host,
              uint32_t bus,
              uint32_t target,
              uint32_t lun,
              int *type)
{
    char *type_path = NULL;
    char typestr[3];
    char *gottype, *p;
    FILE *typefile;
    int retval = 0;

    if (virAsprintf(&type_path, "/sys/bus/scsi/devices/%u:%u:%u:%u/type",
                    host, bus, target, lun) < 0) {
        virReportOOMError();
        goto out;
    }

    typefile = fopen(type_path, "r");
    if (typefile == NULL) {
        virReportSystemError(errno,
                             _("Could not find typefile '%s'"),
                             type_path);
        /* there was no type file; that doesn't seem right */
        retval = -1;
        goto out;
    }

    gottype = fgets(typestr, 3, typefile);
    VIR_FORCE_FCLOSE(typefile);

    if (gottype == NULL) {
        virReportSystemError(errno,
                             _("Could not read typefile '%s'"),
                             type_path);
        /* we couldn't read the type file; have to give up */
        retval = -1;
        goto out;
    }

    /* we don't actually care about p, but if you pass NULL and the last
     * character is not \0, virStrToLong_i complains
     */
    if (virStrToLong_i(typestr, &p, 10, type) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Device type '%s' is not an integer"),
                              typestr);
        /* Hm, type wasn't an integer; seems strange */
        retval = -1;
        goto out;
    }

    VIR_DEBUG("Device type is %d", *type);

out:
    VIR_FREE(type_path);
    return retval;
}

struct diskType {
    int part_table_type;
    unsigned short offset;
    unsigned short length;
    unsigned long long magic;
};

static struct diskType const disk_types[] = {
    { VIR_STORAGE_POOL_DISK_LVM2, 0x218, 8, 0x31303020324D564CULL },
    { VIR_STORAGE_POOL_DISK_GPT,  0x200, 8, 0x5452415020494645ULL },
    { VIR_STORAGE_POOL_DISK_DVH,  0x0,   4, 0x41A9E50BULL },
    { VIR_STORAGE_POOL_DISK_MAC,  0x0,   2, 0x5245ULL },
    { VIR_STORAGE_POOL_DISK_BSD,  0x40,  4, 0x82564557ULL },
    { VIR_STORAGE_POOL_DISK_SUN,  0x1fc, 2, 0xBEDAULL },
    /*
     * NOTE: pc98 is funky; the actual signature is 0x55AA (just like dos), so
     * we can't use that.  At the moment I'm relying on the "dummy" IPL
     * bootloader data that comes from parted.  Luckily, the chances of running
     * into a pc98 machine running libvirt are approximately nil.
     */
    /*{ 0x1fe, 2, 0xAA55UL },*/
    { VIR_STORAGE_POOL_DISK_PC98, 0x0,   8, 0x314C5049000000CBULL },
    /*
     * NOTE: the order is important here; some other disk types (like GPT and
     * and PC98) also have 0x55AA at this offset.  For that reason, the DOS
     * one must be the last one.
     */
    { VIR_STORAGE_POOL_DISK_DOS,  0x1fe, 2, 0xAA55ULL },
    { -1,                         0x0,   0, 0x0ULL },
};

static int
virStorageBackendSCSIUpdateVolTargetInfo(virStorageVolTargetPtr target,
                                         unsigned long long *allocation,
                                         unsigned long long *capacity)
{
    int fdret, fd = -1;
    int ret = -1;

    if ((fdret = virStorageBackendVolOpen(target->path)) < 0)
        goto cleanup;
    fd = fdret;

    if (virStorageBackendUpdateVolTargetInfoFD(target,
                                               fd,
                                               allocation,
                                               capacity) < 0)
        goto cleanup;

    if (virStorageBackendDetectBlockVolFormatFD(target, fd) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);

    return ret;
}


static char *
virStorageBackendSCSISerial(const char *dev)
{
    char *serial = NULL;
#ifdef HAVE_UDEV
    virCommandPtr cmd = virCommandNewArgList(
        "/lib/udev/scsi_id",
        "--replace-whitespace",
        "--whitelisted",
        "--device", dev,
        NULL
        );

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, &serial);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;
#endif

    if (serial && STRNEQ(serial, "")) {
        char *nl = strchr(serial, '\n');
        if (nl)
            *nl = '\0';
    } else {
        VIR_FREE(serial);
        if (!(serial = strdup(dev)))
            virReportOOMError();
    }

#ifdef HAVE_UDEV
cleanup:
    virCommandFree(cmd);
#endif

    return serial;
}


static int
virStorageBackendSCSINewLun(virStoragePoolObjPtr pool,
                            uint32_t host ATTRIBUTE_UNUSED,
                            uint32_t bus,
                            uint32_t target,
                            uint32_t lun,
                            const char *dev)
{
    virStorageVolDefPtr vol;
    char *devpath = NULL;
    int retval = 0;

    if (VIR_ALLOC(vol) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    /* 'host' is dynamically allocated by the kernel, first come,
     * first served, per HBA. As such it isn't suitable for use
     * in the volume name. We only need uniqueness per-pool, so
     * just leave 'host' out
     */
    if (virAsprintf(&(vol->name), "unit:%u:%u:%u", bus, target, lun) < 0) {
        virReportOOMError();
        retval = -1;
        goto free_vol;
    }

    if (virAsprintf(&devpath, "/dev/%s", dev) < 0) {
        virReportOOMError();
        retval = -1;
        goto free_vol;
    }

    VIR_DEBUG("Trying to create volume for '%s'", devpath);

    /* Now figure out the stable path
     *
     * XXX this method is O(N) because it scans the pool target
     * dir every time its run. Should figure out a more efficient
     * way of doing this...
     */
    if ((vol->target.path = virStorageBackendStablePath(pool,
                                                        devpath)) == NULL) {
        retval = -1;
        goto free_vol;
    }

    if (STREQLEN(devpath, vol->target.path, PATH_MAX) &&
        !(STREQ(pool->def->target.path, "/dev") ||
          STREQ(pool->def->target.path, "/dev/"))) {

        VIR_DEBUG("No stable path found for '%s' in '%s'",
                  devpath, pool->def->target.path);

        retval = -1;
        goto free_vol;
    }

    if (virStorageBackendSCSIUpdateVolTargetInfo(&vol->target,
                                                 &vol->allocation,
                                                 &vol->capacity) < 0) {

        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to update volume for '%s'"),
                              devpath);
        retval = -1;
        goto free_vol;
    }

    if (!(vol->key = virStorageBackendSCSISerial(vol->target.path))) {
        retval = -1;
        goto free_vol;
    }

    pool->def->capacity += vol->capacity;
    pool->def->allocation += vol->allocation;

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count + 1) < 0) {
        virReportOOMError();
        retval = -1;
        goto free_vol;
    }
    pool->volumes.objs[pool->volumes.count++] = vol;

    goto out;

free_vol:
    virStorageVolDefFree(vol);
out:
    VIR_FREE(devpath);
    return retval;
}


static int
getNewStyleBlockDevice(const char *lun_path,
                       const char *block_name ATTRIBUTE_UNUSED,
                       char **block_device)
{
    char *block_path = NULL;
    DIR *block_dir = NULL;
    struct dirent *block_dirent = NULL;
    int retval = 0;

    if (virAsprintf(&block_path, "%s/block", lun_path) < 0) {
        virReportOOMError();
        goto out;
    }

    VIR_DEBUG("Looking for block device in '%s'", block_path);

    block_dir = opendir(block_path);
    if (block_dir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir sysfs path '%s'"),
                             block_path);
        retval = -1;
        goto out;
    }

    while ((block_dirent = readdir(block_dir))) {

        if (STREQLEN(block_dirent->d_name, ".", 1)) {
            continue;
        }

        *block_device = strdup(block_dirent->d_name);

        if (*block_device == NULL) {
            virReportOOMError();
            closedir(block_dir);
            retval = -1;
            goto out;
        }

        VIR_DEBUG("Block device is '%s'", *block_device);

        break;
    }

    closedir(block_dir);

out:
    VIR_FREE(block_path);
    return retval;
}


static int
getOldStyleBlockDevice(const char *lun_path ATTRIBUTE_UNUSED,
                       const char *block_name,
                       char **block_device)
{
    char *blockp = NULL;
    int retval = 0;

    /* old-style; just parse out the sd */
    blockp = strrchr(block_name, ':');
    if (blockp == NULL) {
        /* Hm, wasn't what we were expecting; have to give up */
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to parse block name %s"),
                              block_name);
        retval = -1;
    } else {
        blockp++;
        *block_device = strdup(blockp);

        if (*block_device == NULL) {
            virReportOOMError();
            retval = -1;
            goto out;
        }

        VIR_DEBUG("Block device is '%s'", *block_device);
    }

out:
    return retval;
}


static int
getBlockDevice(uint32_t host,
               uint32_t bus,
               uint32_t target,
               uint32_t lun,
               char **block_device)
{
    char *lun_path = NULL;
    DIR *lun_dir = NULL;
    struct dirent *lun_dirent = NULL;
    int retval = 0;

    if (virAsprintf(&lun_path, "/sys/bus/scsi/devices/%u:%u:%u:%u",
                    host, bus, target, lun) < 0) {
        virReportOOMError();
        goto out;
    }

    lun_dir = opendir(lun_path);
    if (lun_dir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir sysfs path '%s'"),
                             lun_path);
        retval = -1;
        goto out;
    }

    while ((lun_dirent = readdir(lun_dir))) {
        if (STREQLEN(lun_dirent->d_name, "block", 5)) {
            if (strlen(lun_dirent->d_name) == 5) {
                retval = getNewStyleBlockDevice(lun_path,
                                                lun_dirent->d_name,
                                                block_device);
            } else {
                retval = getOldStyleBlockDevice(lun_path,
                                                lun_dirent->d_name,
                                                block_device);
            }
            break;
        }
    }

    closedir(lun_dir);

out:
    VIR_FREE(lun_path);
    return retval;
}


static int
processLU(virStoragePoolObjPtr pool,
          uint32_t host,
          uint32_t bus,
          uint32_t target,
          uint32_t lun)
{
    char *type_path = NULL;
    int retval = 0;
    int device_type;
    char *block_device = NULL;

    VIR_DEBUG("Processing LU %u:%u:%u:%u",
              host, bus, target, lun);

    if (getDeviceType(host, bus, target, lun, &device_type) < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Failed to determine if %u:%u:%u:%u is a Direct-Access LUN"),
                              host, bus, target, lun);
        retval = -1;
        goto out;
    }

    /* We don't create volumes for devices other than disk and cdrom
     * devices, but finding a device that isn't one of those types
     * isn't an error, either. */
    if (!(device_type == VIR_STORAGE_DEVICE_TYPE_DISK ||
          device_type == VIR_STORAGE_DEVICE_TYPE_ROM))
    {
        retval = 0;
        goto out;
    }

    VIR_DEBUG("%u:%u:%u:%u is a Direct-Access LUN",
              host, bus, target, lun);

    if (getBlockDevice(host, bus, target, lun, &block_device) < 0) {
        goto out;
    }

    if (virStorageBackendSCSINewLun(pool,
                                    host, bus, target, lun,
                                    block_device) < 0) {
        VIR_DEBUG("Failed to create new storage volume for %u:%u:%u:%u",
                  host, bus, target, lun);
        retval = -1;
        goto out;
    }

    VIR_DEBUG("Created new storage volume for %u:%u:%u:%u successfully",
              host, bus, target, lun);

    VIR_FREE(type_path);

out:
    VIR_FREE(block_device);
    return retval;
}


int
virStorageBackendSCSIFindLUs(virStoragePoolObjPtr pool,
                             uint32_t scanhost)
{
    int retval = 0;
    uint32_t bus, target, lun;
    char *device_path = NULL;
    DIR *devicedir = NULL;
    struct dirent *lun_dirent = NULL;
    char devicepattern[64];

    VIR_DEBUG("Discovering LUs on host %u", scanhost);

    virFileWaitForDevices();

    if (virAsprintf(&device_path, "/sys/bus/scsi/devices") < 0) {
        virReportOOMError();
        goto out;
    }

    devicedir = opendir(device_path);

    if (devicedir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir path '%s'"), device_path);
        retval = -1;
        goto out;
    }

    snprintf(devicepattern, sizeof(devicepattern), "%u:%%u:%%u:%%u\n", scanhost);

    while ((lun_dirent = readdir(devicedir))) {
        if (sscanf(lun_dirent->d_name, devicepattern,
                   &bus, &target, &lun) != 3) {
            continue;
        }

        VIR_DEBUG("Found LU '%s'", lun_dirent->d_name);

        processLU(pool, scanhost, bus, target, lun);
    }

    closedir(devicedir);

out:
    VIR_FREE(device_path);
    return retval;
}


int
virStorageBackendSCSIGetHostNumber(const char *sysfs_path,
                                   uint32_t *host)
{
    int retval = 0;
    DIR *sysdir = NULL;
    struct dirent *dirent = NULL;

    VIR_DEBUG("Finding host number from '%s'", sysfs_path);

    virFileWaitForDevices();

    sysdir = opendir(sysfs_path);

    if (sysdir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir path '%s'"), sysfs_path);
        retval = -1;
        goto out;
    }

    while ((dirent = readdir(sysdir))) {
        if (STREQLEN(dirent->d_name, "target", strlen("target"))) {
            if (sscanf(dirent->d_name,
                       "target%u:", host) != 1) {
                VIR_DEBUG("Failed to parse target '%s'", dirent->d_name);
                retval = -1;
                break;
            }
        }
    }

    closedir(sysdir);
out:
    return retval;
}


static int
virStorageBackendSCSITriggerRescan(uint32_t host)
{
    int fd = -1;
    int retval = 0;
    char *path;

    VIR_DEBUG("Triggering rescan of host %d", host);

    if (virAsprintf(&path, "/sys/class/scsi_host/host%u/scan", host) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    VIR_DEBUG("Scan trigger path is '%s'", path);

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        virReportSystemError(errno,
                             _("Could not open '%s' to trigger host scan"),
                             path);
        retval = -1;
        goto free_path;
    }

    if (safewrite(fd,
                  LINUX_SYSFS_SCSI_HOST_SCAN_STRING,
                  sizeof(LINUX_SYSFS_SCSI_HOST_SCAN_STRING)) < 0) {
        VIR_FORCE_CLOSE(fd);
        virReportSystemError(errno,
                             _("Write to '%s' to trigger host scan failed"),
                             path);
        retval = -1;
    }

    VIR_FORCE_CLOSE(fd);
free_path:
    VIR_FREE(path);
out:
    VIR_DEBUG("Rescan of host %d complete", host);
    return retval;
}

static int
virStorageBackendSCSICheckPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool,
                               bool *isActive)
{
    char *path;

    *isActive = false;
    if (virAsprintf(&path, "/sys/class/scsi_host/%s", pool->def->source.adapter) < 0) {
        virReportOOMError();
        return -1;
    }

    if (access(path, F_OK) == 0)
        *isActive = true;

    VIR_FREE(path);

    return 0;
}

static int
virStorageBackendSCSIRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    int retval = 0;
    uint32_t host;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if (sscanf(pool->def->source.adapter, "host%u", &host) != 1) {
        VIR_DEBUG("Failed to get host number from '%s'",
                    pool->def->source.adapter);
        retval = -1;
        goto out;
    }

    VIR_DEBUG("Scanning host%u", host);

    if (virStorageBackendSCSITriggerRescan(host) < 0) {
        retval = -1;
        goto out;
    }

    virStorageBackendSCSIFindLUs(pool, host);

out:
    return retval;
}


virStorageBackend virStorageBackendSCSI = {
    .type = VIR_STORAGE_POOL_SCSI,

    .checkPool = virStorageBackendSCSICheckPool,
    .refreshPool = virStorageBackendSCSIRefreshPool,
};
