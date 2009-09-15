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

#define VIR_FROM_THIS VIR_FROM_STORAGE

/* Function to check if the type file in the given sysfs_path is a
 * Direct-Access device (i.e. type 0).  Return -1 on failure, type of
 * the device otherwise.
 */
static int
getDeviceType(virConnectPtr conn,
              uint32_t host,
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
        virReportOOMError(conn);
        goto out;
    }

    typefile = fopen(type_path, "r");
    if (typefile == NULL) {
        virReportSystemError(conn, errno,
                             _("Could not find typefile '%s'"),
                             type_path);
        /* there was no type file; that doesn't seem right */
        retval = -1;
        goto out;
    }

    gottype = fgets(typestr, 3, typefile);
    fclose(typefile);

    if (gottype == NULL) {
        virReportSystemError(conn, errno,
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
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Device type '%s' is not an integer"),
                              typestr);
        /* Hm, type wasn't an integer; seems strange */
        retval = -1;
        goto out;
    }

    VIR_DEBUG(_("Device type is %d"), *type);

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
virStorageBackendSCSIUpdateVolTargetInfo(virConnectPtr conn,
                                         virStorageVolTargetPtr target,
                                         unsigned long long *allocation,
                                         unsigned long long *capacity)
{
    int fd, i, ret = -1;
    off_t start;
    unsigned char buffer[1024];
    ssize_t bytes;

    if ((fd = open(target->path, O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot open volume '%s'"),
                             target->path);
        return -1;
    }

    if (virStorageBackendUpdateVolTargetInfoFD(conn,
                                               target,
                                               fd,
                                               allocation,
                                               capacity) < 0)
        goto cleanup;

    /* make sure to set the target format "unknown" to begin with */
    target->format = VIR_STORAGE_POOL_DISK_UNKNOWN;

    start = lseek(fd, 0, SEEK_SET);
    if (start < 0) {
        virReportSystemError(conn, errno,
                             _("cannot seek to beginning of file '%s'"),
                             target->path);
        goto cleanup;
    }
    bytes = saferead(fd, buffer, sizeof(buffer));
    if (bytes < 0) {
        virReportSystemError(conn, errno,
                             _("cannot read beginning of file '%s'"),
                             target->path);
        goto cleanup;
    }

    for (i = 0; disk_types[i].part_table_type != -1; i++) {
        if (disk_types[i].offset + disk_types[i].length > bytes)
            continue;
        if (memcmp(buffer+disk_types[i].offset, &disk_types[i].magic,
            disk_types[i].length) == 0) {
            target->format = disk_types[i].part_table_type;
            break;
        }
    }

    ret = 0;

  cleanup:
    close(fd);

    return ret;
}

static int
virStorageBackendSCSINewLun(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            uint32_t host,
                            uint32_t bus,
                            uint32_t target,
                            uint32_t lun,
                            const char *dev)
{
    virStorageVolDefPtr vol;
    char *devpath = NULL;
    int retval = 0;

    if (VIR_ALLOC(vol) < 0) {
        virReportOOMError(conn);
        retval = -1;
        goto out;
    }

    vol->type = VIR_STORAGE_VOL_BLOCK;

    if (virAsprintf(&(vol->name), "%u.%u.%u.%u", host, bus, target, lun) < 0) {
        virReportOOMError(conn);
        retval = -1;
        goto free_vol;
    }

    if (virAsprintf(&devpath, "/dev/%s", dev) < 0) {
        virReportOOMError(conn);
        retval = -1;
        goto free_vol;
    }

    VIR_DEBUG(_("Trying to create volume for '%s'"), devpath);

    /* Now figure out the stable path
     *
     * XXX this method is O(N) because it scans the pool target
     * dir every time its run. Should figure out a more efficient
     * way of doing this...
     */
    if ((vol->target.path = virStorageBackendStablePath(conn,
                                                        pool,
                                                        devpath)) == NULL) {
        retval = -1;
        goto free_vol;
    }

    if (STREQLEN(devpath, vol->target.path, PATH_MAX) &&
        !(STREQ(pool->def->target.path, "/dev") ||
          STREQ(pool->def->target.path, "/dev/"))) {

        VIR_DEBUG(_("No stable path found for '%s' in '%s'"),
                  devpath, pool->def->target.path);

        retval = -1;
        goto free_vol;
    }

    if (virStorageBackendSCSIUpdateVolTargetInfo(conn,
                                                 &vol->target,
                                                 &vol->allocation,
                                                 &vol->capacity) < 0) {

        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to update volume for '%s'"),
                              devpath);
        retval = -1;
        goto free_vol;
    }

    /* XXX should use logical unit's UUID instead */
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virReportOOMError(conn);
        retval = -1;
        goto free_vol;
    }

    pool->def->capacity += vol->capacity;
    pool->def->allocation += vol->allocation;

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count + 1) < 0) {
        virReportOOMError(conn);
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
getNewStyleBlockDevice(virConnectPtr conn,
                       const char *lun_path,
                       const char *block_name ATTRIBUTE_UNUSED,
                       char **block_device)
{
    char *block_path = NULL;
    DIR *block_dir = NULL;
    struct dirent *block_dirent = NULL;
    int retval = 0;

    if (virAsprintf(&block_path, "%s/block", lun_path) < 0) {
        virReportOOMError(conn);
        goto out;
    }

    VIR_DEBUG(_("Looking for block device in '%s'"), block_path);

    block_dir = opendir(block_path);
    if (block_dir == NULL) {
        virReportSystemError(conn, errno,
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
        VIR_DEBUG(_("Block device is '%s'"), *block_device);

        break;
    }

    closedir(block_dir);

out:
    VIR_FREE(block_path);
    return retval;
}


static int
getOldStyleBlockDevice(virConnectPtr conn,
                       const char *lun_path ATTRIBUTE_UNUSED,
                       const char *block_name,
                       char **block_device)
{
    char *blockp = NULL;
    int retval = 0;

    /* old-style; just parse out the sd */
    blockp = strrchr(block_name, ':');
    if (blockp == NULL) {
        /* Hm, wasn't what we were expecting; have to give up */
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to parse block name %s"),
                              block_name);
        retval = -1;
    } else {
        blockp++;
        *block_device = strdup(blockp);

        VIR_DEBUG(_("Block device is '%s'"), *block_device);
    }

    return retval;
}


static int
getBlockDevice(virConnectPtr conn,
               uint32_t host,
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
        virReportOOMError(conn);
        goto out;
    }

    lun_dir = opendir(lun_path);
    if (lun_dir == NULL) {
        virReportSystemError(conn, errno,
                             _("Failed to opendir sysfs path '%s'"),
                             lun_path);
        retval = -1;
        goto out;
    }

    while ((lun_dirent = readdir(lun_dir))) {
        if (STREQLEN(lun_dirent->d_name, "block", 5)) {
            if (strlen(lun_dirent->d_name) == 5) {
                retval = getNewStyleBlockDevice(conn,
                                                lun_path,
                                                lun_dirent->d_name,
                                                block_device);
            } else {
                retval = getOldStyleBlockDevice(conn,
                                                lun_path,
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
processLU(virConnectPtr conn,
          virStoragePoolObjPtr pool,
          uint32_t host,
          uint32_t bus,
          uint32_t target,
          uint32_t lun)
{
    char *type_path = NULL;
    int retval = 0;
    int device_type;
    char *block_device = NULL;

    VIR_DEBUG(_("Processing LU %u:%u:%u:%u"),
              host, bus, target, lun);

    if (getDeviceType(conn, host, bus, target, lun, &device_type) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
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

    VIR_DEBUG(_("%u:%u:%u:%u is a Direct-Access LUN"),
              host, bus, target, lun);

    if (getBlockDevice(conn, host, bus, target, lun, &block_device) < 0) {
        goto out;
    }

    if (virStorageBackendSCSINewLun(conn, pool,
                                    host, bus, target, lun,
                                    block_device) < 0) {
        VIR_DEBUG(_("Failed to create new storage volume for %u:%u:%u:%u"),
                  host, bus, target, lun);
        retval = -1;
        goto out;
    }

    VIR_DEBUG(_("Created new storage volume for %u:%u:%u:%u successfully"),
              host, bus, target, lun);

    VIR_FREE(type_path);

out:
    return retval;
}


int
virStorageBackendSCSIFindLUs(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             uint32_t scanhost)
{
    int retval = 0;
    uint32_t bus, target, lun;
    char *device_path = NULL;
    DIR *devicedir = NULL;
    struct dirent *lun_dirent = NULL;
    char devicepattern[64];

    VIR_DEBUG(_("Discovering LUs on host %u"), scanhost);

    virFileWaitForDevices(conn);

    if (virAsprintf(&device_path, "/sys/bus/scsi/devices") < 0) {
        virReportOOMError(conn);
        goto out;
    }

    devicedir = opendir(device_path);

    if (devicedir == NULL) {
        virReportSystemError(conn, errno,
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

        VIR_DEBUG(_("Found LU '%s'"), lun_dirent->d_name);

        processLU(conn, pool, scanhost, bus, target, lun);
    }

    closedir(devicedir);

out:
    VIR_FREE(device_path);
    return retval;
}


int
virStorageBackendSCSIGetHostNumber(virConnectPtr conn,
                                   const char *sysfs_path,
                                   uint32_t *host)
{
    int retval = 0;
    DIR *sysdir = NULL;
    struct dirent *dirent = NULL;

    VIR_DEBUG(_("Finding host number from '%s'"), sysfs_path);

    virFileWaitForDevices(conn);

    sysdir = opendir(sysfs_path);

    if (sysdir == NULL) {
        virReportSystemError(conn, errno,
                             _("Failed to opendir path '%s'"), sysfs_path);
        retval = -1;
        goto out;
    }

    while ((dirent = readdir(sysdir))) {
        if (STREQLEN(dirent->d_name, "target", strlen("target"))) {
            if (sscanf(dirent->d_name,
                       "target%u:", host) != 1) {
                VIR_DEBUG(_("Failed to parse target '%s'"), dirent->d_name);
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
virStorageBackendSCSITriggerRescan(virConnectPtr conn,
                                   uint32_t host)
{
    int fd = -1;
    int retval = 0;
    char *path;

    VIR_DEBUG(_("Triggering rescan of host %d"), host);

    if (virAsprintf(&path, "/sys/class/scsi_host/host%u/scan", host) < 0) {
        virReportOOMError(conn);
        retval = -1;
        goto out;
    }

    VIR_DEBUG(_("Scan trigger path is '%s'"), path);

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        virReportSystemError(conn, errno,
                             _("Could not open '%s' to trigger host scan"),
                             path);
        retval = -1;
        goto free_path;
    }

    if (safewrite(fd,
                  LINUX_SYSFS_SCSI_HOST_SCAN_STRING,
                  sizeof(LINUX_SYSFS_SCSI_HOST_SCAN_STRING)) < 0) {

        virReportSystemError(conn, errno,
                             _("Write to '%s' to trigger host scan failed"),
                             path);
        retval = -1;
    }

    close(fd);
free_path:
    VIR_FREE(path);
out:
    VIR_DEBUG(_("Rescan of host %d complete"), host);
    return retval;
}


static int
virStorageBackendSCSIRefreshPool(virConnectPtr conn,
                                 virStoragePoolObjPtr pool)
{
    int retval = 0;
    uint32_t host;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if (sscanf(pool->def->source.adapter, "host%u", &host) != 1) {
        VIR_DEBUG(_("Failed to get host number from '%s'"),
                    pool->def->source.adapter);
        retval = -1;
        goto out;
    }

    VIR_DEBUG(_("Scanning host%u"), host);

    if (virStorageBackendSCSITriggerRescan(conn, host) < 0) {
        retval = -1;
        goto out;
    }

    virStorageBackendSCSIFindLUs(conn, pool, host);

out:
    return retval;
}


virStorageBackend virStorageBackendSCSI = {
    .type = VIR_STORAGE_POOL_SCSI,

    .refreshPool = virStorageBackendSCSIRefreshPool,
};
