/*
 * storage_backend_scsi.c: storage backend for SCSI handling
 *
 * Copyright (C) 2007-2008, 2013-2014 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange redhat com>
 */

#include <config.h>

#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>

#include "virerror.h"
#include "storage_backend_scsi.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_scsi");

typedef struct _virStoragePoolFCRefreshInfo virStoragePoolFCRefreshInfo;
typedef virStoragePoolFCRefreshInfo *virStoragePoolFCRefreshInfoPtr;
struct _virStoragePoolFCRefreshInfo {
    char *name;
    virStoragePoolObjPtr pool;
};

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
                    host, bus, target, lun) < 0)
        goto out;

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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

static char *
virStorageBackendSCSISerial(const char *dev)
{
    char *serial = NULL;
#ifdef WITH_UDEV
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
        ignore_value(VIR_STRDUP(serial, dev));
    }

#ifdef WITH_UDEV
 cleanup:
    virCommandFree(cmd);
#endif

    return serial;
}


/*
 * Attempt to create a new LUN
 *
 * Returns:
 *
 *  0  => Success
 *  -1 => Failure due to some sort of OOM or other fatal issue found when
 *        attempting to get/update information about a found volume
 *  -2 => Failure to find a stable path, not fatal, caller can try another
 */
static int
virStorageBackendSCSINewLun(virStoragePoolObjPtr pool,
                            uint32_t host ATTRIBUTE_UNUSED,
                            uint32_t bus,
                            uint32_t target,
                            uint32_t lun,
                            const char *dev)
{
    virStorageVolDefPtr vol = NULL;
    char *devpath = NULL;
    int retval = -1;

    /* Check if the pool is using a stable target path. The call to
     * virStorageBackendStablePath will fail if the pool target path
     * isn't stable and just return the strdup'd 'devpath' anyway.
     * This would be indistinguishable to failing to find the stable
     * path to the device if the virDirRead loop to search the
     * target pool path for our devpath had failed.
     */
    if (!virStorageBackendPoolPathIsStable(pool->def->target.path) &&
        !(STREQ(pool->def->target.path, "/dev") ||
          STREQ(pool->def->target.path, "/dev/"))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unable to use target path '%s' for dev '%s'"),
                       NULLSTR(pool->def->target.path), dev);
        goto cleanup;
    }

    if (VIR_ALLOC(vol) < 0)
        goto cleanup;

    vol->type = VIR_STORAGE_VOL_BLOCK;

    /* 'host' is dynamically allocated by the kernel, first come,
     * first served, per HBA. As such it isn't suitable for use
     * in the volume name. We only need uniqueness per-pool, so
     * just leave 'host' out
     */
    if (virAsprintf(&(vol->name), "unit:%u:%u:%u", bus, target, lun) < 0)
        goto cleanup;

    if (virAsprintf(&devpath, "/dev/%s", dev) < 0)
        goto cleanup;

    VIR_DEBUG("Trying to create volume for '%s'", devpath);

    /* Now figure out the stable path
     *
     * XXX this method is O(N) because it scans the pool target
     * dir every time its run. Should figure out a more efficient
     * way of doing this...
     */
    if ((vol->target.path = virStorageBackendStablePath(pool,
                                                        devpath,
                                                        true)) == NULL)
        goto cleanup;

    if (STREQ(devpath, vol->target.path) &&
        !(STREQ(pool->def->target.path, "/dev") ||
          STREQ(pool->def->target.path, "/dev/"))) {

        VIR_DEBUG("No stable path found for '%s' in '%s'",
                  devpath, pool->def->target.path);

        retval = -2;
        goto cleanup;
    }

    if (virStorageBackendUpdateVolInfo(vol, true,
                                       VIR_STORAGE_VOL_OPEN_DEFAULT) < 0)
        goto cleanup;

    if (!(vol->key = virStorageBackendSCSISerial(vol->target.path)))
        goto cleanup;

    pool->def->capacity += vol->target.capacity;
    pool->def->allocation += vol->target.allocation;

    if (VIR_APPEND_ELEMENT(pool->volumes.objs, pool->volumes.count, vol) < 0)
        goto cleanup;

    vol = NULL;
    retval = 0;

 cleanup:
    virStorageVolDefFree(vol);
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
    int retval = -1;
    int direrr;

    if (virAsprintf(&block_path, "%s/block", lun_path) < 0)
        goto cleanup;

    VIR_DEBUG("Looking for block device in '%s'", block_path);

    if (!(block_dir = opendir(block_path))) {
        virReportSystemError(errno,
                             _("Failed to opendir sysfs path '%s'"),
                             block_path);
        goto cleanup;
    }

    while ((direrr = virDirRead(block_dir, &block_dirent, block_path)) > 0) {
        if (STREQLEN(block_dirent->d_name, ".", 1))
            continue;

        if (VIR_STRDUP(*block_device, block_dirent->d_name) < 0)
            goto cleanup;

        VIR_DEBUG("Block device is '%s'", *block_device);

        break;
    }

    if (direrr < 0)
        goto cleanup;

    retval = 0;

 cleanup:
    if (block_dir)
        closedir(block_dir);
    VIR_FREE(block_path);
    return retval;
}


static int
getOldStyleBlockDevice(const char *lun_path ATTRIBUTE_UNUSED,
                       const char *block_name,
                       char **block_device)
{
    char *blockp = NULL;
    int retval = -1;

    /* old-style; just parse out the sd */
    if (!(blockp = strrchr(block_name, ':'))) {
        /* Hm, wasn't what we were expecting; have to give up */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse block name %s"),
                       block_name);
        goto cleanup;
    } else {
        blockp++;
        if (VIR_STRDUP(*block_device, blockp) < 0)
            goto cleanup;

        VIR_DEBUG("Block device is '%s'", *block_device);
    }

    retval = 0;
 cleanup:
    return retval;
}


/*
 * Search a device entry for the "block" file
 *
 * Returns
 *
 *   0 => Found it
 *   -1 => Fatal error
 *   -2 => Didn't find in lun_path directory
 */
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
    int retval = -1;
    int direrr;

    *block_device = NULL;

    if (virAsprintf(&lun_path, "/sys/bus/scsi/devices/%u:%u:%u:%u",
                    host, bus, target, lun) < 0)
        goto cleanup;

    if (!(lun_dir = opendir(lun_path))) {
        virReportSystemError(errno,
                             _("Failed to opendir sysfs path '%s'"),
                             lun_path);
        goto cleanup;
    }

    while ((direrr = virDirRead(lun_dir, &lun_dirent, lun_path)) > 0) {
        if (STREQLEN(lun_dirent->d_name, "block", 5)) {
            if (strlen(lun_dirent->d_name) == 5) {
                if (getNewStyleBlockDevice(lun_path,
                                           lun_dirent->d_name,
                                           block_device) < 0)
                    goto cleanup;
            } else {
                if (getOldStyleBlockDevice(lun_path,
                                           lun_dirent->d_name,
                                           block_device) < 0)
                    goto cleanup;
            }
            break;
        }
    }
    if (direrr < 0)
        goto cleanup;
    if (!*block_device) {
        retval = -2;
        goto cleanup;
    }

    retval = 0;

 cleanup:
    if (lun_dir)
        closedir(lun_dir);
    VIR_FREE(lun_path);
    return retval;
}


/*
 * Process a Logical Unit entry from the scsi host device directory
 *
 * Returns:
 *
 *  0  => Found a valid entry
 *  -1 => Some sort of fatal error
 *  -2 => non-fatal error or a non-disk entry
 */
static int
processLU(virStoragePoolObjPtr pool,
          uint32_t host,
          uint32_t bus,
          uint32_t target,
          uint32_t lun)
{
    int retval = -1;
    int device_type;
    char *block_device = NULL;

    VIR_DEBUG("Processing LU %u:%u:%u:%u",
              host, bus, target, lun);

    if (getDeviceType(host, bus, target, lun, &device_type) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to determine if %u:%u:%u:%u is a Direct-Access LUN"),
                       host, bus, target, lun);
        return -1;
    }

    /* We don't create volumes for devices other than disk and cdrom
     * devices, but finding a device that isn't one of those types
     * isn't an error, either. */
    if (!(device_type == VIR_STORAGE_DEVICE_TYPE_DISK ||
          device_type == VIR_STORAGE_DEVICE_TYPE_ROM))
        return -2;

    VIR_DEBUG("%u:%u:%u:%u is a Direct-Access LUN",
              host, bus, target, lun);

    if ((retval = getBlockDevice(host, bus, target, lun, &block_device)) < 0) {
        VIR_DEBUG("Failed to find block device for this LUN");
        return retval;
    }

    retval = virStorageBackendSCSINewLun(pool, host, bus, target, lun,
                                         block_device);
    if (retval < 0) {
        VIR_DEBUG("Failed to create new storage volume for %u:%u:%u:%u",
                  host, bus, target, lun);
        goto cleanup;
    }

    VIR_DEBUG("Created new storage volume for %u:%u:%u:%u successfully",
              host, bus, target, lun);

 cleanup:
    VIR_FREE(block_device);
    return retval;
}


int
virStorageBackendSCSIFindLUs(virStoragePoolObjPtr pool,
                              uint32_t scanhost)
{
    int retval = 0;
    uint32_t bus, target, lun;
    const char *device_path = "/sys/bus/scsi/devices";
    DIR *devicedir = NULL;
    struct dirent *lun_dirent = NULL;
    char devicepattern[64];
    int found = 0;

    VIR_DEBUG("Discovering LUs on host %u", scanhost);

    virFileWaitForDevices();

    devicedir = opendir(device_path);

    if (devicedir == NULL) {
        virReportSystemError(errno,
                             _("Failed to opendir path '%s'"), device_path);
        return -1;
    }

    snprintf(devicepattern, sizeof(devicepattern), "%u:%%u:%%u:%%u\n", scanhost);

    while ((retval = virDirRead(devicedir, &lun_dirent, device_path)) > 0) {
        int rc;

        if (sscanf(lun_dirent->d_name, devicepattern,
                   &bus, &target, &lun) != 3) {
            continue;
        }

        VIR_DEBUG("Found possible LU '%s'", lun_dirent->d_name);

        rc = processLU(pool, scanhost, bus, target, lun);
        if (rc == -1) {
            retval = -1;
            break;
        }
        if (rc == 0)
            found++;
    }

    closedir(devicedir);

    if (retval < 0)
        return -1;

    VIR_DEBUG("Found %d LUs for pool %s", found, pool->def->name);

    return found;
}


static int
virStorageBackendSCSITriggerRescan(uint32_t host)
{
    int fd = -1;
    int retval = 0;
    char *path;

    VIR_DEBUG("Triggering rescan of host %d", host);

    if (virAsprintf(&path, "%s/host%u/scan",
                    LINUX_SYSFS_SCSI_HOST_PREFIX, host) < 0) {
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

/**
 * Frees opaque data
 *
 * @opaque Data to be freed
 */
static void
virStoragePoolFCRefreshDataFree(void *opaque)
{
    virStoragePoolFCRefreshInfoPtr cbdata = opaque;

    VIR_FREE(cbdata->name);
    VIR_FREE(cbdata);
}

/**
 * Thread to handle the pool refresh after a VPORT_CREATE is done. In this
 * case the 'udevEventHandleCallback' will be executed asynchronously as a
 * result of the node device driver callback routine to handle when udev
 * notices some sort of device change (such as adding a new device). It takes
 * some amount of time (usually a few seconds) for udev to go through the
 * process of setting up the new device.  Unfortunately, there is nothing
 * that says "when" it's done. The immediate virStorageBackendSCSIRefreshPool
 * done after virStorageBackendSCSIStartPool (and createVport) occurs too
 * quickly to find any devices.
 *
 * So this thread is designed to wait a few seconds (5), then make the query
 * to find the LUs for the pool.  If none yet exist, we'll try once more
 * to find the LUs before giving up.
 *
 * Attempting to find devices prior to allowing udev to settle down may result
 * in finding devices that then get deleted.
 *
 * @opaque Pool's Refresh Info containing name and pool object pointer
 */
static void
virStoragePoolFCRefreshThread(void *opaque)
{
    virStoragePoolFCRefreshInfoPtr cbdata = opaque;
    const char *name = cbdata->name;
    virStoragePoolObjPtr pool = cbdata->pool;
    unsigned int host;
    int found = 0;
    int tries = 2;

    do {
        sleep(5); /* Give it time */

        /* Lock the pool, if active, we can get the host number, successfully
         * rescan, and find LUN's, then we are happy
         */
        VIR_DEBUG("Attempt FC Refresh for pool='%s' name='%s' tries='%d'",
                  pool->def->name, name, tries);
        virStoragePoolObjLock(pool);
        if (virStoragePoolObjIsActive(pool) &&
            virGetSCSIHostNumber(name, &host) == 0 &&
            virStorageBackendSCSITriggerRescan(host) == 0) {
            virStoragePoolObjClearVols(pool);
            found = virStorageBackendSCSIFindLUs(pool, host);
        }
        virStoragePoolObjUnlock(pool);
    } while (!found && --tries);

    if (!found)
        VIR_DEBUG("FC Refresh Thread failed to find LU's");

    virStoragePoolFCRefreshDataFree(cbdata);
}

static char *
getAdapterName(virStoragePoolSourceAdapter adapter)
{
    char *name = NULL;
    char *parentaddr = NULL;

    if (adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
        if (adapter.data.scsi_host.has_parent) {
            virDevicePCIAddress addr = adapter.data.scsi_host.parentaddr;
            unsigned int unique_id = adapter.data.scsi_host.unique_id;

            if (!(name = virGetSCSIHostNameByParentaddr(addr.domain,
                                                        addr.bus,
                                                        addr.slot,
                                                        addr.function,
                                                        unique_id)))
                goto cleanup;
        } else {
            ignore_value(VIR_STRDUP(name, adapter.data.scsi_host.name));
        }
    } else if (adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
        if (!(name = virGetFCHostNameByWWN(NULL,
                                           adapter.data.fchost.wwnn,
                                           adapter.data.fchost.wwpn))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Failed to find SCSI host with wwnn='%s', "
                             "wwpn='%s'"), adapter.data.fchost.wwnn,
                           adapter.data.fchost.wwpn);
        }
    }

 cleanup:
    VIR_FREE(parentaddr);
    return name;
}

/*
 * Using the host# name found via wwnn/wwpn lookup in the fc_host
 * sysfs tree to get the parent 'scsi_host#' to ensure it matches.
 */
static bool
checkVhbaSCSIHostParent(virConnectPtr conn,
                        const char *name,
                        const char *parent_name)
{
    char *vhba_parent = NULL;
    bool retval = false;

    VIR_DEBUG("conn=%p, name=%s, parent_name=%s", conn, name, parent_name);

    /* autostarted pool - assume we're OK */
    if (!conn)
        return true;

    if (!(vhba_parent = virStoragePoolGetVhbaSCSIHostParent(conn, name)))
        goto cleanup;

    if (STRNEQ(parent_name, vhba_parent)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Parent attribute '%s' does not match parent '%s' "
                         "determined for the '%s' wwnn/wwpn lookup."),
                       parent_name, vhba_parent, name);
        goto cleanup;
    }

    retval = true;

 cleanup:
    VIR_FREE(vhba_parent);
    return retval;
}

static int
createVport(virConnectPtr conn,
            virStoragePoolObjPtr pool)
{
    const char *configFile = pool->configFile;
    virStoragePoolSourceAdapterPtr adapter = &pool->def->source.adapter;
    unsigned int parent_host;
    char *name = NULL;
    char *parent_hoststr = NULL;
    virStoragePoolFCRefreshInfoPtr cbdata = NULL;
    virThread thread;

    if (adapter->type != VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST)
        return 0;

    VIR_DEBUG("conn=%p, configFile='%s' parent='%s', wwnn='%s' wwpn='%s'",
              conn, NULLSTR(configFile), NULLSTR(adapter->data.fchost.parent),
              adapter->data.fchost.wwnn, adapter->data.fchost.wwpn);

    /* If a parent was provided, then let's make sure it's vhost capable */
    if (adapter->data.fchost.parent) {
        if (virGetSCSIHostNumber(adapter->data.fchost.parent, &parent_host) < 0)
            return -1;

        if (!virIsCapableFCHost(NULL, parent_host)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("parent '%s' specified for vHBA "
                             "is not vport capable"),
                           adapter->data.fchost.parent);
            return -1;
        }
    }

    /* If we find an existing HBA/vHBA within the fc_host sysfs
     * using the wwnn/wwpn, then a nodedev is already created for
     * this pool and we don't have to create the vHBA
     */
    if ((name = virGetFCHostNameByWWN(NULL, adapter->data.fchost.wwnn,
                                      adapter->data.fchost.wwpn))) {
        int retval = 0;

        /* If a parent was provided, let's make sure the 'name' we've
         * retrieved has the same parent
         */
        if (adapter->data.fchost.parent &&
            !checkVhbaSCSIHostParent(conn, name, adapter->data.fchost.parent))
            retval = -1;

        VIR_FREE(name);
        return retval;
    }

    if (!adapter->data.fchost.parent) {
        if (!(parent_hoststr = virFindFCHostCapableVport(NULL))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'parent' for vHBA not specified, and "
                             "cannot find one on this host"));
            return -1;
        }

        if (virGetSCSIHostNumber(parent_hoststr, &parent_host) < 0) {
            VIR_FREE(parent_hoststr);
            return -1;
        }

        /* NOTE:
         * We do not save the parent_hoststr in adapter->data.fchost.parent
         * since we could be writing out the 'def' to the saved XML config.
         * If we wrote out the name in the XML, then future starts would
         * always use the same parent rather than finding the "best available"
         * parent. Besides we have a way to determine the parent based on
         * the 'name' field.
         */
        VIR_FREE(parent_hoststr);
    }

    /* Since we're creating the vHBA, then we need to manage removing it
     * as well. Since we need this setting to "live" through a libvirtd
     * restart, we need to save the persistent configuration. So if not
     * already defined as YES, then force the issue.
     */
    if (adapter->data.fchost.managed != VIR_TRISTATE_BOOL_YES) {
        adapter->data.fchost.managed = VIR_TRISTATE_BOOL_YES;
        if (configFile) {
            if (virStoragePoolSaveConfig(configFile, pool->def) < 0)
                return -1;
        }
    }

    if (virManageVport(parent_host, adapter->data.fchost.wwpn,
                       adapter->data.fchost.wwnn, VPORT_CREATE) < 0)
        return -1;

    virFileWaitForDevices();

    /* Creating our own VPORT didn't leave enough time to find any LUN's,
     * so, let's create a thread whose job it is to call the FindLU's with
     * retry logic set to true. If the thread isn't created, then no big
     * deal since it's still possible to refresh the pool later.
     */
    if ((name = virGetFCHostNameByWWN(NULL, adapter->data.fchost.wwnn,
                                      adapter->data.fchost.wwpn))) {
        if (VIR_ALLOC(cbdata) == 0) {
            cbdata->pool = pool;
            cbdata->name = name;
            name = NULL;

            if (virThreadCreate(&thread, false, virStoragePoolFCRefreshThread,
                                cbdata) < 0) {
                /* Oh well - at least someone can still refresh afterwards */
                VIR_DEBUG("Failed to create FC Pool Refresh Thread");
                virStoragePoolFCRefreshDataFree(cbdata);
            }
        }
        VIR_FREE(name);
    }

    return 0;
}

static int
deleteVport(virConnectPtr conn,
            virStoragePoolSourceAdapter adapter)
{
    unsigned int parent_host;
    char *name = NULL;
    char *vhba_parent = NULL;
    int ret = -1;

    if (adapter.type != VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST)
        return 0;

    VIR_DEBUG("conn=%p parent='%s', managed='%d' wwnn='%s' wwpn='%s'",
              conn, NULLSTR(adapter.data.fchost.parent),
              adapter.data.fchost.managed,
              adapter.data.fchost.wwnn,
              adapter.data.fchost.wwpn);

    /* If we're not managing the deletion of the vHBA, then just return */
    if (adapter.data.fchost.managed != VIR_TRISTATE_BOOL_YES)
        return 0;

    /* Find our vHBA by searching the fc_host sysfs tree for our wwnn/wwpn */
    if (!(name = virGetFCHostNameByWWN(NULL, adapter.data.fchost.wwnn,
                                       adapter.data.fchost.wwpn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find fc_host for wwnn='%s' and wwpn='%s'"),
                       adapter.data.fchost.wwnn, adapter.data.fchost.wwpn);
        goto cleanup;
    }

    /* If at startup time we provided a parent, then use that to
     * get the parent_host value; otherwise, we have to determine
     * the parent scsi_host which we did not save at startup time
     */
    if (adapter.data.fchost.parent) {
        if (virGetSCSIHostNumber(adapter.data.fchost.parent, &parent_host) < 0)
            goto cleanup;
    } else {
        if (!(vhba_parent = virStoragePoolGetVhbaSCSIHostParent(conn, name)))
            goto cleanup;

        if (virGetSCSIHostNumber(vhba_parent, &parent_host) < 0)
            goto cleanup;
    }

    if (virManageVport(parent_host, adapter.data.fchost.wwpn,
                       adapter.data.fchost.wwnn, VPORT_DELETE) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(name);
    VIR_FREE(vhba_parent);
    return ret;
}


static int
virStorageBackendSCSICheckPool(virStoragePoolObjPtr pool,
                               bool *isActive)
{
    char *path = NULL;
    char *name = NULL;
    unsigned int host;
    int ret = -1;

    *isActive = false;

    if (!(name = getAdapterName(pool->def->source.adapter))) {
        /* It's normal for the pool with "fc_host" type source
         * adapter fails to get the adapter name, since the vHBA
         * the adapter based on might be not created yet.
         */
        if (pool->def->source.adapter.type ==
            VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST) {
            virResetLastError();
            return 0;
        } else {
            return -1;
        }
    }

    if (virGetSCSIHostNumber(name, &host) < 0)
        goto cleanup;

    if (virAsprintf(&path, "%s/host%d",
                    LINUX_SYSFS_SCSI_HOST_PREFIX, host) < 0)
        goto cleanup;

    *isActive = virFileExists(path);

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(name);
    return ret;
}

static int
virStorageBackendSCSIRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    char *name = NULL;
    unsigned int host;
    int ret = -1;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if (!(name = getAdapterName(pool->def->source.adapter)))
        return -1;

    if (virGetSCSIHostNumber(name, &host) < 0)
        goto out;

    VIR_DEBUG("Scanning host%u", host);

    if (virStorageBackendSCSITriggerRescan(host) < 0)
        goto out;

    if (virStorageBackendSCSIFindLUs(pool, host) < 0)
        goto out;

    ret = 0;
 out:
    VIR_FREE(name);
    return ret;
}

static int
virStorageBackendSCSIStartPool(virConnectPtr conn,
                               virStoragePoolObjPtr pool)
{
    return createVport(conn, pool);
}

static int
virStorageBackendSCSIStopPool(virConnectPtr conn,
                              virStoragePoolObjPtr pool)
{
    virStoragePoolSourceAdapter adapter = pool->def->source.adapter;
    return deleteVport(conn, adapter);
}

virStorageBackend virStorageBackendSCSI = {
    .type = VIR_STORAGE_POOL_SCSI,

    .checkPool = virStorageBackendSCSICheckPool,
    .refreshPool = virStorageBackendSCSIRefreshPool,
    .startPool = virStorageBackendSCSIStartPool,
    .stopPool = virStorageBackendSCSIStopPool,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};
