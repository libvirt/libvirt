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
#include <fcntl.h>

#include "virerror.h"
#include "storage_backend_scsi.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "vircommand.h"
#include "virstring.h"
#include "storage_util.h"
#include "node_device_conf.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_scsi");

#define LINUX_SYSFS_SCSI_HOST_PREFIX "/sys/class/scsi_host"
#define LINUX_SYSFS_SCSI_HOST_POSTFIX "device"
#define LINUX_SYSFS_SCSI_HOST_SCAN_STRING "- - -"

typedef struct _virStoragePoolFCRefreshInfo virStoragePoolFCRefreshInfo;
typedef virStoragePoolFCRefreshInfo *virStoragePoolFCRefreshInfoPtr;
struct _virStoragePoolFCRefreshInfo {
    char *fchost_name;
    unsigned char pool_uuid[VIR_UUID_BUFLEN];
};


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

    VIR_FREE(cbdata->fchost_name);
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
    const char *fchost_name = cbdata->fchost_name;
    const unsigned char *pool_uuid = cbdata->pool_uuid;
    virStoragePoolObjPtr pool = NULL;
    unsigned int host;
    int found = 0;
    int tries = 2;

    do {
        sleep(5); /* Give it time */

        /* Let's see if the pool still exists -  */
        if (!(pool = virStoragePoolObjFindPoolByUUID(pool_uuid)))
            break;

        /* Return with pool lock, if active, we can get the host number,
         * successfully, rescan, and find LUN's, then we are happy
         */
        VIR_DEBUG("Attempt FC Refresh for pool='%s' name='%s' tries='%d'",
                  pool->def->name, fchost_name, tries);

        pool->def->allocation = pool->def->capacity = pool->def->available = 0;

        if (virStoragePoolObjIsActive(pool) &&
            virSCSIHostGetNumber(fchost_name, &host) == 0 &&
            virStorageBackendSCSITriggerRescan(host) == 0) {
            virStoragePoolObjClearVols(pool);
            found = virStorageBackendSCSIFindLUs(pool, host);
        }
        virStoragePoolObjUnlock(pool);
    } while (!found && --tries);

    if (pool && !found)
        VIR_DEBUG("FC Refresh Thread failed to find LU's");

    virStoragePoolFCRefreshDataFree(cbdata);
}

static char *
getAdapterName(virStorageAdapterPtr adapter)
{
    char *name = NULL;
    char *parentaddr = NULL;

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) {
        virStorageAdapterSCSIHostPtr scsi_host = &adapter->data.scsi_host;

        if (scsi_host->has_parent) {
            virPCIDeviceAddressPtr addr = &scsi_host->parentaddr;
            unsigned int unique_id = scsi_host->unique_id;

            if (!(name = virSCSIHostGetNameByParentaddr(addr->domain,
                                                        addr->bus,
                                                        addr->slot,
                                                        addr->function,
                                                        unique_id)))
                goto cleanup;
        } else {
            ignore_value(VIR_STRDUP(name, scsi_host->name));
        }
    } else if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
        virStorageAdapterFCHostPtr fchost = &adapter->data.fchost;

        if (!(name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Failed to find SCSI host with wwnn='%s', "
                             "wwpn='%s'"), fchost->wwnn, fchost->wwpn);
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
checkParent(virConnectPtr conn,
            const char *name,
            const char *parent_name)
{
    char *scsi_host_name = NULL;
    char *vhba_parent = NULL;
    bool retval = false;

    VIR_DEBUG("conn=%p, name=%s, parent_name=%s", conn, name, parent_name);

    /* autostarted pool - assume we're OK */
    if (!conn)
        return true;

    if (virAsprintf(&scsi_host_name, "scsi_%s", name) < 0)
        goto cleanup;

    if (!(vhba_parent = virNodeDeviceGetParentName(conn, scsi_host_name)))
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
    VIR_FREE(scsi_host_name);
    return retval;
}


static int
createVport(virConnectPtr conn,
            virStoragePoolDefPtr def,
            const char *configFile,
            virStorageAdapterFCHostPtr fchost)
{
    char *name = NULL;
    virStoragePoolFCRefreshInfoPtr cbdata = NULL;
    virThread thread;
    int ret = -1;

    VIR_DEBUG("conn=%p, configFile='%s' parent='%s', wwnn='%s' wwpn='%s'",
              conn, NULLSTR(configFile), NULLSTR(fchost->parent),
              fchost->wwnn, fchost->wwpn);

    /* If we find an existing HBA/vHBA within the fc_host sysfs
     * using the wwnn/wwpn, then a nodedev is already created for
     * this pool and we don't have to create the vHBA
     */
    if ((name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {
        /* If a parent was provided, let's make sure the 'name' we've
         * retrieved has the same parent. If not this will cause failure. */
        if (!fchost->parent || checkParent(conn, name, fchost->parent))
            ret = 0;

        goto cleanup;
    }

    /* Since we're creating the vHBA, then we need to manage removing it
     * as well. Since we need this setting to "live" through a libvirtd
     * restart, we need to save the persistent configuration. So if not
     * already defined as YES, then force the issue.
     */
    if (fchost->managed != VIR_TRISTATE_BOOL_YES) {
        fchost->managed = VIR_TRISTATE_BOOL_YES;
        if (configFile) {
            if (virStoragePoolSaveConfig(configFile, def) < 0)
                goto cleanup;
        }
    }

    if (!(name = virNodeDeviceCreateVport(fchost)))
        goto cleanup;

    /* Creating our own VPORT didn't leave enough time to find any LUN's,
     * so, let's create a thread whose job it is to call the FindLU's with
     * retry logic set to true. If the thread isn't created, then no big
     * deal since it's still possible to refresh the pool later.
     */
    if (VIR_ALLOC(cbdata) == 0) {
        memcpy(cbdata->pool_uuid, def->uuid, VIR_UUID_BUFLEN);
        VIR_STEAL_PTR(cbdata->fchost_name, name);

        if (virThreadCreate(&thread, false, virStoragePoolFCRefreshThread,
                            cbdata) < 0) {
            /* Oh well - at least someone can still refresh afterwards */
            VIR_DEBUG("Failed to create FC Pool Refresh Thread");
            virStoragePoolFCRefreshDataFree(cbdata);
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(name);
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

    if (!(name = getAdapterName(&pool->def->source.adapter))) {
        /* It's normal for the pool with "fc_host" type source
         * adapter fails to get the adapter name, since the vHBA
         * the adapter based on might be not created yet.
         */
        if (pool->def->source.adapter.type ==
            VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
            virResetLastError();
            return 0;
        } else {
            return -1;
        }
    }

    if (virSCSIHostGetNumber(name, &host) < 0)
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

    if (!(name = getAdapterName(&pool->def->source.adapter)))
        return -1;

    if (virSCSIHostGetNumber(name, &host) < 0)
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
    if (pool->def->source.adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        return createVport(conn, pool->def, pool->configFile,
                           &pool->def->source.adapter.data.fchost);

    return 0;
}


static int
virStorageBackendSCSIStopPool(virConnectPtr conn,
                              virStoragePoolObjPtr pool)
{
    if (pool->def->source.adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        return virNodeDeviceDeleteVport(conn,
                                        &pool->def->source.adapter.data.fchost);

    return 0;
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


int
virStorageBackendSCSIRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendSCSI);
}
