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
 */

#include <config.h>

#include <unistd.h>
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
#include "node_device_util.h"
#include "driver.h"

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
    VIR_AUTOCLOSE fd = -1;
    VIR_AUTOFREE(char *) path = NULL;

    VIR_DEBUG("Triggering rescan of host %d", host);

    if (virAsprintf(&path, "%s/host%u/scan",
                    LINUX_SYSFS_SCSI_HOST_PREFIX, host) < 0)
        return -1;

    VIR_DEBUG("Scan trigger path is '%s'", path);

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        virReportSystemError(errno,
                             _("Could not open '%s' to trigger host scan"),
                             path);
        return -1;
    }

    if (safewrite(fd,
                  LINUX_SYSFS_SCSI_HOST_SCAN_STRING,
                  sizeof(LINUX_SYSFS_SCSI_HOST_SCAN_STRING)) < 0) {
        virReportSystemError(errno,
                             _("Write to '%s' to trigger host scan failed"),
                             path);
        return -1;
    }

    VIR_DEBUG("Rescan of host %d complete", host);
    return 0;
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
    virStoragePoolDefPtr def;
    unsigned int host;
    int found = 0;
    int tries = 2;

    do {
        sleep(5); /* Give it time */

        /* Let's see if the pool still exists -  */
        if (!(pool = virStoragePoolObjFindPoolByUUID(pool_uuid)))
            break;
        def = virStoragePoolObjGetDef(pool);

        /* Return with pool lock, if active, we can get the host number,
         * successfully, rescan, and find LUN's, then we are happy
         */
        VIR_DEBUG("Attempt FC Refresh for pool='%s' name='%s' tries='%d'",
                  def->name, fchost_name, tries);

        def->allocation = def->capacity = def->available = 0;

        if (virStoragePoolObjIsActive(pool) &&
            virSCSIHostGetNumber(fchost_name, &host) == 0 &&
            virStorageBackendSCSITriggerRescan(host) == 0) {
            virStoragePoolObjClearVols(pool);
            found = virStorageBackendSCSIFindLUs(pool, host);
        }
        virStoragePoolObjEndAPI(&pool);
    } while (!found && --tries);

    if (pool && !found)
        VIR_DEBUG("FC Refresh Thread failed to find LU's");

    virStoragePoolFCRefreshDataFree(cbdata);
}

static char *
getAdapterName(virStorageAdapterPtr adapter)
{
    char *name = NULL;

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
                return NULL;
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

    return name;
}


/**
 * @name: Name from a wwnn/wwpn lookup
 *
 * Validate that the @name fetched from the wwnn/wwpn is a vHBA
 * and not an HBA as that should be a configuration error. It's only
 * possible to use an existing wwnn/wwpn of a vHBA because that's
 * what someone would have created using the node device create via XML
 * functionality. Using the HBA "just because" it has a wwnn/wwpn and
 * the characteristics of a vHBA is just not valid
 *
 * Returns true if the @name is OK, false on error
 */
static bool
checkName(const char *name)
{
    unsigned int host_num;

    if (virSCSIHostGetNumber(name, &host_num) &&
        virVHBAIsVportCapable(NULL, host_num))
        return true;

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("the wwnn/wwpn for '%s' are assigned to an HBA"), name);
    return false;
}


/*
 * Using the host# name found via wwnn/wwpn lookup in the fc_host
 * sysfs tree to get the parent 'scsi_host#' to ensure it matches.
 */
static bool
checkParent(const char *name,
            const char *parent_name)
{
    unsigned int host_num;
    bool retval = false;
    virConnectPtr conn = NULL;
    VIR_AUTOFREE(char *) scsi_host_name = NULL;
    VIR_AUTOFREE(char *) vhba_parent = NULL;

    VIR_DEBUG("name=%s, parent_name=%s", name, parent_name);

    conn = virGetConnectNodeDev();
    if (!conn)
        goto cleanup;

    if (virSCSIHostGetNumber(parent_name, &host_num) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("parent '%s' is not properly formatted"),
                       parent_name);
        goto cleanup;
    }

    if (!virVHBAPathExists(NULL, host_num)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("parent '%s' is not an fc_host for the wwnn/wwpn"),
                       parent_name);
        goto cleanup;
    }

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
    virObjectUnref(conn);
    return retval;
}


static int
createVport(virStoragePoolDefPtr def,
            const char *configFile,
            virStorageAdapterFCHostPtr fchost)
{
    virStoragePoolFCRefreshInfoPtr cbdata = NULL;
    virThread thread;
    VIR_AUTOFREE(char *) name = NULL;

    VIR_DEBUG("configFile='%s' parent='%s', wwnn='%s' wwpn='%s'",
              NULLSTR(configFile), NULLSTR(fchost->parent),
              fchost->wwnn, fchost->wwpn);

    /* If we find an existing HBA/vHBA within the fc_host sysfs
     * using the wwnn/wwpn, then a nodedev is already created for
     * this pool and we don't have to create the vHBA
     */
    if ((name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {
        if (!(checkName(name)))
            return -1;

        /* If a parent was provided, let's make sure the 'name' we've
         * retrieved has the same parent. If not this will cause failure. */
        if (!fchost->parent || checkParent(name, fchost->parent))
            return 0;

        return -1;
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
                return -1;
        }
    }

    if (!(name = virNodeDeviceCreateVport(fchost)))
        return -1;

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

    return 0;
}


static int
virStorageBackendSCSICheckPool(virStoragePoolObjPtr pool,
                               bool *isActive)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    unsigned int host;
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) name = NULL;

    *isActive = false;

    if (!(name = getAdapterName(&def->source.adapter))) {
        /* It's normal for the pool with "fc_host" type source
         * adapter fails to get the adapter name, since the vHBA
         * the adapter based on might be not created yet.
         */
        if (def->source.adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
            virResetLastError();
            return 0;
        } else {
            return -1;
        }
    }

    if (virSCSIHostGetNumber(name, &host) < 0)
        return -1;

    if (virAsprintf(&path, "%s/host%d",
                    LINUX_SYSFS_SCSI_HOST_PREFIX, host) < 0)
        return -1;

    *isActive = virFileExists(path);

    return 0;
}

static int
virStorageBackendSCSIRefreshPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    unsigned int host;
    VIR_AUTOFREE(char *) name = NULL;

    def->allocation = def->capacity = def->available = 0;

    if (!(name = getAdapterName(&def->source.adapter)))
        return -1;

    if (virSCSIHostGetNumber(name, &host) < 0)
        return -1;

    VIR_DEBUG("Scanning host%u", host);

    if (virStorageBackendSCSITriggerRescan(host) < 0)
        return -1;

    if (virStorageBackendSCSIFindLUs(pool, host) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendSCSIStartPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    const char *configFile = virStoragePoolObjGetConfigFile(pool);

    if (def->source.adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        return createVport(def, configFile,
                           &def->source.adapter.data.fchost);

    return 0;
}


static int
virStorageBackendSCSIStopPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (def->source.adapter.type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
        virConnectPtr conn;
        int ret;
        conn = virGetConnectNodeDev();
        if (!conn)
            return -1;

        ret = virNodeDeviceDeleteVport(conn,
                                       &def->source.adapter.data.fchost);
        virObjectUnref(conn);
        return ret;
    }

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
