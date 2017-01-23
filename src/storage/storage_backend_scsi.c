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
#include "virvhba.h"
#include "storage_util.h"

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
            virGetSCSIHostNumber(fchost_name, &host) == 0 &&
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
getAdapterName(virStoragePoolSourceAdapter adapter)
{
    char *name = NULL;
    char *parentaddr = NULL;

    if (adapter.type == VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST) {
        if (adapter.data.scsi_host.has_parent) {
            virPCIDeviceAddress addr = adapter.data.scsi_host.parentaddr;
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
        if (!(name = virVHBAGetHostByWWN(NULL,
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
    bool skip_capable_check = false;
    virStoragePoolFCRefreshInfoPtr cbdata = NULL;
    virThread thread;
    int ret = -1;

    if (adapter->type != VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST)
        return 0;

    VIR_DEBUG("conn=%p, configFile='%s' parent='%s', wwnn='%s' wwpn='%s'",
              conn, NULLSTR(configFile), NULLSTR(adapter->data.fchost.parent),
              adapter->data.fchost.wwnn, adapter->data.fchost.wwpn);

    /* If we find an existing HBA/vHBA within the fc_host sysfs
     * using the wwnn/wwpn, then a nodedev is already created for
     * this pool and we don't have to create the vHBA
     */
    if ((name = virVHBAGetHostByWWN(NULL, adapter->data.fchost.wwnn,
                                    adapter->data.fchost.wwpn))) {
        /* If a parent was provided, let's make sure the 'name' we've
         * retrieved has the same parent
         */
        if (adapter->data.fchost.parent &&
            checkVhbaSCSIHostParent(conn, name, adapter->data.fchost.parent))
            ret = 0;

        goto cleanup;
    }

    if (adapter->data.fchost.parent) {
        if (VIR_STRDUP(parent_hoststr, adapter->data.fchost.parent) < 0)
            goto cleanup;
    } else if (adapter->data.fchost.parent_wwnn &&
               adapter->data.fchost.parent_wwpn) {
        if (!(parent_hoststr =
              virVHBAGetHostByWWN(NULL, adapter->data.fchost.parent_wwnn,
                                  adapter->data.fchost.parent_wwpn))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot find parent using provided wwnn/wwpn"));
            goto cleanup;
        }
    } else if (adapter->data.fchost.parent_fabric_wwn) {
        if (!(parent_hoststr =
              virVHBAGetHostByFabricWWN(NULL,
                                        adapter->data.fchost.parent_fabric_wwn))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot find parent using provided fabric_wwn"));
            goto cleanup;
        }
    } else {
        if (!(parent_hoststr = virVHBAFindVportHost(NULL))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'parent' for vHBA not specified, and "
                             "cannot find one on this host"));
            goto cleanup;
        }
        skip_capable_check = true;
    }

    if (virGetSCSIHostNumber(parent_hoststr, &parent_host) < 0)
        goto cleanup;

    /* NOTE:
     * We do not save the parent_hoststr in adapter->data.fchost.parent
     * since we could be writing out the 'def' to the saved XML config.
     * If we wrote out the name in the XML, then future starts would
     * always use the same parent rather than finding the "best available"
     * parent. Besides we have a way to determine the parent based on
     * the 'name' field.
     */
    if (!skip_capable_check && !virVHBAPathExists(NULL, parent_host)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("parent '%s' specified for vHBA does not exist"),
                       parent_hoststr);
        goto cleanup;
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
                goto cleanup;
        }
    }

    if (virVHBAManageVport(parent_host, adapter->data.fchost.wwpn,
                           adapter->data.fchost.wwnn, VPORT_CREATE) < 0)
        goto cleanup;

    virFileWaitForDevices();

    /* Creating our own VPORT didn't leave enough time to find any LUN's,
     * so, let's create a thread whose job it is to call the FindLU's with
     * retry logic set to true. If the thread isn't created, then no big
     * deal since it's still possible to refresh the pool later.
     */
    if ((name = virVHBAGetHostByWWN(NULL, adapter->data.fchost.wwnn,
                                    adapter->data.fchost.wwpn))) {
        if (VIR_ALLOC(cbdata) == 0) {
            memcpy(cbdata->pool_uuid, pool->def->uuid, VIR_UUID_BUFLEN);
            VIR_STEAL_PTR(cbdata->fchost_name, name);

            if (virThreadCreate(&thread, false, virStoragePoolFCRefreshThread,
                                cbdata) < 0) {
                /* Oh well - at least someone can still refresh afterwards */
                VIR_DEBUG("Failed to create FC Pool Refresh Thread");
                virStoragePoolFCRefreshDataFree(cbdata);
            }
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(name);
    VIR_FREE(parent_hoststr);
    return ret;
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
    if (!(name = virVHBAGetHostByWWN(NULL, adapter.data.fchost.wwnn,
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

    if (virVHBAManageVport(parent_host, adapter.data.fchost.wwpn,
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
