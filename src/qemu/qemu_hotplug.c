/*
 * qemu_hotplug.c: QEMU device hotplug management
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "qemu_hotplug.h"
#include "qemu_alias.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"
#include "qemu_namespace.h"
#include "qemu_command.h"
#include "qemu_hostdev.h"
#include "qemu_interface.h"
#include "qemu_passt.h"
#include "qemu_process.h"
#include "qemu_security.h"
#include "qemu_block.h"
#include "qemu_snapshot.h"
#include "qemu_virtiofs.h"
#include "domain_audit.h"
#include "domain_cgroup.h"
#include "netdev_bandwidth_conf.h"
#include "domain_nwfilter.h"
#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virfile.h"
#include "qemu_cgroup.h"
#include "locking/domain_lock.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virnetdevmidonet.h"
#include "device_conf.h"
#include "storage_source.h"
#include "storage_source_conf.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_hotplug");

#define CHANGE_MEDIA_TIMEOUT 5000

/* Timeout in milliseconds for device removal. PPC64 domains
 * can experience a bigger delay in unplug operations during
 * heavy guest activity (vcpu being the most notable case), thus
 * the timeout for PPC64 is also bigger. */
#define QEMU_UNPLUG_TIMEOUT 1000ull * 5
#define QEMU_UNPLUG_TIMEOUT_PPC64 1000ull * 10


static void
qemuDomainResetDeviceRemoval(virDomainObj *vm);

static int
qemuDomainAttachHostDevice(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainHostdevDef *hostdev);

/**
 * qemuDomainDeleteDevice:
 * @vm: domain object
 * @alias: device to remove
 *
 * This is a wrapper over qemuMonitorDelDevice() plus enter/exit
 * monitor calls.  This function MUST be used instead of plain
 * qemuMonitorDelDevice() in all places where @alias represents a
 * device from domain XML, i.e. caller marks the device for
 * removal and then calls qemuDomainWaitForDeviceRemoval()
 * followed by qemuDomainRemove*Device().
 *
 * For collateral devices (e.g. extension devices like zPCI) it
 * is safe to use plain qemuMonitorDelDevice().
 *
 * Upon entry, @vm must be locked.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 *         -2 device does not exist in qemu, but it still
 *            exists in libvirt
 */
static int
qemuDomainDeleteDevice(virDomainObj *vm,
                       const char *alias)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    qemuDomainObjEnterMonitor(vm);

    rc = qemuMonitorDelDevice(priv->mon, alias);

    qemuDomainObjExitMonitor(vm);

    if (rc < 0) {
        /* Deleting device failed. Let's check if DEVICE_DELETED
         * even arrived. If it did, we need to claim success to
         * make the caller remove device from domain XML. */

        if (priv->unplug.eventSeen) {
            /* The event arrived. Return success. */
            VIR_DEBUG("Detaching of device %s failed, but event arrived", alias);
            qemuDomainResetDeviceRemoval(vm);
            rc = 0;
        } else if (rc == -2) {
            /* The device does not exist in qemu, but it still
             * exists in libvirt. Claim success to make caller
             * qemuDomainWaitForDeviceRemoval(). Otherwise if
             * domain XML is queried right after detach API the
             * device would still be there.  */
            VIR_DEBUG("Detaching of device %s failed and no event arrived", alias);
        }
    }

    return rc;
}


/**
 * qemuHotplugRemoveFDSet:
 * @mon: monitor object
 * @prefix: the prefix of FD names ('opaque' field) to delete
 * @alternate: alternate name for FD, for historical usage (may be NULL)
 *
 * Looks up the 'fdset' by looking for a fd inside one of the fdsets which
 * has the opaque string starting with @prefix. Removes the whole fdset which
 * contains the fd. Alternatively if @alternate is specified fdsets having a fd
 * with that exact 'opaque' string is removed too.
 *
 * Errors are logged, but this is a best-effort hot-unplug cleanup helper so it's
 * pointless to return a value.
 */
static void
qemuHotplugRemoveFDSet(qemuMonitor *mon,
                       const char *prefix,
                       const char *alternate)
{
    g_autoptr(qemuMonitorFdsets) fdsets = NULL;
    size_t i;

    if (qemuMonitorQueryFdsets(mon, &fdsets) < 0)
        return;

    for (i = 0; i < fdsets->nfdsets; i++) {
        qemuMonitorFdsetInfo *set = &fdsets->fdsets[i];
        size_t j;

        for (j = 0; j < set->nfds; j++) {
            qemuMonitorFdsetFdInfo *fdinfo = &set->fds[j];

            if (fdinfo->opaque &&
                (STRPREFIX(fdinfo->opaque, prefix) ||
                 STREQ_NULLABLE(fdinfo->opaque, alternate))) {
                ignore_value(qemuMonitorRemoveFdset(mon, set->id));
                break;
            }
        }
    }
}


static int
qemuDomainDetachZPCIDevice(qemuMonitor *mon,
                           virDomainDeviceInfo *info)
{
    g_autofree char *zpciAlias = NULL;

    zpciAlias = g_strdup_printf("zpci%d", info->addr.pci.zpci.uid.value);

    if (qemuMonitorDelDevice(mon, zpciAlias) < 0)
        return -1;

    return 0;
}


static int
qemuDomainAttachExtensionDevice(qemuMonitor *mon,
                                virDomainDeviceInfo *info)
{
    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        info->addr.pci.extFlags == VIR_PCI_ADDRESS_EXTENSION_NONE) {
        return 0;
    }

    if (info->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        g_autoptr(virJSONValue) devprops = NULL;

        if (!(devprops = qemuBuildZPCIDevProps(info)))
            return -1;

        if (qemuMonitorAddDeviceProps(mon, &devprops) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainDetachExtensionDevice(qemuMonitor *mon,
                                virDomainDeviceInfo *info)
{
    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        info->addr.pci.extFlags == VIR_PCI_ADDRESS_EXTENSION_NONE) {
        return 0;
    }

    if (info->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI)
        return qemuDomainDetachZPCIDevice(mon, info);

    return 0;
}


static int
qemuHotplugChardevAttach(qemuMonitor *mon,
                         const char *alias,
                         virDomainChrSourceDef *def)
{
    return qemuMonitorAttachCharDev(mon, alias, def);
}


static int
qemuHotplugWaitForTrayEject(virDomainObj *vm,
                            virDomainDiskDef *disk)
{
    unsigned long long now;
    int rc;

    if (virTimeMillisNow(&now) < 0)
        return -1;

    while (disk->tray_status != VIR_DOMAIN_DISK_TRAY_OPEN) {
        if ((rc = virDomainObjWaitUntil(vm, now + CHANGE_MEDIA_TIMEOUT)) < 0)
            return -1;

        if (rc > 0) {
            /* the caller called qemuMonitorEjectMedia which usually reports an
             * error. Report the failure in an off-chance that it didn't. */
            if (virGetLastErrorCode() == VIR_ERR_OK) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("timed out waiting to open tray of '%1$s'"),
                               disk->dst);
            }
            return -1;
        }
    }

    return 0;
}


/**
 * qemuHotplugAttachDBusVMState:
 * @driver: QEMU driver object
 * @vm: domain object
 * @asyncJob: asynchronous job identifier
 *
 * Add -object dbus-vmstate if necessary.
 *
 * Returns: 0 on success, -1 on error.
 */
int
qemuHotplugAttachDBusVMState(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) props = NULL;
    int ret;

    if (priv->dbusVMState)
        return 0;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {
        VIR_DEBUG("dbus-vmstate object is not supported by this QEMU binary");
        return 0;
    }

    if (!(props = qemuBuildDBusVMStateInfoProps(driver, vm)))
        return -1;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorAddObject(priv->mon, &props, NULL);

    if (ret == 0)
        priv->dbusVMState = true;

    qemuDomainObjExitMonitor(vm);

    return ret;
}


/**
 * qemuHotplugRemoveDBusVMState:
 * @driver: QEMU driver object
 * @vm: domain object
 * @asyncJob: asynchronous job identifier
 *
 * Remove -object dbus-vmstate from @vm if the configuration does not require
 * it any more.
 *
 * Returns: 0 on success, -1 on error.
 */
int
qemuHotplugRemoveDBusVMState(virDomainObj *vm,
                             virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret;

    if (!priv->dbusVMState)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorDelObject(priv->mon, qemuDomainGetDBusVMStateAlias(), true);

    if (ret == 0)
        priv->dbusVMState = false;

    qemuDomainObjExitMonitor(vm);

    return ret;
}


/**
 * qemuHotplugAttachManagedPR:
 * @driver: QEMU driver object
 * @vm: domain object
 * @src: new disk source to be attached to @vm
 * @asyncJob: asynchronous job identifier
 *
 * Checks if it's needed to start qemu-pr-helper and add the corresponding
 * pr-manager-helper object.
 *
 * Returns: 0 on success, -1 on error.
 */
static int
qemuHotplugAttachManagedPR(virDomainObj *vm,
                           virStorageSource *src,
                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) props = NULL;
    bool daemonStarted = false;
    int ret = -1;
    int rc;

    if (priv->prDaemonRunning ||
        !virStorageSourceChainHasManagedPR(src))
        return 0;

    if (!(props = qemuBuildPRManagedManagerInfoProps(priv)))
        return -1;

    if (qemuProcessStartManagedPRDaemon(vm) < 0)
        goto cleanup;

    daemonStarted = true;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuMonitorAddObject(priv->mon, &props, NULL);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0 && daemonStarted)
        qemuProcessKillManagedPRDaemon(vm);
    return ret;
}


/**
 * qemuHotplugRemoveManagedPR:
 * @driver: QEMU driver object
 * @vm: domain object
 * @asyncJob: asynchronous job identifier
 *
 * Removes the managed PR object from @vm if the configuration does not require
 * it any more.
 */
static int
qemuHotplugRemoveManagedPR(virDomainObj *vm,
                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    int ret = -1;

    if (qemuDomainDefHasManagedPR(vm))
        return 0;

    virErrorPreserveLast(&orig_err);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;
    ignore_value(qemuMonitorDelObject(priv->mon, qemuDomainGetManagedPRAlias(),
                                      false));
    qemuDomainObjExitMonitor(vm);

    qemuProcessKillManagedPRDaemon(vm);

    ret = 0;
 cleanup:
    virErrorRestore(&orig_err);
    return ret;
}


/**
 * qemuDomainChangeMediaBlockdev:
 * @driver: qemu driver structure
 * @vm: domain definition
 * @disk: disk definition to change the source of
 * @oldsrc: old source definition
 * @newsrc: new disk source to change to
 * @force: force the change of media
 *
 * Change the media in an ejectable device to the one described by
 * @newsrc. This function also removes the old source from the
 * shared device table if appropriate. Note that newsrc is consumed
 * on success and the old source is freed on success.
 *
 * Returns 0 on success, -1 on error and reports libvirt error
 */
static int
qemuDomainChangeMediaBlockdev(virDomainObj *vm,
                              virDomainDiskDef *disk,
                              virStorageSource *oldsrc,
                              virStorageSource *newsrc,
                              bool force)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    g_autoptr(qemuBlockStorageSourceChainData) newbackend = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) oldbackend = NULL;
    g_autofree char *nodename = NULL;
    int rc;

    if (!virStorageSourceIsEmpty(oldsrc) &&
        !(oldbackend = qemuBlockStorageSourceChainDetachPrepareBlockdev(oldsrc)))
        return -1;

    if (!virStorageSourceIsEmpty(newsrc)) {
        if (!(newbackend = qemuBuildStorageSourceChainAttachPrepareBlockdev(newsrc)))
            return -1;

        if (qemuDomainDiskGetBackendAlias(disk, &nodename) < 0)
            return -1;
    }

    if (diskPriv->tray && disk->tray_status != VIR_DOMAIN_DISK_TRAY_OPEN) {
        qemuDomainObjEnterMonitor(vm);
        rc = qemuMonitorBlockdevTrayOpen(priv->mon, diskPriv->qomName, force);
        qemuDomainObjExitMonitor(vm);
        if (rc < 0)
            return -1;

        if (!force && qemuHotplugWaitForTrayEject(vm, disk) < 0)
            return -1;
    }

    qemuDomainObjEnterMonitor(vm);

    rc = qemuMonitorBlockdevMediumRemove(priv->mon, diskPriv->qomName);

    if (rc == 0 && oldbackend)
        qemuBlockStorageSourceChainDetach(priv->mon, oldbackend);

    if (newbackend && nodename) {
        if (rc == 0)
            rc = qemuBlockStorageSourceChainAttach(priv->mon, newbackend);

        if (rc == 0)
            rc = qemuMonitorBlockdevMediumInsert(priv->mon, diskPriv->qomName,
                                                 nodename);
    }

    /* set throttling for the new image */
    if (rc == 0 &&
        !virStorageSourceIsEmpty(newsrc) &&
        qemuDiskConfigBlkdeviotuneEnabled(disk)) {
        rc = qemuMonitorSetBlockIoThrottle(priv->mon,
                                           diskPriv->qomName,
                                           &disk->blkdeviotune);
    }

    if (rc == 0)
        rc = qemuMonitorBlockdevTrayClose(priv->mon, diskPriv->qomName);

    if (rc < 0 && newbackend)
        qemuBlockStorageSourceChainDetach(priv->mon, newbackend);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainChangeEjectableMedia:
 * @driver: qemu driver structure
 * @vm: domain definition
 * @disk: disk definition to change the source of
 * @newsrc: new disk source to change to
 * @force: force the change of media
 *
 * Change the media in an ejectable device to the one described by
 * @newsrc. This function also removes the old source from the
 * shared device table if appropriate. Note that newsrc is consumed
 * on success and the old source is freed on success.
 *
 * Returns 0 on success, -1 on error and reports libvirt error
 */
static int
qemuDomainChangeEjectableMedia(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainDiskDef *disk,
                               virStorageSource *newsrc,
                               bool force)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    virStorageSource *oldsrc = disk->src;
    qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    bool managedpr = virStorageSourceChainHasManagedPR(oldsrc) ||
                     virStorageSourceChainHasManagedPR(newsrc);
    int ret = -1;
    int rc;

    if (diskPriv->blockjob && qemuBlockJobIsRunning(diskPriv->blockjob)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("can't change media while a block job is running on the device"));
        return -1;
    }

    disk->src = newsrc;

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        goto cleanup;

    if (qemuDomainDetermineDiskChain(driver, vm, disk, NULL) < 0)
        goto cleanup;

    if (qemuDomainPrepareDiskSource(disk, priv, cfg) < 0)
        goto cleanup;

    if (qemuDomainStorageSourceChainAccessAllow(driver, vm, newsrc) < 0)
        goto cleanup;

    if (qemuHotplugAttachManagedPR(vm, newsrc, VIR_ASYNC_JOB_NONE) < 0)
        goto cleanup;

    rc = qemuDomainChangeMediaBlockdev(vm, disk, oldsrc, newsrc, force);

    virDomainAuditDisk(vm, oldsrc, newsrc, "update", rc >= 0);

    if (rc < 0)
        goto cleanup;

    ignore_value(qemuDomainStorageSourceChainAccessRevoke(driver, vm, oldsrc));

    /* media was changed, so we can remove the old media definition now */
    g_clear_pointer(&oldsrc, virObjectUnref);

    ret = 0;

 cleanup:
    /* undo changes to the new disk */
    if (ret < 0) {
        ignore_value(qemuDomainStorageSourceChainAccessRevoke(driver, vm, newsrc));
    }

    /* remove PR manager object if unneeded */
    if (managedpr)
        ignore_value(qemuHotplugRemoveManagedPR(vm, VIR_ASYNC_JOB_NONE));

    /* revert old image do the disk definition */
    if (oldsrc)
        disk->src = oldsrc;

    return ret;
}


static qemuSnapshotDiskContext *
qemuDomainAttachDiskGenericTransient(virDomainObj *vm,
                                     virDomainDiskDef *disk,
                                     GHashTable *blockNamedNodeData,
                                     virDomainAsyncJob asyncJob)
{
    g_autoptr(qemuSnapshotDiskContext) snapctxt = NULL;
    g_autoptr(virDomainSnapshotDiskDef) snapdiskdef = NULL;

    if (!(snapdiskdef = qemuSnapshotGetTransientDiskDef(disk, vm->def->name)))
        return NULL;

    snapctxt = qemuSnapshotDiskContextNew(1, vm, asyncJob);

    if (qemuSnapshotDiskPrepareOne(snapctxt, disk, snapdiskdef,
                                   blockNamedNodeData, false, false) < 0)
        return NULL;

    return g_steal_pointer(&snapctxt);
}


/**
 * qemuDomainAttachDiskGeneric:
 *
 * Attaches disk to a VM. This function aggregates common code for all bus types.
 * In cases when the VM crashed while adding the disk, -2 is returned. */
int
qemuDomainAttachDiskGeneric(virDomainObj *vm,
                            virDomainDiskDef *disk,
                            virDomainAsyncJob asyncJob)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) devprops = NULL;
    bool extensionDeviceAttached = false;
    int rc;
    g_autoptr(qemuSnapshotDiskContext) transientDiskSnapshotCtxt = NULL;
    bool origReadonly = disk->src->readonly;

    if (disk->transient)
        disk->src->readonly = true;

    if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_VHOST_USER) {
        if (!(data = qemuBuildStorageSourceChainAttachPrepareChardev(disk)))
            return -1;
    } else {
        if (!(data = qemuBuildStorageSourceChainAttachPrepareBlockdev(disk->src)))
            return -1;

        if (disk->copy_on_read == VIR_TRISTATE_SWITCH_ON) {
            if (!(data->copyOnReadProps = qemuBlockStorageGetCopyOnReadProps(disk)))
                return -1;

            data->copyOnReadNodename = g_strdup(QEMU_DOMAIN_DISK_PRIVATE(disk)->nodeCopyOnRead);
        }
    }

    disk->src->readonly = origReadonly;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuBlockStorageSourceChainAttach(priv->mon, data);

    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        goto rollback;

    if (disk->transient) {
        g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;
        g_autoptr(GHashTable) blockNamedNodeData = NULL;

        if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
            goto rollback;

        if (!(transientDiskSnapshotCtxt = qemuDomainAttachDiskGenericTransient(vm, disk, blockNamedNodeData, asyncJob)))
            goto rollback;


        if (qemuSnapshotDiskCreate(transientDiskSnapshotCtxt) < 0)
            goto rollback;

        QEMU_DOMAIN_DISK_PRIVATE(disk)->transientOverlayCreated = true;
        backend = qemuBlockStorageSourceDetachPrepare(disk->src);
        ignore_value(VIR_INSERT_ELEMENT(data->srcdata, 0, data->nsrcdata, backend));
    }

    if (!(devprops = qemuBuildDiskDeviceProps(vm->def, disk, priv->qemuCaps)))
        goto rollback;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto rollback;

    if ((rc = qemuDomainAttachExtensionDevice(priv->mon, &disk->info)) == 0)
        extensionDeviceAttached = true;

    if (rc == 0)
        rc = qemuMonitorAddDeviceProps(priv->mon, &devprops);

    /* Setup throttling of disk via block_set_io_throttle QMP command. This
     * is a hack until the 'throttle' blockdev driver will support modification
     * of the trhottle group. See also qemuProcessSetupDiskThrottlingBlockdev.
     * As there isn't anything sane to do if this fails, let's just return
     * success.
     */
    if (rc == 0) {
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        g_autoptr(GHashTable) blockinfo = NULL;

        if (qemuDiskConfigBlkdeviotuneEnabled(disk)) {
            if (qemuMonitorSetBlockIoThrottle(priv->mon, diskPriv->qomName,
                                              &disk->blkdeviotune) < 0)
                VIR_WARN("failed to set blkdeviotune for '%s' of '%s'", disk->dst, vm->def->name);
        }

        if ((blockinfo = qemuMonitorGetBlockInfo(priv->mon))) {
            struct qemuDomainDiskInfo *diskinfo;

            if ((diskinfo = virHashLookup(blockinfo, diskPriv->qomName))) {
                qemuProcessRefreshDiskProps(disk, diskinfo);
            }
        }
    }

    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        goto rollback;

    return 0;

 rollback:
    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    if (extensionDeviceAttached)
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &disk->info));

    qemuBlockStorageSourceChainDetach(priv->mon, data);

    qemuDomainObjExitMonitor(vm);

    return -1;
}


static int
qemuDomainAttachControllerDevice(virDomainObj *vm,
                                 virDomainControllerDef *controller)
{
    int ret = -1;
    const char* type = virDomainControllerTypeToString(controller->type);
    g_autoptr(virJSONValue) devprops = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_CONTROLLER,
                               { .controller = controller } };
    bool releaseaddr = false;

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%1$s' controller cannot be hot plugged."),
                       virDomainControllerTypeToString(controller->type));
        return -1;
    }

    /* default idx would normally be set by virDomainDefPostParse(),
     * which isn't called in the case of live attach of a single
     * device.
     */
    if (controller->idx == -1)
       controller->idx = virDomainControllerFindUnusedIndex(vm->def,
                                                            controller->type);

    if (virDomainControllerFind(vm->def, controller->type, controller->idx) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %1$s:%2$d already exists"),
                       type, controller->idx);
        return -1;
    }

    if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
        return -1;

    qemuAssignDeviceControllerAlias(vm->def, controller);

    if (qemuBuildControllerDevProps(vm->def, controller, priv->qemuCaps, &devprops) < 0)
        goto cleanup;

    if (!devprops)
        goto cleanup;

    VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers+1);

    qemuDomainObjEnterMonitor(vm);

    if ((ret = qemuDomainAttachExtensionDevice(priv->mon,
                                               &controller->info)) < 0) {
        goto exit_monitor;
    }

    if ((ret = qemuMonitorAddDeviceProps(priv->mon, &devprops)) < 0)
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &controller->info));

 exit_monitor:
    qemuDomainObjExitMonitor(vm);

    if (ret == 0)
        virDomainControllerInsertPreAlloced(vm->def, controller);

 cleanup:
    if (ret != 0 && releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, &controller->info);

    return ret;
}

static virDomainControllerDef *
qemuDomainFindOrCreateSCSIDiskController(virDomainObj *vm,
                                         int controller)
{
    size_t i;
    virDomainControllerDef *cont;
    qemuDomainObjPrivate *priv = vm->privateData;
    int model = -1;

    for (i = 0; i < vm->def->ncontrollers; i++) {
        cont = vm->def->controllers[i];

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (cont->idx == controller)
            return cont;

        /* Because virDomainHostdevAssignAddress called during
         * virDomainHostdevDefPostParse cannot add a new controller
         * it will assign a controller index to a controller that doesn't
         * exist leaving this code to perform the magic of adding the
         * controller. Because that code would be attempting to add a
         * SCSI disk to an existing controller, let's save the model
         * of the "last" SCSI controller we find so that if we end up
         * creating a controller below it uses the same controller model. */
        model = cont->model;
    }

    /* No SCSI controller present, for backward compatibility we
     * now hotplug a controller */
    cont = g_new0(virDomainControllerDef, 1);
    cont->type = VIR_DOMAIN_CONTROLLER_TYPE_SCSI;
    cont->idx = controller;
    if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT)
        cont->model = qemuDomainGetSCSIControllerModel(vm->def, cont, priv->qemuCaps);
    else
        cont->model = model;

    VIR_INFO("No SCSI controller present, hotplugging one model=%s",
             virDomainControllerModelSCSITypeToString(cont->model));
    if (qemuDomainAttachControllerDevice(vm, cont) < 0) {
        VIR_FREE(cont);
        return NULL;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        /* cont doesn't need freeing here, since the reference
         * now held in def->controllers */
        return NULL;
    }

    return cont;
}


static int
qemuDomainAttachDeviceDiskLiveInternal(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       virDomainDeviceDef *dev)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    size_t i;
    virDomainDiskDef *disk = dev->data.disk;
    bool releaseUSB = false;
    bool releaseVirtio = false;
    bool releaseSeclabel = false;
    int ret = -1;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("floppy device hotplug isn't supported"));
        return -1;
    }

    if (virDomainDiskTranslateSourcePool(disk) < 0)
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        if (virDomainDiskDefCheckDuplicateInfo(vm->def->disks[i], disk) < 0)
            goto cleanup;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_USB:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk device='lun' is not supported for usb bus"));
            break;
        }

        if (virDomainUSBAddressEnsure(priv->usbaddrs, &disk->info) < 0)
            goto cleanup;

        releaseUSB = true;
        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cdrom device with virtio bus isn't supported"));
        }
        if (qemuDomainEnsureVirtioAddress(&releaseVirtio, vm, dev) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_DISK_BUS_SCSI:
        /* We should have an address already, so make sure */
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected disk address type %1$s"),
                           virDomainDeviceAddressTypeToString(disk->info.type));
            goto cleanup;
        }

        if (virDomainSCSIDriveAddressIsUsed(vm->def, &disk->info.addr.drive)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("Domain already contains a disk with that address"));
            goto cleanup;
        }

        /* Let's make sure the disk has a controller defined and loaded before
         * trying to add it. The controller used by the disk must exist before a
         * qemu command line string is generated.
         *
         * Ensure that the given controller and all controllers with a smaller index
         * exist; there must not be any missing index in between.
         */
        for (i = 0; i <= disk->info.addr.drive.controller; i++) {
            if (!qemuDomainFindOrCreateSCSIDiskController(vm, i))
                goto cleanup;
        }
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SATA:
    case VIR_DOMAIN_DISK_BUS_SD:
        /* Note that SD card hotplug support should be added only once
         * they support '-device' (don't require -drive only).
         * See also: qemuDiskBusIsSD */
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("disk bus '%1$s' cannot be hotplugged."),
                       virDomainDiskBusTypeToString(disk->bus));
    }

    if (qemuDomainStorageSourceChainAccessAllow(driver, vm, disk->src) < 0)
        goto cleanup;

    releaseSeclabel = true;

    if (qemuAssignDeviceDiskAlias(vm->def, disk) < 0)
        goto cleanup;

    if (qemuDomainPrepareDiskSource(disk, priv, cfg) < 0)
        goto cleanup;

    if (qemuDomainDetermineDiskChain(driver, vm, disk, NULL) < 0)
        goto cleanup;

    if (qemuProcessPrepareHostStorageDisk(vm, disk) < 0)
        goto cleanup;

    if (qemuHotplugAttachManagedPR(vm, disk->src, VIR_ASYNC_JOB_NONE) < 0)
        goto cleanup;

    if (qemuNbdkitStartStorageSource(driver, vm, disk->src) < 0)
        goto cleanup;

    ret = qemuDomainAttachDiskGeneric(vm, disk, VIR_ASYNC_JOB_NONE);

    virDomainAuditDisk(vm, NULL, disk->src, "attach", ret == 0);

    if (ret < 0)
        goto cleanup;

    virDomainDiskInsert(vm->def, disk);

 cleanup:
    if (ret < 0) {
        if (releaseUSB)
            virDomainUSBAddressRelease(priv->usbaddrs, &disk->info);

        if (releaseVirtio && ret == -1)
            qemuDomainReleaseDeviceAddress(vm, &disk->info);

        if (releaseSeclabel)
            ignore_value(qemuDomainStorageSourceChainAccessRevoke(driver, vm, disk->src));

        if (virStorageSourceChainHasManagedPR(disk->src))
            ignore_value(qemuHotplugRemoveManagedPR(vm, VIR_ASYNC_JOB_NONE));

        qemuNbdkitStopStorageSource(disk->src, vm);
    }
    qemuDomainSecretDiskDestroy(disk);
    qemuDomainCleanupStorageSourceFD(disk->src);

    return ret;
}


/**
 * qemuDomainAttachDeviceDiskLive:
 * @driver: qemu driver struct
 * @vm: domain object
 * @dev: device to attach (expected type is DISK)
 *
 * Attach a new disk or in case of cdroms/floppies change the media in the drive.
 * This function handles all the necessary steps to attach a new storage source
 * to the VM.
 */
static int
qemuDomainAttachDeviceDiskLive(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainDeviceDef *dev)
{
    virDomainDiskDef *disk = dev->data.disk;
    virDomainDiskDef *orig_disk = NULL;

    /* this API overloads media change semantics on disk hotplug
     * for devices supporting media changes */
    if ((disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM ||
         disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) &&
        (orig_disk = virDomainDiskByTarget(vm->def, disk->dst))) {
        if (qemuDomainChangeEjectableMedia(driver, vm, orig_disk,
                                           disk->src, false) < 0)
            return -1;

        disk->src = NULL;
        virDomainDiskDefFree(disk);
        return 0;
    }

    return qemuDomainAttachDeviceDiskLiveInternal(driver, vm, dev);
}


static void
qemuDomainNetDeviceVportRemove(virDomainNetDef *net)
{
    const virNetDevVPortProfile *vport = virDomainNetGetActualVirtPortProfile(net);
    const char *brname;

    if (!vport)
        return;

    if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
        ignore_value(virNetDevMidonetUnbindPort(vport));
    } else if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
        brname = virDomainNetGetActualBridgeName(net);
        ignore_value(virNetDevOpenvswitchRemovePort(brname, net->ifname));
    }
}


static int
qemuDomainAttachNetDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainNetDef *net)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_NET, { .net = net } };
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    virErrorPtr originalError = NULL;
    g_autoptr(virJSONValue) nicprops = NULL;
    g_autoptr(virJSONValue) netprops = NULL;
    int ret = -1;
    bool releaseaddr = false;
    bool iface_connected = false;
    bool adjustmemlock = false;
    virDomainNetType actualType;
    const virNetDevBandwidth *actualBandwidth;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainCCWAddressSet *ccwaddrs = NULL;
    g_autofree char *charDevAlias = NULL;
    bool charDevPlugged = false;
    bool netdevPlugged = false;
    g_autofree char *netdev_name = NULL;
    g_autoptr(virConnect) conn = NULL;
    virErrorPtr save_err = NULL;
    bool teardownlabel = false;
    GSList *n;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (!(conn = virGetConnectNetwork()))
            goto cleanup;
        if (virDomainNetAllocateActualDevice(conn, vm->def, net) < 0)
            goto cleanup;
    }

    /* final validation now that we have full info on the type */
    if (qemuDomainValidateActualNetDef(net, priv->qemuCaps) < 0)
        goto cleanup;

    actualType = virDomainNetGetActualType(net);

    qemuAssignDeviceNetAlias(vm->def, net, -1);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* This is really a "smart hostdev", so it should be attached
         * as a hostdev (the hostdev code will reach over into the
         * netdev-specific code as appropriate), then also added to
         * the nets list if successful.
         */
        if (qemuDomainAttachHostDevice(driver, vm,
                                       virDomainNetGetActualHostdev(net)) < 0) {
            goto cleanup;
        }
        VIR_APPEND_ELEMENT_COPY(vm->def->nets, vm->def->nnets, net);

        /* the rest of the setup doesn't apply to hostdev interfaces, so
         * we can skip straight to the cleanup (nothing there applies to
         * hostdev interfaces either, but it might in the future, so we
         * may as well be consistent)
         */
        ret = 0;
        goto cleanup;
    }

    if (qemuDomainIsS390CCW(vm->def) &&
        net->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        if (!(ccwaddrs = virDomainCCWAddressSetCreateFromDomain(vm->def)))
            goto cleanup;
        if (virDomainCCWAddressAssign(&net->info, ccwaddrs,
                                      !net->info.addr.ccw.assigned) < 0)
            goto cleanup;
    } else if (qemuDomainEnsurePCIAddress(vm, &dev) < 0) {
        goto cleanup;
    }

    releaseaddr = true;

    /* We've completed all examinations of the full domain definition
     * that require the new device to *not* be present (e.g. PCI
     * address allocation and alias name assignment) so it is now safe
     * to add the new device to the domain's nets list (in order for
     * it to be in place for checks that *do* need it present in the
     * domain definition, e.g. checking if we need to adjust the
     * locked memory limit). This means we will need to remove it if
     * there is a failure.
     */
    VIR_APPEND_ELEMENT_COPY(vm->def->nets, vm->def->nnets, net);

    if (qemuBuildInterfaceConnect(vm, net, VIR_NETDEV_VPORT_PROFILE_OP_CREATE) < 0)
        goto cleanup;

    iface_connected = true;

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        if (!qemuDomainSupportsNicdev(vm->def, net)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Nicdev support unavailable"));
            goto cleanup;
        }

        if (!(charDevAlias = qemuAliasChardevFromDevAlias(net->info.alias)))
            goto cleanup;

        if (virNetDevOpenvswitchGetVhostuserIfname(net->data.vhostuser->data.nix.path,
                                                   net->data.vhostuser->data.nix.listen,
                                                   &net->ifname) < 0)
            goto cleanup;

        if (qemuSecuritySetNetdevLabel(driver, vm, net) < 0)
            goto cleanup;
        teardownlabel = true;
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
        if (net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {

            if (qemuPasstStart(vm, net) < 0)
                goto cleanup;

        } else if (!priv->disableSlirp &&
                   virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {

            if (qemuInterfacePrepareSlirp(driver, net) < 0)
                goto cleanup;

            if (qemuSlirpStart(vm, net, NULL) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("Failed to start slirp"));
                goto cleanup;
            }
        }
        break;

    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        /* hostdev interfaces were handled earlier in this function */
        break;

    case VIR_DOMAIN_NET_TYPE_VDPA:
        if (qemuDomainAdjustMaxMemLock(vm) < 0)
            goto cleanup;
        adjustmemlock = true;
        break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("hotplug of interface type of %1$s is not implemented yet"),
                       virDomainNetTypeToString(actualType));
        goto cleanup;
    }

    /* Set device online immediately */
    if (qemuInterfaceStartDevice(net) < 0)
        goto cleanup;

    qemuDomainInterfaceSetDefaultQDisc(driver, net);

    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportsBandwidth(actualType)) {
            if (virDomainNetDefIsOvsport(net)) {
                if (virNetDevOpenvswitchInterfaceSetQos(net->ifname, actualBandwidth,
                                                        vm->def->uuid,
                                                        !virDomainNetTypeSharesHostView(net)) < 0)
                    goto cleanup;
            } else if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false,
                                             !virDomainNetTypeSharesHostView(net)) < 0) {
                goto cleanup;
            }
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet",
                     virDomainNetTypeToString(actualType));
        }
    }

    if (net->mtu && net->managed_tap != VIR_TRISTATE_BOOL_NO &&
        virNetDevSetMTU(net->ifname, net->mtu) < 0)
        goto cleanup;

    if (!(netprops = qemuBuildHostNetProps(vm, net)))
        goto cleanup;

    qemuDomainObjEnterMonitor(vm);

    for (n = netpriv->tapfds; n; n = n->next) {
        if (qemuFDPassDirectTransferMonitor(n->data, priv->mon) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }

    for (n = netpriv->vhostfds; n; n = n->next) {
        if (qemuFDPassDirectTransferMonitor(n->data, priv->mon) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }

    if (qemuFDPassDirectTransferMonitor(netpriv->slirpfd, priv->mon) < 0 ||
        qemuFDPassTransferMonitor(netpriv->vdpafd, priv->mon) < 0) {
        qemuDomainObjExitMonitor(vm);
        goto cleanup;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_VHOSTUSER) {
        if (qemuHotplugChardevAttach(priv->mon, charDevAlias, net->data.vhostuser) < 0) {
            qemuDomainObjExitMonitor(vm);
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto cleanup;
        }
        charDevPlugged = true;
    }

    if (qemuMonitorAddNetdev(priv->mon, &netprops) < 0) {
        qemuDomainObjExitMonitor(vm);
        virDomainAuditNet(vm, NULL, net, "attach", false);
        goto try_remove;
    }
    netdevPlugged = true;

    qemuDomainObjExitMonitor(vm);

    if (!(nicprops = qemuBuildNicDevProps(vm->def, net, priv->qemuCaps)))
        goto try_remove;

    qemuDomainObjEnterMonitor(vm);

    if (qemuDomainAttachExtensionDevice(priv->mon, &net->info) < 0) {
        qemuDomainObjExitMonitor(vm);
        virDomainAuditNet(vm, NULL, net, "attach", false);
        goto try_remove;
    }

    if (qemuMonitorAddDeviceProps(priv->mon, &nicprops) < 0) {
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &net->info));
        qemuDomainObjExitMonitor(vm);
        virDomainAuditNet(vm, NULL, net, "attach", false);
        goto try_remove;
    }
    qemuDomainObjExitMonitor(vm);

    /* set link state */
    if (net->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) {
        if (!net->info.alias) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("device alias not found: cannot set link state to down"));
        } else {
            qemuDomainObjEnterMonitor(vm);

            if (qemuMonitorSetLink(priv->mon, net->info.alias, VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) < 0) {
                qemuDomainObjExitMonitor(vm);
                virDomainAuditNet(vm, NULL, net, "attach", false);
                goto try_remove;
            }

            qemuDomainObjExitMonitor(vm);
        }
        /* link set to down */
    }

    virDomainAuditNet(vm, NULL, net, "attach", true);

    ret = 0;

 cleanup:
    qemuDomainNetworkPrivateClearFDs(netpriv);

    if (ret < 0) {
        virErrorPreserveLast(&save_err);
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &net->info);

        if (iface_connected) {
            virErrorPreserveLast(&originalError);
            virDomainConfNWFilterTeardown(net);
            virErrorRestore(&originalError);

            if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
                virNetDevMacVLanDeleteWithVPortProfile(net->ifname, &net->mac,
                                                       virDomainNetGetActualDirectDev(net),
                                                       virDomainNetGetActualDirectMode(net),
                                                       virDomainNetGetActualVirtPortProfile(net),
                                                       cfg->stateDir);
            }

            qemuDomainNetDeviceVportRemove(net);
        }

        if (teardownlabel &&
            qemuSecurityRestoreNetdevLabel(driver, vm, net) < 0)
            VIR_WARN("Unable to restore network device labelling on hotplug fail");

        /* we had potentially pre-added the device to the domain
         * device lists, if so we need to remove it (from def->nets
         * and/or def->hostdevs) on failure
         */
        virDomainNetRemoveByObj(vm->def, net);

        /* if we adjusted the memlock limit (for a vDPA device) then
         * we need to re-adjust since we won't be using the device
         * after all
         */
        if (adjustmemlock)
            qemuDomainAdjustMaxMemLock(vm);

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (conn)
                virDomainNetReleaseActualDevice(conn, vm->def, net);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
        }
        virErrorRestore(&save_err);
    }

    virDomainCCWAddressSetFree(ccwaddrs);

    return ret;

 try_remove:
    if (!virDomainObjIsActive(vm))
        goto cleanup;

    virErrorPreserveLast(&originalError);
    netdev_name = g_strdup_printf("host%s", net->info.alias);
    if (QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp)
        qemuSlirpStop(QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp, vm, driver, net);

    if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
        net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {
        qemuPasstStop(vm, net);
    }

    qemuDomainObjEnterMonitor(vm);
    if (charDevPlugged &&
        qemuMonitorDetachCharDev(priv->mon, charDevAlias) < 0)
        VIR_WARN("Failed to remove associated chardev %s", charDevAlias);
    if (netdevPlugged &&
        qemuMonitorRemoveNetdev(priv->mon, netdev_name) < 0)
        VIR_WARN("Failed to remove network backend for netdev %s",
                 netdev_name);

    for (n = netpriv->tapfds; n; n = n->next)
        qemuFDPassDirectTransferMonitorRollback(n->data, priv->mon);

    for (n = netpriv->vhostfds; n; n = n->next)
        qemuFDPassDirectTransferMonitorRollback(n->data, priv->mon);

    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&originalError);
    goto cleanup;
}


static int
qemuDomainAttachHostPCIDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainHostdevDef *hostdev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_HOSTDEV,
                               { .hostdev = hostdev } };
    virDomainDeviceInfo *info = hostdev->info;
    int ret;
    g_autoptr(virJSONValue) devprops = NULL;
    bool releaseaddr = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    bool teardowndevice = false;
    bool teardownmemlock = false;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    unsigned int flags = 0;

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    if (!cfg->relaxedACS)
        flags |= VIR_HOSTDEV_STRICT_ACS_CHECK;
    if (qemuHostdevPreparePCIDevices(driver, vm->def->name,
                                     vm->def->uuid, &hostdev, 1, flags) < 0)
        return -1;

    if (qemuDomainAdjustMaxMemLockHostdev(vm, hostdev) < 0)
        goto error;
    teardownmemlock = true;

    if (qemuDomainNamespaceSetupHostdev(vm, hostdev, &teardowndevice) < 0)
        goto error;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto error;
    teardowncgroup = true;

    if (qemuSecuritySetHostdevLabel(driver, vm, hostdev) < 0)
        goto error;
    teardownlabel = true;

    qemuAssignDeviceHostdevAlias(vm->def, &info->alias, -1);

    if (qemuDomainIsPSeries(vm->def)) {
        /* Isolation groups are only relevant for pSeries guests */
        qemuDomainFillDeviceIsolationGroup(vm->def, &dev);
    }

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED) {
        /* Unassigned devices are not exposed to QEMU. Our job is done here. */
        ret = 0;
        goto done;
    }

    if (qemuDomainEnsurePCIAddress(vm, &dev) < 0)
        goto error;
    releaseaddr = true;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit during hotplug"));
        goto error;
    }

    if (!(devprops = qemuBuildPCIHostdevDevProps(vm->def, hostdev)))
        goto error;

    qemuDomainObjEnterMonitor(vm);

    if ((ret = qemuDomainAttachExtensionDevice(priv->mon, hostdev->info)) < 0)
        goto exit_monitor;

    if ((ret = qemuMonitorAddDeviceProps(priv->mon, &devprops)) < 0)
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, hostdev->info));

 exit_monitor:
    qemuDomainObjExitMonitor(vm);

 done:
    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    return 0;

 error:
    if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
    if (teardownlabel &&
        qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
        VIR_WARN("Unable to restore host device labelling on hotplug fail");
    if (teardowndevice &&
        qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device from /dev");
    if (teardownmemlock && qemuDomainAdjustMaxMemLock(vm) < 0)
        VIR_WARN("Unable to reset maximum locked memory on hotplug fail");

    if (releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, info);

    qemuHostdevReAttachPCIDevices(driver, vm->def->name, &hostdev, 1);

    return -1;
}


void
qemuDomainDelTLSObjects(virDomainObj *vm,
                        virDomainAsyncJob asyncJob,
                        const char *secAlias,
                        const char *tlsAlias)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;

    if (!tlsAlias && !secAlias)
        return;

    virErrorPreserveLast(&orig_err);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    if (tlsAlias)
        ignore_value(qemuMonitorDelObject(priv->mon, tlsAlias, false));

    if (secAlias)
        ignore_value(qemuMonitorDelObject(priv->mon, secAlias, false));

    qemuDomainObjExitMonitor(vm);

 cleanup:
    virErrorRestore(&orig_err);
}


int
qemuDomainAddTLSObjects(virDomainObj *vm,
                        virDomainAsyncJob asyncJob,
                        virJSONValue **secProps,
                        virJSONValue **tlsProps)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    g_autofree char *secAlias = NULL;

    if (!tlsProps && !secProps)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    if (secProps && *secProps &&
        qemuMonitorAddObject(priv->mon, secProps, &secAlias) < 0)
        goto error;

    if (tlsProps &&
        qemuMonitorAddObject(priv->mon, tlsProps, NULL) < 0)
        goto error;

    qemuDomainObjExitMonitor(vm);
    return 0;

 error:
    virErrorPreserveLast(&orig_err);
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&orig_err);
    qemuDomainDelTLSObjects(vm, asyncJob, secAlias, NULL);

    return -1;
}


int
qemuDomainGetTLSObjects(qemuDomainSecretInfo *secinfo,
                        const char *tlsCertdir,
                        bool tlsListen,
                        bool tlsVerify,
                        const char *alias,
                        virJSONValue **tlsProps,
                        virJSONValue **secProps)
{
    const char *secAlias = NULL;

    if (secinfo) {
        if (qemuBuildSecretInfoProps(secinfo, secProps) < 0)
            return -1;

        secAlias = secinfo->alias;
    }

    if (qemuBuildTLSx509BackendProps(tlsCertdir, tlsListen, tlsVerify,
                                     alias, secAlias, tlsProps) < 0)
        return -1;

    return 0;
}


static int
qemuDomainAddChardevTLSObjects(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainChrSourceDef *dev,
                               char *devAlias,
                               char *charAlias,
                               char **tlsAlias,
                               const char **secAlias)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainChrSourcePrivate *chrSourcePriv;
    qemuDomainSecretInfo *secinfo = NULL;
    g_autoptr(virJSONValue) tlsProps = NULL;
    g_autoptr(virJSONValue) secProps = NULL;

    if (dev->type != VIR_DOMAIN_CHR_TYPE_TCP ||
        dev->data.tcp.haveTLS != VIR_TRISTATE_BOOL_YES)
        return 0;

    if (qemuDomainSecretChardevPrepare(cfg, priv, devAlias, dev) < 0)
        return -1;

    if ((chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(dev)))
        secinfo = chrSourcePriv->secinfo;

    if (secinfo)
        *secAlias = secinfo->alias;

    if (!(*tlsAlias = qemuAliasTLSObjFromSrcAlias(charAlias)))
        return -1;

    if (qemuDomainGetTLSObjects(secinfo,
                                cfg->chardevTLSx509certdir,
                                dev->data.tcp.listen,
                                cfg->chardevTLSx509verify,
                                *tlsAlias, &tlsProps, &secProps) < 0)
        return -1;

    dev->data.tcp.tlscreds = true;

    if (qemuDomainAddTLSObjects(vm, VIR_ASYNC_JOB_NONE,
                                &secProps, &tlsProps) < 0)
        return -1;

    return 0;
}


static int
qemuDomainDelChardevTLSObjects(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainChrSourceDef *dev,
                               const char *inAlias)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *tlsAlias = NULL;
    g_autofree char *secAlias = NULL;

    if (dev->type != VIR_DOMAIN_CHR_TYPE_TCP ||
        dev->data.tcp.haveTLS != VIR_TRISTATE_BOOL_YES) {
        return 0;
    }

    if (!(tlsAlias = qemuAliasTLSObjFromSrcAlias(inAlias)))
        return -1;

    /* Best shot at this as the secinfo is destroyed after process launch
     * and this path does not recreate it. Thus, if the config has the
     * secret UUID and we have a serial TCP chardev, then formulate a
     * secAlias which we'll attempt to destroy. */
    if (cfg->chardevTLSx509secretUUID &&
        !(secAlias = qemuAliasForSecret(inAlias, NULL, 0)))
        return -1;

    qemuDomainObjEnterMonitor(vm);

    ignore_value(qemuMonitorDelObject(priv->mon, tlsAlias, false));
    if (secAlias)
        ignore_value(qemuMonitorDelObject(priv->mon, secAlias, false));

    qemuDomainObjExitMonitor(vm);

    return 0;
}


static int
qemuDomainAttachRedirdevDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainRedirdevDef *redirdev)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDef *def = vm->def;
    g_autofree char *charAlias = NULL;
    g_autoptr(virJSONValue) devprops = NULL;
    bool chardevAdded = false;
    g_autofree char *tlsAlias = NULL;
    const char *secAlias = NULL;
    virErrorPtr orig_err;

    qemuAssignDeviceRedirdevAlias(def, redirdev, -1);

    if (!(charAlias = qemuAliasChardevFromDevAlias(redirdev->info.alias)))
        return -1;

    if ((virDomainUSBAddressEnsure(priv->usbaddrs, &redirdev->info)) < 0)
        return -1;

    if (!(devprops = qemuBuildRedirdevDevProps(def, redirdev)))
        goto cleanup;

    VIR_REALLOC_N(def->redirdevs, def->nredirdevs+1);

    if (qemuDomainAddChardevTLSObjects(driver, vm, redirdev->source,
                                       redirdev->info.alias, charAlias,
                                       &tlsAlias, &secAlias) < 0)
        goto audit;

    qemuDomainObjEnterMonitor(vm);

    if (qemuHotplugChardevAttach(priv->mon, charAlias, redirdev->source) < 0)
        goto exit_monitor;
    chardevAdded = true;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0)
        goto exit_monitor;

    qemuDomainObjExitMonitor(vm);

    def->redirdevs[def->nredirdevs++] = redirdev;
    ret = 0;
 audit:
    virDomainAuditRedirdev(vm, redirdev, "attach", ret == 0);
 cleanup:
    if (ret < 0)
        qemuDomainReleaseDeviceAddress(vm, &redirdev->info);
    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    /* detach associated chardev on error */
    if (chardevAdded)
        ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&orig_err);
    qemuDomainDelTLSObjects(vm, VIR_ASYNC_JOB_NONE, secAlias, tlsAlias);
    goto audit;
}

static int
qemuDomainChrPreInsert(virDomainDef *vmdef,
                       virDomainChrDef *chr)
{
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("attaching serial console is not supported"));
        return -1;
    }

    if (virDomainChrFind(vmdef, chr)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("chardev already exists"));
        return -1;
    }

    if (virDomainChrPreAlloc(vmdef, chr) < 0)
        return -1;

    /* Due to historical reasons, the first console is an alias to the
     * first serial device (if such exists). If this is the case, we need to
     * create an object for the first console as well.
     */
    if (vmdef->nserials == 0 && vmdef->nconsoles == 0 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        if (!vmdef->consoles)
            vmdef->consoles = g_new0(virDomainChrDef *, 1);

        /* We'll be dealing with serials[0] directly, so NULL is fine here. */
        if (!(vmdef->consoles[0] = virDomainChrDefNew(NULL))) {
            VIR_FREE(vmdef->consoles);
            return -1;
        }
        vmdef->nconsoles++;
    }
    return 0;
}

static void
qemuDomainChrInsertPreAlloced(virDomainDef *vmdef,
                              virDomainChrDef *chr)
{
    virDomainChrInsertPreAlloced(vmdef, chr);
    if (vmdef->nserials == 1 && vmdef->nconsoles == 1 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {

        /* Create an console alias for the serial port */
        vmdef->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        vmdef->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    }
}

static void
qemuDomainChrInsertPreAllocCleanup(virDomainDef *vmdef,
                                   virDomainChrDef *chr)
{
    /* Remove the stub console added by qemuDomainChrPreInsert */
    if (vmdef->nserials == 0 && vmdef->nconsoles == 1 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        virDomainChrDefFree(vmdef->consoles[0]);
        VIR_FREE(vmdef->consoles);
        vmdef->nconsoles = 0;
    }
}

int
qemuDomainChrInsert(virDomainDef *vmdef,
                    virDomainChrDef *chr)
{
    if (qemuDomainChrPreInsert(vmdef, chr) < 0) {
        qemuDomainChrInsertPreAllocCleanup(vmdef, chr);
        return -1;
    }
    qemuDomainChrInsertPreAlloced(vmdef, chr);
    return 0;
}

virDomainChrDef *
qemuDomainChrRemove(virDomainDef *vmdef,
                    virDomainChrDef *chr)
{
    virDomainChrDef *ret;
    bool removeCompat;

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("detaching serial console is not supported"));
        return NULL;
    }

    /* Due to some crazy backcompat stuff, the first serial device is an alias
     * to the first console too. If this is the case, the definition must be
     * duplicated as first console device. */
    removeCompat = vmdef->nserials && vmdef->nconsoles &&
        vmdef->consoles[0]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        vmdef->consoles[0]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL &&
        virDomainChrEquals(vmdef->serials[0], chr);

    if (!(ret = virDomainChrRemove(vmdef, chr))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("device not present in domain configuration"));
            return NULL;
    }

    if (removeCompat) {
        virDomainChrDefFree(vmdef->consoles[0]);
        VIR_DELETE_ELEMENT(vmdef->consoles, 0, vmdef->nconsoles);
    }

    return ret;
}



static int
qemuDomainAttachChrDeviceAssignAddr(virDomainObj *vm,
                                    virDomainChrDef *chr,
                                    bool *need_release)
{
    virDomainDef *def = vm->def;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_CHR, { .chr = chr } };

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO) {
        if (virDomainVirtioSerialAddrAutoAssign(def, &chr->info, true) < 0)
            return -1;
        return 0;

    } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
               chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI) {
        if (qemuDomainEnsurePCIAddress(vm, &dev) < 0)
            return -1;

        *need_release = true;
        return 0;
    } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
               chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB) {
        if (virDomainUSBAddressEnsure(priv->usbaddrs, &chr->info) < 0)
            return -1;

        *need_release = true;
        return 0;

    } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
               chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {
        if (virDomainVirtioSerialAddrAutoAssign(def, &chr->info, false) < 0)
            return -1;
        return 0;
    }

    if (chr->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL ||
        chr->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported address type for character device"));
        return -1;
    }

    return 0;
}


static int
qemuDomainAttachChrDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainDeviceDef *dev)
{
    virDomainChrDef *chr = dev->data.chr;
    qemuDomainChrSourcePrivate *charpriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chr->source);
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    virDomainDef *vmdef = vm->def;
    g_autoptr(virJSONValue) devprops = NULL;
    g_autoptr(virJSONValue) netdevprops = NULL;
    g_autofree char *charAlias = NULL;
    bool chardevAttached = false;
    bool teardowncgroup = false;
    bool teardowndevice = false;
    bool teardownlabel = false;
    g_autofree char *tlsAlias = NULL;
    const char *secAlias = NULL;
    bool need_release = false;
    bool guestfwd = false;

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL) {
        guestfwd = chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD;

        if (qemuDomainPrepareChannel(chr, priv->channelTargetDir) < 0)
            goto cleanup;
    }

    if (qemuAssignDeviceChrAlias(vmdef, chr, -1) < 0)
        goto cleanup;

    if (qemuDomainAttachChrDeviceAssignAddr(vm, chr, &need_release) < 0)
        goto cleanup;

    if (qemuProcessPrepareHostBackendChardevHotplug(vm, dev) < 0)
        goto cleanup;

    if (qemuDomainNamespaceSetupChardev(vm, chr, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSecuritySetChardevLabel(driver, vm, chr) < 0)
        goto cleanup;
    teardownlabel = true;

    if (qemuSetupChardevCgroup(vm, chr) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (guestfwd) {
        if (!(netdevprops = qemuBuildChannelGuestfwdNetdevProps(chr)))
            goto cleanup;
    } else {
        if (!(devprops = qemuBuildChrDeviceProps(vmdef, chr, priv->qemuCaps)))
            goto cleanup;
    }

    if (!(charAlias = qemuAliasChardevFromDevAlias(chr->info.alias)))
        goto cleanup;

    if (qemuDomainChrPreInsert(vmdef, chr) < 0)
        goto cleanup;

    if (qemuDomainAddChardevTLSObjects(driver, vm, chr->source,
                                       chr->info.alias, charAlias,
                                       &tlsAlias, &secAlias) < 0)
        goto audit;

    qemuDomainObjEnterMonitor(vm);

    if (qemuFDPassTransferMonitor(charpriv->sourcefd, priv->mon) < 0 ||
        qemuFDPassTransferMonitor(charpriv->logfd, priv->mon) < 0 ||
        qemuFDPassDirectTransferMonitor(charpriv->directfd, priv->mon) < 0)
        goto exit_monitor;

    if (qemuHotplugChardevAttach(priv->mon, charAlias, chr->source) < 0)
        goto exit_monitor;
    chardevAttached = true;

    if (netdevprops) {
        if (qemuMonitorAddNetdev(priv->mon, &netdevprops) < 0)
            goto exit_monitor;
    }

    if (devprops) {
        if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0)
            goto exit_monitor;
    }

    qemuDomainObjExitMonitor(vm);

    qemuDomainChrInsertPreAlloced(vmdef, chr);
    ret = 0;
 audit:
    virDomainAuditChardev(vm, NULL, chr, "attach", ret == 0);
 cleanup:
    if (ret < 0) {
        if (virDomainObjIsActive(vm))
            qemuDomainChrInsertPreAllocCleanup(vmdef, chr);
        if (need_release)
            qemuDomainReleaseDeviceAddress(vm, &chr->info);
        if (teardowncgroup && qemuTeardownChardevCgroup(vm, chr) < 0)
            VIR_WARN("Unable to remove chr device cgroup ACL on hotplug fail");
        if (teardownlabel && qemuSecurityRestoreChardevLabel(driver, vm, chr) < 0)
            VIR_WARN("Unable to restore security label on char device");
        if (teardowndevice && qemuDomainNamespaceTeardownChardev(vm, chr) < 0)
            VIR_WARN("Unable to remove chr device from /dev");
    }

    qemuDomainChrSourcePrivateClearFDPass(charpriv);

    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    /* detach associated chardev on error */
    if (chardevAttached)
        qemuMonitorDetachCharDev(priv->mon, charAlias);
    qemuFDPassTransferMonitorRollback(charpriv->sourcefd, priv->mon);
    qemuFDPassTransferMonitorRollback(charpriv->logfd, priv->mon);
    qemuFDPassDirectTransferMonitorRollback(charpriv->directfd, priv->mon);
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&orig_err);

    qemuDomainDelTLSObjects(vm, VIR_ASYNC_JOB_NONE, secAlias, tlsAlias);
    goto audit;
}


static int
qemuDomainAttachRNGDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainRNGDef *rng)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_RNG, { .rng = rng } };
    virErrorPtr orig_err;
    g_autoptr(virJSONValue) devprops = NULL;
    g_autofree char *charAlias = NULL;
    g_autofree char *objAlias = NULL;
    g_autofree char *tlsAlias = NULL;
    const char *secAlias = NULL;
    bool releaseaddr = false;
    bool teardowncgroup = false;
    bool teardowndevice = false;
    bool chardevAdded = false;
    g_autoptr(virJSONValue) props = NULL;
    int ret = -1;

    qemuAssignDeviceRNGAlias(vm->def, rng);

    /* preallocate space for the device definition */
    VIR_REALLOC_N(vm->def->rngs, vm->def->nrngs + 1);

    if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
        return -1;

    if (qemuDomainNamespaceSetupRNG(vm, rng, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupRNGCgroup(vm, rng) < 0)
        goto cleanup;
    teardowncgroup = true;

    /* build required metadata */
    if (!(devprops = qemuBuildRNGDevProps(vm->def, rng, priv->qemuCaps)))
        goto cleanup;

    if (qemuBuildRNGBackendProps(rng, &props) < 0)
        goto cleanup;

    if (!(charAlias = qemuAliasChardevFromDevAlias(rng->info.alias)))
        goto cleanup;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD) {
        if (qemuDomainAddChardevTLSObjects(driver, vm,
                                           rng->source.chardev,
                                           rng->info.alias, charAlias,
                                           &tlsAlias, &secAlias) < 0)
            goto audit;
    }

    qemuDomainObjEnterMonitor(vm);

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD &&
        qemuHotplugChardevAttach(priv->mon, charAlias, rng->source.chardev) < 0)
        goto exit_monitor;
    chardevAdded = true;

    if (qemuMonitorAddObject(priv->mon, &props, &objAlias) < 0)
        goto exit_monitor;

    if (qemuDomainAttachExtensionDevice(priv->mon, &rng->info) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0) {
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &rng->info));
        goto exit_monitor;
    }

    qemuDomainObjExitMonitor(vm);

    VIR_APPEND_ELEMENT_INPLACE(vm->def->rngs, vm->def->nrngs, rng);

    ret = 0;

 audit:
    virDomainAuditRNG(vm, NULL, rng, "attach", ret == 0);
 cleanup:
    if (ret < 0) {
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &rng->info);
        if (teardowncgroup && qemuTeardownRNGCgroup(vm, rng) < 0)
            VIR_WARN("Unable to remove RNG device cgroup ACL on hotplug fail");
        if (teardowndevice && qemuDomainNamespaceTeardownRNG(vm, rng) < 0)
            VIR_WARN("Unable to remove chr device from /dev");
    }

    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    if (objAlias)
        ignore_value(qemuMonitorDelObject(priv->mon, objAlias, false));
    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD && chardevAdded)
        ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&orig_err);

    qemuDomainDelTLSObjects(vm, VIR_ASYNC_JOB_NONE, secAlias, tlsAlias);
    goto audit;
}


/**
 * qemuDomainAttachMemory:
 * @driver: qemu driver data
 * @vm: VM object
 * @mem: Definition of the memory device to be attached. @mem is always consumed
 *
 * Attaches memory device described by @mem to domain @vm.
 *
 * Returns 0 on success -1 on error.
 */
static int
qemuDomainAttachMemory(virQEMUDriver *driver,
                       virDomainObj *vm,
                       virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    unsigned long long oldmem = virDomainDefGetMemoryTotal(vm->def);
    unsigned long long newmem = oldmem + mem->size;
    g_autoptr(virJSONValue) devprops = NULL;
    g_autofree char *objalias = NULL;
    bool objAdded = false;
    bool releaseaddr = false;
    bool teardownlabel = false;
    bool teardowncgroup = false;
    bool teardowndevice = false;
    bool restoreemulatorcgroup = false;
    g_autoptr(virJSONValue) props = NULL;
    virObjectEvent *event;
    int id;
    int ret = -1;

    if (qemuDomainMemoryDeviceAlignSize(vm->def, mem) < 0)
        goto cleanup;

    if (qemuDomainDefValidateMemoryHotplug(vm->def, mem) < 0)
        goto cleanup;

    if (qemuDomainAssignMemoryDeviceSlot(vm, mem) < 0)
        goto cleanup;
    releaseaddr = true;

    if (qemuAssignDeviceMemoryAlias(vm->def, mem) < 0)
        goto cleanup;

    objalias = g_strdup_printf("mem%s", mem->info.alias);

    if (!(devprops = qemuBuildMemoryDeviceProps(cfg, priv, vm->def, mem)))
        goto cleanup;

    if (qemuBuildMemoryBackendProps(&props, objalias, cfg,
                                    priv, vm->def, mem, true, false, NULL) < 0)
        goto cleanup;

    if (qemuProcessBuildDestroyMemoryPaths(driver, vm, mem, true) < 0)
        goto cleanup;

    if (qemuDomainNamespaceSetupMemory(vm, mem, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupMemoryDevicesCgroup(vm, mem) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetMemoryLabel(driver, vm, mem) < 0)
        goto cleanup;
    teardownlabel = true;

    if (virDomainMemoryInsert(vm->def, mem) < 0)
        goto cleanup;

    if (qemuDomainAdjustMaxMemLock(vm) < 0)
        goto removedef;

    if (qemuProcessSetupEmulator(vm) < 0)
        goto removedef;
    restoreemulatorcgroup = true;

    qemuDomainObjEnterMonitor(vm);
    if (qemuMonitorAddObject(priv->mon, &props, NULL) < 0)
        goto exit_monitor;
    objAdded = true;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0)
        goto exit_monitor;

    qemuDomainObjExitMonitor(vm);

    event = virDomainEventDeviceAddedNewFromObj(vm, objalias);
    virObjectEventStateQueue(driver->domainEventState, event);

    /* fix the balloon size */
    ignore_value(qemuProcessRefreshBalloonState(vm, VIR_ASYNC_JOB_NONE));

    /* mem is consumed by vm->def */
    mem = NULL;

    /* this step is best effort, removing the device would be so much trouble */
    ignore_value(qemuDomainUpdateMemoryDeviceInfo(vm, VIR_ASYNC_JOB_NONE));

    ret = 0;

 audit:
    virDomainAuditMemory(vm, oldmem, newmem, "update", ret == 0);
 cleanup:
    if (mem && ret < 0) {
        if (teardowncgroup && qemuTeardownMemoryDevicesCgroup(vm, mem) < 0)
            VIR_WARN("Unable to remove memory device cgroup ACL on hotplug fail");
        if (teardownlabel && qemuSecurityRestoreMemoryLabel(driver, vm, mem) < 0)
            VIR_WARN("Unable to restore security label on memdev");
        if (teardowndevice &&
            qemuDomainNamespaceTeardownMemory(vm, mem) <  0)
            VIR_WARN("Unable to remove memory device from /dev");
        if (releaseaddr)
            qemuDomainReleaseMemoryDeviceSlot(vm, mem);
        if (restoreemulatorcgroup)
            qemuProcessSetupEmulator(vm);
    }

    virDomainMemoryDefFree(mem);
    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    if (objAdded)
        ignore_value(qemuMonitorDelObject(priv->mon, objalias, false));
    qemuDomainObjExitMonitor(vm);

    if (objAdded && mem)
        ignore_value(qemuProcessDestroyMemoryBackingPath(driver, vm, mem));

    virErrorRestore(&orig_err);
    if (!mem)
        goto audit;

 removedef:
    if ((id = virDomainMemoryFindByDef(vm->def, mem)) >= 0)
        mem = virDomainMemoryRemove(vm->def, id);
    else
        mem = NULL;

    /* reset the mlock limit */
    virErrorPreserveLast(&orig_err);
    ignore_value(qemuDomainAdjustMaxMemLock(vm));
    virErrorRestore(&orig_err);

    goto audit;
}


static int
qemuDomainAttachHostUSBDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainHostdevDef *hostdev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) devprops = NULL;
    bool added = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    bool teardowndevice = false;
    int ret = -1;

    if (virDomainUSBAddressEnsure(priv->usbaddrs, hostdev->info) < 0)
        return -1;

    if (qemuHostdevPrepareUSBDevices(driver, vm->def->name, &hostdev, 1, 0) < 0)
        goto cleanup;

    added = true;

    if (qemuDomainNamespaceSetupHostdev(vm, hostdev, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetHostdevLabel(driver, vm, hostdev) < 0)
        goto cleanup;
    teardownlabel = true;

    qemuAssignDeviceHostdevAlias(vm->def, &hostdev->info->alias, -1);

    if (!(devprops = qemuBuildUSBHostdevDevProps(vm->def, hostdev, priv->qemuCaps)))
        goto cleanup;

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1);

    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorAddDeviceProps(priv->mon, &devprops);
    qemuDomainObjExitMonitor(vm);
    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto cleanup;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    ret = 0;
 cleanup:
    if (ret < 0) {
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
        if (teardownlabel &&
            qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
        if (teardowndevice &&
            qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device from /dev");
        if (added)
            qemuHostdevReAttachUSBDevices(driver, vm->def->name, &hostdev, 1);
        virDomainUSBAddressRelease(priv->usbaddrs, hostdev->info);
    }
    return ret;
}


static int
qemuDomainAttachHostSCSIDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    size_t i;
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virErrorPtr orig_err;
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;
    const char *backendalias = NULL;
    g_autoptr(virJSONValue) devprops = NULL;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    bool teardowndevice = false;

    /* Let's make sure the disk has a controller defined and loaded before
     * trying to add it. The controller used by the disk must exist before a
     * qemu command line string is generated.
     *
     * Ensure that the given controller and all controllers with a smaller index
     * exist; there must not be any missing index in between.
     */
    for (i = 0; i <= hostdev->info->addr.drive.controller; i++) {
        if (!qemuDomainFindOrCreateSCSIDiskController(vm, i))
            return -1;
    }

    if (qemuHostdevPrepareSCSIDevices(driver, vm->def->name, &hostdev, 1) < 0)
        return -1;

    if (qemuDomainNamespaceSetupHostdev(vm, hostdev, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetHostdevLabel(driver, vm, hostdev) < 0)
        goto cleanup;
    teardownlabel = true;

    qemuAssignDeviceHostdevAlias(vm->def, &hostdev->info->alias, -1);

    if (!(data = qemuBuildHostdevSCSIAttachPrepare(hostdev, &backendalias,
                                                   priv->qemuCaps)))
        goto cleanup;

    if (!(devprops = qemuBuildSCSIHostdevDevProps(vm->def, hostdev, backendalias)))
        goto cleanup;

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    qemuDomainObjEnterMonitor(vm);

    if (qemuBlockStorageSourceAttachApply(priv->mon, data) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0)
        goto exit_monitor;

    qemuDomainObjExitMonitor(vm);

    virDomainAuditHostdev(vm, hostdev, "attach", true);

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    ret = 0;

 cleanup:
    if (ret < 0) {
        qemuHostdevReAttachSCSIDevices(driver, vm->def->name, &hostdev, 1);
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
        if (teardownlabel &&
            qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
        if (teardowndevice &&
            qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device from /dev");
    }
    qemuDomainSecretHostdevDestroy(hostdev);
    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    qemuBlockStorageSourceAttachRollback(priv->mon, data);
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&orig_err);

    virDomainAuditHostdev(vm, hostdev, "attach", false);

    goto cleanup;
}

static int
qemuDomainAttachSCSIVHostDevice(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainHostdevDef *hostdev)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_HOSTDEV,
                               { .hostdev = hostdev } };
    virDomainCCWAddressSet *ccwaddrs = NULL;
    g_autofree char *vhostfdName = NULL;
    int vhostfd = -1;
    g_autoptr(virJSONValue) devprops = NULL;
    bool removeextension = false;
    bool removehandle = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    bool teardowndevice = false;
    bool releaseaddr = false;

    if (qemuHostdevPrepareSCSIVHostDevices(driver, vm->def->name, &hostdev, 1) < 0)
        return -1;

    if (qemuDomainNamespaceSetupHostdev(vm, hostdev, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetHostdevLabel(driver, vm, hostdev) < 0)
        goto cleanup;
    teardownlabel = true;

    if (virSCSIVHostOpenVhostSCSI(&vhostfd) < 0)
        goto cleanup;

    vhostfdName = g_strdup_printf("vhostfd-%d", vhostfd);

    if (hostdev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainIsS390CCW(vm->def))
            hostdev->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
    }

    if (hostdev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        hostdev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        if (qemuDomainEnsurePCIAddress(vm, &dev) < 0)
            goto cleanup;
    } else if (hostdev->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        if (!(ccwaddrs = virDomainCCWAddressSetCreateFromDomain(vm->def)))
            goto cleanup;
        if (virDomainCCWAddressAssign(hostdev->info, ccwaddrs,
                                      !hostdev->info->addr.ccw.assigned) < 0)
            goto cleanup;
    }
    releaseaddr = true;

    qemuAssignDeviceHostdevAlias(vm->def, &hostdev->info->alias, -1);

    if (!(devprops = qemuBuildSCSIVHostHostdevDevProps(vm->def,
                                                       hostdev,
                                                       priv->qemuCaps,
                                                       vhostfdName)))
        goto cleanup;

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    qemuDomainObjEnterMonitor(vm);

    if ((ret = qemuDomainAttachExtensionDevice(priv->mon, hostdev->info)) < 0)
        goto exit_monitor;

    removeextension = true;

    if ((ret = qemuMonitorSendFileHandle(priv->mon, vhostfdName, vhostfd)))
        goto exit_monitor;

    removehandle = true;

    if ((ret = qemuMonitorAddDeviceProps(priv->mon, &devprops)) < 0)
        goto exit_monitor;

    removeextension = false;
    removehandle = false;

 exit_monitor:
    if (removehandle)
        ignore_value(qemuMonitorCloseFileHandle(priv->mon, vhostfdName));
    if (removeextension)
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, hostdev->info));
    qemuDomainObjExitMonitor(vm);
    if (ret < 0)
        goto audit;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;
    ret = 0;

 audit:
    virDomainAuditHostdev(vm, hostdev, "attach", (ret == 0));

 cleanup:
    if (ret < 0) {
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
        if (teardownlabel &&
            qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
        if (teardowndevice &&
            qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device from /dev");
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, hostdev->info);
    }

    virDomainCCWAddressSetFree(ccwaddrs);

    VIR_FORCE_CLOSE(vhostfd);
    return ret;
}


static int
qemuDomainAttachMediatedDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    int ret = -1;
    g_autoptr(virJSONValue) devprops = NULL;
    bool added = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    bool teardowndevice = false;
    bool teardownmemlock = false;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_HOSTDEV,
                                { .hostdev = hostdev } };

    switch (hostdev->source.subsys.u.mdev.model) {
    case VIR_MDEV_MODEL_TYPE_VFIO_PCI:
        if (qemuDomainEnsurePCIAddress(vm, &dev) < 0)
            return -1;
        break;
    case VIR_MDEV_MODEL_TYPE_VFIO_CCW: {
        bool releaseaddr = false;

        if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
            return -1;
    }   break;
    case VIR_MDEV_MODEL_TYPE_VFIO_AP:
    case VIR_MDEV_MODEL_TYPE_LAST:
        break;
    }

    if (qemuHostdevPrepareMediatedDevices(driver,
                                          vm->def->name,
                                          &hostdev,
                                          1) < 0)
        goto cleanup;
    added = true;

    if (qemuDomainNamespaceSetupHostdev(vm, hostdev, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetHostdevLabel(driver, vm, hostdev) < 0)
        goto cleanup;
    teardownlabel = true;

    qemuAssignDeviceHostdevAlias(vm->def, &hostdev->info->alias, -1);

    if (!(devprops = qemuBuildHostdevMediatedDevProps(vm->def, hostdev)))
        goto cleanup;

    VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1);

    if (qemuDomainAdjustMaxMemLockHostdev(vm, hostdev) < 0)
        goto cleanup;
    teardownmemlock = true;

    qemuDomainObjEnterMonitor(vm);
    ret = qemuMonitorAddDeviceProps(priv->mon, &devprops);
    qemuDomainObjExitMonitor(vm);

    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto cleanup;

    VIR_APPEND_ELEMENT_INPLACE(vm->def->hostdevs, vm->def->nhostdevs, hostdev);
    ret = 0;
 cleanup:
    if (ret < 0) {
        if (teardownmemlock && qemuDomainAdjustMaxMemLock(vm) < 0)
            VIR_WARN("Unable to reset maximum locked memory on hotplug fail");
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
        if (teardownlabel &&
            qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
        if (teardowndevice &&
            qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device from /dev");
        if (added)
            qemuHostdevReAttachMediatedDevices(driver,
                                               vm->def->name,
                                               &hostdev,
                                               1);
        qemuDomainReleaseDeviceAddress(vm, hostdev->info);
    }
    return ret;
}


static int
qemuDomainAttachHostDevice(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainHostdevDef *hostdev)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hotplug is not supported for hostdev mode '%1$s'"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    if (qemuDomainPrepareHostdev(hostdev, vm->privateData) < 0)
        return -1;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (qemuDomainAttachHostPCIDevice(driver, vm,
                                          hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (qemuDomainAttachHostUSBDevice(driver, vm,
                                          hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (qemuDomainAttachHostSCSIDevice(driver, vm,
                                           hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        if (qemuDomainAttachSCSIVHostDevice(driver, vm, hostdev) < 0)
            return -1;
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        if (qemuDomainAttachMediatedDevice(driver, vm, hostdev) < 0)
            return -1;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hotplug is not supported for hostdev subsys type '%1$s'"),
                       virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    return 0;
}


static int
qemuDomainAttachShmemDevice(virDomainObj *vm,
                            virDomainShmemDef *shmem)
{
    int ret = -1;
    g_autoptr(virJSONValue) devProps = NULL;
    g_autofree char *charAlias = NULL;
    g_autofree char *memAlias = NULL;
    bool release_backing = false;
    bool release_address = true;
    virErrorPtr orig_err = NULL;
    g_autoptr(virJSONValue) props = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_SHMEM, { .shmem = shmem } };

    /* validation ensures that the legacy 'ivshmem' device is rejected */

    qemuAssignDeviceShmemAlias(vm->def, shmem, -1);

    qemuDomainPrepareShmemChardev(shmem);

    VIR_REALLOC_N(vm->def->shmems, vm->def->nshmems + 1);

    if ((shmem->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
         shmem->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        (qemuDomainEnsurePCIAddress(vm, &dev) < 0))
        return -1;

    if (!(devProps = qemuBuildShmemDevProps(vm->def, shmem)))
        goto cleanup;

    if (shmem->server.enabled) {
        charAlias = g_strdup_printf("char%s", shmem->info.alias);
    } else {
        if (!(props = qemuBuildShmemBackendMemProps(shmem)))
            goto cleanup;

    }

    qemuDomainObjEnterMonitor(vm);

    if (shmem->server.enabled) {
        if (qemuHotplugChardevAttach(priv->mon, charAlias, shmem->server.chr) < 0)
            goto exit_monitor;
    } else {
        if (qemuMonitorAddObject(priv->mon, &props, &memAlias) < 0)
            goto exit_monitor;
    }

    release_backing = true;

    if (qemuDomainAttachExtensionDevice(priv->mon, &shmem->info) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDeviceProps(priv->mon, &devProps) < 0) {
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &shmem->info));
        goto exit_monitor;
    }

    qemuDomainObjExitMonitor(vm);

    /* Doing a copy here just so the pointer doesn't get nullified
     * because we need it in the audit function */
    VIR_APPEND_ELEMENT_COPY_INPLACE(vm->def->shmems, vm->def->nshmems, shmem);

    ret = 0;
    release_address = false;

 audit:
    virDomainAuditShmem(vm, shmem, "attach", ret == 0);

 cleanup:
    if (release_address)
        qemuDomainReleaseDeviceAddress(vm, &shmem->info);

    return ret;

 exit_monitor:
    virErrorPreserveLast(&orig_err);
    if (release_backing) {
        if (shmem->server.enabled)
            ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));
        else
            ignore_value(qemuMonitorDelObject(priv->mon, memAlias, false));
    }

    qemuDomainObjExitMonitor(vm);

    virErrorRestore(&orig_err);

    goto audit;
}


static int
qemuDomainAttachWatchdog(virDomainObj *vm,
                         virDomainWatchdogDef *watchdog)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_WATCHDOG, { .watchdog = watchdog } };
    g_autoptr(virJSONValue) props = NULL;
    bool releaseAddress = false;
    int rv = 0;

    qemuAssignDeviceWatchdogAlias(vm->def, watchdog, -1);

    if (watchdog->model != VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("hotplug of watchdog model '%1$s' is not supported"),
                       virDomainWatchdogModelTypeToString(watchdog->model));
        goto cleanup;
    }

    if (qemuDomainEnsurePCIAddress(vm, &dev) < 0)
        goto cleanup;
    releaseAddress = true;

    if (!(props = qemuBuildWatchdogDevProps(vm->def, watchdog)))
        goto cleanup;

    qemuDomainObjEnterMonitor(vm);

    if (vm->def->nwatchdogs) {
        /* Domain already has a watchdog and all must have the same action. */
        rv = 0;
    } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SET_ACTION)) {
        /* QEMU doesn't have a 'dump' action; we tell qemu to 'pause', then
           libvirt listens for the watchdog event, and we perform the dump
           ourselves. so convert 'dump' to 'pause' for the qemu cli */
        qemuMonitorActionWatchdog watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_KEEP;

        switch (watchdog->action) {
        case VIR_DOMAIN_WATCHDOG_ACTION_RESET:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_RESET;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_SHUTDOWN:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_SHUTDOWN;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_POWEROFF:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_POWEROFF;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_PAUSE:
        case VIR_DOMAIN_WATCHDOG_ACTION_DUMP:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_PAUSE;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_NONE:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_NONE;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_INJECTNMI:
            watchdogaction = QEMU_MONITOR_ACTION_WATCHDOG_INJECT_NMI;
            break;

        case VIR_DOMAIN_WATCHDOG_ACTION_LAST:
        default:
            break;
        };

        rv = qemuMonitorSetAction(priv->mon,
                                  QEMU_MONITOR_ACTION_SHUTDOWN_KEEP,
                                  QEMU_MONITOR_ACTION_REBOOT_KEEP,
                                  watchdogaction,
                                  QEMU_MONITOR_ACTION_PANIC_KEEP);
    } else {
        virDomainWatchdogAction actualAction = watchdog->action;

        if (actualAction == VIR_DOMAIN_WATCHDOG_ACTION_DUMP)
            actualAction = VIR_DOMAIN_WATCHDOG_ACTION_PAUSE;

        rv = qemuMonitorSetWatchdogAction(priv->mon,
                                          virDomainWatchdogActionTypeToString(actualAction));
    }

    if (rv >= 0)
        rv = qemuMonitorAddDeviceProps(priv->mon, &props);

    qemuDomainObjExitMonitor(vm);

    if (rv < 0)
        goto cleanup;

    releaseAddress = false;
    VIR_APPEND_ELEMENT_COPY(vm->def->watchdogs, vm->def->nwatchdogs, watchdog);
    ret = 0;

 cleanup:
    if (releaseAddress)
        qemuDomainReleaseDeviceAddress(vm, &watchdog->info);
    return ret;
}


static int
qemuDomainAttachInputDevice(virDomainObj *vm,
                            virDomainInputDef *input)
{
    int ret = -1;
    g_autoptr(virJSONValue) devprops = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_INPUT,
                               { .input = input } };
    virErrorPtr originalError = NULL;
    bool releaseaddr = false;
    bool teardowndevice = false;
    bool teardownlabel = false;
    bool teardowncgroup = false;

    qemuAssignDeviceInputAlias(vm->def, input, -1);

    switch ((virDomainInputBus) input->bus) {
    case VIR_DOMAIN_INPUT_BUS_USB:
        if (virDomainUSBAddressEnsure(priv->usbaddrs, &input->info) < 0)
            return -1;

        releaseaddr = true;

        if (!(devprops = qemuBuildInputUSBDevProps(vm->def, input)))
            goto cleanup;
        break;

    case VIR_DOMAIN_INPUT_BUS_VIRTIO:
        if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
            goto cleanup;

        if (!(devprops = qemuBuildInputVirtioDevProps(vm->def, input, priv->qemuCaps)))
            goto cleanup;
        break;

    case VIR_DOMAIN_INPUT_BUS_DEFAULT:
    case VIR_DOMAIN_INPUT_BUS_PS2:
    case VIR_DOMAIN_INPUT_BUS_XEN:
    case VIR_DOMAIN_INPUT_BUS_PARALLELS:
    case VIR_DOMAIN_INPUT_BUS_NONE:
    case VIR_DOMAIN_INPUT_BUS_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("input device on bus '%1$s' cannot be hot plugged."),
                       virDomainInputBusTypeToString(input->bus));
        return -1;
    }

    if (qemuDomainNamespaceSetupInput(vm, input, &teardowndevice) < 0)
        goto cleanup;

    if (qemuSetupInputCgroup(vm, input) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuSecuritySetInputLabel(vm, input) < 0)
        goto cleanup;
    teardownlabel = true;

    VIR_REALLOC_N(vm->def->inputs, vm->def->ninputs + 1);

    qemuDomainObjEnterMonitor(vm);

    if (qemuDomainAttachExtensionDevice(priv->mon, &input->info) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0) {
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &input->info));
        goto exit_monitor;
    }

    qemuDomainObjExitMonitor(vm);

    VIR_APPEND_ELEMENT_COPY_INPLACE(vm->def->inputs, vm->def->ninputs, input);

    ret = 0;

 audit:
    virDomainAuditInput(vm, input, "attach", ret == 0);

 cleanup:
    if (ret < 0) {
        virErrorPreserveLast(&originalError);
        if (teardownlabel)
            qemuSecurityRestoreInputLabel(vm, input);
        if (teardowncgroup)
            qemuTeardownInputCgroup(vm, input);
        if (teardowndevice)
            qemuDomainNamespaceTeardownInput(vm, input);
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &input->info);
        virErrorRestore(&originalError);
    }

    return ret;

 exit_monitor:
    qemuDomainObjExitMonitor(vm);
    goto audit;
}


static int
qemuDomainAttachVsockDevice(virDomainObj *vm,
                            virDomainVsockDef *vsock)
{
    qemuDomainVsockPrivate *vsockPriv = (qemuDomainVsockPrivate *)vsock->privateData;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_VSOCK,
                               { .vsock = vsock } };
    virErrorPtr originalError = NULL;
    const char *fdprefix = "vsockfd";
    bool releaseaddr = false;
    g_autofree char *fdname = NULL;
    g_autoptr(virJSONValue) devprops = NULL;
    bool removeextension = false;
    bool removehandle = false;
    int ret = -1;

    if (vm->def->vsock) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("the domain already has a vsock device"));
        return -1;
    }

    if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
        return -1;

    qemuAssignDeviceVsockAlias(vsock);

    if (qemuProcessOpenVhostVsock(vsock) < 0)
        goto cleanup;

    fdname = g_strdup_printf("%s%u", fdprefix, vsockPriv->vhostfd);

    if (!(devprops = qemuBuildVsockDevProps(vm->def, vsock, priv->qemuCaps, fdprefix)))
        goto cleanup;

    qemuDomainObjEnterMonitor(vm);

    if (qemuDomainAttachExtensionDevice(priv->mon, &vsock->info) < 0)
        goto exit_monitor;

    removeextension = true;

    if ((ret = qemuMonitorSendFileHandle(priv->mon, fdname, vsockPriv->vhostfd)) < 0)
        goto exit_monitor;

    removehandle = true;

    if ((ret = qemuMonitorAddDeviceProps(priv->mon, &devprops)) < 0)
        goto exit_monitor;

    qemuDomainObjExitMonitor(vm);

    vm->def->vsock = g_steal_pointer(&vsock);

    ret = 0;

 cleanup:
    if (ret < 0) {
        virErrorPreserveLast(&originalError);
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &vsock->info);
        virErrorRestore(&originalError);
    }

    return ret;

 exit_monitor:
    if (removehandle)
        ignore_value(qemuMonitorCloseFileHandle(priv->mon, fdname));
    if (removeextension)
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &vsock->info));
    qemuDomainObjExitMonitor(vm);
    goto cleanup;
}


static int
qemuDomainAttachFSDevice(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainFSDef *fs)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDeviceDef dev = { VIR_DOMAIN_DEVICE_FS,
                               { .fs = fs } };
    g_autoptr(virDomainChrSourceDef) chardev = NULL;
    g_autoptr(virJSONValue) devprops = NULL;
    virErrorPtr origErr = NULL;
    bool releaseaddr = false;
    bool chardevAdded = false;
    bool started = false;
    g_autofree char *charAlias = NULL;
    int ret = -1;

    if (fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("only virtiofs filesystems can be hotplugged"));
        return -1;
    }

    if (qemuDomainEnsureVirtioAddress(&releaseaddr, vm, &dev) < 0)
        return -1;

    qemuAssignDeviceFSAlias(vm->def, fs);

    chardev = virDomainChrSourceDefNew(priv->driver->xmlopt);
    chardev->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    chardev->data.nix.path = qemuDomainGetVHostUserFSSocketPath(priv, fs);

    charAlias = qemuDomainGetVhostUserChrAlias(fs->info.alias);

    if (!(devprops = qemuBuildVHostUserFsDevProps(fs, vm->def, charAlias, priv)))
        goto cleanup;

    if (!fs->sock) {
        if (qemuVirtioFSPrepareDomain(driver, fs) < 0)
            goto cleanup;

        if (qemuVirtioFSStart(driver, vm, fs) < 0)
            goto cleanup;
        started = true;

        if (qemuVirtioFSSetupCgroup(vm, fs, priv->cgroup) < 0)
            goto cleanup;
    }

    qemuDomainObjEnterMonitor(vm);

    if (qemuHotplugChardevAttach(priv->mon, charAlias, chardev) < 0)
        goto exit_monitor;
    chardevAdded = true;

    if (qemuDomainAttachExtensionDevice(priv->mon, &fs->info) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDeviceProps(priv->mon, &devprops) < 0) {
        ignore_value(qemuDomainDetachExtensionDevice(priv->mon, &fs->info));
        goto exit_monitor;
    }

    qemuDomainObjExitMonitor(vm);

    VIR_APPEND_ELEMENT_COPY(vm->def->fss, vm->def->nfss, fs);

    ret = 0;

 audit:
    virDomainAuditFS(vm, NULL, fs, "attach", ret == 0);
 cleanup:
    if (ret < 0) {
        virErrorPreserveLast(&origErr);
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &fs->info);
        if (started)
            qemuVirtioFSStop(driver, vm, fs);
        virErrorRestore(&origErr);
    }

    return ret;

 exit_monitor:
    virErrorPreserveLast(&origErr);
    if (chardevAdded)
        ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));
    qemuDomainObjExitMonitor(vm);
    virErrorRestore(&origErr);
    goto audit;
}


static int
qemuDomainAttachLease(virQEMUDriver *driver,
                      virDomainObj *vm,
                      virDomainLeaseDef *lease)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    virDomainLeaseInsertPreAlloc(vm->def);

    if (virDomainLockLeaseAttach(driver->lockManager, cfg->uri,
                                 vm, lease) < 0) {
        virDomainLeaseInsertPreAlloced(vm->def, NULL);
        return -1;
    }

    virDomainLeaseInsertPreAlloced(vm->def, lease);
    return 0;
}


int
qemuDomainAttachDeviceLive(virDomainObj *vm,
                           virDomainDeviceDef *dev,
                           virQEMUDriver *driver)
{
    int ret = -1;
    const char *alias = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    struct qemuDomainPrepareChardevSourceData chardevBackendData = { .cfg = cfg,
                                                                     .hotplug = true };

    if (qemuDomainDeviceBackendChardevForeachOne(dev,
                                                 qemuDomainPrepareChardevSourceOne,
                                                 &chardevBackendData) < 0)
        return -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, NULL);
        ret = qemuDomainAttachDeviceDiskLive(driver, vm, dev);
        if (!ret) {
            alias = dev->data.disk->info.alias;
            dev->data.disk = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainAttachControllerDevice(vm, dev->data.controller);
        if (!ret) {
            alias = dev->data.controller->info.alias;
            dev->data.controller = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
        ret = qemuDomainAttachLease(driver, vm,
                                    dev->data.lease);
        if (ret == 0)
            dev->data.lease = NULL;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        qemuDomainObjCheckNetTaint(driver, vm, dev->data.net, NULL);
        ret = qemuDomainAttachNetDevice(driver, vm, dev->data.net);
        if (!ret) {
            alias = dev->data.net->info.alias;
            dev->data.net = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        qemuDomainObjCheckHostdevTaint(driver, vm, dev->data.hostdev, NULL);
        ret = qemuDomainAttachHostDevice(driver, vm,
                                         dev->data.hostdev);
        if (!ret) {
            alias = dev->data.hostdev->info->alias;
            dev->data.hostdev = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        ret = qemuDomainAttachRedirdevDevice(driver, vm,
                                             dev->data.redirdev);
        if (!ret) {
            alias = dev->data.redirdev->info.alias;
            dev->data.redirdev = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(driver, vm, dev);
        if (!ret) {
            alias = dev->data.chr->info.alias;
            dev->data.chr = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        ret = qemuDomainAttachRNGDevice(driver, vm,
                                        dev->data.rng);
        if (!ret) {
            alias = dev->data.rng->info.alias;
            dev->data.rng = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        /* note that qemuDomainAttachMemory always consumes dev->data.memory
         * and dispatches DeviceAdded event on success */
        ret = qemuDomainAttachMemory(driver, vm,
                                     dev->data.memory);
        dev->data.memory = NULL;
        break;

    case VIR_DOMAIN_DEVICE_SHMEM:
        ret = qemuDomainAttachShmemDevice(vm, dev->data.shmem);
        if (!ret) {
            alias = dev->data.shmem->info.alias;
            dev->data.shmem = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_WATCHDOG:
        ret = qemuDomainAttachWatchdog(vm, dev->data.watchdog);
        if (!ret) {
            alias = dev->data.watchdog->info.alias;
            dev->data.watchdog = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_INPUT:
        ret = qemuDomainAttachInputDevice(vm, dev->data.input);
        if (ret == 0) {
            alias = dev->data.input->info.alias;
            dev->data.input = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_VSOCK:
        ret = qemuDomainAttachVsockDevice(vm, dev->data.vsock);
        if (ret == 0) {
            alias = dev->data.vsock->info.alias;
            dev->data.vsock = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_FS:
        ret = qemuDomainAttachFSDevice(driver, vm, dev->data.fs);
        if (ret == 0) {
            alias = dev->data.fs->info.alias;
            dev->data.fs = NULL;
        }
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live attach of device '%1$s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (alias) {
        /* queue the event before the alias has a chance to get freed
         * if the domain disappears while qemuDomainUpdateDeviceList
         * is in monitor */
        virObjectEvent *event;
        event = virDomainEventDeviceAddedNewFromObj(vm, alias);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (ret == 0)
        ret = qemuDomainUpdateDeviceList(vm, VIR_ASYNC_JOB_NONE);

    return ret;
}


static int
qemuDomainChangeNetBridge(virDomainObj *vm,
                          virDomainNetDef *olddev,
                          virDomainNetDef *newdev)
{
    int ret = -1;
    const char *oldbridge = virDomainNetGetActualBridgeName(olddev);
    const char *newbridge = virDomainNetGetActualBridgeName(newdev);

    if (!oldbridge || !newbridge) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing bridge name"));
        return -1;
    }

    VIR_DEBUG("Change bridge for interface %s: %s -> %s",
              olddev->ifname, oldbridge, newbridge);

    if (virNetDevExists(newbridge) != 1) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("bridge %1$s doesn't exist"), newbridge);
        return -1;
    }

    ret = virNetDevBridgeRemovePort(oldbridge, olddev->ifname);
    virDomainAuditNet(vm, olddev, NULL, "detach", ret == 0);
    if (ret < 0) {
        /* warn but continue - possibly the old network
         * had been destroyed and reconstructed, leaving the
         * tap device orphaned.
         */
        VIR_WARN("Unable to detach device %s from bridge %s",
                 olddev->ifname, oldbridge);
    }

    ret = virNetDevBridgeAddPort(newbridge, olddev->ifname);
    if (ret == 0 &&
        virDomainNetGetActualPortOptionsIsolated(newdev) == VIR_TRISTATE_BOOL_YES) {

        ret = virNetDevBridgePortSetIsolated(newbridge, olddev->ifname, true);
        if (ret < 0) {
            virErrorPtr err;

            virErrorPreserveLast(&err);
            ignore_value(virNetDevBridgeRemovePort(newbridge, olddev->ifname));
            virErrorRestore(&err);
        }
    }
    virDomainAuditNet(vm, NULL, newdev, "attach", ret == 0);
    if (ret < 0) {
        virErrorPtr err;

        virErrorPreserveLast(&err);
        ret = virNetDevBridgeAddPort(oldbridge, olddev->ifname);
        if (ret == 0 &&
            virDomainNetGetActualPortOptionsIsolated(olddev) == VIR_TRISTATE_BOOL_YES) {
            ignore_value(virNetDevBridgePortSetIsolated(newbridge, olddev->ifname, true));
        }
        virDomainAuditNet(vm, NULL, olddev, "attach", ret == 0);
        virErrorRestore(&err);
        return -1;
    }
    /* caller will replace entire olddev with newdev in domain nets list */
    return 0;
}

static int
qemuDomainChangeNetFilter(virDomainObj *vm,
                          virDomainNetDef *olddev,
                          virDomainNetDef *newdev)
{
    /* make sure this type of device supports filters. */
    switch (virDomainNetGetActualType(newdev)) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("filters not supported on interfaces of type %1$s"),
                       virDomainNetTypeToString(virDomainNetGetActualType(newdev)));
        return -1;
    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainNetType,
                                virDomainNetGetActualType(newdev));
        return -1;
    }

    virDomainConfNWFilterTeardown(olddev);

    if (newdev->filter &&
        virDomainConfNWFilterInstantiate(vm->def->name,
                                         vm->def->uuid, newdev, false) < 0) {
        virErrorPtr errobj;

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to add new filter rules to '%1$s' - attempting to restore old rules"),
                       olddev->ifname);
        virErrorPreserveLast(&errobj);
        ignore_value(virDomainConfNWFilterInstantiate(vm->def->name,
                                                      vm->def->uuid, olddev, false));
        virErrorRestore(&errobj);
        return -1;
    }
    return 0;
}

static int
qemuDomainChangeNetLinkState(virDomainObj *vm,
                             virDomainNetDef *dev,
                             int linkstate)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!dev->info.alias) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("can't change link state: device alias not found"));
        return -1;
    }

    VIR_DEBUG("dev: %s, state: %d", dev->info.alias, linkstate);

    qemuDomainObjEnterMonitor(vm);

    ret = qemuMonitorSetLink(priv->mon, dev->info.alias, linkstate);
    if (ret < 0)
        goto cleanup;

    /* modify the device configuration */
    dev->linkstate = linkstate;

 cleanup:
    qemuDomainObjExitMonitor(vm);

    return ret;
}

static int
qemuDomainChangeNet(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virDomainDeviceDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainNetDef *newdev = dev->data.net;
    virDomainNetDef **devslot = NULL;
    virDomainNetDef *olddev;
    virDomainNetType oldType, newType;
    bool needReconnect = false;
    bool needBridgeChange = false;
    bool needFilterChange = false;
    bool needLinkStateChange = false;
    bool needReplaceDevDef = false;
    bool needBandwidthSet = false;
    bool needCoalesceChange = false;
    bool needVlanUpdate = false;
    bool needIsolatedPortChange = false;
    int ret = -1;
    int changeidx = -1;
    g_autoptr(virConnect) conn = NULL;
    virErrorPtr save_err = NULL;

    if ((changeidx = virDomainNetFindIdx(vm->def, newdev)) < 0)
        goto cleanup;
    devslot = &vm->def->nets[changeidx];
    olddev = *devslot;

    oldType = virDomainNetGetActualType(olddev);
    if (oldType == VIR_DOMAIN_NET_TYPE_HOSTDEV ||
        oldType == VIR_DOMAIN_NET_TYPE_VDPA) {
        /* no changes are possible to a type='hostdev' or type='vdpa' interface */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change config of '%1$s' network interface type"),
                       virDomainNetTypeToString(oldType));
        goto cleanup;
    }

    /* Check individual attributes for changes that can't be done to a
     * live netdev. These checks *mostly* go in order of the
     * declarations in virDomainNetDef in order to assure nothing is
     * omitted. (exceptiong where noted in comments - in particular,
     * some things require that a new "actual device" be allocated
     * from the network driver first, but we delay doing that until
     * after we've made as many other checks as possible)
     */

    /* type: this can change (with some restrictions), but the actual
     * type of the new device connection isn't known until after we
     * allocate the "actual" device.
     */

    if (virMacAddrCmp(&olddev->mac, &newdev->mac)) {
        char oldmac[VIR_MAC_STRING_BUFLEN], newmac[VIR_MAC_STRING_BUFLEN];

        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change network interface mac address from %1$s to %2$s"),
                       virMacAddrFormat(&olddev->mac, oldmac),
                       virMacAddrFormat(&newdev->mac, newmac));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(virDomainNetGetModelString(olddev),
                        virDomainNetGetModelString(newdev))) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify network device model from %1$s to %2$s"),
                       NULLSTR(virDomainNetGetModelString(olddev)),
                       NULLSTR(virDomainNetGetModelString(newdev)));
        goto cleanup;
    }

    if (olddev->model != newdev->model) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify network device model from %1$s to %2$s"),
                       virDomainNetModelTypeToString(olddev->model),
                       virDomainNetModelTypeToString(newdev->model));
        goto cleanup;
    }

    if (virDomainNetIsVirtioModel(olddev) &&
        (olddev->driver.virtio.name != newdev->driver.virtio.name ||
         olddev->driver.virtio.txmode != newdev->driver.virtio.txmode ||
         olddev->driver.virtio.ioeventfd != newdev->driver.virtio.ioeventfd ||
         olddev->driver.virtio.event_idx != newdev->driver.virtio.event_idx ||
         olddev->driver.virtio.queues != newdev->driver.virtio.queues ||
         olddev->driver.virtio.rx_queue_size != newdev->driver.virtio.rx_queue_size ||
         olddev->driver.virtio.tx_queue_size != newdev->driver.virtio.tx_queue_size ||
         olddev->driver.virtio.host.csum != newdev->driver.virtio.host.csum ||
         olddev->driver.virtio.host.gso != newdev->driver.virtio.host.gso ||
         olddev->driver.virtio.host.tso4 != newdev->driver.virtio.host.tso4 ||
         olddev->driver.virtio.host.tso6 != newdev->driver.virtio.host.tso6 ||
         olddev->driver.virtio.host.ecn != newdev->driver.virtio.host.ecn ||
         olddev->driver.virtio.host.ufo != newdev->driver.virtio.host.ufo ||
         olddev->driver.virtio.host.mrg_rxbuf != newdev->driver.virtio.host.mrg_rxbuf ||
         olddev->driver.virtio.guest.csum != newdev->driver.virtio.guest.csum ||
         olddev->driver.virtio.guest.tso4 != newdev->driver.virtio.guest.tso4 ||
         olddev->driver.virtio.guest.tso6 != newdev->driver.virtio.guest.tso6 ||
         olddev->driver.virtio.guest.ecn != newdev->driver.virtio.guest.ecn ||
         olddev->driver.virtio.guest.ufo != newdev->driver.virtio.guest.ufo ||
         olddev->driver.virtio.rss != newdev->driver.virtio.rss ||
         olddev->driver.virtio.rss_hash_report != newdev->driver.virtio.rss_hash_report)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify virtio network device driver attributes"));
        goto cleanup;
    }

    if (!!olddev->virtio != !!newdev->virtio ||
        (olddev->virtio && newdev->virtio &&
         (olddev->virtio->iommu != newdev->virtio->iommu ||
          olddev->virtio->ats != newdev->virtio->ats ||
          olddev->virtio->packed != newdev->virtio->packed ||
          olddev->virtio->page_per_vq != newdev->virtio->page_per_vq))) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify virtio network device driver options"));
           goto cleanup;
   }

    /* data: this union will be examined later, after allocating new actualdev */
    /* virtPortProfile: will be examined later, after allocating new actualdev */

    if (olddev->tune.sndbuf_specified != newdev->tune.sndbuf_specified ||
        olddev->tune.sndbuf != newdev->tune.sndbuf) {
        needReconnect = true;
    }

    if (STRNEQ_NULLABLE(olddev->script, newdev->script)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device script attribute"));
        goto cleanup;
    }

    /* ifname: check if it's set in newdev. If not, retain the autogenerated one */
    if (!newdev->ifname)
        newdev->ifname = g_strdup(olddev->ifname);
    if (STRNEQ_NULLABLE(olddev->ifname, newdev->ifname)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device tap name"));
        goto cleanup;
    }

    /* info: Nothing is allowed to change. First fill the missing newdev->info
     * from olddev and then check for changes.
     */
    /* if pci addr is missing or is invalid we overwrite it from olddev */
    if (newdev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        !virDomainDeviceAddressIsValid(&newdev->info,
                                       newdev->info.type)) {
        newdev->info.type = olddev->info.type;
        newdev->info.addr = olddev->info.addr;
    }
    if (olddev->info.type != newdev->info.type) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device address type"));
    }
    if (!virPCIDeviceAddressEqual(&olddev->info.addr.pci,
                                  &newdev->info.addr.pci)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device guest PCI address"));
        goto cleanup;
    }
    /* grab alias from olddev if not set in newdev */
    if (!newdev->info.alias)
        newdev->info.alias = g_strdup(olddev->info.alias);

    /* device alias is checked already in virDomainDefCompatibleDevice */

    if (newdev->info.rombar == VIR_TRISTATE_SWITCH_ABSENT)
        newdev->info.rombar = olddev->info.rombar;
    if (olddev->info.rombar != newdev->info.rombar) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device rom bar setting"));
        goto cleanup;
    }

    if (!newdev->info.romfile)
        newdev->info.romfile = g_strdup(olddev->info.romfile);
    if (STRNEQ_NULLABLE(olddev->info.romfile, newdev->info.romfile)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network rom file"));
        goto cleanup;
    }

    if (newdev->info.bootIndex == 0)
        newdev->info.bootIndex = olddev->info.bootIndex;
    if (olddev->info.bootIndex != newdev->info.bootIndex) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device boot index setting"));
        goto cleanup;
    }

    if (newdev->info.romenabled == VIR_TRISTATE_BOOL_ABSENT)
        newdev->info.romenabled = olddev->info.romenabled;
    if (olddev->info.romenabled != newdev->info.romenabled) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device rom enabled setting"));
        goto cleanup;
    }
    /* (end of device info checks) */

    if (STRNEQ_NULLABLE(olddev->filter, newdev->filter) ||
        !virNWFilterHashTableEqual(olddev->filterparams, newdev->filterparams)) {
        needFilterChange = true;
    }

    /* bandwidth can be modified, and will be checked later */
    /* vlan can be modified, and will be checked later */
    /* linkstate can be modified */

    if (olddev->mtu != newdev->mtu) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify MTU"));
        goto cleanup;
    }

    /* nothing in <backend> can be modified in an existing interface -
     * the entire device will need to be removed and re-added.
     */
    if (!virDomainNetBackendIsEqual(&olddev->backend, &newdev->backend)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device backend settings"));
        goto cleanup;
    }

    /* allocate new actual device to compare to old - we will need to
     * free it if we fail for any reason
     */
    if (newdev->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (!(conn = virGetConnectNetwork()))
            goto cleanup;
        if (virDomainNetAllocateActualDevice(conn, vm->def, newdev) < 0)
            goto cleanup;
    }

    /* final validation now that we have full info on the type */
    if (qemuDomainValidateActualNetDef(newdev, priv->qemuCaps) < 0)
        goto cleanup;

    newType = virDomainNetGetActualType(newdev);

    if (newType == VIR_DOMAIN_NET_TYPE_HOSTDEV ||
        newType == VIR_DOMAIN_NET_TYPE_VDPA) {
        /* can't turn it into a type='hostdev' or type='vdpa' interface */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change network interface type to '%1$s'"),
                       virDomainNetTypeToString(newType));
        goto cleanup;
    }

    if (olddev->type == newdev->type && oldType == newType) {

        /* if type hasn't changed, check the relevant fields for the type */
        switch (newdev->type) {
        case VIR_DOMAIN_NET_TYPE_USER:
            break;

        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            break;

        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
            if (STRNEQ_NULLABLE(olddev->data.socket.address,
                                newdev->data.socket.address) ||
                olddev->data.socket.port != newdev->data.socket.port) {
                needReconnect = true;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_NETWORK:
            if (STRNEQ(olddev->data.network.name, newdev->data.network.name)) {
                if (virDomainNetGetActualVirtPortProfile(newdev))
                    needReconnect = true;
                else
                    needBridgeChange = true;
            }
            /* other things handled in common code directly below this switch */
            break;

        case VIR_DOMAIN_NET_TYPE_BRIDGE:
            /* all handled in bridge name checked in common code below */
            break;

        case VIR_DOMAIN_NET_TYPE_INTERNAL:
            if (STRNEQ_NULLABLE(olddev->data.internal.name,
                                newdev->data.internal.name)) {
                needReconnect = true;
            }
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            /* all handled in common code directly below this switch */
            break;

        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("unable to change config on '%1$s' network type"),
                           virDomainNetTypeToString(newdev->type));
            goto cleanup;
        case VIR_DOMAIN_NET_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainNetType, newdev->type);
            goto cleanup;
        }
    } else {
        /* interface type has changed. There are a few special cases
         * where this can only require a minor (or even no) change,
         * but in most cases we need to do a full reconnection.
         *
         * As long as both the new and old types use a tap device
         * connected to a host bridge (ie VIR_DOMAIN_NET_TYPE_NETWORK
         * or VIR_DOMAIN_NET_TYPE_BRIDGE), we just need to connect to
         * the new bridge.
         */
        if ((oldType == VIR_DOMAIN_NET_TYPE_NETWORK ||
             oldType == VIR_DOMAIN_NET_TYPE_BRIDGE) &&
            (newType == VIR_DOMAIN_NET_TYPE_NETWORK ||
             newType == VIR_DOMAIN_NET_TYPE_BRIDGE)) {

            needBridgeChange = true;

        } else if (oldType == VIR_DOMAIN_NET_TYPE_DIRECT &&
                   newType == VIR_DOMAIN_NET_TYPE_DIRECT) {

            /* this is the case of switching from type='direct' to
             * type='network' for a network that itself uses direct
             * (macvtap) devices. If the physical device and mode are
             * the same, this doesn't require any actual setup
             * change. If the physical device or mode *does* change,
             * that will be caught in the common section below */

        } else {

            /* for all other combinations, we'll need a full reconnect */
            needReconnect = true;

        }
    }

    /* now several things that are in multiple (but not all)
     * different types, and can be safely compared even for those
     * cases where they don't apply to a particular type.
     */
    if (STRNEQ_NULLABLE(virDomainNetGetActualBridgeName(olddev),
                        virDomainNetGetActualBridgeName(newdev))) {
        if (virDomainNetGetActualVirtPortProfile(newdev))
            needReconnect = true;
        else
            needBridgeChange = true;
    }

    if (STRNEQ_NULLABLE(virDomainNetGetActualDirectDev(olddev),
                        virDomainNetGetActualDirectDev(newdev)) ||
        virDomainNetGetActualDirectMode(olddev) != virDomainNetGetActualDirectMode(newdev) ||
        !virNetDevVPortProfileEqual(virDomainNetGetActualVirtPortProfile(olddev),
                                    virDomainNetGetActualVirtPortProfile(newdev))) {
        needReconnect = true;
    }

    if (!virNetDevVlanEqual(virDomainNetGetActualVlan(olddev),
                             virDomainNetGetActualVlan(newdev))) {
        needVlanUpdate = true;
    }

    if (virDomainNetGetActualPortOptionsIsolated(olddev) !=
        virDomainNetGetActualPortOptionsIsolated(newdev)) {
        needIsolatedPortChange = true;
    }

    if (olddev->linkstate != newdev->linkstate)
        needLinkStateChange = true;

    if (!virNetDevBandwidthEqual(virDomainNetGetActualBandwidth(olddev),
                                 virDomainNetGetActualBandwidth(newdev)))
        needBandwidthSet = true;

    if (!!olddev->coalesce != !!newdev->coalesce ||
        (olddev->coalesce && newdev->coalesce &&
         memcmp(olddev->coalesce, newdev->coalesce,
                sizeof(*olddev->coalesce))))
        needCoalesceChange = true;

    /* FINALLY - actually perform the required actions */

    if (needReconnect) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unable to change config on '%1$s' network type"),
                       virDomainNetTypeToString(newdev->type));
        goto cleanup;
    }

    if (needBandwidthSet) {
        const virNetDevBandwidth *newb = virDomainNetGetActualBandwidth(newdev);

        if (newb) {
            if (virDomainNetDefIsOvsport(newdev)) {
                if (virNetDevOpenvswitchInterfaceSetQos(newdev->ifname, newb,
                                                        vm->def->uuid,
                                                        !virDomainNetTypeSharesHostView(newdev)) < 0)
                    goto cleanup;
            } else if (virNetDevBandwidthSet(newdev->ifname, newb, false,
                                             !virDomainNetTypeSharesHostView(newdev)) < 0) {
                goto cleanup;
            }
        } else {
            /*
             * virNetDevBandwidthSet() doesn't clear any existing
             * setting unless something new is being set.
             */
            virNetDevBandwidthClear(newdev->ifname);
        }

        /* If the old bandwidth was cleared out, restore qdisc. */
        if (virDomainNetTypeSharesHostView(newdev)) {
            if (!newb || !newb->out || newb->out->average == 0)
                qemuDomainInterfaceSetDefaultQDisc(driver, newdev);
        } else {
            if (!newb || !newb->in || newb->in->average == 0)
                qemuDomainInterfaceSetDefaultQDisc(driver, newdev);
        }
        needReplaceDevDef = true;
    }

    if (needBridgeChange) {
        if (qemuDomainChangeNetBridge(vm, olddev, newdev) < 0)
            goto cleanup;
        /* we successfully switched to the new bridge, and we've
         * determined that the rest of newdev is equivalent to olddev,
         * so move newdev into place */
        needReplaceDevDef = true;

        /* this is already updated as a part of reconnecting the bridge */
        needIsolatedPortChange = false;
    }

    if (needIsolatedPortChange) {
        const char *bridge = virDomainNetGetActualBridgeName(newdev);
        bool isolatedOn = (virDomainNetGetActualPortOptionsIsolated(newdev) ==
                           VIR_TRISTATE_BOOL_YES);

        if (virNetDevBridgePortSetIsolated(bridge, newdev->ifname, isolatedOn) < 0)
            goto cleanup;

        needReplaceDevDef = true;
    }

    if (needFilterChange) {
        if (qemuDomainChangeNetFilter(vm, olddev, newdev) < 0)
            goto cleanup;
        /* we successfully switched to the new filter, and we've
         * determined that the rest of newdev is equivalent to olddev,
         * so move newdev into place */
        needReplaceDevDef = true;
    }

    if (needCoalesceChange) {
        if (virNetDevSetCoalesce(newdev->ifname, newdev->coalesce, true) < 0)
            goto cleanup;
        needReplaceDevDef = true;
    }

    if (needLinkStateChange &&
        qemuDomainChangeNetLinkState(vm, olddev, newdev->linkstate) < 0) {
        goto cleanup;
    }

    if (needVlanUpdate) {
        if (virNetDevOpenvswitchUpdateVlan(newdev->ifname, &newdev->vlan) < 0)
            goto cleanup;
        needReplaceDevDef = true;
    }

    if (needReplaceDevDef) {
        /* the changes above warrant replacing olddev with newdev in
         * the domain's nets list.
         */

        /* this function doesn't work with HOSTDEV networks yet, thus
         * no need to change the pointer in the hostdev structure */
        if (olddev->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (conn || (conn = virGetConnectNetwork()))
                virDomainNetReleaseActualDevice(conn, vm->def, olddev);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(olddev->ifname));
        }
        virDomainNetDefFree(olddev);
        /* move newdev into the nets list, and NULL it out from the
         * virDomainDeviceDef that we were given so that the caller
         * won't delete it on return.
         */
        *devslot = newdev;
        newdev = dev->data.net = NULL;
        dev->type = VIR_DOMAIN_DEVICE_NONE;
    }

    ret = 0;
 cleanup:
    virErrorPreserveLast(&save_err);
    /* When we get here, we will be in one of these two states:
     *
     * 1) newdev has been moved into the domain's list of nets and
     *    newdev set to NULL, and dev->data.net will be NULL (and
     *    dev->type is NONE). olddev will have been completely
     *    released and freed. (aka success) In this case no extra
     *    cleanup is needed.
     *
     * 2) newdev has *not* been moved into the domain's list of nets,
     *    and dev->data.net == newdev (and dev->type == NET). In this *
     *    case, we need to at least release the "actual device" from *
     *    newdev (the caller will free dev->data.net a.k.a. newdev, and
     *    the original olddev is still in used)
     *
     * Note that case (2) isn't necessarily a failure. It may just be
     * that the changes were minor enough that we didn't need to
     * replace the entire device object.
     */
    if (newdev && newdev->type == VIR_DOMAIN_NET_TYPE_NETWORK && conn)
        virDomainNetReleaseActualDevice(conn, vm->def, newdev);
    virErrorRestore(&save_err);

    return ret;
}

static virDomainGraphicsDef *
qemuDomainFindGraphics(virDomainObj *vm,
                       virDomainGraphicsDef *dev)
{
    size_t i;

    for (i = 0; i < vm->def->ngraphics; i++) {
        if (vm->def->graphics[i]->type == dev->type)
            return vm->def->graphics[i];
    }

    return NULL;
}

int
qemuDomainFindGraphicsIndex(virDomainDef *def,
                            virDomainGraphicsDef *dev)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        if (def->graphics[i]->type == dev->type)
            return i;
    }

    return -1;
}


int
qemuDomainChangeGraphicsPasswords(virDomainObj *vm,
                                  int type,
                                  virDomainGraphicsAuthDef *auth,
                                  const char *defaultPasswd,
                                  int asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    time_t now = time(NULL);
    const char *expire;
    g_autofree char *validTo = NULL;
    const char *connected = NULL;
    const char *password;
    int ret = -1;

    if (!auth->passwd && !defaultPasswd)
        return 0;

    password = auth->passwd ? auth->passwd : defaultPasswd;

    if (auth->connected)
        connected = virDomainGraphicsAuthConnectedTypeToString(auth->connected);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return ret;
    ret = qemuMonitorSetPassword(priv->mon, type, password, connected);

    if (ret != 0)
        goto end_job;

    if (password[0] == '\0' ||
        (auth->expires && auth->validTo <= now)) {
        expire = "now";
    } else if (auth->expires) {
        validTo = g_strdup_printf("%lu", (unsigned long)auth->validTo);
        expire = validTo;
    } else {
        expire = "never";
    }

    ret = qemuMonitorExpirePassword(priv->mon, type, expire);

 end_job:
    qemuDomainObjExitMonitor(vm);

    return ret;
}


static int
qemuDomainChangeGraphics(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainGraphicsDef *dev)
{
    virDomainGraphicsDef *olddev = qemuDomainFindGraphics(vm, dev);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *type = virDomainGraphicsTypeToString(dev->type);
    size_t i;

    if (!olddev) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("cannot find existing graphics device to modify of type '%1$s'"),
                       type);
        return -1;
    }

    if (dev->nListens != olddev->nListens) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change the number of listen addresses on '%1$s' graphics"),
                       type);
        return -1;
    }

    for (i = 0; i < dev->nListens; i++) {
        virDomainGraphicsListenDef *newlisten = &dev->listens[i];
        virDomainGraphicsListenDef *oldlisten = &olddev->listens[i];

        if (newlisten->type != oldlisten->type) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("cannot change the type of listen address on '%1$s' graphics"),
                           type);
            return -1;
        }

        switch (newlisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            if (STRNEQ_NULLABLE(newlisten->address, oldlisten->address)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("cannot change listen address setting on '%1$s' graphics"),
                               type);
                return -1;
            }

            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (STRNEQ_NULLABLE(newlisten->network, oldlisten->network)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("cannot change listen address setting on '%1$s' graphics"),
                               type);
                return -1;
            }

            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            if (STRNEQ_NULLABLE(newlisten->socket, oldlisten->socket)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("cannot change listen socket setting on '%1$s' graphics"),
                               type);
                return -1;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
            /* nada */
            break;
        }
    }

    switch (dev->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if ((olddev->data.vnc.autoport != dev->data.vnc.autoport) ||
            (!dev->data.vnc.autoport &&
             (olddev->data.vnc.port != dev->data.vnc.port))) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot change port settings on vnc graphics"));
            return -1;
        }
        if (STRNEQ_NULLABLE(olddev->data.vnc.keymap, dev->data.vnc.keymap)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot change keymap setting on vnc graphics"));
            return -1;
        }

        /* If a password lifetime was, or is set, or action if connected has
         * changed, then we must always run, even if new password matches
         * old password */
        if (olddev->data.vnc.auth.expires ||
            dev->data.vnc.auth.expires ||
            olddev->data.vnc.auth.connected != dev->data.vnc.auth.connected ||
            STRNEQ_NULLABLE(olddev->data.vnc.auth.passwd,
                            dev->data.vnc.auth.passwd)) {
            VIR_DEBUG("Updating password on VNC server %p %p",
                      dev->data.vnc.auth.passwd, cfg->vncPassword);
            if (qemuDomainChangeGraphicsPasswords(vm,
                                                  VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                                                  &dev->data.vnc.auth,
                                                  cfg->vncPassword,
                                                  VIR_ASYNC_JOB_NONE) < 0)
                return -1;

            /* Steal the new dev's  char * reference */
            VIR_FREE(olddev->data.vnc.auth.passwd);
            olddev->data.vnc.auth.passwd = g_steal_pointer(&dev->data.vnc.auth.passwd);
            olddev->data.vnc.auth.validTo = dev->data.vnc.auth.validTo;
            olddev->data.vnc.auth.expires = dev->data.vnc.auth.expires;
            olddev->data.vnc.auth.connected = dev->data.vnc.auth.connected;
        }
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        if ((olddev->data.spice.autoport != dev->data.spice.autoport) ||
            (!dev->data.spice.autoport &&
             (olddev->data.spice.port != dev->data.spice.port)) ||
            (!dev->data.spice.autoport &&
             (olddev->data.spice.tlsPort != dev->data.spice.tlsPort))) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot change port settings on spice graphics"));
            return -1;
        }
        if (STRNEQ_NULLABLE(olddev->data.spice.keymap,
                            dev->data.spice.keymap)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                            _("cannot change keymap setting on spice graphics"));
            return -1;
        }

        /* We must reset the password if it has changed but also if:
         * - password lifetime is or was set
         * - the requested action has changed
         * - the action is "disconnect"
         */
        if (olddev->data.spice.auth.expires ||
            dev->data.spice.auth.expires ||
            olddev->data.spice.auth.connected != dev->data.spice.auth.connected ||
            dev->data.spice.auth.connected ==
            VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_DISCONNECT ||
            STRNEQ_NULLABLE(olddev->data.spice.auth.passwd,
                            dev->data.spice.auth.passwd)) {
            VIR_DEBUG("Updating password on SPICE server %p %p",
                      dev->data.spice.auth.passwd, cfg->spicePassword);
            if (qemuDomainChangeGraphicsPasswords(vm,
                                                  VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
                                                  &dev->data.spice.auth,
                                                  cfg->spicePassword,
                                                  VIR_ASYNC_JOB_NONE) < 0)
                return -1;

            /* Steal the new dev's char * reference */
            VIR_FREE(olddev->data.spice.auth.passwd);
            olddev->data.spice.auth.passwd = g_steal_pointer(&dev->data.spice.auth.passwd);
            olddev->data.spice.auth.validTo = dev->data.spice.auth.validTo;
            olddev->data.spice.auth.expires = dev->data.spice.auth.expires;
            olddev->data.spice.auth.connected = dev->data.spice.auth.connected;
        } else {
            VIR_DEBUG("Not updating since password didn't change");
        }
        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_EGL_HEADLESS:
    case VIR_DOMAIN_GRAPHICS_TYPE_DBUS:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to change config on '%1$s' graphics type"), type);
        break;
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainGraphicsType, dev->type);
        break;
    }

    return 0;
}


static int qemuComparePCIDevice(virDomainDef *def G_GNUC_UNUSED,
                                virDomainDeviceDef *device G_GNUC_UNUSED,
                                virDomainDeviceInfo *info1,
                                void *opaque)
{
    virDomainDeviceInfo *info2 = opaque;

    if (info1->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
        info2->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return 0;

    if (info1->addr.pci.domain == info2->addr.pci.domain &&
        info1->addr.pci.bus == info2->addr.pci.bus &&
        info1->addr.pci.slot == info2->addr.pci.slot &&
        info1->addr.pci.function != info2->addr.pci.function)
        return -1;
    return 0;
}

static bool qemuIsMultiFunctionDevice(virDomainDef *def,
                                      virDomainDeviceInfo *info)
{
    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return false;

    if (virDomainDeviceInfoIterate(def, qemuComparePCIDevice, info) < 0)
        return true;
    return false;
}


static int
qemuDomainRemoveDiskDevice(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainDiskDef *disk)
{
    qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    g_autoptr(qemuBlockStorageSourceChainData) diskBackend = NULL;
    size_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret = -1;

    VIR_DEBUG("Removing disk %s from domain %p %s",
              disk->info.alias, vm, vm->def->name);


    if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_VHOST_USER) {
        char *chardevAlias = qemuDomainGetVhostUserChrAlias(disk->info.alias);

        if (!(diskBackend = qemuBlockStorageSourceChainDetachPrepareChardev(chardevAlias)))
            goto cleanup;
    } else {
        if (diskPriv->blockjob) {
            /* the block job keeps reference to the disk chain */
            diskPriv->blockjob->disk = NULL;
            g_clear_pointer(&diskPriv->blockjob, virObjectUnref);
        } else {
            if (!(diskBackend = qemuBlockStorageSourceChainDetachPrepareBlockdev(disk->src)))
                goto cleanup;
        }

        if (diskPriv->nodeCopyOnRead) {
            if (!diskBackend)
                diskBackend = g_new0(qemuBlockStorageSourceChainData, 1);
            diskBackend->copyOnReadNodename = g_strdup(diskPriv->nodeCopyOnRead);
            diskBackend->copyOnReadAttached = true;
        }
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i] == disk) {
            virDomainDiskRemove(vm->def, i);
            break;
        }
    }

    qemuDomainObjEnterMonitor(vm);

    if (diskBackend)
        qemuBlockStorageSourceChainDetach(priv->mon, diskBackend);

    qemuDomainObjExitMonitor(vm);

    virDomainAuditDisk(vm, disk->src, NULL, "detach", true);

    qemuDomainReleaseDeviceAddress(vm, &disk->info);

    /* tear down disk security access */
    if (diskBackend)
        qemuDomainStorageSourceChainAccessRevoke(driver, vm, disk->src);

    if (virStorageSourceChainHasManagedPR(disk->src) &&
        qemuHotplugRemoveManagedPR(vm, VIR_ASYNC_JOB_NONE) < 0)
        goto cleanup;

    qemuNbdkitStopStorageSource(disk->src, vm);

    if (disk->transient) {
        VIR_DEBUG("Removing transient overlay '%s' of disk '%s'",
                  disk->src->path, disk->dst);
        if (qemuDomainStorageFileInit(driver, vm, disk->src, NULL) >= 0) {
            virStorageSourceUnlink(disk->src);
            virStorageSourceDeinit(disk->src);
        }
    }

    ret = 0;

 cleanup:
    virDomainDiskDefFree(disk);
    return ret;
}


static int
qemuDomainRemoveControllerDevice(virDomainObj *vm,
                                 virDomainControllerDef *controller)
{
    size_t i;

    VIR_DEBUG("Removing controller %s from domain %p %s",
              controller->info.alias, vm, vm->def->name);

    for (i = 0; i < vm->def->ncontrollers; i++) {
        if (vm->def->controllers[i] == controller) {
            virDomainControllerRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &controller->info);
    virDomainControllerDefFree(controller);
    return 0;
}


static int
qemuDomainRemoveMemoryDevice(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainMemoryDef *mem)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    unsigned long long oldmem = virDomainDefGetMemoryTotal(vm->def);
    unsigned long long newmem = oldmem - mem->size;
    g_autofree char *backendAlias = NULL;
    int rc;
    int idx;

    VIR_DEBUG("Removing memory device %s from domain %p %s",
              mem->info.alias, vm, vm->def->name);

    backendAlias = g_strdup_printf("mem%s", mem->info.alias);

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorDelObject(priv->mon, backendAlias, true);
    qemuDomainObjExitMonitor(vm);

    virDomainAuditMemory(vm, oldmem, newmem, "update", rc == 0);
    if (rc < 0)
        return -1;

    if ((idx = virDomainMemoryFindByDef(vm->def, mem)) >= 0)
        virDomainMemoryRemove(vm->def, idx);

    if (qemuSecurityRestoreMemoryLabel(driver, vm, mem) < 0)
        VIR_WARN("Unable to restore security label on memdev");

    if (qemuTeardownMemoryDevicesCgroup(vm, mem) < 0)
        VIR_WARN("Unable to remove memory device cgroup ACL");

    if (qemuDomainNamespaceTeardownMemory(vm, mem) <  0)
        VIR_WARN("Unable to remove memory device from /dev");

    if (qemuProcessDestroyMemoryBackingPath(driver, vm, mem) < 0)
        VIR_WARN("Unable to destroy memory backing path");

    qemuDomainReleaseMemoryDeviceSlot(vm, mem);

    virDomainMemoryDefFree(mem);

    /* fix the balloon size */
    ignore_value(qemuProcessRefreshBalloonState(vm, VIR_ASYNC_JOB_NONE));

    /* decrease the mlock limit after memory unplug if necessary */
    ignore_value(qemuDomainAdjustMaxMemLock(vm));

    return 0;
}


static void
qemuDomainRemovePCIHostDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainHostdevDef *hostdev)
{
    qemuHostdevReAttachPCIDevices(driver, vm->def->name, &hostdev, 1);
    qemuDomainReleaseDeviceAddress(vm, hostdev->info);
}

static void
qemuDomainRemoveUSBHostDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainHostdevDef *hostdev)
{
    qemuHostdevReAttachUSBDevices(driver, vm->def->name, &hostdev, 1);
    qemuDomainReleaseDeviceAddress(vm, hostdev->info);
}

static void
qemuDomainRemoveSCSIHostDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    qemuHostdevReAttachSCSIDevices(driver, vm->def->name, &hostdev, 1);
}

static void
qemuDomainRemoveSCSIVHostDevice(virQEMUDriver *driver,
                                virDomainObj *vm,
                                virDomainHostdevDef *hostdev)
{
    qemuHostdevReAttachSCSIVHostDevices(driver, vm->def->name, &hostdev, 1);
}


static void
qemuDomainRemoveMediatedDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev)
{
    qemuHostdevReAttachMediatedDevices(driver, vm->def->name, &hostdev, 1);
    qemuDomainReleaseDeviceAddress(vm, hostdev->info);
}


static int
qemuDomainRemoveHostDevice(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainHostdevDef *hostdev)
{
    virDomainNetDef *net = NULL;
    size_t i;
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Removing host device %s from domain %p %s",
              hostdev->info->alias, vm, vm->def->name);

    if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
        g_autoptr(qemuBlockStorageSourceAttachData) detachscsi = NULL;

        detachscsi = qemuBuildHostdevSCSIDetachPrepare(hostdev, priv->qemuCaps);

        qemuDomainObjEnterMonitor(vm);
        qemuBlockStorageSourceAttachRollback(priv->mon, detachscsi);
        qemuDomainObjExitMonitor(vm);
    }

    if (hostdev->parentnet) {
        net = hostdev->parentnet;
        for (i = 0; i < vm->def->nnets; i++) {
            if (vm->def->nets[i] == hostdev->parentnet) {
                virDomainNetRemove(vm->def, i);
                break;
            }
        }
    }

    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (vm->def->hostdevs[i] == hostdev) {
            virDomainHostdevRemove(vm->def, i);
            break;
        }
    }

    virDomainAuditHostdev(vm, hostdev, "detach", true);

    if (!virHostdevIsVFIODevice(hostdev) &&
        qemuSecurityRestoreHostdevLabel(driver, vm, hostdev) < 0)
        VIR_WARN("Failed to restore host device labelling");

    if (qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Failed to remove host device cgroup ACL");

    if (qemuDomainNamespaceTeardownHostdev(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device from /dev");

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        qemuDomainRemovePCIHostDevice(driver, vm, hostdev);
        /* QEMU might no longer need to lock as much memory, eg. we just
         * detached the last VFIO device, so adjust the limit here */
        if (qemuDomainAdjustMaxMemLock(vm) < 0)
            VIR_WARN("Failed to adjust locked memory limit");
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        qemuDomainRemoveUSBHostDevice(driver, vm, hostdev);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        qemuDomainRemoveSCSIHostDevice(driver, vm, hostdev);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
        qemuDomainRemoveSCSIVHostDevice(driver, vm, hostdev);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        qemuDomainRemoveMediatedDevice(driver, vm, hostdev);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        break;
    }

    virDomainHostdevDefFree(hostdev);

    if (net) {
        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            g_autoptr(virConnect) conn = virGetConnectNetwork();
            if (conn)
                virDomainNetReleaseActualDevice(conn, vm->def, net);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
        }
        virDomainNetDefFree(net);
    }

    return 0;
}


static int
qemuDomainRemoveNetDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainNetDef *net)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *hostnet_name = NULL;
    g_autofree char *charDevAlias = NULL;
    size_t i;
    int actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* this function handles all hostdev and netdev cleanup */
        return qemuDomainRemoveHostDevice(driver, vm,
                                          virDomainNetGetActualHostdev(net));
    }

    VIR_DEBUG("Removing network interface %s from domain %p %s",
              net->info.alias, vm, vm->def->name);

    hostnet_name = g_strdup_printf("host%s", net->info.alias);
    if (!(charDevAlias = qemuAliasChardevFromDevAlias(net->info.alias)))
        return -1;

    if (virNetDevSupportsBandwidth(virDomainNetGetActualType(net))) {
        if (virDomainNetDefIsOvsport(net)) {
            if (virNetDevOpenvswitchInterfaceClearQos(net->ifname, vm->def->uuid) < 0)
                VIR_WARN("cannot clear bandwidth setting for ovs device : %s",
                         net->ifname);
        } else if (virNetDevBandwidthClear(net->ifname) < 0) {
            VIR_WARN("cannot clear bandwidth setting for device : %s",
                     net->ifname);
        }
    }

    /* deactivate the tap/macvtap device on the host, which could also
     * affect the parent device (e.g. macvtap passthrough mode sets
     * the parent device offline)
     */
    ignore_value(qemuInterfaceStopDevice(net));

    qemuDomainObjEnterMonitor(vm);
    if (qemuMonitorRemoveNetdev(priv->mon, hostnet_name) < 0) {
        qemuDomainObjExitMonitor(vm);
        virDomainAuditNet(vm, net, NULL, "detach", false);
        return -1;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_VHOSTUSER) {
        /* vhostuser has a chardev too */
        if (qemuMonitorDetachCharDev(priv->mon, charDevAlias) < 0) {
            /* well, this is a messy situation. Guest visible PCI device has
             * been removed, netdev too but chardev not. The best seems to be
             * to just ignore the error and carry on.
             */
        }
    } else if (actualType == VIR_DOMAIN_NET_TYPE_VDPA) {
        qemuHotplugRemoveFDSet(priv->mon, net->info.alias, net->data.vdpa.devicepath);
    }

    qemuDomainObjExitMonitor(vm);

    if (QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp)
        qemuSlirpStop(QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp, vm, driver, net);

    if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
        net->backend.type == VIR_DOMAIN_NET_BACKEND_PASST) {
        qemuPasstStop(vm, net);
    }

    virDomainAuditNet(vm, net, NULL, "detach", true);

    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i] == net) {
            virDomainNetRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &net->info);
    virDomainConfNWFilterTeardown(net);

    if (cfg->macFilter && (net->ifname != NULL)) {
        ignore_value(ebtablesRemoveForwardAllowIn(driver->ebtables,
                                                  net->ifname,
                                                  &net->mac));
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        virNetDevMacVLanDeleteWithVPortProfile(net->ifname, &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               virDomainNetGetActualDirectMode(net),
                                               virDomainNetGetActualVirtPortProfile(net),
                                               cfg->stateDir);
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_VHOSTUSER) {
        if (qemuSecurityRestoreNetdevLabel(driver, vm, net) < 0)
            VIR_WARN("Unable to restore security label on vhostuser char device");
    }

    qemuDomainNetDeviceVportRemove(net);

    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        g_autoptr(virConnect) conn = virGetConnectNetwork();
        if (conn)
            virDomainNetReleaseActualDevice(conn, vm->def, net);
        else
            VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
    } else if (net->type == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        if (net->downscript)
            virNetDevRunEthernetScript(net->ifname, net->downscript);
    }
    virDomainNetDefFree(net);
    return 0;
}


static int
qemuDomainRemoveChrDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainChrDef *chr,
                          bool monitor)
{
    virObjectEvent *event;
    g_autofree char *charAlias = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainChrDef *chrRemoved = NULL;
    int rc = 0;

    VIR_DEBUG("Removing character device %s from domain %p %s",
              chr->info.alias, vm, vm->def->name);

    if (!(charAlias = qemuAliasChardevFromDevAlias(chr->info.alias)))
        return -1;

    if (monitor) {
        qemuDomainObjEnterMonitor(vm);
        rc = qemuMonitorDetachCharDev(priv->mon, charAlias);
        qemuHotplugRemoveFDSet(priv->mon, chr->info.alias, NULL);
        qemuDomainObjExitMonitor(vm);
    }

    if (rc == 0 &&
        qemuDomainDelChardevTLSObjects(driver, vm, chr->source, charAlias) < 0)
        return -1;

    virDomainAuditChardev(vm, chr, NULL, "detach", rc == 0);

    if (rc < 0)
        return -1;

    if (qemuTeardownChardevCgroup(vm, chr) < 0)
        VIR_WARN("Failed to remove chr device cgroup ACL");

    if (qemuSecurityRestoreChardevLabel(driver, vm, chr) < 0)
        VIR_WARN("Unable to restore security label on char device");

    if (qemuDomainNamespaceTeardownChardev(vm, chr) < 0)
        VIR_WARN("Unable to remove chr device from /dev");

    if (!(chrRemoved = qemuDomainChrRemove(vm->def, chr))) {
        /* At this point, we only have bad options. The device
         * was successfully removed from QEMU, denied in CGropus,
         * etc. and yet, we failed to remove it from domain
         * definition. */
        VIR_WARN("Unable to remove chr device from domain definition");
    } else {
        qemuDomainReleaseDeviceAddress(vm, &chrRemoved->info);

        /* The caller does not emit the event, so we must do it here. Note
         * that the event should be reported only after all backend
         * teardown is completed.
         */
        event = virDomainEventDeviceRemovedNewFromObj(vm, chrRemoved->info.alias);
        virObjectEventStateQueue(driver->domainEventState, event);

        virDomainChrDefFree(chrRemoved);
    }
    return 0;
}


static int
qemuDomainRemoveRNGDevice(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainRNGDef *rng)
{
    g_autofree char *charAlias = NULL;
    g_autofree char *objAlias = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    ssize_t idx;
    int rc = 0;

    VIR_DEBUG("Removing RNG device %s from domain %p %s",
              rng->info.alias, vm, vm->def->name);


    objAlias = g_strdup_printf("obj%s", rng->info.alias);

    if (!(charAlias = qemuAliasChardevFromDevAlias(rng->info.alias)))
        return -1;

    qemuDomainObjEnterMonitor(vm);

    if (qemuMonitorDelObject(priv->mon, objAlias, true) < 0)
        rc = -1;

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD &&
        rc == 0 &&
        qemuMonitorDetachCharDev(priv->mon, charAlias) < 0)
        rc = -1;

    qemuDomainObjExitMonitor(vm);

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD &&
        rc == 0 &&
        qemuDomainDelChardevTLSObjects(driver, vm, rng->source.chardev,
                                       charAlias) < 0)
        rc = -1;

    virDomainAuditRNG(vm, rng, NULL, "detach", rc == 0);

    if (rc < 0)
        return -1;

    if (qemuTeardownRNGCgroup(vm, rng) < 0)
        VIR_WARN("Failed to remove RNG device cgroup ACL");

    if (qemuDomainNamespaceTeardownRNG(vm, rng) < 0)
        VIR_WARN("Unable to remove RNG device from /dev");

    if ((idx = virDomainRNGFind(vm->def, rng)) >= 0)
        virDomainRNGRemove(vm->def, idx);
    qemuDomainReleaseDeviceAddress(vm, &rng->info);
    virDomainRNGDefFree(rng);
    return 0;
}


static int
qemuDomainRemoveShmemDevice(virDomainObj *vm,
                            virDomainShmemDef *shmem)
{
    int rc;
    ssize_t idx = -1;
    g_autofree char *charAlias = NULL;
    g_autofree char *memAlias = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("Removing shmem device %s from domain %p %s",
              shmem->info.alias, vm, vm->def->name);

    if (shmem->server.enabled) {
        charAlias = g_strdup_printf("char%s", shmem->info.alias);
    } else {
        memAlias = g_strdup_printf("shmmem-%s", shmem->info.alias);
    }

    qemuDomainObjEnterMonitor(vm);

    if (shmem->server.enabled)
        rc = qemuMonitorDetachCharDev(priv->mon, charAlias);
    else
        rc = qemuMonitorDelObject(priv->mon, memAlias, true);

    qemuDomainObjExitMonitor(vm);

    virDomainAuditShmem(vm, shmem, "detach", rc == 0);

    if (rc < 0)
        return -1;

    if ((idx = virDomainShmemDefFind(vm->def, shmem)) >= 0)
        virDomainShmemDefRemove(vm->def, idx);
    qemuDomainReleaseDeviceAddress(vm, &shmem->info);
    virDomainShmemDefFree(shmem);

    return 0;
}


static int
qemuDomainRemoveWatchdog(virDomainObj *vm,
                         virDomainWatchdogDef *watchdog)
{
    size_t i = 0;

    VIR_DEBUG("Removing watchdog %s from domain %p %s",
              watchdog->info.alias, vm, vm->def->name);

    for (i = 0; i < vm->def->nwatchdogs; i++) {
        if (vm->def->watchdogs[i] == watchdog)
            break;
    }

    qemuDomainReleaseDeviceAddress(vm, &watchdog->info);
    virDomainWatchdogDefFree(watchdog);
    VIR_DELETE_ELEMENT(vm->def->watchdogs, i, vm->def->nwatchdogs);

    return 0;
}


static int
qemuDomainRemoveInputDevice(virDomainObj *vm,
                            virDomainInputDef *dev)
{
    size_t i;

    VIR_DEBUG("Removing input device %s from domain %p %s",
              dev->info.alias, vm, vm->def->name);

    for (i = 0; i < vm->def->ninputs; i++) {
        if (vm->def->inputs[i] == dev)
            break;
    }
    qemuDomainReleaseDeviceAddress(vm, &dev->info);
    if (qemuSecurityRestoreInputLabel(vm, dev) < 0)
        VIR_WARN("Unable to restore security label on input device");

    if (qemuTeardownInputCgroup(vm, dev) < 0)
        VIR_WARN("Unable to remove input device cgroup ACL");

    if (qemuDomainNamespaceTeardownInput(vm, dev) < 0)
        VIR_WARN("Unable to remove input device from /dev");

    virDomainInputDefFree(vm->def->inputs[i]);
    VIR_DELETE_ELEMENT(vm->def->inputs, i, vm->def->ninputs);
    return 0;
}


static int
qemuDomainRemoveVsockDevice(virDomainObj *vm,
                            virDomainVsockDef *dev)
{
    VIR_DEBUG("Removing vsock device %s from domain %p %s",
              dev->info.alias, vm, vm->def->name);

    qemuDomainReleaseDeviceAddress(vm, &dev->info);
    g_clear_pointer(&vm->def->vsock, virDomainVsockDefFree);
    return 0;
}


static int
qemuDomainRemoveRedirdevDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainRedirdevDef *dev)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *charAlias = NULL;
    ssize_t idx;

    VIR_DEBUG("Removing redirdev device %s from domain %p %s",
              dev->info.alias, vm, vm->def->name);

    if (!(charAlias = qemuAliasChardevFromDevAlias(dev->info.alias)))
        return -1;

    qemuDomainObjEnterMonitor(vm);
    /* DeviceDel from Detach may remove chardev,
     * so we cannot rely on return status to delete TLS chardevs.
     */
    ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));

    qemuDomainObjExitMonitor(vm);

    if (qemuDomainDelChardevTLSObjects(driver, vm, dev->source, charAlias) < 0)
        return -1;

    virDomainAuditRedirdev(vm, dev, "detach", true);

    if ((idx = virDomainRedirdevDefFind(vm->def, dev)) >= 0)
        virDomainRedirdevDefRemove(vm->def, idx);
    qemuDomainReleaseDeviceAddress(vm, &dev->info);
    virDomainRedirdevDefFree(dev);

    return 0;
}


static int
qemuDomainRemoveFSDevice(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainFSDef *fs)
{
    g_autofree char *charAlias = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    ssize_t idx;
    int rc = 0;

    VIR_DEBUG("Removing FS device %s from domain %p %s",
              fs->info.alias, vm, vm->def->name);

    if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        charAlias = qemuDomainGetVhostUserChrAlias(fs->info.alias);

        qemuDomainObjEnterMonitor(vm);

        if (qemuMonitorDetachCharDev(priv->mon, charAlias) < 0)
            rc = -1;

        qemuDomainObjExitMonitor(vm);
    }

    virDomainAuditFS(vm, fs, NULL, "detach", rc == 0);

    if (rc < 0)
        return -1;

    if (!fs->sock && fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS)
        qemuVirtioFSStop(driver, vm, fs);

    if ((idx = virDomainFSDefFind(vm->def, fs)) >= 0)
        virDomainFSRemove(vm->def, idx);
    qemuDomainReleaseDeviceAddress(vm, &fs->info);
    virDomainFSDefFree(fs);
    return 0;
}


static void
qemuDomainRemoveAuditDevice(virDomainObj *vm,
                            virDomainDeviceDef *detach,
                            bool success)
{
    switch (detach->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        virDomainAuditDisk(vm, detach->data.disk->src, NULL, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        virDomainAuditNet(vm, detach->data.net, NULL, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        virDomainAuditHostdev(vm, detach->data.hostdev, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        virDomainAuditInput(vm, detach->data.input, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        virDomainAuditChardev(vm, detach->data.chr, NULL, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        virDomainAuditRNG(vm, detach->data.rng, NULL, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_MEMORY: {
        unsigned long long oldmem = virDomainDefGetMemoryTotal(vm->def);
        unsigned long long newmem = oldmem - detach->data.memory->size;

        virDomainAuditMemory(vm, oldmem, newmem, "update", success);
        break;
    }
    case VIR_DOMAIN_DEVICE_SHMEM:
        virDomainAuditShmem(vm, detach->data.shmem, "detach", success);
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        virDomainAuditRedirdev(vm, detach->data.redirdev, "detach", success);
        break;

    case VIR_DOMAIN_DEVICE_FS:
        virDomainAuditFS(vm, detach->data.fs, NULL, "detach", success);
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_VSOCK:
        /* These devices don't have associated audit logs */
        break;

    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_LAST:
        /* libvirt doesn't yet support detaching these devices */
        break;
    }
}


int
qemuDomainRemoveDevice(virQEMUDriver *driver,
                       virDomainObj *vm,
                       virDomainDeviceDef *dev)
{
    virDomainDeviceInfo *info;
    virObjectEvent *event;
    g_autofree char *alias = NULL;

    /*
     * save the alias to use when sending a DEVICE_REMOVED event after
     * all other teardown is complete
     */
    if ((info = virDomainDeviceGetInfo(dev)))
        alias = g_strdup(info->alias);
    info = NULL;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_CHR:
        /* We must return directly after calling
         * qemuDomainRemoveChrDevice because it is called directly
         * from other places, so it must be completely self-contained
         * and can't take advantage of any common code at the end of
         * qemuDomainRemoveDevice().
         */
        return qemuDomainRemoveChrDevice(driver, vm, dev->data.chr, true);

        /*
         * all of the following qemuDomainRemove*Device() functions
         * are (and must be) only called from this function, so any
         * code that is common to them all can be pulled out and put
         * into this function.
         */
    case VIR_DOMAIN_DEVICE_DISK:
        if (qemuDomainRemoveDiskDevice(driver, vm, dev->data.disk) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        if (qemuDomainRemoveControllerDevice(vm, dev->data.controller) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (qemuDomainRemoveNetDevice(driver, vm, dev->data.net) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (qemuDomainRemoveHostDevice(driver, vm, dev->data.hostdev) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        if (qemuDomainRemoveRNGDevice(driver, vm, dev->data.rng) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        if (qemuDomainRemoveMemoryDevice(driver, vm, dev->data.memory) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        if (qemuDomainRemoveShmemDevice(vm, dev->data.shmem) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        if (qemuDomainRemoveInputDevice(vm, dev->data.input) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        if (qemuDomainRemoveRedirdevDevice(driver, vm, dev->data.redirdev) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        if (qemuDomainRemoveWatchdog(vm, dev->data.watchdog) < 0)
            return -1;
        break;
    case VIR_DOMAIN_DEVICE_VSOCK:
        if (qemuDomainRemoveVsockDevice(vm, dev->data.vsock) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_FS:
        if (qemuDomainRemoveFSDevice(driver, vm, dev->data.fs) < 0)
            return -1;
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("don't know how to remove a %1$s device"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    event = virDomainEventDeviceRemovedNewFromObj(vm, alias);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}


static void
qemuDomainMarkDeviceAliasForRemoval(virDomainObj *vm,
                                    const char *alias)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    memset(&priv->unplug, 0, sizeof(priv->unplug));

    priv->unplug.alias = alias;
}


static void
qemuDomainMarkDeviceForRemoval(virDomainObj *vm,
                               virDomainDeviceInfo *info)

{
    qemuDomainMarkDeviceAliasForRemoval(vm, info->alias);
}


static void
qemuDomainResetDeviceRemoval(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    priv->unplug.alias = NULL;
    priv->unplug.eventSeen = false;
}


unsigned long long G_NO_INLINE
qemuDomainGetUnplugTimeout(virDomainObj *vm)
{
    if (qemuDomainIsPSeries(vm->def))
        return QEMU_UNPLUG_TIMEOUT_PPC64;

    return QEMU_UNPLUG_TIMEOUT;
}


/* Returns:
 *  -1 Unplug of the device failed
 *
 *   0 removal of the device did not finish in qemuDomainRemoveDeviceWaitTime
 *
 *   1 when the caller is responsible for finishing the device removal:
 *      - DEVICE_DELETED event arrived before the timeout time
 *      - we failed to reliably wait for the event and thus use fallback behavior
 */
static int
qemuDomainWaitForDeviceRemoval(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    unsigned long long until;

    if (virTimeMillisNow(&until) < 0)
        return 1;
    until += qemuDomainGetUnplugTimeout(vm);

    while (true) {
        int rc;

        if ((rc = virDomainObjWaitUntil(vm, until)) < 0) {
            VIR_WARN("Failed to wait on unplug condition for domain '%s' device '%s'",
                     vm->def->name, priv->unplug.alias);
            return 1;
        }

        /* unplug event for this device was received, check the status */
        if (!priv->unplug.alias)
            break;

        /* timeout */
        if (rc == 1)
            return 0;
    }

    if (priv->unplug.status == QEMU_DOMAIN_UNPLUGGING_DEVICE_STATUS_GUEST_REJECTED) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("unplug of device was rejected by the guest"));
        return -1;
    }

    return 1;
}

/* Returns:
 *  true    there was a thread waiting for devAlias to be removed and this
 *          thread will take care of finishing the removal
 *  false   the thread that started the removal is already gone and delegate
 *          finishing the removal to a new thread
 */
bool
qemuDomainSignalDeviceRemoval(virDomainObj *vm,
                              const char *devAlias,
                              qemuDomainUnpluggingDeviceStatus status)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (STREQ_NULLABLE(priv->unplug.alias, devAlias)) {
        VIR_DEBUG("Removal of device '%s' continues in waiting thread", devAlias);
        qemuDomainResetDeviceRemoval(vm);
        priv->unplug.status = status;
        priv->unplug.eventSeen = true;
        virDomainObjBroadcast(vm);
        return true;
    }
    return false;
}


static int
qemuFindDisk(virDomainDef *def, const char *dst)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ(def->disks[i]->dst, dst))
            return i;
    }

    return -1;
}

static int
qemuDomainDetachPrepDisk(virDomainObj *vm,
                         virDomainDiskDef *match,
                         virDomainDiskDef **detach)
{
    virDomainDiskDef *disk;
    int idx;

    if ((idx = qemuFindDisk(vm->def, match->dst)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("disk %1$s not found"), match->dst);
        return -1;
    }
    *detach = disk = vm->def->disks[idx];

    switch ((virDomainDiskDevice) disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_DISK:
    case VIR_DOMAIN_DISK_DEVICE_LUN:

        switch (disk->bus) {
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_SCSI:
            break;

        case VIR_DOMAIN_DISK_BUS_IDE:
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("This type of disk cannot be hot unplugged"));
            return -1;

        case VIR_DOMAIN_DISK_BUS_NONE:
        case VIR_DOMAIN_DISK_BUS_LAST:
        default:
            virReportEnumRangeError(virDomainDiskBus, disk->bus);
            return -1;
        }
        break;

    case VIR_DOMAIN_DISK_DEVICE_CDROM:
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB ||
            disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            break;
        }
        G_GNUC_FALLTHROUGH;

    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("disk device type '%1$s' cannot be detached"),
                       virDomainDiskDeviceTypeToString(disk->device));
        return -1;

    case VIR_DOMAIN_DISK_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDiskDevice, disk->device);
        return -1;
    }

    if (qemuDomainDiskBlockJobIsActive(disk))
        return -1;

    return 0;
}


static bool
qemuDomainDiskControllerIsBusy(virDomainObj *vm,
                               virDomainControllerDef *detach)
{
    size_t i;
    virDomainDiskDef *disk;
    virDomainHostdevDef *hostdev;

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            /* the disk does not use disk controller */
            continue;

        /* check whether the disk uses this type controller */
        switch (detach->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
            if (disk->bus != VIR_DOMAIN_DISK_BUS_IDE)
                continue;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
            if (disk->bus != VIR_DOMAIN_DISK_BUS_FDC)
                continue;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
            if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI)
                continue;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            if (disk->bus != VIR_DOMAIN_DISK_BUS_SATA)
                continue;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
            /* xenbus is not supported by the qemu driver */
            continue;

        case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
            /* virtio-serial does not host any disks */
            continue;

        case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
            /* These buses have (also) other device types too so they need to
             * be checked elsewhere */
            continue;

        case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        default:
            continue;
        }

        if (disk->info.addr.drive.controller == detach->idx)
            return true;
    }

    if (detach->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
        for (i = 0; i < vm->def->nhostdevs; i++) {
            hostdev = vm->def->hostdevs[i];
            if (!virHostdevIsSCSIDevice(hostdev))
                continue;

            if (hostdev->info->addr.drive.controller == detach->idx)
                return true;
        }
    }

    return false;
}


static bool
qemuDomainControllerIsBusy(virDomainObj *vm,
                           virDomainControllerDef *detach)
{
    switch (detach->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        return qemuDomainDiskControllerIsBusy(vm, detach);

    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
        /* detach of the controller types above is not yet supported */
        return false;

    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
        /* qemu driver doesn't support xenbus */
        return false;

    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
    default:
        return false;
    }
}


static int
qemuDomainDetachPrepController(virDomainObj *vm,
                               virDomainControllerDef *match,
                               virDomainControllerDef **detach)
{
    int idx;
    virDomainControllerDef *controller = NULL;

    if (match->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%1$s' controller cannot be hot unplugged."),
                       virDomainControllerTypeToString(match->type));
        return -1;
    }

    if ((idx = virDomainControllerFind(vm->def, match->type, match->idx)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("controller %1$s:%2$d not found"),
                       virDomainControllerTypeToString(match->type),
                       match->idx);
        return -1;
    }

    *detach = controller = vm->def->controllers[idx];

    if (qemuDomainControllerIsBusy(vm, controller)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("device cannot be detached: device is busy"));
        return -1;
    }

    return 0;
}


/* search for a hostdev matching dev and detach it */
static int
qemuDomainDetachPrepHostdev(virDomainObj *vm,
                            virDomainHostdevDef *match,
                            virDomainHostdevDef **detach)
{
    virDomainHostdevSubsys *subsys = &match->source.subsys;
    virDomainHostdevSubsysUSB *usbsrc = &subsys->u.usb;
    virDomainHostdevSubsysPCI *pcisrc = &subsys->u.pci;
    virDomainHostdevSubsysSCSI *scsisrc = &subsys->u.scsi;
    virDomainHostdevSubsysMediatedDev *mdevsrc = &subsys->u.mdev;
    virDomainHostdevDef *hostdev = NULL;
    int idx;

    if (match->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hot unplug is not supported for hostdev mode '%1$s'"),
                       virDomainHostdevModeTypeToString(match->mode));
        return -1;
    }

    idx = virDomainHostdevFind(vm->def, match, &hostdev);
    *detach = hostdev;

    if (idx < 0) {
        switch (subsys->type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            virReportError(VIR_ERR_DEVICE_MISSING,
                           _("host pci device %1$04x:%2$02x:%3$02x.%4$d not found"),
                           pcisrc->addr.domain, pcisrc->addr.bus,
                           pcisrc->addr.slot, pcisrc->addr.function);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (usbsrc->bus && usbsrc->device) {
                virReportError(VIR_ERR_DEVICE_MISSING,
                               _("host usb device %1$03d.%2$03d not found"),
                               usbsrc->bus, usbsrc->device);
            } else {
                virReportError(VIR_ERR_DEVICE_MISSING,
                               _("host usb device vendor=0x%1$.4x product=0x%2$.4x not found"),
                               usbsrc->vendor, usbsrc->product);
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
            if (scsisrc->protocol ==
                VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
                virDomainHostdevSubsysSCSIiSCSI *iscsisrc = &scsisrc->u.iscsi;
                virReportError(VIR_ERR_DEVICE_MISSING,
                               _("host scsi iSCSI path %1$s not found"),
                               iscsisrc->src->path);
            } else {
                 virDomainHostdevSubsysSCSIHost *scsihostsrc =
                     &scsisrc->u.host;
                 virReportError(VIR_ERR_DEVICE_MISSING,
                                _("host scsi device %1$s:%2$u:%3$u.%4$llu not found"),
                                scsihostsrc->adapter, scsihostsrc->bus,
                                scsihostsrc->target, scsihostsrc->unit);
            }
            break;
        }
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
            virReportError(VIR_ERR_DEVICE_MISSING,
                           _("mediated device '%1$s' not found"),
                           mdevsrc->uuidstr);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %1$d"), subsys->type);
            break;
        }
        return -1;
    }

    return 0;
}


static int
qemuDomainDetachPrepShmem(virDomainObj *vm,
                          virDomainShmemDef *match,
                          virDomainShmemDef **detach)
{
    ssize_t idx = -1;
    virDomainShmemDef *shmem = NULL;

    if ((idx = virDomainShmemDefFind(vm->def, match)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("model '%1$s' shmem device not present in domain configuration"),
                       virDomainShmemModelTypeToString(match->model));
        return -1;
    }

    *detach = shmem = vm->def->shmems[idx];

    switch (shmem->model) {
    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN:
    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL:
        break;

    case VIR_DOMAIN_SHMEM_MODEL_IVSHMEM:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live detach of shmem model '%1$s' is not supported"),
                       virDomainShmemModelTypeToString(shmem->model));
        G_GNUC_FALLTHROUGH;
    case VIR_DOMAIN_SHMEM_MODEL_LAST:
        return -1;
    }

    return 0;
}


static int
qemuDomainDetachPrepWatchdog(virDomainObj *vm,
                             virDomainWatchdogDef *match,
                             virDomainWatchdogDef **detach)
{
    ssize_t idx = virDomainWatchdogDefFind(vm->def, match);

    if (idx < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("no matching watchdog was found"));
        return -1;
    }

    *detach = vm->def->watchdogs[idx];

    if ((*detach)->model != VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("hot unplug of watchdog of model %1$s is not supported"),
                       virDomainWatchdogModelTypeToString((*detach)->model));
        return -1;
    }

    return 0;
}


static int
qemuDomainDetachPrepRedirdev(virDomainObj *vm,
                             virDomainRedirdevDef *match,
                             virDomainRedirdevDef **detach)
{
    ssize_t idx;

    if ((idx = virDomainRedirdevDefFind(vm->def, match)) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("no matching redirdev was not found"));
        return -1;
    }

    *detach = vm->def->redirdevs[idx];

    return 0;
}


static int
qemuDomainDetachPrepNet(virDomainObj *vm,
                        virDomainNetDef *match,
                        virDomainNetDef **detach)
{
    int detachidx;

    if ((detachidx = virDomainNetFindIdx(vm->def, match)) < 0)
        return -1;

    *detach = vm->def->nets[detachidx];

    return 0;
}


static int
qemuDomainDetachDeviceChr(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainChrDef *chr,
                          bool async)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDef *vmdef = vm->def;
    virDomainChrDef *tmpChr;
    bool guestfwd = false;

    if (!(tmpChr = virDomainChrFind(vmdef, chr))) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("chr type '%1$s' device not present in domain configuration"),
                       virDomainChrDeviceTypeToString(chr->deviceType));
        goto cleanup;
    }

    if (vmdef->os.type == VIR_DOMAIN_OSTYPE_HVM &&
        tmpChr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        (tmpChr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL ||
         tmpChr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE)) {
        /* Raise this limitation once device removal works. */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("detaching of <console/> is unsupported. Try corresponding <serial/> instead"));
        goto cleanup;
    }

    /* guestfwd channels are not really -device rather than
     * -netdev. We need to treat them slightly differently. */
    guestfwd = tmpChr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
               tmpChr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD;

    if (!async && !guestfwd)
        qemuDomainMarkDeviceForRemoval(vm, &tmpChr->info);

    if (guestfwd) {
        int rc;
        qemuDomainObjEnterMonitor(vm);
        rc = qemuMonitorRemoveNetdev(priv->mon, tmpChr->info.alias);
        qemuDomainObjExitMonitor(vm);

        if (rc < 0)
            goto cleanup;
    } else {
        if (qemuDomainDeleteDevice(vm, tmpChr->info.alias) < 0)
            goto cleanup;
    }

    if (guestfwd) {
        ret = qemuDomainRemoveChrDevice(driver, vm, tmpChr, false);
    } else if (async) {
        ret = 0;
    } else {
        if ((ret = qemuDomainWaitForDeviceRemoval(vm)) == 1)
            ret = qemuDomainRemoveChrDevice(driver, vm, tmpChr, true);
    }

 cleanup:
    if (!async)
        qemuDomainResetDeviceRemoval(vm);
    return ret;
}


static int
qemuDomainDetachPrepRNG(virDomainObj *vm,
                        virDomainRNGDef *match,
                        virDomainRNGDef **detach)
{
    ssize_t idx;

    if ((idx = virDomainRNGFind(vm->def, match)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("model '%1$s' RNG device not present in domain configuration"),
                       virDomainRNGBackendTypeToString(match->model));
        return -1;
    }

    *detach = vm->def->rngs[idx];

    return 0;
}


static int
qemuDomainDetachPrepMemory(virDomainObj *vm,
                           virDomainMemoryDef *match,
                           virDomainMemoryDef **detach)
{
    int idx;

    if (qemuDomainMemoryDeviceAlignSize(vm->def, match) < 0)
        return -1;

    if ((idx = virDomainMemoryFindByDef(vm->def, match)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("model '%1$s' memory device not present in the domain configuration"),
                       virDomainMemoryModelTypeToString(match->model));
        return -1;
    }

    *detach = vm->def->mems[idx];

    return 0;
}


static int
qemuDomainDetachPrepInput(virDomainObj *vm,
                          virDomainInputDef *match,
                          virDomainInputDef **detach)
{
    virDomainInputDef *input;
    int idx;

    if ((idx = virDomainInputDefFind(vm->def, match)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING, "%s",
                       _("matching input device not found"));
        return -1;
    }
    *detach = input = vm->def->inputs[idx];

    switch ((virDomainInputBus) input->bus) {
    case VIR_DOMAIN_INPUT_BUS_DEFAULT:
    case VIR_DOMAIN_INPUT_BUS_PS2:
    case VIR_DOMAIN_INPUT_BUS_XEN:
    case VIR_DOMAIN_INPUT_BUS_PARALLELS:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("input device on bus '%1$s' cannot be detached"),
                       virDomainInputBusTypeToString(input->bus));
        return -1;

    case VIR_DOMAIN_INPUT_BUS_LAST:
    case VIR_DOMAIN_INPUT_BUS_USB:
    case VIR_DOMAIN_INPUT_BUS_VIRTIO:
    case VIR_DOMAIN_INPUT_BUS_NONE:
        break;
    }

    return 0;
}


static int
qemuDomainDetachPrepVsock(virDomainObj *vm,
                          virDomainVsockDef *match,
                          virDomainVsockDef **detach)
{
    virDomainVsockDef *vsock;

    *detach = vsock = vm->def->vsock;
    if (!vsock ||
        !virDomainVsockDefEquals(match, vsock)) {
        virReportError(VIR_ERR_DEVICE_MISSING, "%s",
                       _("matching vsock device not found"));
        return -1;
    }

    return 0;
}


static int
qemuDomainDetachPrepFS(virDomainObj *vm,
                       virDomainFSDef *match,
                       virDomainFSDef **detach)
{
    ssize_t idx;

    if ((idx = virDomainFSDefFind(vm->def, match)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING, "%s",
                       _("matching filesystem not found"));
        return -1;
    }

    if (vm->def->fss[idx]->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("only virtiofs filesystems can be hotplugged"));
        return -1;
    }

    *detach = vm->def->fss[idx];

    return 0;
}


static int
qemuDomainDetachDeviceLease(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virDomainLeaseDef *lease)
{
    virDomainLeaseDef *det_lease;
    int idx;

    if ((idx = virDomainLeaseIndex(vm->def, lease)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Lease %1$s in lockspace %2$s does not exist"),
                       lease->key, NULLSTR(lease->lockspace));
        return -1;
    }

    if (virDomainLockLeaseDetach(driver->lockManager, vm, lease) < 0)
        return -1;

    det_lease = virDomainLeaseRemoveAt(vm->def, idx);
    virDomainLeaseDefFree(det_lease);
    return 0;
}


int
qemuDomainDetachDeviceLive(virDomainObj *vm,
                           virDomainDeviceDef *match,
                           virQEMUDriver *driver,
                           bool async)
{
    virDomainDeviceDef detach = { .type = match->type };
    virDomainDeviceInfo *info = NULL;
    int ret = -1;
    int rc;

    switch (match->type) {
        /*
         * lease and chr devices don't follow the standard pattern of
         * the others, so they must have their own self-contained
         * Detach functions.
         */
    case VIR_DOMAIN_DEVICE_LEASE:
        return qemuDomainDetachDeviceLease(driver, vm, match->data.lease);

    case VIR_DOMAIN_DEVICE_CHR:
        return qemuDomainDetachDeviceChr(driver, vm, match->data.chr, async);

        /*
         * All the other device types follow a very similar pattern -
         * First we call type-specific functions to 1) locate the
         * device we want to detach (based on the prototype device in
         * match) and 2) do any device-type-specific validation to
         * assure it is okay to detach the device.
         */
    case VIR_DOMAIN_DEVICE_DISK:
        if (qemuDomainDetachPrepDisk(vm, match->data.disk,
                                     &detach.data.disk) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        if (qemuDomainDetachPrepController(vm, match->data.controller,
                                           &detach.data.controller) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_NET:
        if (qemuDomainDetachPrepNet(vm, match->data.net,
                                    &detach.data.net) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        if (qemuDomainDetachPrepHostdev(vm, match->data.hostdev,
                                        &detach.data.hostdev) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        if (qemuDomainDetachPrepRNG(vm, match->data.rng,
                                    &detach.data.rng) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_MEMORY:
        if (qemuDomainDetachPrepMemory(vm, match->data.memory,
                                       &detach.data.memory) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        if (qemuDomainDetachPrepShmem(vm, match->data.shmem,
                                      &detach.data.shmem) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        if (qemuDomainDetachPrepWatchdog(vm, match->data.watchdog,
                                         &detach.data.watchdog) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_INPUT:
        if (qemuDomainDetachPrepInput(vm, match->data.input,
                                      &detach.data.input) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_REDIRDEV:
        if (qemuDomainDetachPrepRedirdev(vm, match->data.redirdev,
                                         &detach.data.redirdev) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_VSOCK:
        if (qemuDomainDetachPrepVsock(vm, match->data.vsock,
                                      &detach.data.vsock) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_FS:
        if (qemuDomainDetachPrepFS(vm, match->data.fs,
                                   &detach.data.fs) < 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live detach of device '%1$s' is not supported"),
                       virDomainDeviceTypeToString(match->type));
        return -1;
    }

    /* "detach" now points to the actual device we want to detach */

    if (!(info = virDomainDeviceGetInfo(&detach))) {
        /*
         * This should never happen, since all of the device types in
         * the switch cases that end with a "break" instead of a
         * return have a virDeviceInfo in them.
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device of type '%1$s' has no device info"),
                       virDomainDeviceTypeToString(detach.type));
        return -1;
    }


    /* Make generic validation checks common to all device types */

    if (!info->alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot detach %1$s device with no alias"),
                       virDomainDeviceTypeToString(detach.type));
        return -1;
    }

    if (qemuIsMultiFunctionDevice(vm->def, info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug %1$s device with multifunction PCI guest address: %2$04x:%3$02x:%4$02x.%5$d"),
                       virDomainDeviceTypeToString(detach.type),
                       info->addr.pci.domain, info->addr.pci.bus,
                       info->addr.pci.slot, info->addr.pci.function);
        return -1;
    }

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {

        virDomainControllerDef *controller;
        int controllerIdx = virDomainControllerFind(vm->def,
                                                    VIR_DOMAIN_CONTROLLER_TYPE_PCI,
                                                    info->addr.pci.bus);
        if (controllerIdx < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot hot unplug %1$s device with PCI guest address: %2$04x:%3$02x:%4$02x.%5$d - controller not found"),
                           virDomainDeviceTypeToString(detach.type),
                           info->addr.pci.domain, info->addr.pci.bus,
                           info->addr.pci.slot, info->addr.pci.function);
            return -1;
        }

        controller = vm->def->controllers[controllerIdx];
        if (controller->opts.pciopts.hotplug == VIR_TRISTATE_SWITCH_OFF) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("cannot hot unplug %1$s device with PCI guest address: %2$04x:%3$02x:%4$02x.%5$d - not allowed by controller"),
                           virDomainDeviceTypeToString(detach.type),
                           info->addr.pci.domain, info->addr.pci.bus,
                           info->addr.pci.slot, info->addr.pci.function);
            return -1;
        }
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED) {
        /* Unassigned devices are not exposed to QEMU, so remove the device
         * explicitly, just like if we received DEVICE_DELETED event.*/
        return qemuDomainRemoveDevice(driver, vm, &detach);
    }

    /*
     * Issue the qemu monitor command to delete the device (based on
     * its alias), and optionally wait a short time in case the
     * DEVICE_DELETED event arrives from qemu right away.
     */
    if (!async)
        qemuDomainMarkDeviceForRemoval(vm, info);

    rc = qemuDomainDeleteDevice(vm, info->alias);
    if (rc < 0) {
        if (rc == -2)
            ret = qemuDomainRemoveDevice(driver, vm, &detach);
        if (virDomainObjIsActive(vm))
            qemuDomainRemoveAuditDevice(vm, &detach, false);
        goto cleanup;
    }

    if (async) {
        ret = 0;
    } else {
        if ((ret = qemuDomainWaitForDeviceRemoval(vm)) == 1)
            ret = qemuDomainRemoveDevice(driver, vm, &detach);
    }

 cleanup:
    if (!async)
        qemuDomainResetDeviceRemoval(vm);

    return ret;
}


static int
qemuDomainRemoveVcpu(virDomainObj *vm,
                     unsigned int vcpu)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainVcpuDef *vcpuinfo = virDomainDefGetVcpu(vm->def, vcpu);
    qemuDomainVcpuPrivate *vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpuinfo);
    int oldvcpus = virDomainDefGetVcpus(vm->def);
    unsigned int nvcpus = vcpupriv->vcpus;
    size_t i;
    ssize_t offlineVcpuWithTid = -1;

    if (qemuDomainRefreshVcpuInfo(vm, VIR_ASYNC_JOB_NONE, false) < 0)
        return -1;

    for (i = vcpu; i < vcpu + nvcpus; i++) {
        vcpuinfo = virDomainDefGetVcpu(vm->def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpuinfo);

        if (vcpupriv->tid == 0) {
            vcpuinfo->online = false;
            /* Clear the alias as VCPU is now unplugged */
            VIR_FREE(vcpupriv->alias);
            ignore_value(virCgroupDelThread(priv->cgroup, VIR_CGROUP_THREAD_VCPU, i));
        } else {
            if (offlineVcpuWithTid == -1)
                offlineVcpuWithTid = i;
        }
    }

    if (offlineVcpuWithTid != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu reported thread id for inactive vcpu '%1$zu'"),
                       offlineVcpuWithTid);
        virDomainAuditVcpu(vm, oldvcpus, oldvcpus - nvcpus, "update", false);
        return -1;
    }

    virDomainAuditVcpu(vm, oldvcpus, oldvcpus - nvcpus, "update", true);

    return 0;
}


void
qemuDomainRemoveVcpuAlias(virDomainObj *vm,
                          const char *alias)
{
    virDomainVcpuDef *vcpu;
    qemuDomainVcpuPrivate *vcpupriv;
    size_t i;

    for (i = 0; i < virDomainDefGetVcpusMax(vm->def); i++) {
        vcpu = virDomainDefGetVcpu(vm->def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

        if (STREQ_NULLABLE(alias, vcpupriv->alias)) {
            qemuDomainRemoveVcpu(vm, i);
            return;
        }
    }

    VIR_DEBUG("vcpu '%s' not found in vcpulist of domain '%s'",
              alias, vm->def->name);
}


static int
qemuDomainHotplugDelVcpu(virQEMUDriver *driver,
                         virQEMUDriverConfig *cfg,
                         virDomainObj *vm,
                         unsigned int vcpu)
{
    virDomainVcpuDef *vcpuinfo = virDomainDefGetVcpu(vm->def, vcpu);
    qemuDomainVcpuPrivate *vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpuinfo);
    int oldvcpus = virDomainDefGetVcpus(vm->def);
    unsigned int nvcpus = vcpupriv->vcpus;
    int rc;
    int ret = -1;

    if (!vcpupriv->alias) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("vcpu '%1$u' can't be unplugged"), vcpu);
        return -1;
    }

    qemuDomainMarkDeviceAliasForRemoval(vm, vcpupriv->alias);

    if (qemuDomainDeleteDevice(vm, vcpupriv->alias) < 0) {
        if (virDomainObjIsActive(vm))
            virDomainAuditVcpu(vm, oldvcpus, oldvcpus - nvcpus, "update", false);
        goto cleanup;
    }

    if ((rc = qemuDomainWaitForDeviceRemoval(vm)) <= 0) {
        if (rc == 0)
            virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                           _("vcpu unplug request timed out. Unplug result must be manually inspected in the domain"));

        goto cleanup;
    }

    if (qemuDomainRemoveVcpu(vm, vcpu) < 0)
        goto cleanup;

    qemuDomainVcpuPersistOrder(vm->def);

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}


static int
qemuDomainHotplugAddVcpu(virQEMUDriver *driver,
                         virQEMUDriverConfig *cfg,
                         virDomainObj *vm,
                         unsigned int vcpu)
{
    g_autoptr(virJSONValue) vcpuprops = NULL;
    virDomainVcpuDef *vcpuinfo = virDomainDefGetVcpu(vm->def, vcpu);
    qemuDomainVcpuPrivate *vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpuinfo);
    unsigned int nvcpus = vcpupriv->vcpus;
    int rc;
    int oldvcpus = virDomainDefGetVcpus(vm->def);
    size_t i;
    bool vcpuTidMissing = false;

    if (!qemuDomainSupportsVcpuHotplug(vm)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cpu hotplug is not supported"));
        return -1;
    }

    vcpupriv->alias = g_strdup_printf("vcpu%u", vcpu);

    if (!(vcpuprops = qemuBuildHotpluggableCPUProps(vcpuinfo)))
        return -1;

    qemuDomainObjEnterMonitor(vm);

    rc = qemuMonitorAddDeviceProps(qemuDomainGetMonitor(vm), &vcpuprops);

    qemuDomainObjExitMonitor(vm);

    virDomainAuditVcpu(vm, oldvcpus, oldvcpus + nvcpus, "update", rc == 0);

    if (rc < 0)
        return -1;

    /* start outputting of the new XML element to allow keeping unpluggability */
    vm->def->individualvcpus = true;

    if (qemuDomainRefreshVcpuInfo(vm, VIR_ASYNC_JOB_NONE, false) < 0)
        return -1;

    for (i = vcpu; i < vcpu + nvcpus; i++) {
        vcpuinfo = virDomainDefGetVcpu(vm->def, i);
        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpuinfo);

        vcpuinfo->online = true;

        if (vcpupriv->tid > 0) {
            if (qemuProcessSetupVcpu(vm, i, true) < 0) {
                return -1;
            }
        } else {
            vcpuTidMissing = true;
        }
    }

    if (vcpuTidMissing && qemuDomainHasVcpuPids(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu didn't report thread id for vcpu '%1$zu'"), i);
        return -1;
    }

    qemuDomainVcpuPersistOrder(vm->def);

    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainSelectHotplugVcpuEntities:
 *
 * @def: domain definition
 * @nvcpus: target vcpu count
 * @enable: set to true if vcpus should be enabled
 *
 * Tries to find which vcpu entities need to be enabled or disabled to reach
 * @nvcpus. This function works in order of the legacy hotplug but is able to
 * skip over entries that are added out of order.
 *
 * Returns the bitmap of vcpus to modify on success, NULL on error.
 */
static virBitmap *
qemuDomainSelectHotplugVcpuEntities(virDomainDef *def,
                                    unsigned int nvcpus,
                                    bool *enable)
{
    g_autoptr(virBitmap) ret = NULL;
    virDomainVcpuDef *vcpu;
    qemuDomainVcpuPrivate *vcpupriv;
    unsigned int maxvcpus = virDomainDefGetVcpusMax(def);
    unsigned int curvcpus = virDomainDefGetVcpus(def);
    ssize_t i;

    ret = virBitmapNew(maxvcpus);

    if (nvcpus > curvcpus) {
        *enable = true;

        for (i = 0; i < maxvcpus && curvcpus < nvcpus; i++) {
            vcpu = virDomainDefGetVcpu(def, i);
            vcpupriv =  QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

            if (vcpu->online)
                continue;

            if (vcpupriv->vcpus == 0)
                continue;

            curvcpus += vcpupriv->vcpus;

            if (curvcpus > nvcpus) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("target vm vcpu granularity does not allow the desired vcpu count"));
                return NULL;
            }

            ignore_value(virBitmapSetBit(ret, i));
        }
    } else {
        *enable = false;

        for (i = maxvcpus - 1; i >= 0 && curvcpus > nvcpus; i--) {
            vcpu = virDomainDefGetVcpu(def, i);
            vcpupriv =  QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

            if (!vcpu->online)
                continue;

            if (vcpupriv->vcpus == 0)
                continue;

            if (!vcpupriv->alias)
                continue;

            curvcpus -= vcpupriv->vcpus;

            if (curvcpus < nvcpus) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("target vm vcpu granularity does not allow the desired vcpu count"));
                return NULL;
            }

            ignore_value(virBitmapSetBit(ret, i));
        }
    }

    if (curvcpus != nvcpus) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("failed to find appropriate hotpluggable vcpus to reach the desired target vcpu count"));
        return NULL;
    }

    return g_steal_pointer(&ret);
}


static int
qemuDomainSetVcpusLive(virQEMUDriver *driver,
                       virQEMUDriverConfig *cfg,
                       virDomainObj *vm,
                       virBitmap *vcpumap,
                       bool enable)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virCgroupEmulatorAllNodesData *emulatorCgroup = NULL;
    ssize_t nextvcpu = -1;
    int ret = -1;

    if (virDomainCgroupEmulatorAllNodesAllow(priv->cgroup, &emulatorCgroup) < 0)
        goto cleanup;

    if (enable) {
        while ((nextvcpu = virBitmapNextSetBit(vcpumap, nextvcpu)) != -1) {
            if (qemuDomainHotplugAddVcpu(driver, cfg, vm, nextvcpu) < 0)
                goto cleanup;
        }
    } else {
        for (nextvcpu = virDomainDefGetVcpusMax(vm->def) - 1; nextvcpu >= 0; nextvcpu--) {
            if (!virBitmapIsBitSet(vcpumap, nextvcpu))
                continue;

            if (qemuDomainHotplugDelVcpu(driver, cfg, vm, nextvcpu) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virDomainCgroupEmulatorAllNodesRestore(emulatorCgroup);

    return ret;
}


/**
 * qemuDomainSetVcpusConfig:
 * @def: config/offline definition of a domain
 * @nvcpus: target vcpu count
 *
 * Properly handle cold(un)plug of vcpus:
 * - plug in inactive vcpus/uplug active rather than rewriting state
 * - fix hotpluggable state
 */
static void
qemuDomainSetVcpusConfig(virDomainDef *def,
                         unsigned int nvcpus,
                         bool hotpluggable)
{
    virDomainVcpuDef *vcpu;
    size_t curvcpus = virDomainDefGetVcpus(def);
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    size_t i;

    /* ordering information may become invalid, thus clear it */
    virDomainDefVcpuOrderClear(def);

    if (curvcpus == nvcpus)
        return;

    if (curvcpus < nvcpus) {
        for (i = 0; i < maxvcpus; i++) {
            vcpu = virDomainDefGetVcpu(def, i);

            if (!vcpu)
                continue;

            if (vcpu->online) {
                /* non-hotpluggable vcpus need to be clustered at the beginning,
                 * thus we need to force vcpus to be hotpluggable when we find
                 * vcpus that are hotpluggable and online prior to the ones
                 * we are going to add */
                if (vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES)
                    hotpluggable = true;

                continue;
            }

            vcpu->online = true;
            if (hotpluggable) {
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_YES;
                def->individualvcpus = true;
            } else {
                vcpu->hotpluggable = VIR_TRISTATE_BOOL_NO;
            }

            if (++curvcpus == nvcpus)
                break;
        }
    } else {
        for (i = maxvcpus; i != 0; i--) {
            vcpu = virDomainDefGetVcpu(def, i - 1);

            if (!vcpu || !vcpu->online)
                continue;

            vcpu->online = false;
            vcpu->hotpluggable = VIR_TRISTATE_BOOL_YES;

            if (--curvcpus == nvcpus)
                break;
        }
    }
}


int
qemuDomainSetVcpusInternal(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainDef *def,
                           virDomainDef *persistentDef,
                           unsigned int nvcpus,
                           bool hotpluggable)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virBitmap) vcpumap = NULL;
    bool enable;

    if (def && nvcpus > virDomainDefGetVcpusMax(def)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable vcpus for the live domain: %1$u > %2$u"),
                       nvcpus, virDomainDefGetVcpusMax(def));
        return -1;
    }

    if (persistentDef && nvcpus > virDomainDefGetVcpusMax(persistentDef)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpus is greater than max allowable vcpus for the persistent domain: %1$u > %2$u"),
                       nvcpus, virDomainDefGetVcpusMax(persistentDef));
        return -1;
    }

    if (def) {
        if (!(vcpumap = qemuDomainSelectHotplugVcpuEntities(vm->def, nvcpus,
                                                            &enable)))
            return -1;

        if (qemuDomainSetVcpusLive(driver, cfg, vm, vcpumap, enable) < 0)
            return -1;
    }

    if (persistentDef) {
        qemuDomainSetVcpusConfig(persistentDef, nvcpus, hotpluggable);

        if (virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir) < 0)
            return -1;
    }

    return 0;
}


static void
qemuDomainSetVcpuConfig(virDomainDef *def,
                        virBitmap *map,
                        bool state)
{
    virDomainVcpuDef *vcpu;
    ssize_t next = -1;

    def->individualvcpus = true;

    /* ordering information may become invalid, thus clear it */
    virDomainDefVcpuOrderClear(def);

    while ((next = virBitmapNextSetBit(map, next)) >= 0) {
        if (!(vcpu = virDomainDefGetVcpu(def, next)))
            continue;

        vcpu->online = state;
        vcpu->hotpluggable = VIR_TRISTATE_BOOL_YES;
    }
}


/**
 * qemuDomainFilterHotplugVcpuEntities:
 *
 * Returns a bitmap of hotpluggable vcpu entities that correspond to the logical
 * vcpus requested in @vcpus.
 */
static virBitmap *
qemuDomainFilterHotplugVcpuEntities(virDomainDef *def,
                                    virBitmap *vcpus,
                                    bool state)
{
    qemuDomainVcpuPrivate *vcpupriv;
    virDomainVcpuDef *vcpu;
    g_autoptr(virBitmap) map = virBitmapNewCopy(vcpus);
    ssize_t next = -1;
    size_t i;

    /* make sure that all selected vcpus are in the correct state */
    while ((next = virBitmapNextSetBit(map, next)) >= 0) {
        if (!(vcpu = virDomainDefGetVcpu(def, next)))
            continue;

        if (vcpu->online == state) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("vcpu '%1$zd' is already in requested state"), next);
            return NULL;
        }

        if (vcpu->online && !vcpu->hotpluggable) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("vcpu '%1$zd' can't be hotunplugged"), next);
            return NULL;
        }
    }

    /* Make sure that all vCPUs belonging to a single hotpluggable entity were
     * selected and then de-select any sub-threads of it. */
    next = -1;
    while ((next = virBitmapNextSetBit(map, next)) >= 0) {
        if (!(vcpu = virDomainDefGetVcpu(def, next)))
            continue;

        vcpupriv = QEMU_DOMAIN_VCPU_PRIVATE(vcpu);

        if (vcpupriv->vcpus == 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("vcpu '%1$zd' belongs to a larger hotpluggable entity, but siblings were not selected"), next);
            return NULL;
        }

        for (i = next + 1; i < next + vcpupriv->vcpus; i++) {
            if (!virBitmapIsBitSet(map, i)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("vcpu '%1$zu' was not selected but it belongs to hotpluggable entity '%2$zd-%3$zd' which was partially selected"),
                               i, next, next + vcpupriv->vcpus - 1);
                return NULL;
            }

            /* clear the subthreads */
            ignore_value(virBitmapClearBit(map, i));
        }
    }

    return g_steal_pointer(&map);
}


static int
qemuDomainVcpuValidateConfig(virDomainDef *def,
                             virBitmap *map)
{
    virDomainVcpuDef *vcpu;
    size_t maxvcpus = virDomainDefGetVcpusMax(def);
    ssize_t next;
    ssize_t firstvcpu = -1;

    /* vcpu 0 can't be modified */
    if (virBitmapIsBitSet(map, 0)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("vCPU '0' can't be modified"));
        return -1;
    }

    firstvcpu = virBitmapNextSetBit(map, -1);

    /* non-hotpluggable vcpus need to stay clustered starting from vcpu 0 */
    for (next = firstvcpu + 1; next < maxvcpus; next++) {
        if (!(vcpu = virDomainDefGetVcpu(def, next)))
            continue;

        /* skip vcpus being modified */
        if (virBitmapIsBitSet(map, next))
            continue;

        if (vcpu->online && vcpu->hotpluggable == VIR_TRISTATE_BOOL_NO) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("vcpu '%1$zd' can't be modified as it is followed by non-hotpluggable online vcpus"),
                           firstvcpu);
            return -1;
        }
    }

    return 0;
}


int
qemuDomainSetVcpuInternal(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainDef *def,
                          virDomainDef *persistentDef,
                          virBitmap *map,
                          bool state)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virBitmap) livevcpus = NULL;

    if (def) {
        if (!qemuDomainSupportsVcpuHotplug(vm)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("this qemu version does not support specific vCPU hotplug"));
            return -1;
        }

        if (!(livevcpus = qemuDomainFilterHotplugVcpuEntities(def, map, state)))
            return -1;

        /* Make sure that only one hotpluggable entity is selected.
         * qemuDomainSetVcpusLive allows setting more at once but error
         * resolution in case of a partial failure is hard, so don't let users
         * do so */
        if (virBitmapCountBits(livevcpus) != 1) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("only one hotpluggable entity can be selected"));
            return -1;
        }
    }

    if (persistentDef) {
        if (qemuDomainVcpuValidateConfig(persistentDef, map) < 0)
            return -1;
    }

    if (livevcpus &&
        qemuDomainSetVcpusLive(driver, cfg, vm, livevcpus, state) < 0)
        return -1;

    if (persistentDef) {
        qemuDomainSetVcpuConfig(persistentDef, map, state);

        if (virDomainDefSave(persistentDef, driver->xmlopt, cfg->configDir) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainChangeMemoryRequestedSize(virDomainObj *vm,
                                    const char *alias,
                                    unsigned long long requestedsize)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    qemuDomainObjEnterMonitor(vm);
    rc = qemuMonitorChangeMemoryRequestedSize(priv->mon, alias, requestedsize);
    qemuDomainObjExitMonitor(vm);

    return rc;
}


static int
qemuDomainChangeDiskLive(virDomainObj *vm,
                         virDomainDeviceDef *dev,
                         virQEMUDriver *driver,
                         bool force)
{
    virDomainDiskDef *disk = dev->data.disk;
    virDomainDiskDef *orig_disk = NULL;
    virDomainStartupPolicy origStartupPolicy;
    virDomainDeviceDef oldDev = { .type = dev->type };

    if (!(orig_disk = virDomainDiskByTarget(vm->def, disk->dst))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("disk '%1$s' not found"), disk->dst);
        return -1;
    }

    oldDev.data.disk = orig_disk;
    origStartupPolicy = orig_disk->startupPolicy;
    if (virDomainDefCompatibleDevice(vm->def, dev, &oldDev,
                                     VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                     true) < 0)
        return -1;

    if (!qemuDomainDiskChangeSupported(disk, orig_disk))
        return -1;

    if (!virStorageSourceIsSameLocation(disk->src, orig_disk->src)) {
        /* Disk source can be changed only for removable devices */
        if (disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
            disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk source can be changed only in removable drives"));
            return -1;
        }

        /* update startup policy first before updating disk image */
        orig_disk->startupPolicy = dev->data.disk->startupPolicy;

        if (qemuDomainChangeEjectableMedia(driver, vm, orig_disk,
                                           dev->data.disk->src, force) < 0) {
            /* revert startup policy before failing */
            orig_disk->startupPolicy = origStartupPolicy;
            return -1;
        }

        dev->data.disk->src = NULL;
    }

    /* in case when we aren't updating disk source we update startup policy here */
    orig_disk->startupPolicy = dev->data.disk->startupPolicy;
    orig_disk->snapshot = dev->data.disk->snapshot;

    return 0;
}


static bool
qemuDomainChangeMemoryLiveValidateChange(const virDomainMemoryDef *oldDef,
                                         const virDomainMemoryDef *newDef)
{
    /* The only thing that is allowed to change is 'requestedsize' for
     * virtio-mem model. Check if user isn't trying to sneak in change for
     * something else. */

    switch (oldDef->model) {
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory of model '%1$s'"),
                       virDomainMemoryModelTypeToString(oldDef->model));
        return false;
        break;
    }

    if (oldDef->model != newDef->model) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory model from '%1$s' to '%2$s'"),
                       virDomainMemoryModelTypeToString(oldDef->model),
                       virDomainMemoryModelTypeToString(newDef->model));
        return false;
    }

    if (oldDef->access != newDef->access) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory access from '%1$s' to '%2$s'"),
                       virDomainMemoryAccessTypeToString(oldDef->access),
                       virDomainMemoryAccessTypeToString(newDef->access));
        return false;
    }

    if (oldDef->discard != newDef->discard) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory discard from '%1$s' to '%2$s'"),
                       virTristateBoolTypeToString(oldDef->discard),
                       virTristateBoolTypeToString(newDef->discard));
        return false;
    }

    if (!virBitmapEqual(oldDef->source.virtio_mem.nodes,
                        newDef->source.virtio_mem.nodes)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cannot modify memory source nodes"));
        return false;
    }

    if (oldDef->source.virtio_mem.pagesize != newDef->source.virtio_mem.pagesize) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory pagesize from '%1$llu' to '%2$llu'"),
                       oldDef->source.virtio_mem.pagesize,
                       newDef->source.virtio_mem.pagesize);
        return false;
    }

    if (oldDef->targetNode != newDef->targetNode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory targetNode from '%1$d' to '%2$d'"),
                       oldDef->targetNode, newDef->targetNode);
        return false;
    }

    if (oldDef->size != newDef->size) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory size from '%1$llu' to '%2$llu'"),
                       oldDef->size, newDef->size);
        return false;
    }

    if (oldDef->target.virtio_mem.blocksize != newDef->target.virtio_mem.blocksize) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory block size from '%1$llu' to '%2$llu'"),
                       oldDef->target.virtio_mem.blocksize,
                       newDef->target.virtio_mem.blocksize);
        return false;
    }

    /* requestedsize can change */


    if (oldDef->target.virtio_mem.address != newDef->target.virtio_mem.address) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("cannot modify memory address from '0x%1$llx' to '0x%2$llx'"),
                       oldDef->target.virtio_mem.address,
                       newDef->target.virtio_mem.address);
        return false;
    }

    return true;
}


static int
qemuDomainChangeMemoryLive(virQEMUDriver *driver G_GNUC_UNUSED,
                           virDomainObj *vm,
                           virDomainDeviceDef *dev)
{
    virDomainDeviceDef oldDev = { .type = VIR_DOMAIN_DEVICE_MEMORY };
    virDomainMemoryDef *newDef = dev->data.memory;
    virDomainMemoryDef *oldDef = NULL;

    oldDef = virDomainMemoryFindByDeviceInfo(vm->def, &dev->data.memory->info, NULL);
    if (!oldDef) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("memory '%1$s' not found"), dev->data.memory->info.alias);
        return -1;
    }

    oldDev.data.memory = oldDef;

    if (virDomainDefCompatibleDevice(vm->def, dev, &oldDev,
                                     VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                     true) < 0)
        return -1;

    if (!qemuDomainChangeMemoryLiveValidateChange(oldDef, newDef))
        return -1;

    if (qemuDomainChangeMemoryRequestedSize(vm, newDef->info.alias,
                                            newDef->target.virtio_mem.requestedsize) < 0)
        return -1;

    oldDef->target.virtio_mem.requestedsize = newDef->target.virtio_mem.requestedsize;
    return 0;
}


int
qemuDomainUpdateDeviceLive(virDomainObj *vm,
                           virDomainDeviceDef *dev,
                           virQEMUDriver *driver,
                           bool force)
{
    virDomainDeviceDef oldDev = { .type = dev->type };
    int idx;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainObjCheckDiskTaint(driver, vm, dev->data.disk, NULL);
        return qemuDomainChangeDiskLive(vm, dev, driver, force);

    case VIR_DOMAIN_DEVICE_GRAPHICS:
        if ((idx = qemuDomainFindGraphicsIndex(vm->def, dev->data.graphics)) >= 0) {
            oldDev.data.graphics = vm->def->graphics[idx];
            if (virDomainDefCompatibleDevice(vm->def, dev, &oldDev,
                                             VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                             true) < 0)
                return -1;
        }

        return qemuDomainChangeGraphics(driver, vm, dev->data.graphics);

    case VIR_DOMAIN_DEVICE_NET:
        if ((idx = virDomainNetFindIdx(vm->def, dev->data.net)) >= 0) {
            oldDev.data.net = vm->def->nets[idx];
            if (virDomainDefCompatibleDevice(vm->def, dev, &oldDev,
                                             VIR_DOMAIN_DEVICE_ACTION_UPDATE,
                                             true) < 0)
                return -1;
        }

        return qemuDomainChangeNet(driver, vm, dev);

    case VIR_DOMAIN_DEVICE_MEMORY:
        return qemuDomainChangeMemoryLive(driver, vm, dev);

    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("live update of device '%1$s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        return -1;
    }

    return -1;
}
