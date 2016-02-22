/*
 * qemu_hotplug.c: QEMU device hotplug management
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#include <config.h>

#include "qemu_hotplug.h"
#include "qemu_hotplugpriv.h"
#include "qemu_alias.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"
#include "qemu_command.h"
#include "qemu_hostdev.h"
#include "qemu_interface.h"
#include "domain_audit.h"
#include "netdev_bandwidth_conf.h"
#include "domain_nwfilter.h"
#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virfile.h"
#include "virprocess.h"
#include "qemu_cgroup.h"
#include "locking/domain_lock.h"
#include "network/bridge_driver.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevtap.h"
#include "virnetdevopenvswitch.h"
#include "virnetdevmidonet.h"
#include "device_conf.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "virtime.h"
#include "storage/storage_driver.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_hotplug");

#define CHANGE_MEDIA_TIMEOUT 5000

/* Wait up to 5 seconds for device removal to finish. */
unsigned long long qemuDomainRemoveDeviceWaitTime = 1000ull * 5;


/**
 * qemuDomainPrepareDisk:
 * @driver: qemu driver struct
 * @vm: domain object
 * @disk: disk to prepare
 * @overridesrc: Source different than @disk->src when necessary
 * @teardown: Teardown the disk instead of adding it to a vm
 *
 * Setup the locks, cgroups and security permissions on a disk of a VM.
 * If @overridesrc is specified the source struct is used instead of the
 * one present in @disk. If @teardown is true, then the labels and cgroups
 * are removed instead.
 *
 * Returns 0 on success and -1 on error. Reports libvirt error.
 */
static int
qemuDomainPrepareDisk(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainDiskDefPtr disk,
                      virStorageSourcePtr overridesrc,
                      bool teardown)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;
    virStorageSourcePtr origsrc = NULL;

    if (overridesrc) {
        origsrc = disk->src;
        disk->src = overridesrc;
    }

    /* just tear down the disk access */
    if (teardown) {
        ret = 0;
        goto rollback_cgroup;
    }

    if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                vm, disk) < 0)
        goto cleanup;

    if (virSecurityManagerSetDiskLabel(driver->securityManager,
                                       vm->def, disk) < 0)
        goto rollback_lock;

    if (qemuSetupDiskCgroup(vm, disk) < 0)
        goto rollback_label;

    ret = 0;
    goto cleanup;

 rollback_cgroup:
    if (qemuTeardownDiskCgroup(vm, disk) < 0)
        VIR_WARN("Unable to tear down cgroup access on %s",
                 virDomainDiskGetSource(disk));

 rollback_label:
    if (virSecurityManagerRestoreDiskLabel(driver->securityManager,
                                           vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s",
                 virDomainDiskGetSource(disk));

 rollback_lock:
    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s",
                 virDomainDiskGetSource(disk));

 cleanup:
    if (origsrc)
        disk->src = origsrc;

    virObjectUnref(cfg);

    return ret;
}


/**
 * qemuDomainChangeEjectableMedia:
 * @driver: qemu driver structure
 * @conn: connection structure
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
int
qemuDomainChangeEjectableMedia(virQEMUDriverPtr driver,
                               virConnectPtr conn,
                               virDomainObjPtr vm,
                               virDomainDiskDefPtr disk,
                               virStorageSourcePtr newsrc,
                               bool force)
{
    int ret = -1, rc;
    char *driveAlias = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    const char *format = NULL;
    char *sourcestr = NULL;
    bool ejectRetry = false;
    unsigned long long now;

    if (!disk->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %s"), disk->dst);
        goto cleanup;
    }

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Removable media not supported for %s device"),
                       virDomainDiskDeviceTypeToString(disk->device));
        goto cleanup;
    }

    if (qemuDomainPrepareDisk(driver, vm, disk, newsrc, false) < 0)
        goto cleanup;

    if (!(driveAlias = qemuDeviceDriveHostAlias(disk, priv->qemuCaps)))
        goto error;

    do {
        qemuDomainObjEnterMonitor(driver, vm);
        rc = qemuMonitorEjectMedia(priv->mon, driveAlias, force);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;

        if (rc == -2) {
            /* we've already tried, error out */
            if (ejectRetry)
                goto error;
            VIR_DEBUG("tray is locked, wait for the guest to unlock "
                      "the tray and try to eject it again");
            ejectRetry = true;
        } else if (rc < 0) {
            goto error;
        }

        if (virTimeMillisNow(&now) < 0)
            goto error;

        while (disk->tray_status != VIR_DOMAIN_DISK_TRAY_OPEN) {
            if (virDomainObjWaitUntil(vm, now + CHANGE_MEDIA_TIMEOUT) != 0)
                goto error;
        }
    } while (ejectRetry && rc != 0);

    if (!virStorageSourceIsEmpty(newsrc)) {
        if (qemuGetDriveSourceString(newsrc, conn, &sourcestr) < 0)
            goto error;

        if (virStorageSourceGetActualType(newsrc) != VIR_STORAGE_TYPE_DIR) {
            if (newsrc->format > 0) {
                format = virStorageFileFormatTypeToString(newsrc->format);
            } else {
                if (disk->src->format > 0)
                    format = virStorageFileFormatTypeToString(disk->src->format);
            }
        }
        qemuDomainObjEnterMonitor(driver, vm);
        rc = qemuMonitorChangeMedia(priv->mon,
                                    driveAlias,
                                    sourcestr,
                                    format);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    virDomainAuditDisk(vm, disk->src, newsrc, "update", rc >= 0);

    if (rc < 0)
        goto error;

    /* remove the old source from shared device list */
    ignore_value(qemuRemoveSharedDisk(driver, disk, vm->def->name));
    ignore_value(qemuDomainPrepareDisk(driver, vm, disk, NULL, true));

    virStorageSourceFree(disk->src);
    disk->src = newsrc;
    newsrc = NULL;
    ret = 0;

 cleanup:
    VIR_FREE(driveAlias);
    VIR_FREE(sourcestr);
    return ret;

 error:
    virDomainAuditDisk(vm, disk->src, newsrc, "update", false);
    ignore_value(qemuDomainPrepareDisk(driver, vm, disk, newsrc, true));
    goto cleanup;
}

int
qemuDomainCheckEjectableMedia(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr table = NULL;
    int ret = -1;
    size_t i;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        table = qemuMonitorGetBlockInfo(priv->mon);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    if (!table)
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        struct qemuDomainDiskInfo *info;

        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
            disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
                 continue;
        }

        info = qemuMonitorBlockInfoLookup(table, disk->info.alias);
        if (!info)
            goto cleanup;

        if (info->tray_open && virDomainDiskGetSource(disk))
            ignore_value(virDomainDiskSetSource(disk, NULL));
    }

    ret = 0;

 cleanup:
    virHashFree(table);
    return ret;
}

static int
qemuDomainAttachVirtioDiskDevice(virConnectPtr conn,
                                 virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr disk)
{
    int ret = -1;
    const char* type = virDomainDiskBusTypeToString(disk->bus);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    char *drivestr = NULL;
    char *drivealias = NULL;
    bool releaseaddr = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *src = virDomainDiskGetSource(disk);

    if (!disk->info.type) {
        if (qemuDomainMachineIsS390CCW(vm->def) &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW))
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
    } else {
        if (!qemuCheckCCWS390AddressSupport(vm->def, disk->info, priv->qemuCaps,
                                            disk->dst))
            goto cleanup;
    }

    if (qemuDomainPrepareDisk(driver, vm, disk, NULL, false) < 0)
        goto cleanup;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            if (virDomainCCWAddressAssign(&disk->info, priv->ccwaddrs,
                                          !disk->info.addr.ccw.assigned) < 0)
                goto error;
        } else if (!disk->info.type ||
                    disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            if (virDomainPCIAddressEnsureAddr(priv->pciaddrs, &disk->info) < 0)
                goto error;
        }
        releaseaddr = true;
        if (qemuAssignDeviceDiskAlias(vm->def, disk, priv->qemuCaps) < 0)
            goto error;

        if (!(drivestr = qemuBuildDriveStr(conn, disk, false, priv->qemuCaps)))
            goto error;

        if (!(drivealias = qemuDeviceDriveHostAlias(disk, priv->qemuCaps)))
            goto error;

        if (!(devstr = qemuBuildDriveDevStr(vm->def, disk, 0, priv->qemuCaps)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
        goto error;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        ret = qemuMonitorAddDrive(priv->mon, drivestr);
        if (ret == 0) {
            ret = qemuMonitorAddDevice(priv->mon, devstr);
            if (ret < 0) {
                virErrorPtr orig_err = virSaveLastError();
                if (!drivealias ||
                    qemuMonitorDriveDel(priv->mon, drivealias) < 0) {
                    VIR_WARN("Unable to remove drive %s (%s) after failed "
                             "qemuMonitorAddDevice",
                             NULLSTR(drivealias), drivestr);
                }
                if (orig_err) {
                    virSetError(orig_err);
                    virFreeError(orig_err);
                }
            }
        }
    } else if (!disk->info.type ||
                disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virDevicePCIAddress guestAddr = disk->info.addr.pci;
        ret = qemuMonitorAddPCIDisk(priv->mon, src, type, &guestAddr);
        if (ret == 0) {
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            memcpy(&disk->info.addr.pci, &guestAddr, sizeof(guestAddr));
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        releaseaddr = false;
        ret = -1;
        goto error;
    }

    virDomainAuditDisk(vm, NULL, disk->src, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

 cleanup:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);
    VIR_FREE(drivealias);
    virObjectUnref(cfg);
    return ret;

 error:
    if (releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, &disk->info, src);

    ignore_value(qemuDomainPrepareDisk(driver, vm, disk, NULL, true));
    goto cleanup;
}


int qemuDomainAttachControllerDevice(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainControllerDefPtr controller)
{
    int ret = -1;
    const char* type = virDomainControllerTypeToString(controller->type);
    char *devstr = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool releaseaddr = false;

    if (controller->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("'%s' controller cannot be hot plugged."),
                       virDomainControllerTypeToString(controller->type));
        return -1;
    }

    if (virDomainControllerFind(vm->def, controller->type, controller->idx) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %s:%d already exists"),
                       type, controller->idx);
        return -1;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            if (qemuDomainMachineIsS390CCW(vm->def) &&
                virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW))
                controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
            else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
                controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
        } else {
            if (!qemuCheckCCWS390AddressSupport(vm->def, controller->info,
                                                priv->qemuCaps, "controller"))
                goto cleanup;
        }

        if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
            controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            if (virDomainPCIAddressEnsureAddr(priv->pciaddrs, &controller->info) < 0)
                goto cleanup;
        } else if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            if (virDomainCCWAddressAssign(&controller->info, priv->ccwaddrs,
                                          !controller->info.addr.ccw.assigned) < 0)
                goto cleanup;
        }
        releaseaddr = true;
        if (qemuAssignDeviceControllerAlias(vm->def, priv->qemuCaps, controller) < 0)
            goto cleanup;

        if (!(devstr = qemuBuildControllerDevStr(vm->def, controller, priv->qemuCaps, NULL)))
            goto cleanup;
    }

    if (VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers+1) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    } else {
        ret = qemuMonitorAttachPCIDiskController(priv->mon,
                                                 type,
                                                 &controller->info.addr.pci);
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        releaseaddr = false;
        ret = -1;
        goto cleanup;
    }

    if (ret == 0) {
        if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        virDomainControllerInsertPreAlloced(vm->def, controller);
    }

 cleanup:
    if (ret != 0 && releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, &controller->info, NULL);

    VIR_FREE(devstr);
    return ret;
}

static virDomainControllerDefPtr
qemuDomainFindOrCreateSCSIDiskController(virQEMUDriverPtr driver,
                                         virDomainObjPtr vm,
                                         int controller)
{
    size_t i;
    virDomainControllerDefPtr cont;

    for (i = 0; i < vm->def->ncontrollers; i++) {
        cont = vm->def->controllers[i];

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (cont->idx == controller)
            return cont;
    }

    /* No SCSI controller present, for backward compatibility we
     * now hotplug a controller */
    if (VIR_ALLOC(cont) < 0)
        return NULL;
    cont->type = VIR_DOMAIN_CONTROLLER_TYPE_SCSI;
    cont->idx = controller;
    cont->model = -1;

    VIR_INFO("No SCSI controller present, hotplugging one");
    if (qemuDomainAttachControllerDevice(driver,
                                         vm, cont) < 0) {
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
qemuDomainAttachSCSIDisk(virConnectPtr conn,
                         virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainDiskDefPtr disk)
{
    size_t i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainControllerDefPtr cont = NULL;
    char *drivestr = NULL;
    char *devstr = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainPrepareDisk(driver, vm, disk, NULL, false) < 0)
        goto cleanup;

    /* We should have an address already, so make sure */
    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk address type %s"),
                       virDomainDeviceAddressTypeToString(disk->info.type));
        goto error;
    }

    /* Let's make sure our disk has a controller defined and loaded
     * before trying add the disk. The controller the disk is going
     * to use must exist before a qemu command line string is generated.
     */
    for (i = 0; i <= disk->info.addr.drive.controller; i++) {
        cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, i);
        if (!cont)
            goto error;
    }

    /* Tell clang that "cont" is non-NULL.
       This is because disk->info.addr.driver.controller is unsigned,
       and hence the above loop must iterate at least once.  */
    sa_assert(cont);

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceDiskAlias(vm->def, disk, priv->qemuCaps) < 0)
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(vm->def, disk, 0, priv->qemuCaps)))
            goto error;
    }

    if (!(drivestr = qemuBuildDriveStr(conn, disk, false, priv->qemuCaps)))
        goto error;

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
        goto error;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        ret = qemuMonitorAddDrive(priv->mon, drivestr);
        if (ret == 0) {
            ret = qemuMonitorAddDevice(priv->mon, devstr);
            if (ret < 0) {
                VIR_WARN("qemuMonitorAddDevice failed on %s (%s)",
                         drivestr, devstr);
                /* XXX should call 'drive_del' on error but this does not
                   exist yet */
            }
        }
    } else {
        if (cont->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("SCSI controller %d was missing its PCI address"),
                           cont->idx);
            goto error;
        }

        virDomainDeviceDriveAddress driveAddr;
        ret = qemuMonitorAttachDrive(priv->mon,
                                     drivestr,
                                     &cont->info.addr.pci,
                                     &driveAddr);
        if (ret == 0) {
            /* XXX we should probably validate that the addr matches
             * our existing defined addr instead of overwriting */
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
            disk->info.addr.drive.bus = driveAddr.bus;
            disk->info.addr.drive.unit = driveAddr.unit;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto error;
    }

    virDomainAuditDisk(vm, NULL, disk->src, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

 cleanup:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);
    virObjectUnref(cfg);
    return ret;

 error:
    ignore_value(qemuDomainPrepareDisk(driver, vm, disk, NULL, true));
    goto cleanup;
}


static int
qemuDomainAttachUSBMassStorageDevice(virConnectPtr conn,
                                     virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDiskDefPtr disk)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    char *drivestr = NULL;
    char *devstr = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *src = virDomainDiskGetSource(disk);

    if (qemuDomainPrepareDisk(driver, vm, disk, NULL, false) < 0)
        goto cleanup;

    /* XXX not correct once we allow attaching a USB CDROM */
    if (!src) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("disk source path is missing"));
        goto error;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceDiskAlias(vm->def, disk, priv->qemuCaps) < 0)
            goto error;
        if (!(drivestr = qemuBuildDriveStr(conn, disk, false, priv->qemuCaps)))
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(vm->def, disk, 0, priv->qemuCaps)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0)
        goto error;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        ret = qemuMonitorAddDrive(priv->mon, drivestr);
        if (ret == 0) {
            ret = qemuMonitorAddDevice(priv->mon, devstr);
            if (ret < 0) {
                VIR_WARN("qemuMonitorAddDevice failed on %s (%s)",
                         drivestr, devstr);
                /* XXX should call 'drive_del' on error but this does not
                   exist yet */
            }
        }
    } else {
        ret = qemuMonitorAddUSBDisk(priv->mon, src);
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto error;
    }

    virDomainAuditDisk(vm, NULL, disk->src, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

 cleanup:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);
    virObjectUnref(cfg);
    return ret;

 error:
    ignore_value(qemuDomainPrepareDisk(driver, vm, disk, NULL, true));
    goto cleanup;
}


int
qemuDomainAttachDeviceDiskLive(virConnectPtr conn,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    size_t i;
    virDomainDiskDefPtr disk = dev->data.disk;
    virDomainDiskDefPtr orig_disk = NULL;
    int ret = -1;
    const char *src = virDomainDiskGetSource(disk);

    if (STRNEQ_NULLABLE(virDomainDiskGetDriver(disk), "qemu")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported driver name '%s' for disk '%s'"),
                       virDomainDiskGetDriver(disk), src);
        goto cleanup;
    }

    if (virStorageTranslateDiskSourcePool(conn, disk) < 0)
        goto cleanup;

    if (qemuAddSharedDevice(driver, dev, vm->def->name) < 0)
        goto cleanup;

    if (qemuSetUnprivSGIO(dev) < 0)
        goto cleanup;

    if (qemuDomainDetermineDiskChain(driver, vm, disk, false, true) < 0)
        goto cleanup;

    switch ((virDomainDiskDevice) disk->device)  {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        if (!(orig_disk = virDomainDiskFindByBusAndDst(vm->def,
                                                       disk->bus, disk->dst))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No device with bus '%s' and target '%s'. "
                             "cdrom and floppy device hotplug isn't supported "
                             "by libvirt"),
                           virDomainDiskBusTypeToString(disk->bus),
                           disk->dst);
            goto cleanup;
        }

        if (qemuDomainChangeEjectableMedia(driver, conn, vm, orig_disk,
                                           disk->src, false) < 0)
            goto cleanup;

        disk->src = NULL;
        ret = 0;
        break;

    case VIR_DOMAIN_DISK_DEVICE_DISK:
    case VIR_DOMAIN_DISK_DEVICE_LUN:
        for (i = 0; i < vm->def->ndisks; i++) {
            if (virDomainDiskDefCheckDuplicateInfo(vm->def->disks[i], disk) < 0)
                goto cleanup;
        }

        switch ((virDomainDiskBus) disk->bus) {
        case VIR_DOMAIN_DISK_BUS_USB:
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("disk device='lun' is not supported for usb bus"));
                break;
            }
            ret = qemuDomainAttachUSBMassStorageDevice(conn, driver, vm, disk);
            break;

        case VIR_DOMAIN_DISK_BUS_VIRTIO:
            ret = qemuDomainAttachVirtioDiskDevice(conn, driver, vm, disk);
            break;

        case VIR_DOMAIN_DISK_BUS_SCSI:
            ret = qemuDomainAttachSCSIDisk(conn, driver, vm, disk);
            break;

        case VIR_DOMAIN_DISK_BUS_IDE:
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
        case VIR_DOMAIN_DISK_BUS_LAST:
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("disk bus '%s' cannot be hotplugged."),
                           virDomainDiskBusTypeToString(disk->bus));
        }
        break;

    case VIR_DOMAIN_DISK_DEVICE_LAST:
        break;
    }

 cleanup:
    if (ret != 0)
        ignore_value(qemuRemoveSharedDevice(driver, dev, vm->def->name));
    return ret;
}


/* XXX conn required for network -> bridge resolution */
int qemuDomainAttachNetDevice(virConnectPtr conn,
                              virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainNetDefPtr net)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char **tapfdName = NULL;
    int *tapfd = NULL;
    size_t tapfdSize = 0;
    char **vhostfdName = NULL;
    int *vhostfd = NULL;
    size_t vhostfdSize = 0;
    char *nicstr = NULL;
    char *netstr = NULL;
    virNetDevVPortProfilePtr vport = NULL;
    int ret = -1;
    virDevicePCIAddress guestAddr;
    int vlan;
    bool releaseaddr = false;
    bool iface_connected = false;
    int actualType;
    virNetDevBandwidthPtr actualBandwidth;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    /* preallocate new slot for device */
    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets + 1) < 0)
        goto cleanup;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (networkAllocateActualDevice(vm->def, net) < 0)
        goto cleanup;

    actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* This is really a "smart hostdev", so it should be attached
         * as a hostdev (the hostdev code will reach over into the
         * netdev-specific code as appropriate), then also added to
         * the nets list (see cleanup:) if successful.
         */
        ret = qemuDomainAttachHostDevice(conn, driver, vm,
                                         virDomainNetGetActualHostdev(net));
        goto cleanup;
    }

    /* Currently nothing besides TAP devices supports multiqueue. */
    if (net->driver.virtio.queues > 0 &&
        !(actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
          actualType == VIR_DOMAIN_NET_TYPE_BRIDGE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Multiqueue network is not supported for: %s"),
                       virDomainNetTypeToString(actualType));
        return -1;
    }

    /* and only TAP devices support nwfilter rules */
    if (net->filter &&
        !(actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
          actualType == VIR_DOMAIN_NET_TYPE_BRIDGE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("filterref is not supported for "
                         "network interfaces of type %s"),
                       virDomainNetTypeToString(actualType));
        return -1;
    }

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        actualType == VIR_DOMAIN_NET_TYPE_NETWORK) {
        tapfdSize = vhostfdSize = net->driver.virtio.queues;
        if (!tapfdSize)
            tapfdSize = vhostfdSize = 1;
        if (VIR_ALLOC_N(tapfd, tapfdSize) < 0)
            goto cleanup;
        memset(tapfd, -1, sizeof(*tapfd) * tapfdSize);
        if (VIR_ALLOC_N(vhostfd, vhostfdSize) < 0)
            goto cleanup;
        memset(vhostfd, -1, sizeof(*vhostfd) * vhostfdSize);
        if (qemuInterfaceBridgeConnect(vm->def, driver, net,
                                       tapfd, &tapfdSize) < 0)
            goto cleanup;
        iface_connected = true;
        if (qemuInterfaceOpenVhostNet(vm->def, net, priv->qemuCaps,
                                      vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        tapfdSize = vhostfdSize = net->driver.virtio.queues;
        if (!tapfdSize)
            tapfdSize = vhostfdSize = 1;
        if (VIR_ALLOC_N(tapfd, tapfdSize) < 0)
            goto cleanup;
        memset(tapfd, -1, sizeof(*tapfd) * tapfdSize);
        if (VIR_ALLOC_N(vhostfd, vhostfdSize) < 0)
            goto cleanup;
        memset(vhostfd, -1, sizeof(*vhostfd) * vhostfdSize);
        if (qemuInterfaceDirectConnect(vm->def, driver, net,
                                       tapfd, tapfdSize,
                                       VIR_NETDEV_VPORT_PROFILE_OP_CREATE) < 0)
            goto cleanup;
        iface_connected = true;
        if (qemuInterfaceOpenVhostNet(vm->def, net, priv->qemuCaps,
                                      vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        vhostfdSize = 1;
        if (VIR_ALLOC(vhostfd) < 0)
            goto cleanup;
        *vhostfd = -1;
        if (qemuInterfaceOpenVhostNet(vm->def, net, priv->qemuCaps,
                                      vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    }

    /* Set device online immediately */
    if (qemuInterfaceStartDevice(net) < 0)
        goto cleanup;

    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportBandwidth(actualType)) {
            if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false) < 0)
                goto cleanup;
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet",
                     virDomainNetTypeToString(actualType));
        }
    }

    for (i = 0; i < tapfdSize; i++) {
        if (virSecurityManagerSetTapFDLabel(driver->securityManager,
                                            vm->def, tapfd[i]) < 0)
            goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceNetAlias(vm->def, net, -1) < 0)
            goto cleanup;
    }

    if (qemuDomainMachineIsS390CCW(vm->def) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        if (virDomainCCWAddressAssign(&net->info, priv->ccwaddrs,
                                      !net->info.addr.ccw.assigned) < 0)
            goto cleanup;
    } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("virtio-s390 net device cannot be hotplugged."));
        goto cleanup;
    } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
               virDomainPCIAddressEnsureAddr(priv->pciaddrs, &net->info) < 0) {
        goto cleanup;
    }

    releaseaddr = true;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        vlan = -1;
    } else {
        vlan = qemuDomainNetVLAN(net);

        if (vlan < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Unable to attach network devices without vlan"));
            goto cleanup;
        }
    }

    if (VIR_ALLOC_N(tapfdName, tapfdSize) < 0 ||
        VIR_ALLOC_N(vhostfdName, vhostfdSize) < 0)
        goto cleanup;

    for (i = 0; i < tapfdSize; i++) {
        if (virAsprintf(&tapfdName[i], "fd-%s%zu", net->info.alias, i) < 0)
            goto cleanup;
    }

    for (i = 0; i < vhostfdSize; i++) {
        if (virAsprintf(&vhostfdName[i], "vhostfd-%s%zu", net->info.alias, i) < 0)
            goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (!(netstr = qemuBuildHostNetStr(net, driver,
                                           ',', -1,
                                           tapfdName, tapfdSize,
                                           vhostfdName, vhostfdSize)))
            goto cleanup;
    } else {
        if (!(netstr = qemuBuildHostNetStr(net, driver,
                                           ' ', vlan,
                                           tapfdName, tapfdSize,
                                           vhostfdName, vhostfdSize)))
            goto cleanup;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorAddNetdev(priv->mon, netstr,
                                 tapfd, tapfdName, tapfdSize,
                                 vhostfd, vhostfdName, vhostfdSize) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorAddHostNetwork(priv->mon, netstr,
                                      tapfd, tapfdName, tapfdSize,
                                      vhostfd, vhostfdName, vhostfdSize) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto cleanup;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    for (i = 0; i < tapfdSize; i++)
        VIR_FORCE_CLOSE(tapfd[i]);
    for (i = 0; i < vhostfdSize; i++)
        VIR_FORCE_CLOSE(vhostfd[i]);

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (!(nicstr = qemuBuildNicDevStr(vm->def, net, vlan, 0,
                                          vhostfdSize, priv->qemuCaps)))
            goto try_remove;
    } else {
        if (!(nicstr = qemuBuildNicStr(net, NULL, vlan)))
            goto try_remove;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorAddDevice(priv->mon, nicstr) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto try_remove;
        }
    } else {
        guestAddr = net->info.addr.pci;
        if (qemuMonitorAddPCINetwork(priv->mon, nicstr,
                                     &guestAddr) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto try_remove;
        }
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        memcpy(&net->info.addr.pci, &guestAddr, sizeof(guestAddr));
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    /* set link state */
    if (net->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) {
        if (!net->info.alias) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("device alias not found: cannot set link state to down"));
        } else {
            qemuDomainObjEnterMonitor(driver, vm);

            if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV)) {
                if (qemuMonitorSetLink(priv->mon, net->info.alias, VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) < 0) {
                    ignore_value(qemuDomainObjExitMonitor(driver, vm));
                    virDomainAuditNet(vm, NULL, net, "attach", false);
                    goto try_remove;
                }
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("setting of link state not supported: Link is up"));
            }

            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
        }
        /* link set to down */
    }

    virDomainAuditNet(vm, NULL, net, "attach", true);

    ret = 0;

 cleanup:
    if (!ret) {
        vm->def->nets[vm->def->nnets++] = net;
    } else {
        if (releaseaddr)
            qemuDomainReleaseDeviceAddress(vm, &net->info, NULL);

        if (iface_connected) {
            virDomainConfNWFilterTeardown(net);

            if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
                ignore_value(virNetDevMacVLanDeleteWithVPortProfile(
                                 net->ifname, &net->mac,
                                 virDomainNetGetActualDirectDev(net),
                                 virDomainNetGetActualDirectMode(net),
                                 virDomainNetGetActualVirtPortProfile(net),
                                 cfg->stateDir));
            }

            vport = virDomainNetGetActualVirtPortProfile(net);
            if (vport) {
                if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
                    ignore_value(virNetDevMidonetUnbindPort(vport));
                } else if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
                    ignore_value(virNetDevOpenvswitchRemovePort(
                                     virDomainNetGetActualBridgeName(net),
                                     net->ifname));
                }
            }
        }

        virDomainNetRemoveHostdev(vm->def, net);

        networkReleaseActualDevice(vm->def, net);
    }

    VIR_FREE(nicstr);
    VIR_FREE(netstr);
    for (i = 0; tapfd && i < tapfdSize; i++) {
        VIR_FORCE_CLOSE(tapfd[i]);
        if (tapfdName)
            VIR_FREE(tapfdName[i]);
    }
    VIR_FREE(tapfd);
    VIR_FREE(tapfdName);
    for (i = 0; vhostfd && i < vhostfdSize; i++) {
        VIR_FORCE_CLOSE(vhostfd[i]);
        if (vhostfdName)
            VIR_FREE(vhostfdName[i]);
    }
    VIR_FREE(vhostfd);
    VIR_FREE(vhostfdName);
    virObjectUnref(cfg);

    return ret;

 try_remove:
    if (!virDomainObjIsActive(vm))
        goto cleanup;

    if (vlan < 0) {
        if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
            char *netdev_name;
            if (virAsprintf(&netdev_name, "host%s", net->info.alias) < 0)
                goto cleanup;
            qemuDomainObjEnterMonitor(driver, vm);
            if (qemuMonitorRemoveNetdev(priv->mon, netdev_name) < 0)
                VIR_WARN("Failed to remove network backend for netdev %s",
                         netdev_name);
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            VIR_FREE(netdev_name);
        } else {
            VIR_WARN("Unable to remove network backend");
        }
    } else {
        char *hostnet_name;
        if (virAsprintf(&hostnet_name, "host%s", net->info.alias) < 0)
            goto cleanup;
        qemuDomainObjEnterMonitor(driver, vm);
        if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0)
            VIR_WARN("Failed to remove network backend for vlan %d, net %s",
                     vlan, hostnet_name);
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        VIR_FREE(hostnet_name);
    }
    goto cleanup;
}


static int
qemuDomainAttachHostPCIDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr hostdev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;
    char *devstr = NULL;
    int configfd = -1;
    char *configfd_name = NULL;
    bool releaseaddr = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    int backend;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned int flags = 0;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1) < 0)
        return -1;

    if (!cfg->relaxedACS)
        flags |= VIR_HOSTDEV_STRICT_ACS_CHECK;
    if (qemuHostdevPreparePCIDevices(driver, vm->def->name, vm->def->uuid,
                                     &hostdev, 1, priv->qemuCaps, flags) < 0)
        goto cleanup;

    /* this could have been changed by qemuHostdevPreparePCIDevices */
    backend = hostdev->source.subsys.u.pci.backend;

    switch ((virDomainHostdevSubsysPCIBackendType) backend) {
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VFIO PCI device assignment is not "
                             "supported by this version of qemu"));
            goto error;
        }
        break;

    default:
        break;
    }

    /* Temporarily add the hostdev to the domain definition. This is needed
     * because qemuDomainAdjustMaxMemLock() requires the hostdev to be already
     * part of the domain definition, but other functions like
     * qemuAssignDeviceHostdevAlias() used below expect it *not* to be there.
     * A better way to handle this would be nice */
    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;
    if (qemuDomainAdjustMaxMemLock(vm) < 0) {
        vm->def->hostdevs[--(vm->def->nhostdevs)] = NULL;
        goto error;
    }
    vm->def->hostdevs[--(vm->def->nhostdevs)] = NULL;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto error;
    teardowncgroup = true;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, hostdev, NULL) < 0)
        goto error;
    if (backend != VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO)
        teardownlabel = true;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (virDomainPCIAddressEnsureAddr(priv->pciaddrs, hostdev->info) < 0)
            goto error;
        releaseaddr = true;
        if (backend != VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_PCI_CONFIGFD)) {
            configfd = qemuOpenPCIConfig(hostdev);
            if (configfd >= 0) {
                if (virAsprintf(&configfd_name, "fd-%s",
                                hostdev->info->alias) < 0)
                    goto error;
            }
        }

        if (!virDomainObjIsActive(vm)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest unexpectedly quit during hotplug"));
            goto error;
        }

        if (!(devstr = qemuBuildPCIHostdevDevStr(vm->def, hostdev, 0,
                                                 configfd_name, priv->qemuCaps)))
            goto error;

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorAddDeviceWithFd(priv->mon, devstr,
                                         configfd, configfd_name);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto error;
    } else {
        virDevicePCIAddressPtr guestAddr = &hostdev->info->addr.pci;
        virDevicePCIAddressPtr hostAddr = &hostdev->source.subsys.u.pci.addr;

        if (hostAddr->domain &&
            !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_HOST_PCI_MULTIDOMAIN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("non-zero domain='%.4x' in host device "
                             "PCI address not supported in this QEMU binary"),
                           hostAddr->domain);
            goto error;
        }

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorAddPCIHostDevice(priv->mon, hostAddr, guestAddr);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto error;

        hostdev->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    }
    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);
    virObjectUnref(cfg);

    return 0;

 error:
    if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
    if (teardownlabel &&
        virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def, hostdev, NULL) < 0)
        VIR_WARN("Unable to restore host device labelling on hotplug fail");

    if (releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, hostdev->info, NULL);

    qemuHostdevReAttachPCIDevices(driver, vm->def->name, &hostdev, 1);

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);

 cleanup:
    virObjectUnref(cfg);
    return -1;
}


int qemuDomainAttachRedirdevDevice(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainRedirdevDefPtr redirdev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    char *charAlias = NULL;
    char *devstr = NULL;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("redirected devices are not supported by this QEMU"));
        return ret;
    }

    if (qemuAssignDeviceRedirdevAlias(vm->def, redirdev, -1) < 0)
        goto cleanup;

    if (virAsprintf(&charAlias, "char%s", redirdev->info.alias) < 0)
        goto cleanup;

    if (!(devstr = qemuBuildRedirdevDevStr(def, redirdev, priv->qemuCaps)))
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->redirdevs, vm->def->nredirdevs+1) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorAttachCharDev(priv->mon,
                                 charAlias,
                                 &(redirdev->source.chr)) < 0) {
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto audit;
    }

    if (qemuMonitorAddDevice(priv->mon, devstr) < 0) {
        /* detach associated chardev on error */
        qemuMonitorDetachCharDev(priv->mon, charAlias);
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto audit;
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto audit;

    vm->def->redirdevs[vm->def->nredirdevs++] = redirdev;
    ret = 0;
 audit:
    virDomainAuditRedirdev(vm, redirdev, "attach", ret == 0);
 cleanup:
    VIR_FREE(charAlias);
    VIR_FREE(devstr);
    return ret;
}

static int
qemuDomainChrPreInsert(virDomainDefPtr vmdef,
                       virDomainChrDefPtr chr)
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

    /* Due to some crazy backcompat stuff, the first serial device is an alias
     * to the first console too. If this is the case, the definition must be
     * duplicated as first console device. */
    if (vmdef->nserials == 0 && vmdef->nconsoles == 0 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        if (!vmdef->consoles && VIR_ALLOC(vmdef->consoles) < 0)
            return -1;

        if (VIR_ALLOC(vmdef->consoles[0]) < 0) {
            VIR_FREE(vmdef->consoles);
            return -1;
        }
        vmdef->nconsoles++;
    }
    return 0;
}

static void
qemuDomainChrInsertPreAlloced(virDomainDefPtr vmdef,
                              virDomainChrDefPtr chr)
{
    virDomainChrInsertPreAlloced(vmdef, chr);
    if (vmdef->nserials == 1 && vmdef->nconsoles == 0 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        vmdef->nconsoles = 1;

        /* Create an console alias for the serial port */
        vmdef->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        vmdef->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    }
}

static void
qemuDomainChrInsertPreAllocCleanup(virDomainDefPtr vmdef,
                                   virDomainChrDefPtr chr)
{
    /* Remove the stub console added by qemuDomainChrPreInsert */
    if (vmdef->nserials == 0 && vmdef->nconsoles == 1 &&
        chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
        VIR_FREE(vmdef->consoles[0]);
        VIR_FREE(vmdef->consoles);
        vmdef->nconsoles = 0;
    }
}

int
qemuDomainChrInsert(virDomainDefPtr vmdef,
                    virDomainChrDefPtr chr)
{
    if (qemuDomainChrPreInsert(vmdef, chr) < 0) {
        qemuDomainChrInsertPreAllocCleanup(vmdef, chr);
        return -1;
    }
    qemuDomainChrInsertPreAlloced(vmdef, chr);
    return 0;
}

virDomainChrDefPtr
qemuDomainChrRemove(virDomainDefPtr vmdef,
                    virDomainChrDefPtr chr)
{
    virDomainChrDefPtr ret;
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

    if (removeCompat)
        VIR_DELETE_ELEMENT(vmdef->consoles, 0, vmdef->nconsoles);

    return ret;
}

static int
qemuDomainAttachChrDeviceAssignAddr(qemuDomainObjPrivatePtr priv,
                                    virDomainChrDefPtr chr)
{
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO) {
        if (virDomainVirtioSerialAddrAutoAssign(NULL, priv->vioserialaddrs,
                                                &chr->info, true) < 0)
            return -1;
        return 1;

    } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
               chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI) {
        if (virDomainPCIAddressEnsureAddr(priv->pciaddrs, &chr->info) < 0)
            return -1;
        return 1;

    } else if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
               chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO) {
        if (virDomainVirtioSerialAddrAutoAssign(NULL, priv->vioserialaddrs,
                                                &chr->info, false) < 0)
            return -1;
        return 1;
    }

    if (chr->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL ||
        chr->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unsupported address type for character device"));
        return -1;
    }

    return 0;
}

int qemuDomainAttachChrDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainChrDefPtr chr)
{
    int ret = -1, rc;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr vmdef = vm->def;
    char *devstr = NULL;
    char *charAlias = NULL;
    bool need_release = false;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("qemu does not support -device"));
        goto cleanup;
    }

    if (qemuAssignDeviceChrAlias(vmdef, chr, -1) < 0)
        goto cleanup;

    if ((rc = qemuDomainAttachChrDeviceAssignAddr(priv, chr)) < 0)
        goto cleanup;
    if (rc == 1)
        need_release = true;

    if (qemuBuildChrDeviceStr(&devstr, vm->def, chr, priv->qemuCaps) < 0)
        goto cleanup;

    if (virAsprintf(&charAlias, "char%s", chr->info.alias) < 0)
        goto cleanup;

    if (qemuDomainChrPreInsert(vmdef, chr) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorAttachCharDev(priv->mon, charAlias, &chr->source) < 0) {
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto audit;
    }

    if (devstr && qemuMonitorAddDevice(priv->mon, devstr) < 0) {
        /* detach associated chardev on error */
        qemuMonitorDetachCharDev(priv->mon, charAlias);
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto audit;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto audit;

    qemuDomainChrInsertPreAlloced(vm->def, chr);
    ret = 0;
 audit:
    virDomainAuditChardev(vm, NULL, chr, "attach", ret == 0);
 cleanup:
    if (ret < 0 && virDomainObjIsActive(vm))
        qemuDomainChrInsertPreAllocCleanup(vm->def, chr);
    if (ret < 0 && need_release)
        qemuDomainReleaseDeviceAddress(vm, &chr->info, NULL);
    VIR_FREE(charAlias);
    VIR_FREE(devstr);
    return ret;
}


int
qemuDomainAttachRNGDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainRNGDefPtr rng)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    char *charAlias = NULL;
    char *objAlias = NULL;
    virJSONValuePtr props = NULL;
    const char *type;
    int ret = -1;

    if (qemuAssignDeviceRNGAlias(rng, vm->def->nrngs) < 0)
        return -1;

    /* preallocate space for the device definition */
    if (VIR_REALLOC_N(vm->def->rngs, vm->def->nrngs + 1) < 0)
        return -1;

    if (rng->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainMachineIsS390CCW(vm->def) &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
            rng->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
            rng->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
        }
    } else {
        if (!qemuCheckCCWS390AddressSupport(vm->def, rng->info, priv->qemuCaps,
                                            rng->source.file))
            return -1;
    }

    if (rng->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        rng->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        if (virDomainPCIAddressEnsureAddr(priv->pciaddrs, &rng->info) < 0)
            return -1;
    } else if (rng->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        if (virDomainCCWAddressAssign(&rng->info, priv->ccwaddrs,
                                      !rng->info.addr.ccw.assigned) < 0)
            return -1;
    }

    /* build required metadata */
    if (!(devstr = qemuBuildRNGDevStr(vm->def, rng, priv->qemuCaps)))
        goto cleanup;

    if (qemuBuildRNGBackendProps(rng, priv->qemuCaps, &type, &props) < 0)
        goto cleanup;

    if (virAsprintf(&objAlias, "obj%s", rng->info.alias) < 0)
        goto cleanup;

    if (virAsprintf(&charAlias, "char%s", rng->info.alias) < 0)
        goto cleanup;

    /* attach the device - up to a 3 stage process */
    qemuDomainObjEnterMonitor(driver, vm);

    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD &&
        qemuMonitorAttachCharDev(priv->mon, charAlias,
                                 rng->source.chardev) < 0)
        goto failchardev;

    if (qemuMonitorAddObject(priv->mon, type, objAlias, props) < 0)
        goto failbackend;

    if (qemuMonitorAddDevice(priv->mon, devstr) < 0)
        goto failfrontend;

    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        vm = NULL;
        goto cleanup;
    }

    if (virDomainRNGInsert(vm->def, rng, true) < 0)
        goto audit;

    ret = 0;

 audit:
    virDomainAuditRNG(vm, NULL, rng, "attach", ret == 0);
 cleanup:
    if (ret < 0 && vm)
        qemuDomainReleaseDeviceAddress(vm, &rng->info, NULL);
    VIR_FREE(charAlias);
    VIR_FREE(objAlias);
    VIR_FREE(devstr);
    return ret;

    /* rollback */
 failfrontend:
    ignore_value(qemuMonitorDelObject(priv->mon, objAlias));
 failbackend:
    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD)
        ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));
 failchardev:
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        vm = NULL;
        goto cleanup;
    }

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
int
qemuDomainAttachMemory(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       virDomainMemoryDefPtr mem)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned long long oldmem = virDomainDefGetMemoryActual(vm->def);
    unsigned long long newmem = oldmem + mem->size;
    char *devstr = NULL;
    char *objalias = NULL;
    const char *backendType;
    virJSONValuePtr props = NULL;
    virObjectEventPtr event;
    bool fix_balloon = false;
    int id;
    int ret = -1;

    qemuDomainMemoryDeviceAlignSize(vm->def, mem);

    if (qemuDomainDefValidateMemoryHotplug(vm->def, priv->qemuCaps, mem) < 0)
        goto cleanup;

    if (virAsprintf(&mem->info.alias, "dimm%zu", vm->def->nmems) < 0)
        goto cleanup;

    if (virAsprintf(&objalias, "mem%s", mem->info.alias) < 0)
        goto cleanup;

    if (vm->def->mem.cur_balloon == virDomainDefGetMemoryActual(vm->def))
        fix_balloon = true;

    if (!(devstr = qemuBuildMemoryDeviceStr(mem)))
        goto cleanup;

    if (qemuBuildMemoryBackendStr(mem->size, mem->pagesize,
                                  mem->targetNode, mem->sourceNodes, NULL,
                                  vm->def, priv->qemuCaps, cfg,
                                  &backendType, &props, true) < 0)
        goto cleanup;

    if (virDomainMemoryInsert(vm->def, mem) < 0) {
        virJSONValueFree(props);
        goto cleanup;
    }

    if (qemuDomainAdjustMaxMemLock(vm) < 0) {
        virJSONValueFree(props);
        goto removedef;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorAddObject(priv->mon, backendType, objalias, props) < 0)
        goto exit_monitor;

    if (qemuMonitorAddDevice(priv->mon, devstr) < 0) {
        virErrorPtr err = virSaveLastError();
        ignore_value(qemuMonitorDelObject(priv->mon, objalias));
        virSetError(err);
        virFreeError(err);
        goto exit_monitor;
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        /* we shouldn't touch mem now, as the def might be freed */
        mem = NULL;
        goto audit;
    }

    event = virDomainEventDeviceAddedNewFromObj(vm, objalias);
    qemuDomainEventQueue(driver, event);

    /* fix the balloon size if it was set to maximum */
    if (fix_balloon)
        vm->def->mem.cur_balloon += mem->size;

    /* mem is consumed by vm->def */
    mem = NULL;

    /* this step is best effort, removing the device would be so much trouble */
    ignore_value(qemuDomainUpdateMemoryDeviceInfo(driver, vm,
                                                  QEMU_ASYNC_JOB_NONE));

    ret = 0;

 audit:
    virDomainAuditMemory(vm, oldmem, newmem, "update", ret == 0);
 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(devstr);
    VIR_FREE(objalias);
    virDomainMemoryDefFree(mem);
    return ret;

 exit_monitor:
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        mem = NULL;
        goto audit;
    }

 removedef:
    if ((id = virDomainMemoryFindByDef(vm->def, mem)) >= 0)
        mem = virDomainMemoryRemove(vm->def, id);
    else
        mem = NULL;

    /* reset the mlock limit */
    virErrorPtr err = virSaveLastError();
    ignore_value(qemuDomainAdjustMaxMemLock(vm));
    virSetError(err);
    virFreeError(err);

    goto audit;
}


static int
qemuDomainAttachHostUSBDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr hostdev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    bool added = false;
    bool teardowncgroup = false;
    bool teardownlabel = false;
    int ret = -1;

    if (qemuHostdevPrepareUSBDevices(driver, vm->def->name, &hostdev, 1, 0) < 0)
        goto cleanup;

    added = true;

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, hostdev, NULL) < 0)
        goto cleanup;
    teardownlabel = true;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto cleanup;
        if (!(devstr = qemuBuildUSBHostdevDevStr(vm->def, hostdev, priv->qemuCaps)))
            goto cleanup;
    }

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE))
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    else
        ret = qemuMonitorAddUSBDeviceExact(priv->mon,
                                           hostdev->source.subsys.u.usb.bus,
                                           hostdev->source.subsys.u.usb.device);
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto cleanup;
    }
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
            virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                                  vm->def, hostdev, NULL) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
        if (added)
            qemuHostdevReAttachUSBDevices(driver, vm->def->name, &hostdev, 1);
    }
    VIR_FREE(devstr);
    return ret;
}

static int
qemuDomainAttachHostSCSIDevice(virConnectPtr conn,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainControllerDefPtr cont = NULL;
    char *devstr = NULL;
    char *drvstr = NULL;
    bool teardowncgroup = false;
    bool teardownlabel = false;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) ||
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_SCSI_GENERIC)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("SCSI passthrough is not supported by this version of qemu"));
        return -1;
    }

    cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, hostdev->info->addr.drive.controller);
    if (!cont)
        return -1;

    if (qemuHostdevPrepareSCSIDevices(driver, vm->def->name,
                                      &hostdev, 1)) {
        virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;
        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &scsisrc->u.iscsi;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to prepare scsi hostdev for iSCSI: %s"),
                           iscsisrc->path);
        } else {
            virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to prepare scsi hostdev: %s:%u:%u:%llu"),
                           scsihostsrc->adapter, scsihostsrc->bus,
                           scsihostsrc->target, scsihostsrc->unit);
        }
        return -1;
    }

    if (qemuSetupHostdevCgroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, hostdev, NULL) < 0)
        goto cleanup;
    teardownlabel = true;

    if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
        goto cleanup;

    if (!(drvstr = qemuBuildSCSIHostdevDrvStr(conn, hostdev, priv->qemuCaps,
                                              &buildCommandLineCallbacks)))
        goto cleanup;

    if (!(devstr = qemuBuildSCSIHostdevDevStr(vm->def, hostdev, priv->qemuCaps)))
        goto cleanup;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if ((ret = qemuMonitorAddDrive(priv->mon, drvstr)) == 0) {
        if ((ret = qemuMonitorAddDevice(priv->mon, devstr)) < 0) {
            virErrorPtr orig_err = virSaveLastError();
            if (qemuMonitorDriveDel(priv->mon, drvstr) < 0)
                VIR_WARN("Unable to remove drive %s (%s) after failed "
                         "qemuMonitorAddDevice",
                         drvstr, devstr);
            if (orig_err) {
                virSetError(orig_err);
                virFreeError(orig_err);
            }
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0) {
        ret = -1;
        goto cleanup;
    }

    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto cleanup;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    ret = 0;
 cleanup:
    if (ret < 0) {
        qemuHostdevReAttachSCSIDevices(driver, vm->def->name, &hostdev, 1);
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
        if (teardownlabel &&
            virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                                  vm->def, hostdev, NULL) < 0)
            VIR_WARN("Unable to restore host device labelling on hotplug fail");
    }
    VIR_FREE(drvstr);
    VIR_FREE(devstr);
    return ret;
}

int qemuDomainAttachHostDevice(virConnectPtr conn,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (qemuDomainAttachHostPCIDevice(driver, vm,
                                          hostdev) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (qemuDomainAttachHostUSBDevice(driver, vm,
                                          hostdev) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (qemuDomainAttachHostSCSIDevice(conn, driver, vm,
                                           hostdev) < 0)
            goto error;
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev subsys type '%s' not supported"),
                       virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        goto error;
    }

    return 0;

 error:
    return -1;
}

static int
qemuDomainChangeNetBridge(virDomainObjPtr vm,
                          virDomainNetDefPtr olddev,
                          virDomainNetDefPtr newdev)
{
    int ret = -1;
    const char *oldbridge = virDomainNetGetActualBridgeName(olddev);
    const char *newbridge = virDomainNetGetActualBridgeName(newdev);

    if (!oldbridge || !newbridge) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing bridge name"));
        goto cleanup;
    }

    VIR_DEBUG("Change bridge for interface %s: %s -> %s",
              olddev->ifname, oldbridge, newbridge);

    if (virNetDevExists(newbridge) != 1) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("bridge %s doesn't exist"), newbridge);
        goto cleanup;
    }

    if (oldbridge) {
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
    }

    ret = virNetDevBridgeAddPort(newbridge, olddev->ifname);
    virDomainAuditNet(vm, NULL, newdev, "attach", ret == 0);
    if (ret < 0) {
        ret = virNetDevBridgeAddPort(oldbridge, olddev->ifname);
        virDomainAuditNet(vm, NULL, olddev, "attach", ret == 0);
        if (ret < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("unable to recover former state by adding port "
                             "to bridge %s"), oldbridge);
        }
        goto cleanup;
    }
    /* caller will replace entire olddev with newdev in domain nets list */
    ret = 0;
 cleanup:
    return ret;
}

static int
qemuDomainChangeNetFilter(virDomainObjPtr vm,
                          virDomainNetDefPtr olddev,
                          virDomainNetDefPtr newdev)
{
    /* make sure this type of device supports filters. */
    switch (virDomainNetGetActualType(newdev)) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("filters not supported on interfaces of type %s"),
                       virDomainNetTypeToString(virDomainNetGetActualType(newdev)));
        return -1;
    }

    virDomainConfNWFilterTeardown(olddev);

    if (newdev->filter &&
        virDomainConfNWFilterInstantiate(vm->def->uuid, newdev) < 0) {
        virErrorPtr errobj;

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to add new filter rules to '%s' "
                         "- attempting to restore old rules"),
                       olddev->ifname);
        errobj = virSaveLastError();
        ignore_value(virDomainConfNWFilterInstantiate(vm->def->uuid, olddev));
        virSetError(errobj);
        virFreeError(errobj);
        return -1;
    }
    return 0;
}

int qemuDomainChangeNetLinkState(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainNetDefPtr dev,
                                 int linkstate)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!dev->info.alias) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("can't change link state: device alias not found"));
        return -1;
    }

    VIR_DEBUG("dev: %s, state: %d", dev->info.alias, linkstate);

    qemuDomainObjEnterMonitor(driver, vm);

    ret = qemuMonitorSetLink(priv->mon, dev->info.alias, linkstate);
    if (ret < 0)
        goto cleanup;

    /* modify the device configuration */
    dev->linkstate = linkstate;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    return ret;
}

int
qemuDomainChangeNet(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    virDomainDeviceDefPtr dev)
{
    virDomainNetDefPtr newdev = dev->data.net;
    virDomainNetDefPtr *devslot = NULL;
    virDomainNetDefPtr olddev;
    int oldType, newType;
    bool needReconnect = false;
    bool needBridgeChange = false;
    bool needFilterChange = false;
    bool needLinkStateChange = false;
    bool needReplaceDevDef = false;
    bool needBandwidthSet = false;
    int ret = -1;
    int changeidx = -1;

    if ((changeidx = virDomainNetFindIdx(vm->def, newdev)) < 0)
        goto cleanup;
    devslot = &vm->def->nets[changeidx];

    if (!(olddev = *devslot)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("cannot find existing network device to modify"));
        goto cleanup;
    }

    oldType = virDomainNetGetActualType(olddev);
    if (oldType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* no changes are possible to a type='hostdev' interface */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change config of '%s' network type"),
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
                       _("cannot change network interface mac address "
                         "from %s to %s"),
                       virMacAddrFormat(&olddev->mac, oldmac),
                       virMacAddrFormat(&newdev->mac, newmac));
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(olddev->model, newdev->model)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot modify network device model from %s to %s"),
                       olddev->model ? olddev->model : "(default)",
                       newdev->model ? newdev->model : "(default)");
        goto cleanup;
    }

    if (olddev->model && STREQ(olddev->model, "virtio") &&
        (olddev->driver.virtio.name != newdev->driver.virtio.name ||
         olddev->driver.virtio.txmode != newdev->driver.virtio.txmode ||
         olddev->driver.virtio.ioeventfd != newdev->driver.virtio.ioeventfd ||
         olddev->driver.virtio.event_idx != newdev->driver.virtio.event_idx ||
         olddev->driver.virtio.queues != newdev->driver.virtio.queues ||
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
         olddev->driver.virtio.guest.ufo != newdev->driver.virtio.guest.ufo)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify virtio network device driver attributes"));
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
    if (!newdev->ifname && VIR_STRDUP(newdev->ifname, olddev->ifname) < 0)
        goto cleanup;
    if (STRNEQ_NULLABLE(olddev->ifname, newdev->ifname)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device tap name"));
        goto cleanup;
    }

    /* info: if newdev->info is empty, fill it in from olddev,
     * otherwise verify that it matches - nothing is allowed to
     * change. (There is no helper function to do this, so
     * individually check the few feidls of virDomainDeviceInfo that
     * are relevant in this case).
     */
    if (!virDomainDeviceAddressIsValid(&newdev->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        virDomainDeviceInfoCopy(&newdev->info, &olddev->info) < 0) {
        goto cleanup;
    }
    if (!virDevicePCIAddressEqual(&olddev->info.addr.pci,
                                  &newdev->info.addr.pci)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device guest PCI address"));
        goto cleanup;
    }
    /* grab alias from olddev if not set in newdev */
    if (!newdev->info.alias &&
        VIR_STRDUP(newdev->info.alias, olddev->info.alias) < 0)
        goto cleanup;
    if (STRNEQ_NULLABLE(olddev->info.alias, newdev->info.alias)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device alias"));
        goto cleanup;
    }
    if (olddev->info.rombar != newdev->info.rombar) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device rom bar setting"));
        goto cleanup;
    }
    if (STRNEQ_NULLABLE(olddev->info.romfile, newdev->info.romfile)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network rom file"));
        goto cleanup;
    }
    if (olddev->info.bootIndex != newdev->info.bootIndex) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot modify network device boot index setting"));
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

    /* allocate new actual device to compare to old - we will need to
     * free it if we fail for any reason
     */
    if (newdev->type == VIR_DOMAIN_NET_TYPE_NETWORK &&
        networkAllocateActualDevice(vm->def, newdev) < 0) {
        goto cleanup;
    }

    newType = virDomainNetGetActualType(newdev);

    if (newType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* can't turn it into a type='hostdev' interface */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("cannot change network interface type to '%s'"),
                       virDomainNetTypeToString(newType));
        goto cleanup;
    }

    if (olddev->type == newdev->type && oldType == newType) {

        /* if type hasn't changed, check the relevant fields for the type */
        switch (newdev->type) {
        case VIR_DOMAIN_NET_TYPE_USER:
            break;

        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (STRNEQ_NULLABLE(olddev->data.ethernet.dev,
                                newdev->data.ethernet.dev)) {
                needReconnect = true;
            }
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

        default:
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("unable to change config on '%s' network type"),
                           virDomainNetTypeToString(newdev->type));
            break;

        }
    } else {
        /* interface type has changed. There are a few special cases
         * where this can only require a minor (or even no) change,
         * but in most cases we need to do a full reconnection.
         *
         * If we switch (in either direction) between type='bridge'
         * and type='network' (for a traditional managed virtual
         * network that uses a host bridge, i.e. forward
         * mode='route|nat'), we just need to change the bridge.
         */
        if ((oldType == VIR_DOMAIN_NET_TYPE_NETWORK &&
             newType == VIR_DOMAIN_NET_TYPE_BRIDGE) ||
            (oldType == VIR_DOMAIN_NET_TYPE_BRIDGE &&
             newType == VIR_DOMAIN_NET_TYPE_NETWORK)) {

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
        virDomainNetGetActualDirectMode(olddev) != virDomainNetGetActualDirectMode(olddev) ||
        !virNetDevVPortProfileEqual(virDomainNetGetActualVirtPortProfile(olddev),
                                    virDomainNetGetActualVirtPortProfile(newdev)) ||
        !virNetDevVlanEqual(virDomainNetGetActualVlan(olddev),
                            virDomainNetGetActualVlan(newdev))) {
        needReconnect = true;
    }

    if (olddev->linkstate != newdev->linkstate)
        needLinkStateChange = true;

    if (!virNetDevBandwidthEqual(virDomainNetGetActualBandwidth(olddev),
                                 virDomainNetGetActualBandwidth(newdev)))
        needBandwidthSet = true;

    /* FINALLY - actually perform the required actions */

    if (needReconnect) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unable to change config on '%s' network type"),
                       virDomainNetTypeToString(newdev->type));
        goto cleanup;
    }

    if (needBandwidthSet) {
        if (virNetDevBandwidthSet(newdev->ifname,
                                  virDomainNetGetActualBandwidth(newdev),
                                  false) < 0)
            goto cleanup;
        needReplaceDevDef = true;
    }

    if (needBridgeChange) {
        if (qemuDomainChangeNetBridge(vm, olddev, newdev) < 0)
            goto cleanup;
        /* we successfully switched to the new bridge, and we've
         * determined that the rest of newdev is equivalent to olddev,
         * so move newdev into place */
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

    if (needLinkStateChange &&
        qemuDomainChangeNetLinkState(driver, vm, olddev, newdev->linkstate) < 0) {
        goto cleanup;
    }

    if (needReplaceDevDef) {
        /* the changes above warrant replacing olddev with newdev in
         * the domain's nets list.
         */

        /* this function doesn't work with HOSTDEV networks yet, thus
         * no need to change the pointer in the hostdev structure */
        networkReleaseActualDevice(vm->def, olddev);
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
    if (newdev)
        networkReleaseActualDevice(vm->def, newdev);

    return ret;
}

static virDomainGraphicsDefPtr
qemuDomainFindGraphics(virDomainObjPtr vm,
                       virDomainGraphicsDefPtr dev)
{
    size_t i;

    for (i = 0; i < vm->def->ngraphics; i++) {
        if (vm->def->graphics[i]->type == dev->type)
            return vm->def->graphics[i];
    }

    return NULL;
}

int
qemuDomainFindGraphicsIndex(virDomainDefPtr def,
                            virDomainGraphicsDefPtr dev)
{
    size_t i;

    for (i = 0; i < def->ngraphics; i++) {
        if (def->graphics[i]->type == dev->type)
            return i;
    }

    return -1;
}

int
qemuDomainChangeGraphics(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainGraphicsDefPtr dev)
{
    virDomainGraphicsDefPtr olddev = qemuDomainFindGraphics(vm, dev);
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    if (!olddev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find existing graphics device to modify"));
        goto cleanup;
    }

    if (dev->nListens != olddev->nListens) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot change the number of listen addresses"));
        goto cleanup;
    }

    for (i = 0; i < dev->nListens; i++) {
        virDomainGraphicsListenDefPtr newlisten = &dev->listens[i];
        virDomainGraphicsListenDefPtr oldlisten = &olddev->listens[i];

        if (newlisten->type != oldlisten->type) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot change the type of listen address"));
            goto cleanup;
        }

        switch ((virDomainGraphicsListenType) newlisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            if (STRNEQ_NULLABLE(newlisten->address, oldlisten->address)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               dev->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC ?
                               _("cannot change listen address setting on vnc graphics") :
                               _("cannot change listen address setting on spice graphics"));
                goto cleanup;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (STRNEQ_NULLABLE(newlisten->network, oldlisten->network)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               dev->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC ?
                           _("cannot change listen network setting on vnc graphics") :
                           _("cannot change listen network setting on spice graphics"));
                goto cleanup;
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
            goto cleanup;
        }
        if (STRNEQ_NULLABLE(olddev->data.vnc.keymap, dev->data.vnc.keymap)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot change keymap setting on vnc graphics"));
            goto cleanup;
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
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
                                                    &dev->data.vnc.auth,
                                                    cfg->vncPassword,
                                                    QEMU_ASYNC_JOB_NONE);
            if (ret < 0)
                goto cleanup;

            /* Steal the new dev's  char * reference */
            VIR_FREE(olddev->data.vnc.auth.passwd);
            olddev->data.vnc.auth.passwd = dev->data.vnc.auth.passwd;
            dev->data.vnc.auth.passwd = NULL;
            olddev->data.vnc.auth.validTo = dev->data.vnc.auth.validTo;
            olddev->data.vnc.auth.expires = dev->data.vnc.auth.expires;
            olddev->data.vnc.auth.connected = dev->data.vnc.auth.connected;
        } else {
            ret = 0;
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
            goto cleanup;
        }
        if (STRNEQ_NULLABLE(olddev->data.spice.keymap,
                            dev->data.spice.keymap)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                            _("cannot change keymap setting on spice graphics"));
            goto cleanup;
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
            ret = qemuDomainChangeGraphicsPasswords(driver, vm,
                                                    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
                                                    &dev->data.spice.auth,
                                                    cfg->spicePassword,
                                                    QEMU_ASYNC_JOB_NONE);

            if (ret < 0)
                goto cleanup;

            /* Steal the new dev's char * reference */
            VIR_FREE(olddev->data.spice.auth.passwd);
            olddev->data.spice.auth.passwd = dev->data.spice.auth.passwd;
            dev->data.spice.auth.passwd = NULL;
            olddev->data.spice.auth.validTo = dev->data.spice.auth.validTo;
            olddev->data.spice.auth.expires = dev->data.spice.auth.expires;
            olddev->data.spice.auth.connected = dev->data.spice.auth.connected;
        } else {
            VIR_DEBUG("Not updating since password didn't change");
            ret = 0;
        }
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to change config on '%s' graphics type"),
                       virDomainGraphicsTypeToString(dev->type));
        break;
    }

 cleanup:
    virObjectUnref(cfg);
    return ret;
}


static int qemuComparePCIDevice(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                                virDomainDeviceInfoPtr info1,
                                void *opaque)
{
    virDomainDeviceInfoPtr info2 = opaque;

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

static bool qemuIsMultiFunctionDevice(virDomainDefPtr def,
                                      virDomainDeviceInfoPtr dev)
{
    if (virDomainDeviceInfoIterate(def, qemuComparePCIDevice, dev) < 0)
        return true;
    return false;
}


static int
qemuDomainRemoveDiskDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainDiskDefPtr disk)
{
    virDomainDeviceDef dev;
    virObjectEventPtr event;
    size_t i;
    const char *src = virDomainDiskGetSource(disk);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *drivestr;

    VIR_DEBUG("Removing disk %s from domain %p %s",
              disk->info.alias, vm, vm->def->name);

    /* build the actual drive id string as the disk->info.alias doesn't
     * contain the QEMU_DRIVE_HOST_PREFIX that is passed to qemu */
    if (virAsprintf(&drivestr, "%s%s",
                    QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0)
        return -1;

    qemuDomainObjEnterMonitor(driver, vm);
    qemuMonitorDriveDel(priv->mon, drivestr);
    VIR_FREE(drivestr);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    virDomainAuditDisk(vm, disk->src, NULL, "detach", true);

    event = virDomainEventDeviceRemovedNewFromObj(vm, disk->info.alias);
    qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i] == disk) {
            virDomainDiskRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &disk->info, src);

    if (virSecurityManagerRestoreDiskLabel(driver->securityManager,
                                           vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", src);

    if (qemuTeardownDiskCgroup(vm, disk) < 0)
        VIR_WARN("Failed to tear down cgroup for disk path %s", src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", src);

    dev.type = VIR_DOMAIN_DEVICE_DISK;
    dev.data.disk = disk;
    ignore_value(qemuRemoveSharedDevice(driver, &dev, vm->def->name));

    virDomainDiskDefFree(disk);
    return 0;
}


static int
qemuDomainRemoveControllerDevice(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainControllerDefPtr controller)
{
    virObjectEventPtr event;
    size_t i;

    VIR_DEBUG("Removing controller %s from domain %p %s",
              controller->info.alias, vm, vm->def->name);

    event = virDomainEventDeviceRemovedNewFromObj(vm, controller->info.alias);
    qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->ncontrollers; i++) {
        if (vm->def->controllers[i] == controller) {
            virDomainControllerRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &controller->info, NULL);
    virDomainControllerDefFree(controller);
    return 0;
}


static int
qemuDomainRemoveMemoryDevice(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainMemoryDefPtr mem)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long oldmem = virDomainDefGetMemoryActual(vm->def);
    unsigned long long newmem = oldmem - mem->size;
    virObjectEventPtr event;
    char *backendAlias = NULL;
    int rc;
    int idx;

    VIR_DEBUG("Removing memory device %s from domain %p %s",
              mem->info.alias, vm, vm->def->name);

    event = virDomainEventDeviceRemovedNewFromObj(vm, mem->info.alias);
    qemuDomainEventQueue(driver, event);

    if (virAsprintf(&backendAlias, "mem%s", mem->info.alias) < 0)
        return -1;

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorDelObject(priv->mon, backendAlias);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        rc = -1;

    VIR_FREE(backendAlias);

    virDomainAuditMemory(vm, oldmem, newmem, "update", rc == 0);
    if (rc < 0)
        return -1;

    vm->def->mem.cur_balloon -= mem->size;

    if ((idx = virDomainMemoryFindByDef(vm->def, mem)) >= 0)
        virDomainMemoryRemove(vm->def, idx);

    virDomainMemoryDefFree(mem);

    /* decrease the mlock limit after memory unplug if necessary */
    ignore_value(qemuDomainAdjustMaxMemLock(vm));

    return 0;
}


static void
qemuDomainRemovePCIHostDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr hostdev)
{
    qemuHostdevReAttachPCIDevices(driver, vm->def->name, &hostdev, 1);
    qemuDomainReleaseDeviceAddress(vm, hostdev->info, NULL);
}

static void
qemuDomainRemoveUSBHostDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr hostdev)
{
    qemuHostdevReAttachUSBDevices(driver, vm->def->name, &hostdev, 1);
}

static void
qemuDomainRemoveSCSIHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    qemuHostdevReAttachSCSIDevices(driver, vm->def->name, &hostdev, 1);
}

static int
qemuDomainRemoveHostDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainHostdevDefPtr hostdev)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainNetDefPtr net = NULL;
    virObjectEventPtr event;
    size_t i;
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *drivestr = NULL;
    int backend;
    bool is_vfio = false;

    VIR_DEBUG("Removing host device %s from domain %p %s",
              hostdev->info->alias, vm, vm->def->name);

    if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
        /* build the actual drive id string as generated during
         * qemuBuildSCSIHostdevDrvStr that is passed to qemu */
        if (virAsprintf(&drivestr, "%s-%s",
                        virDomainDeviceAddressTypeToString(hostdev->info->type),
                        hostdev->info->alias) < 0)
            goto cleanup;

        qemuDomainObjEnterMonitor(driver, vm);
        qemuMonitorDriveDel(priv->mon, drivestr);
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    event = virDomainEventDeviceRemovedNewFromObj(vm, hostdev->info->alias);
    qemuDomainEventQueue(driver, event);

    if (hostdev->parent.type == VIR_DOMAIN_DEVICE_NET) {
        net = hostdev->parent.data.net;

        for (i = 0; i < vm->def->nnets; i++) {
            if (vm->def->nets[i] == net) {
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

    switch ((virDomainHostdevSubsysType) hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        backend = hostdev->source.subsys.u.pci.backend;
        is_vfio = backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
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
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        break;
    }

    if (qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Failed to remove host device cgroup ACL");

    if (!is_vfio &&
        virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def, hostdev, NULL) < 0) {
        VIR_WARN("Failed to restore host device labelling");
    }

    virDomainHostdevDefFree(hostdev);

    if (net) {
        networkReleaseActualDevice(vm->def, net);
        virDomainNetDefFree(net);
    }

    ret = 0;

 cleanup:
    VIR_FREE(drivestr);
    virObjectUnref(cfg);
    return ret;
}


static int
qemuDomainRemoveNetDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainNetDefPtr net)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virNetDevVPortProfilePtr vport;
    virObjectEventPtr event;
    char *hostnet_name = NULL;
    size_t i;
    int ret = -1;

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* this function handles all hostdev and netdev cleanup */
        ret = qemuDomainRemoveHostDevice(driver, vm,
                                         virDomainNetGetActualHostdev(net));
        goto cleanup;
    }

    VIR_DEBUG("Removing network interface %s from domain %p %s",
              net->info.alias, vm, vm->def->name);

    if (virAsprintf(&hostnet_name, "host%s", net->info.alias) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorRemoveNetdev(priv->mon, hostnet_name) < 0) {
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditNet(vm, net, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        int vlan;
        if ((vlan = qemuDomainNetVLAN(net)) < 0 ||
            qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0) {
            if (vlan < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("unable to determine original VLAN"));
            }
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditNet(vm, net, NULL, "detach", false);
            goto cleanup;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    virDomainAuditNet(vm, net, NULL, "detach", true);

    event = virDomainEventDeviceRemovedNewFromObj(vm, net->info.alias);
    qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i] == net) {
            virDomainNetRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &net->info, NULL);
    virDomainConfNWFilterTeardown(net);

    if (cfg->macFilter && (net->ifname != NULL)) {
        ignore_value(ebtablesRemoveForwardAllowIn(driver->ebtables,
                                                  net->ifname,
                                                  &net->mac));
    }

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
        ignore_value(virNetDevMacVLanDeleteWithVPortProfile(
                         net->ifname, &net->mac,
                         virDomainNetGetActualDirectDev(net),
                         virDomainNetGetActualDirectMode(net),
                         virDomainNetGetActualVirtPortProfile(net),
                         cfg->stateDir));
    }

    vport = virDomainNetGetActualVirtPortProfile(net);
    if (vport) {
        if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
            ignore_value(virNetDevMidonetUnbindPort(vport));
        } else if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            ignore_value(virNetDevOpenvswitchRemovePort(
                             virDomainNetGetActualBridgeName(net),
                             net->ifname));
        }
    }

    networkReleaseActualDevice(vm->def, net);
    virDomainNetDefFree(net);
    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(hostnet_name);
    return ret;
}


static int
qemuDomainRemoveChrDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainChrDefPtr chr)
{
    virObjectEventPtr event;
    char *charAlias = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rc;

    VIR_DEBUG("Removing character device %s from domain %p %s",
              chr->info.alias, vm, vm->def->name);

    if (virAsprintf(&charAlias, "char%s", chr->info.alias) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorDetachCharDev(priv->mon, charAlias);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    virDomainAuditChardev(vm, chr, NULL, "detach", rc == 0);

    if (rc < 0)
        goto cleanup;

    event = virDomainEventDeviceRemovedNewFromObj(vm, chr->info.alias);
    qemuDomainEventQueue(driver, event);

    qemuDomainChrRemove(vm->def, chr);
    virDomainChrDefFree(chr);
    ret = 0;

 cleanup:
    VIR_FREE(charAlias);
    return ret;
}


static int
qemuDomainRemoveRNGDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainRNGDefPtr rng)
{
    virObjectEventPtr event;
    char *charAlias = NULL;
    char *objAlias = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    ssize_t idx;
    int ret = -1;
    int rc;

    VIR_DEBUG("Removing RNG device %s from domain %p %s",
              rng->info.alias, vm, vm->def->name);

    if (virAsprintf(&objAlias, "obj%s", rng->info.alias) < 0)
        goto cleanup;

    if (virAsprintf(&charAlias, "char%s", rng->info.alias) < 0)
        goto cleanup;

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorDelObject(priv->mon, objAlias);

    if (rc == 0 && rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD)
        ignore_value(qemuMonitorDetachCharDev(priv->mon, charAlias));

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    virDomainAuditRNG(vm, rng, NULL, "detach", rc == 0);

    if (rc < 0)
        goto cleanup;

    event = virDomainEventDeviceRemovedNewFromObj(vm, rng->info.alias);
    qemuDomainEventQueue(driver, event);

    if ((idx = virDomainRNGFind(vm->def, rng)) >= 0)
        virDomainRNGRemove(vm->def, idx);
    qemuDomainReleaseDeviceAddress(vm, &rng->info, NULL);
    virDomainRNGDefFree(rng);
    ret = 0;

 cleanup:
    VIR_FREE(charAlias);
    VIR_FREE(objAlias);
    return ret;
}


int
qemuDomainRemoveDevice(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       virDomainDeviceDefPtr dev)
{
    int ret = -1;
    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainRemoveDiskDevice(driver, vm, dev->data.disk);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainRemoveControllerDevice(driver, vm, dev->data.controller);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainRemoveNetDevice(driver, vm, dev->data.net);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = qemuDomainRemoveHostDevice(driver, vm, dev->data.hostdev);
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainRemoveChrDevice(driver, vm, dev->data.chr);
        break;
    case VIR_DOMAIN_DEVICE_RNG:
        ret = qemuDomainRemoveRNGDevice(driver, vm, dev->data.rng);
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        ret = qemuDomainRemoveMemoryDevice(driver, vm, dev->data.memory);
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("don't know how to remove a %s device"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }
    return ret;
}


static void
qemuDomainMarkDeviceForRemoval(virDomainObjPtr vm,
                               virDomainDeviceInfoPtr info)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_DEL_EVENT))
        priv->unpluggingDevice = info->alias;
    else
        priv->unpluggingDevice = NULL;
}

static void
qemuDomainResetDeviceRemoval(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    priv->unpluggingDevice = NULL;
}

/* Returns:
 *  -1 on error
 *   0 when DEVICE_DELETED event is unsupported
 *   1 when DEVICE_DELETED arrived before the timeout and the caller is
 *     responsible for finishing the removal
 *   2 device removal did not finish in qemuDomainRemoveDeviceWaitTime
 */
static int
qemuDomainWaitForDeviceRemoval(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned long long until;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_DEL_EVENT))
        return 0;

    if (virTimeMillisNow(&until) < 0)
        return -1;
    until += qemuDomainRemoveDeviceWaitTime;

    while (priv->unpluggingDevice) {
        if (virCondWaitUntil(&priv->unplugFinished,
                             &vm->parent.lock, until) < 0) {
            if (errno == ETIMEDOUT) {
                return 2;
            } else {
                virReportSystemError(errno, "%s",
                                     _("Unable to wait on unplug condition"));
                return -1;
            }
        }
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
qemuDomainSignalDeviceRemoval(virDomainObjPtr vm,
                              const char *devAlias)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (STREQ_NULLABLE(priv->unpluggingDevice, devAlias)) {
        qemuDomainResetDeviceRemoval(vm);
        virCondSignal(&priv->unplugFinished);
        return true;
    }
    return false;
}


static int
qemuDomainDetachVirtioDiskDevice(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr detach)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (qemuIsMultiFunctionDevice(vm->def, &detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %s"),
                       detach->dst);
        goto cleanup;
    }

    if (qemuDomainMachineIsS390CCW(vm->def) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        if (!virDomainDeviceAddressIsValid(&detach->info,
                                           VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("device cannot be detached without a valid CCW address"));
            goto cleanup;
        }
    } else {
        if (!virDomainDeviceAddressIsValid(&detach->info,
                                           VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("device cannot be detached without a valid PCI address"));
            goto cleanup;
        }
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
        !detach->info.alias) {
        if (qemuAssignDeviceDiskAlias(vm->def, detach, priv->qemuCaps) < 0)
            goto cleanup;
    }

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
            goto cleanup;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveDiskDevice(driver, vm, detach);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}

static int
qemuDomainDetachDiskDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainDiskDefPtr detach)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Underlying qemu does not support %s disk removal"),
                       virDomainDiskBusTypeToString(detach->bus));
        goto cleanup;
    }

    if (detach->mirror) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' is in an active block job"),
                       detach->dst);
        goto cleanup;
    }

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
        virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
        goto cleanup;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveDiskDevice(driver, vm, detach);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}

static int
qemuFindDisk(virDomainDefPtr def, const char *dst)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ(def->disks[i]->dst, dst))
            return i;
    }

    return -1;
}

int
qemuDomainDetachDeviceDiskLive(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk;
    int ret = -1;
    int idx;

    if ((idx = qemuFindDisk(vm->def, dev->data.disk->dst)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("disk %s not found"), dev->data.disk->dst);
        return -1;
    }
    disk = vm->def->disks[idx];

    switch (disk->device) {
    case VIR_DOMAIN_DISK_DEVICE_DISK:
    case VIR_DOMAIN_DISK_DEVICE_LUN:
        if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
            ret = qemuDomainDetachVirtioDiskDevice(driver, vm, disk);
        else if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
                 disk->bus == VIR_DOMAIN_DISK_BUS_USB)
            ret = qemuDomainDetachDiskDevice(driver, vm, disk);
        else
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("This type of disk cannot be hot unplugged"));
        break;
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("disk device type '%s' cannot be detached"),
                       virDomainDiskDeviceTypeToString(disk->device));
        break;
    }

    return ret;
}


static bool qemuDomainDiskControllerIsBusy(virDomainObjPtr vm,
                                           virDomainControllerDefPtr detach)
{
    size_t i;
    virDomainDiskDefPtr disk;

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            /* the disk does not use disk controller */
            continue;

        /* check whether the disk uses this type controller */
        if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE &&
            detach->type != VIR_DOMAIN_CONTROLLER_TYPE_IDE)
            continue;
        if (disk->bus == VIR_DOMAIN_DISK_BUS_FDC &&
            detach->type != VIR_DOMAIN_CONTROLLER_TYPE_FDC)
            continue;
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
            detach->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (disk->info.addr.drive.controller == detach->idx)
            return true;
    }

    return false;
}

static bool qemuDomainControllerIsBusy(virDomainObjPtr vm,
                                       virDomainControllerDefPtr detach)
{
    switch (detach->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        return qemuDomainDiskControllerIsBusy(vm, detach);

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    default:
        /* libvirt does not support sata controller, and does not support to
         * detach virtio and smart card controller.
         */
        return true;
    }
}

int qemuDomainDetachControllerDevice(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDeviceDefPtr dev)
{
    int idx, ret = -1;
    virDomainControllerDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if ((idx = virDomainControllerFind(vm->def,
                                       dev->data.controller->type,
                                       dev->data.controller->idx)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("controller %s:%d not found"),
                       virDomainControllerTypeToString(dev->data.controller->type),
                       dev->data.controller->idx);
        goto cleanup;
    }

    detach = vm->def->controllers[idx];

    if (detach->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
        detach->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
        detach->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("device with '%s' address cannot be detached"),
                       virDomainDeviceAddressTypeToString(detach->info.type));
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info, detach->info.type)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("device with invalid '%s' address cannot be detached"),
                       virDomainDeviceAddressTypeToString(detach->info.type));
        goto cleanup;
    }

    if (detach->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
        qemuIsMultiFunctionDevice(vm->def, &detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %s"),
                       dev->data.disk->dst);
        goto cleanup;
    }

    if (qemuDomainControllerIsBusy(vm, detach)) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("device cannot be detached: device is busy"));
        goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
        !detach->info.alias) {
        if (qemuAssignDeviceControllerAlias(vm->def, priv->qemuCaps, detach) < 0)
            goto cleanup;
    }

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias)) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveControllerDevice(driver, vm, detach);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}

static int
qemuDomainDetachHostPCIDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevSubsysPCIPtr pcisrc = &detach->source.subsys.u.pci;
    int ret;

    if (qemuIsMultiFunctionDevice(vm->def, detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %.4x:%.2x:%.2x.%.1x"),
                       pcisrc->addr.domain, pcisrc->addr.bus,
                       pcisrc->addr.slot, pcisrc->addr.function);
        return -1;
    }

    if (!virDomainDeviceAddressIsValid(detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device cannot be detached without a PCI address"));
        return -1;
    }

    qemuDomainMarkDeviceForRemoval(vm, detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        ret = qemuMonitorDelDevice(priv->mon, detach->info->alias);
    } else {
        ret = qemuMonitorRemovePCIDevice(priv->mon, &detach->info->addr.pci);
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}

static int
qemuDomainDetachHostUSBDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (!detach->info->alias) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device cannot be detached without a device alias"));
        return -1;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device cannot be detached with this QEMU version"));
        return -1;
    }

    qemuDomainMarkDeviceForRemoval(vm, detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDelDevice(priv->mon, detach->info->alias);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}

static int
qemuDomainDetachHostSCSIDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!detach->info->alias) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device cannot be detached without a device alias"));
        return -1;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("device cannot be detached with this QEMU version"));
        return -1;
    }

    qemuDomainMarkDeviceForRemoval(vm, detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorDelDevice(priv->mon, detach->info->alias);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    return ret;
}

static int
qemuDomainDetachThisHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
        !detach->info->alias) {
        if (qemuAssignDeviceHostdevAlias(vm->def, detach, -1) < 0)
            return -1;
    }

    switch (detach->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        ret = qemuDomainDetachHostPCIDevice(driver, vm, detach);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        ret = qemuDomainDetachHostUSBDevice(driver, vm, detach);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        ret = qemuDomainDetachHostSCSIDevice(driver, vm, detach);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev subsys type '%s' not supported"),
                       virDomainHostdevSubsysTypeToString(detach->source.subsys.type));
        return -1;
    }

    if (ret < 0) {
        if (virDomainObjIsActive(vm))
            virDomainAuditHostdev(vm, detach, "detach", false);
    } else {
        int rc = qemuDomainWaitForDeviceRemoval(vm);
        if (rc == 0 || rc == 1)
            ret = qemuDomainRemoveHostDevice(driver, vm, detach);
    }

    qemuDomainResetDeviceRemoval(vm);

    return ret;
}

/* search for a hostdev matching dev and detach it */
int qemuDomainDetachHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;
    virDomainHostdevSubsysUSBPtr usbsrc = &subsys->u.usb;
    virDomainHostdevSubsysPCIPtr pcisrc = &subsys->u.pci;
    virDomainHostdevSubsysSCSIPtr scsisrc = &subsys->u.scsi;
    virDomainHostdevDefPtr detach = NULL;
    int idx;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    idx = virDomainHostdevFind(vm->def, hostdev, &detach);

    if (idx < 0) {
        switch (subsys->type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("host pci device %.4x:%.2x:%.2x.%.1x not found"),
                           pcisrc->addr.domain, pcisrc->addr.bus,
                           pcisrc->addr.slot, pcisrc->addr.function);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (usbsrc->bus && usbsrc->device) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("host usb device %03d.%03d not found"),
                               usbsrc->bus, usbsrc->device);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("host usb device vendor=0x%.4x product=0x%.4x not found"),
                               usbsrc->vendor, usbsrc->product);
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI: {
            if (scsisrc->protocol ==
                VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
                virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &scsisrc->u.iscsi;
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("host scsi iSCSI path %s not found"),
                               iscsisrc->path);
            } else {
                 virDomainHostdevSubsysSCSIHostPtr scsihostsrc =
                     &scsisrc->u.host;
                 virReportError(VIR_ERR_OPERATION_FAILED,
                                _("host scsi device %s:%u:%u.%llu not found"),
                                scsihostsrc->adapter, scsihostsrc->bus,
                                scsihostsrc->target, scsihostsrc->unit);
            }
            break;
        }
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected hostdev type %d"), subsys->type);
            break;
        }
        return -1;
    }

    /* If this is a network hostdev, we need to use the higher-level detach
     * function so that mac address / virtualport are reset
     */
    if (detach->parent.type == VIR_DOMAIN_DEVICE_NET)
        return qemuDomainDetachNetDevice(driver, vm, &detach->parent);
    else
        return qemuDomainDetachThisHostDevice(driver, vm, detach);
}

int
qemuDomainDetachNetDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainDeviceDefPtr dev)
{
    int detachidx, ret = -1;
    virDomainNetDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if ((detachidx = virDomainNetFindIdx(vm->def, dev->data.net)) < 0)
        goto cleanup;

    detach = vm->def->nets[detachidx];

    if (virDomainNetGetActualType(detach) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* coverity[negative_returns] */
        ret = qemuDomainDetachThisHostDevice(driver, vm,
                                             virDomainNetGetActualHostdev(detach));
        goto cleanup;
    }
    if (qemuDomainMachineIsS390CCW(vm->def) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        if (!virDomainDeviceAddressIsValid(&detach->info,
                                           VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("device cannot be detached without a CCW address"));
            goto cleanup;
        }
    } else {
        if (!virDomainDeviceAddressIsValid(&detach->info,
                                           VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                            "%s", _("device cannot be detached without a PCI address"));
            goto cleanup;
        }

        if (qemuIsMultiFunctionDevice(vm->def, &detach->info)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                            _("cannot hot unplug multifunction PCI device :%s"),
                            dev->data.disk->dst);
            goto cleanup;
        }
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
        !detach->info.alias) {
        if (qemuAssignDeviceNetAlias(vm->def, detach, -1) < 0)
            goto cleanup;
    }

    if (virDomainNetGetActualBandwidth(detach) &&
        virNetDevSupportBandwidth(virDomainNetGetActualType(detach)) &&
        virNetDevBandwidthClear(detach->ifname) < 0)
        VIR_WARN("cannot clear bandwidth setting for device : %s",
                 detach->ifname);

    /* deactivate the tap/macvtap device on the host, which could also
     * affect the parent device (e.g. macvtap passthrough mode sets
     * the parent device offline)
     */
    ignore_value(qemuInterfaceStopDevice(detach));

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveNetDevice(driver, vm, detach);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}

int
qemuDomainChangeGraphicsPasswords(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  int type,
                                  virDomainGraphicsAuthDefPtr auth,
                                  const char *defaultPasswd,
                                  int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    time_t now = time(NULL);
    char expire_time [64];
    const char *connected = NULL;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!auth->passwd && !defaultPasswd) {
        ret = 0;
        goto cleanup;
    }

    if (auth->connected)
        connected = virDomainGraphicsAuthConnectedTypeToString(auth->connected);

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;
    ret = qemuMonitorSetPassword(priv->mon,
                                 type,
                                 auth->passwd ? auth->passwd : defaultPasswd,
                                 connected);

    if (ret == -2) {
        if (type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Graphics password only supported for VNC"));
            ret = -1;
        } else {
            ret = qemuMonitorSetVNCPassword(priv->mon,
                                            auth->passwd ? auth->passwd : defaultPasswd);
        }
    }
    if (ret != 0)
        goto end_job;

    if (auth->expires) {
        time_t lifetime = auth->validTo - now;
        if (lifetime <= 0)
            snprintf(expire_time, sizeof(expire_time), "now");
        else
            snprintf(expire_time, sizeof(expire_time), "%lu", (long unsigned)auth->validTo);
    } else {
        snprintf(expire_time, sizeof(expire_time), "never");
    }

    ret = qemuMonitorExpirePassword(priv->mon, type, expire_time);

    if (ret == -2) {
        /* XXX we could fake this with a timer */
        if (auth->expires) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Expiry of passwords is not supported"));
            ret = -1;
        } else {
            ret = 0;
        }
    }

 end_job:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
 cleanup:
    virObjectUnref(cfg);
    return ret;
}

int qemuDomainAttachLease(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainLeaseDefPtr lease)
{
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (virDomainLeaseInsertPreAlloc(vm->def) < 0)
        goto cleanup;

    if (virDomainLockLeaseAttach(driver->lockManager, cfg->uri,
                                 vm, lease) < 0) {
        virDomainLeaseInsertPreAlloced(vm->def, NULL);
        goto cleanup;
    }

    virDomainLeaseInsertPreAlloced(vm->def, lease);
    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}

int qemuDomainDetachLease(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainLeaseDefPtr lease)
{
    virDomainLeaseDefPtr det_lease;
    int idx;

    if ((idx = virDomainLeaseIndex(vm->def, lease)) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Lease %s in lockspace %s does not exist"),
                       lease->key, NULLSTR(lease->lockspace));
        return -1;
    }

    if (virDomainLockLeaseDetach(driver->lockManager, vm, lease) < 0)
        return -1;

    det_lease = virDomainLeaseRemoveAt(vm->def, idx);
    virDomainLeaseDefFree(det_lease);
    return 0;
}

int qemuDomainDetachChrDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainChrDefPtr chr)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr vmdef = vm->def;
    virDomainChrDefPtr tmpChr;
    char *devstr = NULL;
    int rc;

    if (!(tmpChr = virDomainChrFind(vmdef, chr))) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("device not present in domain configuration"));
        return ret;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("qemu does not support -device"));
        return ret;
    }

    if (!tmpChr->info.alias && qemuAssignDeviceChrAlias(vmdef, tmpChr, -1) < 0)
        return ret;

    sa_assert(tmpChr->info.alias);

    if (qemuBuildChrDeviceStr(&devstr, vm->def, chr, priv->qemuCaps) < 0)
        return ret;

    qemuDomainMarkDeviceForRemoval(vm, &tmpChr->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (devstr && qemuMonitorDelDevice(priv->mon, tmpChr->info.alias) < 0) {
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        goto cleanup;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1) {
        qemuDomainReleaseDeviceAddress(vm, &tmpChr->info, NULL);
        ret = qemuDomainRemoveChrDevice(driver, vm, tmpChr);
    } else {
        ret = 0;
    }


 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    VIR_FREE(devstr);
    return ret;
}


int
qemuDomainDetachRNGDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainRNGDefPtr rng)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    ssize_t idx;
    virDomainRNGDefPtr tmpRNG;
    int rc;
    int ret = -1;

    if ((idx = virDomainRNGFind(vm->def, rng) < 0)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("device not present in domain configuration"));
        return -1;
    }

    tmpRNG = vm->def->rngs[idx];

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("qemu does not support -device"));
        return -1;
    }

    if (!tmpRNG->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("alias not set for RNG device"));
        return -1;
    }

    qemuDomainMarkDeviceForRemoval(vm, &tmpRNG->info);

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorDelDevice(priv->mon, tmpRNG->info.alias);
    if (qemuDomainObjExitMonitor(driver, vm) || rc < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveRNGDevice(driver, vm, tmpRNG);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}


int
qemuDomainDetachMemoryDevice(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             virDomainMemoryDefPtr memdef)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainMemoryDefPtr mem;
    int idx;
    int rc;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("qemu does not support -device"));
        return -1;
    }

    qemuDomainMemoryDeviceAlignSize(vm->def, memdef);

    if ((idx = virDomainMemoryFindByDef(vm->def, memdef)) < 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("device not present in domain configuration"));
        return -1;
    }

    mem = vm->def->mems[idx];

    if (!mem->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("alias for the memory device was not found"));
        return -1;
    }

    qemuDomainMarkDeviceForRemoval(vm, &mem->info);

    qemuDomainObjEnterMonitor(driver, vm);
    rc = qemuMonitorDelDevice(priv->mon, mem->info.alias);
    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    rc = qemuDomainWaitForDeviceRemoval(vm);
    if (rc == 0 || rc == 1)
        ret = qemuDomainRemoveMemoryDevice(driver, vm, mem);
    else
        ret = 0;

 cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}
