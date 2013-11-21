/*
 * qemu_hotplug.h: QEMU device hotplug management
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_command.h"
#include "qemu_bridge_filter.h"
#include "qemu_hostdev.h"
#include "domain_audit.h"
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
#include "device_conf.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_QEMU
#define CHANGE_MEDIA_RETRIES 10

/* Wait up to 5 seconds for device removal to finish. */
unsigned long long qemuDomainRemoveDeviceWaitTime = 1000ull * 5;


int qemuDomainChangeEjectableMedia(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainDiskDefPtr disk,
                                   virDomainDiskDefPtr origdisk,
                                   bool force)
{
    int ret = -1;
    char *driveAlias = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int retries = CHANGE_MEDIA_RETRIES;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!origdisk->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing disk device alias name for %s"), origdisk->dst);
        goto cleanup;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Removable media not supported for %s device"),
                       virDomainDiskDeviceTypeToString(disk->device));
        goto cleanup;
    }

    if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                vm, disk) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, disk) < 0) {
        if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
            VIR_WARN("Unable to release lock on %s", disk->src);
        goto cleanup;
    }

    if (!(driveAlias = qemuDeviceDriveHostAlias(origdisk, priv->qemuCaps)))
        goto error;

    qemuDomainObjEnterMonitor(driver, vm);
    ret = qemuMonitorEjectMedia(priv->mon, driveAlias, force);
    qemuDomainObjExitMonitor(driver, vm);

    virObjectRef(vm);
    /* we don't want to report errors from media tray_open polling */
    while (retries) {
        if (origdisk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN)
            break;

        retries--;
        virObjectUnlock(vm);
        VIR_DEBUG("Waiting 500ms for tray to open. Retries left %d", retries);
        usleep(500 * 1000); /* sleep 500ms */
        virObjectLock(vm);
    }
    virObjectUnref(vm);

    if (retries <= 0) {
        if (ret == 0) {
            /* If ret == -1, EjectMedia already set an error message */
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Unable to eject media"));
        }
        goto audit;
    }
    ret = 0;

    if (disk->src) {
        /* deliberately don't depend on 'ret' as 'eject' may have failed the
         * first time and we are going to check the drive state anyway */
        const char *format = NULL;

        if (disk->type != VIR_DOMAIN_DISK_TYPE_DIR) {
            if (disk->format > 0)
                format = virStorageFileFormatTypeToString(disk->format);
            else if (origdisk->format > 0)
                format = virStorageFileFormatTypeToString(origdisk->format);
        }
        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorChangeMedia(priv->mon,
                                     driveAlias,
                                     disk->src, format);
        qemuDomainObjExitMonitor(driver, vm);
    }
audit:
    virDomainAuditDisk(vm, origdisk->src, disk->src, "update", ret >= 0);

    if (ret < 0)
        goto error;

    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, origdisk) < 0)
        VIR_WARN("Unable to restore security label on ejected image %s", origdisk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, origdisk) < 0)
        VIR_WARN("Unable to release lock on disk %s", origdisk->src);

    VIR_FREE(origdisk->src);
    origdisk->src = disk->src;
    disk->src = NULL;
    origdisk->type = disk->type;


    virDomainDiskDefFree(disk);

cleanup:
    VIR_FREE(driveAlias);
    virObjectUnref(cfg);
    return ret;

error:
    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on new media %s", disk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", disk->src);

    goto cleanup;
}

int
qemuDomainCheckEjectableMedia(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             enum qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr table = NULL;
    int ret = -1;
    size_t i;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        table = qemuMonitorGetBlockInfo(priv->mon);
        qemuDomainObjExitMonitor(driver, vm);
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

        if (info->tray_open && disk->src)
            VIR_FREE(disk->src);
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
    size_t i;
    int ret = -1;
    const char* type = virDomainDiskBusTypeToString(disk->bus);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    char *drivestr = NULL;
    bool releaseaddr = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!disk->info.type) {
        if (STREQLEN(vm->def->os.machine, "s390-ccw", 8) &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW))
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), disk->dst);
            goto cleanup;
        }
    }

    if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                vm, disk) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, disk) < 0) {
        if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
            VIR_WARN("Unable to release lock on %s", disk->src);
        goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            if (qemuDomainCCWAddressAssign(&disk->info, priv->ccwaddrs,
                                           !disk->info.addr.ccw.assigned) < 0)
                goto error;
        } else if (!disk->info.type ||
                    disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &disk->info) < 0)
                goto error;
        }
        releaseaddr = true;
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
                virErrorPtr orig_err = virSaveLastError();
                if (qemuMonitorDriveDel(priv->mon, drivestr) < 0) {
                    VIR_WARN("Unable to remove drive %s (%s) after failed "
                             "qemuMonitorAddDevice",
                             drivestr, devstr);
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
        ret = qemuMonitorAddPCIDisk(priv->mon,
                                    disk->src,
                                    type,
                                    &guestAddr);
        if (ret == 0) {
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            memcpy(&disk->info.addr.pci, &guestAddr, sizeof(guestAddr));
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

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
    if (releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, &disk->info, disk->src);

    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", disk->src);

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

    if (virDomainControllerFind(vm->def, controller->type, controller->idx) >= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("target %s:%d already exists"),
                       type, controller->idx);
        return -1;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            if (STRPREFIX(vm->def->os.machine, "s390-ccw") &&
                virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW))
                controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
            else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
                controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
        }

        if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
            controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &controller->info) < 0)
                goto cleanup;
        } else if (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            if (qemuDomainCCWAddressAssign(&controller->info, priv->ccwaddrs,
                                           !controller->info.addr.ccw.assigned) < 0)
                goto cleanup;
        }
        releaseaddr = true;
        if (qemuAssignDeviceControllerAlias(controller) < 0)
            goto cleanup;

        if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            controller->model == -1 &&
            !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_PIIX3_USB_UHCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("USB controller hotplug unsupported in this QEMU binary"));
            goto cleanup;
        }

        if (!(devstr = qemuBuildControllerDevStr(vm->def, controller, priv->qemuCaps, NULL))) {
            goto cleanup;
        }
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
    qemuDomainObjExitMonitor(driver, vm);

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

    for (i = 0; i < vm->def->ndisks; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), disk->dst);
            goto cleanup;
        }
    }

    if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                vm, disk) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, disk) < 0) {
        if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
            VIR_WARN("Unable to release lock on %s", disk->src);
        goto cleanup;
    }

    /* We should have an address already, so make sure */
    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected disk address type %s"),
                       virDomainDeviceAddressTypeToString(disk->info.type));
        goto error;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceDiskAlias(vm->def, disk, priv->qemuCaps) < 0)
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(vm->def, disk, 0, priv->qemuCaps)))
            goto error;
    }

    if (!(drivestr = qemuBuildDriveStr(conn, disk, false, priv->qemuCaps)))
        goto error;

    for (i = 0; i <= disk->info.addr.drive.controller; i++) {
        cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, i);
        if (!cont)
            goto error;
    }

    /* Tell clang that "cont" is non-NULL.
       This is because disk->info.addr.driver.controller is unsigned,
       and hence the above loop must iterate at least once.  */
    sa_assert(cont);

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
    qemuDomainObjExitMonitor(driver, vm);

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
    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", disk->src);

    goto cleanup;
}


static int
qemuDomainAttachUsbMassstorageDevice(virConnectPtr conn,
                                     virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     virDomainDiskDefPtr disk)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    int ret = -1;
    char *drivestr = NULL;
    char *devstr = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    for (i = 0; i < vm->def->ndisks; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("target %s already exists"), disk->dst);
            goto cleanup;
        }
    }

    if (virDomainLockDiskAttach(driver->lockManager, cfg->uri,
                                vm, disk) < 0)
        goto cleanup;

    if (virSecurityManagerSetImageLabel(driver->securityManager,
                                        vm->def, disk) < 0) {
        if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
            VIR_WARN("Unable to release lock on %s", disk->src);
        goto cleanup;
    }

    /* XXX not correct once we allow attaching a USB CDROM */
    if (!disk->src) {
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
        ret = qemuMonitorAddUSBDisk(priv->mon, disk->src);
    }
    qemuDomainObjExitMonitor(driver, vm);

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
    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", disk->src);

    goto cleanup;
}


int
qemuDomainAttachDeviceDiskLive(virConnectPtr conn,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = dev->data.disk;
    virDomainDiskDefPtr orig_disk = NULL;
    virDomainDeviceDefPtr dev_copy = NULL;
    virDomainDiskDefPtr tmp = NULL;
    virCapsPtr caps = NULL;
    int ret = -1;

    if (disk->driverName != NULL && !STREQ(disk->driverName, "qemu")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported driver name '%s' for disk '%s'"),
                       disk->driverName, disk->src);
        goto end;
    }

    if (qemuTranslateDiskSourcePool(conn, disk) < 0)
        goto end;

    if (qemuAddSharedDevice(driver, dev, vm->def->name) < 0)
        goto end;

    if (qemuSetUnprivSGIO(dev) < 0)
        goto end;

    if (qemuDomainDetermineDiskChain(driver, disk, false) < 0)
        goto end;

    if (qemuSetupDiskCgroup(vm, disk) < 0)
        goto end;

    switch (disk->device)  {
    case VIR_DOMAIN_DISK_DEVICE_CDROM:
    case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
        if (!(orig_disk = virDomainDiskFindByBusAndDst(vm->def,
                                                       disk->bus, disk->dst))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No device with bus '%s' and target '%s'"),
                           virDomainDiskBusTypeToString(disk->bus),
                           disk->dst);
            goto end;
        }

        if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
            goto end;

        tmp = dev->data.disk;
        dev->data.disk = orig_disk;

        if (!(dev_copy = virDomainDeviceDefCopy(dev, vm->def,
                                                caps, driver->xmlopt))) {
            dev->data.disk = tmp;
            goto end;
        }
        dev->data.disk = tmp;

        ret = qemuDomainChangeEjectableMedia(driver, vm, disk, orig_disk, false);
        /* 'disk' must not be accessed now - it has been free'd.
         * 'orig_disk' now points to the new disk, while 'dev_copy'
         * now points to the old disk */

        /* Need to remove the shared disk entry for the original disk src
         * if the operation is either ejecting or updating.
         */
        if (ret == 0)
            ignore_value(qemuRemoveSharedDevice(driver, dev_copy,
                                                vm->def->name));
        break;
    case VIR_DOMAIN_DISK_DEVICE_DISK:
    case VIR_DOMAIN_DISK_DEVICE_LUN:
        if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("disk device='lun' is not supported for usb bus"));
                break;
            }
            ret = qemuDomainAttachUsbMassstorageDevice(conn, driver, vm,
                                                       disk);
        } else if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
            ret = qemuDomainAttachVirtioDiskDevice(conn, driver, vm, disk);
        } else if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            ret = qemuDomainAttachSCSIDisk(conn, driver, vm, disk);
        } else {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("disk bus '%s' cannot be hotplugged."),
                           virDomainDiskBusTypeToString(disk->bus));
        }
        break;
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("disk device type '%s' cannot be hotplugged"),
                       virDomainDiskDeviceTypeToString(disk->device));
        break;
    }

    if (ret != 0 &&
        qemuTeardownDiskCgroup(vm, disk) < 0) {
        VIR_WARN("Failed to teardown cgroup for disk path %s",
                 NULLSTR(disk->src));
    }

end:
    if (ret != 0)
        ignore_value(qemuRemoveSharedDevice(driver, dev, vm->def->name));
    virObjectUnref(caps);
    virDomainDeviceDefFree(dev_copy);
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
    int tapfdSize = 0;
    char **vhostfdName = NULL;
    int *vhostfd = NULL;
    int vhostfdSize = 0;
    char *nicstr = NULL;
    char *netstr = NULL;
    virNetDevVPortProfilePtr vport = NULL;
    int ret = -1;
    virDevicePCIAddress guestAddr;
    int vlan;
    bool releaseaddr = false;
    bool iface_connected = false;
    int actualType;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    /* preallocate new slot for device */
    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets + 1) < 0)
        goto cleanup;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (networkAllocateActualDevice(net) < 0)
        goto cleanup;

    actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* This is really a "smart hostdev", so it should be attached
         * as a hostdev (the hostdev code will reach over into the
         * netdev-specific code as appropriate), then also added to
         * the nets list (see cleanup:) if successful.
         */
        ret = qemuDomainAttachHostDevice(driver, vm,
                                         virDomainNetGetActualHostdev(net));
        goto cleanup;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_HOST_NET_ADD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("installed qemu version does not support host_net_add"));
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

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        actualType == VIR_DOMAIN_NET_TYPE_NETWORK) {
        tapfdSize = vhostfdSize = net->driver.virtio.queues;
        if (!tapfdSize)
            tapfdSize = vhostfdSize = 1;
        if (VIR_ALLOC_N(tapfd, tapfdSize) < 0 ||
            VIR_ALLOC_N(vhostfd, vhostfdSize) < 0)
            goto cleanup;
        if (qemuNetworkIfaceConnect(vm->def, conn, driver, net,
                                    priv->qemuCaps, tapfd, &tapfdSize) < 0)
            goto cleanup;
        iface_connected = true;
        if (qemuOpenVhostNet(vm->def, net, priv->qemuCaps, vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        tapfdSize = vhostfdSize = 1;
        if (VIR_ALLOC(tapfd) < 0 || VIR_ALLOC(vhostfd) < 0)
            goto cleanup;
        if ((tapfd[0] = qemuPhysIfaceConnect(vm->def, driver, net,
                                             priv->qemuCaps,
                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE)) < 0)
            goto cleanup;
        iface_connected = true;
        if (qemuOpenVhostNet(vm->def, net, priv->qemuCaps, vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        vhostfdSize = 1;
        if (VIR_ALLOC(vhostfd) < 0)
            goto cleanup;
        if (qemuOpenVhostNet(vm->def, net, priv->qemuCaps, vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NET_NAME) ||
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceNetAlias(vm->def, net, -1) < 0)
            goto cleanup;
    }

    if (STREQLEN(vm->def->os.machine, "s390-ccw", 8) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        if (qemuDomainCCWAddressAssign(&net->info, priv->ccwaddrs,
                                       !net->info.addr.ccw.assigned) < 0)
            goto cleanup;
    } else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("virtio-s390 net device cannot be hotplugged."));
    else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
             qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &net->info) < 0)
             goto cleanup;

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
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorAddHostNetwork(priv->mon, netstr,
                                      tapfd, tapfdName, tapfdSize,
                                      vhostfd, vhostfdName, vhostfdSize) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

    for (i = 0; i < tapfdSize; i++)
        VIR_FORCE_CLOSE(tapfd[i]);
    for (i = 0; i < vhostfdSize; i++)
        VIR_FORCE_CLOSE(vhostfd[i]);

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        bool multiqueue = tapfdSize > 1 || vhostfdSize > 1;

        if (!(nicstr = qemuBuildNicDevStr(vm->def, net, vlan, 0,
                                          multiqueue, priv->qemuCaps)))
            goto try_remove;
    } else {
        if (!(nicstr = qemuBuildNicStr(net, NULL, vlan)))
            goto try_remove;
    }

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorAddDevice(priv->mon, nicstr) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto try_remove;
        }
    } else {
        guestAddr = net->info.addr.pci;
        if (qemuMonitorAddPCINetwork(priv->mon, nicstr,
                                     &guestAddr) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, NULL, net, "attach", false);
            goto try_remove;
        }
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        memcpy(&net->info.addr.pci, &guestAddr, sizeof(guestAddr));
    }
    qemuDomainObjExitMonitor(driver, vm);

    /* set link state */
    if (net->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) {
        if (!net->info.alias) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("device alias not found: cannot set link state to down"));
        } else {
            qemuDomainObjEnterMonitor(driver, vm);

            if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV)) {
                if (qemuMonitorSetLink(priv->mon, net->info.alias, VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN) < 0) {
                    qemuDomainObjExitMonitor(driver, vm);
                    virDomainAuditNet(vm, NULL, net, "attach", false);
                    goto try_remove;
                }
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("setting of link state not supported: Link is up"));
            }

            qemuDomainObjExitMonitor(driver, vm);
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
                VIR_FREE(net->ifname);
            }

            vport = virDomainNetGetActualVirtPortProfile(net);
            if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
               ignore_value(virNetDevOpenvswitchRemovePort(
                               virDomainNetGetActualBridgeName(net), net->ifname));
        }

        virDomainNetRemoveHostdev(vm->def, net);

        networkReleaseActualDevice(net);
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
            qemuDomainObjExitMonitor(driver, vm);
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
        qemuDomainObjExitMonitor(driver, vm);
        VIR_FREE(hostnet_name);
    }
    goto cleanup;
}


int qemuDomainAttachHostPciDevice(virQEMUDriverPtr driver,
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
    int backend = hostdev->source.subsys.u.pci.backend;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs + 1) < 0)
        return -1;

    if (qemuPrepareHostdevPCIDevices(driver, vm->def->name, vm->def->uuid,
                                     &hostdev, 1, priv->qemuCaps) < 0)
        return -1;

    switch ((virDomainHostdevSubsysPciBackendType) backend) {
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VFIO PCI device assignment is not "
                             "supported by this version of qemu"));
            goto error;
        }

        /* VFIO requires all of the guest's memory to be locked resident.
         * In this case, the guest's memory may already be locked, but it
         * doesn't hurt to "change" the limit to the same value.
         */
        if (vm->def->mem.hard_limit)
            virProcessSetMaxMemLock(vm->pid, vm->def->mem.hard_limit);
        else
            virProcessSetMaxMemLock(vm->pid,
                                    vm->def->mem.max_balloon + (1024 * 1024));

        break;

    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
        break;
    }

    if (qemuSetupHostdevCGroup(vm, hostdev) < 0)
        goto error;
    teardowncgroup = true;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, hostdev->info) < 0)
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

        if (!(devstr = qemuBuildPCIHostdevDevStr(vm->def, hostdev, configfd_name,
                                                 priv->qemuCaps)))
            goto error;

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorAddDeviceWithFd(priv->mon, devstr,
                                         configfd, configfd_name);
        qemuDomainObjExitMonitor(driver, vm);
    } else {
        virDevicePCIAddress guestAddr = hostdev->info->addr.pci;

        qemuDomainObjEnterMonitor(driver, vm);
        ret = qemuMonitorAddPCIHostDevice(priv->mon,
                                          &hostdev->source.subsys.u.pci.addr,
                                          &guestAddr);
        qemuDomainObjExitMonitor(driver, vm);

        hostdev->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        memcpy(&hostdev->info->addr.pci, &guestAddr, sizeof(guestAddr));
    }
    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);

    return 0;

error:
    if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");

    if (releaseaddr)
        qemuDomainReleaseDeviceAddress(vm, hostdev->info, NULL);

    qemuDomainReAttachHostdevDevices(driver, vm->def->name, &hostdev, 1);

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);

    return -1;
}


int qemuDomainAttachRedirdevDevice(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   virDomainRedirdevDefPtr redirdev)
{
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr def = vm->def;
    char *devstr = NULL;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceRedirdevAlias(vm->def, redirdev, -1) < 0)
            goto error;
        if (!(devstr = qemuBuildRedirdevDevStr(def, redirdev, priv->qemuCaps)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->redirdevs, vm->def->nredirdevs+1) < 0)
        goto error;

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE))
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    else
        goto error;

    qemuDomainObjExitMonitor(driver, vm);
    virDomainAuditRedirdev(vm, redirdev, "attach", ret == 0);
    if (ret < 0)
        goto error;

    vm->def->redirdevs[vm->def->nredirdevs++] = redirdev;

    VIR_FREE(devstr);

    return 0;

error:
    VIR_FREE(devstr);
    return -1;

}

int
qemuDomainChrInsert(virDomainDefPtr vmdef,
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

    if (virDomainChrInsert(vmdef, chr) < 0)
        return -1;

    /* Due to some crazy backcompat stuff, the first serial device is an alias
     * to the first console too. If this is the case, the definition must be
     * duplicated as first console device. */
    if (vmdef->nserials == 1 && vmdef->nconsoles == 0) {
        if ((!vmdef->consoles && VIR_ALLOC(vmdef->consoles) < 0) ||
            VIR_ALLOC(vmdef->consoles[0]) < 0) {
            virDomainChrRemove(vmdef, chr);
            return -1;
        }
        vmdef->nconsoles = 1;

        /* Create an console alias for the serial port */
        vmdef->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        vmdef->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL;
    }

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

int qemuDomainAttachChrDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainChrDefPtr chr)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainDefPtr vmdef = vm->def;
    char *devstr = NULL;
    char *charAlias = NULL;
    bool need_remove = false;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("qemu does not support -device"));
        return ret;
    }

    if (qemuAssignDeviceChrAlias(vmdef, chr, -1) < 0)
        return ret;

    if (qemuBuildChrDeviceStr(&devstr, vm->def, chr, priv->qemuCaps) < 0)
        return ret;

    if (virAsprintf(&charAlias, "char%s", chr->info.alias) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (qemuDomainChrInsert(vmdef, chr) < 0)
        goto cleanup;
    need_remove = true;

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorAttachCharDev(priv->mon, charAlias, &chr->source) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }

    if (devstr && qemuMonitorAddDevice(priv->mon, devstr) < 0) {
        /* detach associated chardev on error */
        qemuMonitorDetachCharDev(priv->mon, charAlias);
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitor(driver, vm);

    ret = 0;
cleanup:
    if (ret < 0 && need_remove)
        qemuDomainChrRemove(vmdef, chr);
    VIR_FREE(charAlias);
    VIR_FREE(devstr);
    return ret;
}

int qemuDomainAttachHostUsbDevice(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virUSBDeviceList *list = NULL;
    virUSBDevicePtr usb = NULL;
    char *devstr = NULL;
    bool added = false;
    bool teardowncgroup = false;
    int ret = -1;

    if (qemuFindHostdevUSBDevice(hostdev, true, &usb) < 0)
        return -1;

    if (!(list = virUSBDeviceListNew()))
        goto cleanup;

    if (virUSBDeviceListAdd(list, usb) < 0)
        goto cleanup;

    if (qemuPrepareHostdevUSBDevices(driver, vm->def->name, list) < 0)
        goto cleanup;

    added = true;
    virUSBDeviceListSteal(list, usb);

    if (qemuSetupHostdevCGroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

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
    qemuDomainObjExitMonitor(driver, vm);
    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto cleanup;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    ret = 0;
cleanup:
    if (ret < 0 &&
        teardowncgroup &&
        qemuTeardownHostdevCgroup(vm, hostdev) < 0)
        VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
    if (added)
        virUSBDeviceListSteal(driver->activeUsbHostdevs, usb);
    virUSBDeviceFree(usb);
    virObjectUnref(list);
    VIR_FREE(devstr);
    return ret;
}

static int
qemuDomainAttachHostScsiDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainControllerDefPtr cont = NULL;
    char *devstr = NULL;
    char *drvstr = NULL;
    bool teardowncgroup = false;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DRIVE) ||
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) ||
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE_SCSI_GENERIC)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("SCSI passthrough is not supported by this version of qemu"));
        return -1;
    }

    cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, hostdev->info->addr.drive.controller);
    if (!cont)
        return -1;

    if (qemuPrepareHostdevSCSIDevices(driver, vm->def->name,
                                      &hostdev, 1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to prepare scsi hostdev: %s:%d:%d:%d"),
                       hostdev->source.subsys.u.scsi.adapter,
                       hostdev->source.subsys.u.scsi.bus,
                       hostdev->source.subsys.u.scsi.target,
                       hostdev->source.subsys.u.scsi.unit);
        return -1;
    }

    if (qemuSetupHostdevCGroup(vm, hostdev) < 0)
        goto cleanup;
    teardowncgroup = true;

    if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
        goto cleanup;

    if (!(drvstr = qemuBuildSCSIHostdevDrvStr(hostdev, priv->qemuCaps,
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
    qemuDomainObjExitMonitor(driver, vm);

    virDomainAuditHostdev(vm, hostdev, "attach", ret == 0);
    if (ret < 0)
        goto cleanup;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    ret = 0;
cleanup:
    if (ret < 0) {
        qemuDomainReAttachHostScsiDevices(driver, vm->def->name, &hostdev, 1);
        if (teardowncgroup && qemuTeardownHostdevCgroup(vm, hostdev) < 0)
            VIR_WARN("Unable to remove host device cgroup ACL on hotplug fail");
    }
    VIR_FREE(drvstr);
    VIR_FREE(devstr);
    return ret;
}

int qemuDomainAttachHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev mode '%s' not supported"),
                       virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    if (virSecurityManagerSetHostdevLabel(driver->securityManager,
                                          vm->def, hostdev, NULL) < 0)
        return -1;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (qemuDomainAttachHostPciDevice(driver, vm,
                                          hostdev) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (qemuDomainAttachHostUsbDevice(driver, vm,
                                          hostdev) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        if (qemuDomainAttachHostScsiDevice(driver, vm,
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
    if (virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def, hostdev, NULL) < 0)
        VIR_WARN("Unable to restore host device labelling on hotplug fail");
    return -1;
}

static virDomainNetDefPtr *qemuDomainFindNet(virDomainObjPtr vm,
                                             virDomainNetDefPtr dev)
{
    size_t i;

    for (i = 0; i < vm->def->nnets; i++) {
        if (virMacAddrCmp(&vm->def->nets[i]->mac, &dev->mac) == 0)
            return &vm->def->nets[i];
    }

    return NULL;
}

static char *
qemuDomainNetGetBridgeName(virConnectPtr conn, virDomainNetDefPtr net)
{
    char *brname = NULL;
    int actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        const char *tmpbr = virDomainNetGetActualBridgeName(net);
        if (!tmpbr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("interface is missing bridge name"));
            goto cleanup;
        }
        /* we need a copy, not just a pointer to the original */
        if (VIR_STRDUP(brname, tmpbr) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK) {
        int active;
        virErrorPtr errobj;
        virNetworkPtr network;

        if (!(network = virNetworkLookupByName(conn, net->data.network.name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Couldn't find network '%s'"),
                           net->data.network.name);
            goto cleanup;
        }

        active = virNetworkIsActive(network);
        if (active == 1) {
            brname = virNetworkGetBridgeName(network);
        } else if (active == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Network '%s' is not active."),
                           net->data.network.name);
        }

        /* Make sure any above failure is preserved */
        errobj = virSaveLastError();
        virNetworkFree(network);
        virSetError(errobj);
        virFreeError(errobj);

    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Interface type %d has no bridge name"),
                       virDomainNetGetActualType(net));
    }

cleanup:
    return brname;
}

static int
qemuDomainChangeNetBridge(virConnectPtr conn,
                          virDomainObjPtr vm,
                          virDomainNetDefPtr olddev,
                          virDomainNetDefPtr newdev)
{
    int ret = -1;
    char *oldbridge = NULL, *newbridge = NULL;

    if (!(oldbridge = qemuDomainNetGetBridgeName(conn, olddev)))
        goto cleanup;

    if (!(newbridge = qemuDomainNetGetBridgeName(conn, newdev)))
        goto cleanup;

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
    VIR_FREE(oldbridge);
    VIR_FREE(newbridge);
    return ret;
}

static int
qemuDomainChangeNetFilter(virConnectPtr conn,
                          virDomainObjPtr vm,
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

    if (virDomainConfNWFilterInstantiate(conn, vm->def->uuid, newdev) < 0) {
        virErrorPtr errobj;

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("failed to add new filter rules to '%s' "
                         "- attempting to restore old rules"),
                       olddev->ifname);
        errobj = virSaveLastError();
        ignore_value(virDomainConfNWFilterInstantiate(conn, vm->def->uuid, olddev));
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

    VIR_DEBUG("dev: %s, state: %d", dev->info.alias, linkstate);

    if (!dev->info.alias) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("can't change link state: device alias not found"));
        return -1;
    }

    qemuDomainObjEnterMonitor(driver, vm);

    ret = qemuMonitorSetLink(priv->mon, dev->info.alias, linkstate);
    if (ret < 0)
        goto cleanup;

    /* modify the device configuration */
    dev->linkstate = linkstate;

cleanup:
    qemuDomainObjExitMonitor(driver, vm);

    return ret;
}

int
qemuDomainChangeNet(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    virDomainPtr dom,
                    virDomainDeviceDefPtr dev)
{
    virDomainNetDefPtr newdev = dev->data.net;
    virDomainNetDefPtr *devslot = qemuDomainFindNet(vm, newdev);
    virDomainNetDefPtr olddev;
    int oldType, newType;
    bool needReconnect = false;
    bool needBridgeChange = false;
    bool needFilterChange = false;
    bool needLinkStateChange = false;
    bool needReplaceDevDef = false;
    bool needBandwidthSet = false;
    int ret = -1;

    if (!devslot || !(olddev = *devslot)) {
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
         olddev->driver.virtio.event_idx != newdev->driver.virtio.event_idx)) {
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
        networkAllocateActualDevice(newdev) < 0) {
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
                                newdev->data.ethernet.dev) ||
                STRNEQ_NULLABLE(olddev->data.ethernet.ipaddr,
                                newdev->data.ethernet.ipaddr)) {
                needReconnect = true;
            }
        break;

        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
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
                                  false) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot set bandwidth limits on %s"),
                           newdev->ifname);
            goto cleanup;
        }
        needReplaceDevDef = true;
    }

    if (needBridgeChange) {
        if (qemuDomainChangeNetBridge(dom->conn, vm, olddev, newdev) < 0)
            goto cleanup;
        /* we successfully switched to the new bridge, and we've
         * determined that the rest of newdev is equivalent to olddev,
         * so move newdev into place */
        needReplaceDevDef = true;
    }

    if (needFilterChange) {
        if (qemuDomainChangeNetFilter(dom->conn, vm, olddev, newdev) < 0)
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
        networkReleaseActualDevice(olddev);
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
        networkReleaseActualDevice(newdev);

    return ret;
}



static virDomainGraphicsDefPtr qemuDomainFindGraphics(virDomainObjPtr vm,
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
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("cannot change the number of listen addresses"));
        goto cleanup;
    }

    for (i = 0; i < dev->nListens; i++) {
        virDomainGraphicsListenDefPtr newlisten = &dev->listens[i];
        virDomainGraphicsListenDefPtr oldlisten = &olddev->listens[i];

        if (newlisten->type != oldlisten->type) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("cannot change the type of listen address"));
            goto cleanup;
        }

        switch ((enum virDomainGraphicsListenType) newlisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            if (STRNEQ_NULLABLE(newlisten->address, oldlisten->address)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               dev->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC ?
                               _("cannot change listen address setting on vnc graphics") :
                               _("cannot change listen address setting on spice graphics"));
                goto cleanup;
            }
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (STRNEQ_NULLABLE(newlisten->network, oldlisten->network)) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
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
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot change port settings on vnc graphics"));
            goto cleanup;
        }
        if (STRNEQ_NULLABLE(olddev->data.vnc.keymap, dev->data.vnc.keymap)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
                                                    cfg->vncPassword);
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
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot change port settings on spice graphics"));
            goto cleanup;
        }
        if (STRNEQ_NULLABLE(olddev->data.spice.keymap,
                            dev->data.spice.keymap)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
                                                    cfg->spicePassword);

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


static void
qemuDomainRemoveDiskDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainDiskDefPtr disk)
{
    virDomainDeviceDef dev;
    virDomainEventPtr event;
    size_t i;

    VIR_DEBUG("Removing disk %s from domain %p %s",
              disk->info.alias, vm, vm->def->name);

    virDomainAuditDisk(vm, disk->src, NULL, "detach", true);

    event = virDomainEventDeviceRemovedNewFromObj(vm, disk->info.alias);
    if (event)
        qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->ndisks; i++) {
        if (vm->def->disks[i] == disk) {
            virDomainDiskRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &disk->info, disk->src);

    if (virSecurityManagerRestoreImageLabel(driver->securityManager,
                                            vm->def, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    if (qemuTeardownDiskCgroup(vm, disk) < 0)
        VIR_WARN("Failed to tear down cgroup for disk path %s", disk->src);

    if (virDomainLockDiskDetach(driver->lockManager, vm, disk) < 0)
        VIR_WARN("Unable to release lock on %s", disk->src);

    dev.type = VIR_DOMAIN_DEVICE_DISK;
    dev.data.disk = disk;
    ignore_value(qemuRemoveSharedDevice(driver, &dev, vm->def->name));

    virDomainDiskDefFree(disk);
}


static void
qemuDomainRemoveControllerDevice(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainControllerDefPtr controller)
{
    virDomainEventPtr event;
    size_t i;

    VIR_DEBUG("Removing controller %s from domain %p %s",
              controller->info.alias, vm, vm->def->name);

    event = virDomainEventDeviceRemovedNewFromObj(vm, controller->info.alias);
    if (event)
        qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->ncontrollers; i++) {
        if (vm->def->controllers[i] == controller) {
            virDomainControllerRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &controller->info, NULL);
    virDomainControllerDefFree(controller);
}


static void
qemuDomainRemovePCIHostDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr hostdev)
{
    virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;
    virPCIDevicePtr pci;
    virPCIDevicePtr activePci;

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);
    pci = virPCIDeviceNew(subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                          subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
    if (pci) {
        activePci = virPCIDeviceListSteal(driver->activePciHostdevs, pci);
        if (activePci &&
            virPCIDeviceReset(activePci, driver->activePciHostdevs,
                              driver->inactivePciHostdevs) == 0) {
            qemuReattachPciDevice(activePci, driver);
        } else {
            /* reset of the device failed, treat it as if it was returned */
            virPCIDeviceFree(activePci);
        }
        virPCIDeviceFree(pci);
    }
    virObjectUnlock(driver->activePciHostdevs);
    virObjectUnlock(driver->inactivePciHostdevs);

    qemuDomainReleaseDeviceAddress(vm, hostdev->info, NULL);
}

static void
qemuDomainRemoveUSBHostDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm ATTRIBUTE_UNUSED,
                              virDomainHostdevDefPtr hostdev)
{
    virDomainHostdevSubsysPtr subsys = &hostdev->source.subsys;
    virUSBDevicePtr usb;

    usb = virUSBDeviceNew(subsys->u.usb.bus, subsys->u.usb.device, NULL);
    if (usb) {
        virObjectLock(driver->activeUsbHostdevs);
        virUSBDeviceListDel(driver->activeUsbHostdevs, usb);
        virObjectUnlock(driver->activeUsbHostdevs);
        virUSBDeviceFree(usb);
    } else {
        VIR_WARN("Unable to find device %03d.%03d in list of used USB devices",
                 subsys->u.usb.bus, subsys->u.usb.device);
    }
}

static void
qemuDomainRemoveSCSIHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev)
{
    qemuDomainReAttachHostScsiDevices(driver, vm->def->name, &hostdev, 1);
}

static void
qemuDomainRemoveHostDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainHostdevDefPtr hostdev)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainNetDefPtr net = NULL;
    virDomainEventPtr event;
    size_t i;

    VIR_DEBUG("Removing host device %s from domain %p %s",
              hostdev->info->alias, vm, vm->def->name);

    event = virDomainEventDeviceRemovedNewFromObj(vm, hostdev->info->alias);
    if (event)
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

    qemuDomainHostdevNetConfigRestore(hostdev, cfg->stateDir);

    switch ((enum virDomainHostdevSubsysType) hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        qemuDomainRemovePCIHostDevice(driver, vm, hostdev);
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

    if (virSecurityManagerRestoreHostdevLabel(driver->securityManager,
                                              vm->def, hostdev, NULL) < 0) {
        VIR_WARN("Failed to restore host device labelling");
    }

    virDomainHostdevDefFree(hostdev);

    if (net) {
        networkReleaseActualDevice(net);
        virDomainNetDefFree(net);
    }
    virObjectUnref(cfg);
}


static void
qemuDomainRemoveNetDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainNetDefPtr net)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virNetDevVPortProfilePtr vport;
    virDomainEventPtr event;
    size_t i;

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* this function handles all hostdev and netdev cleanup */
        qemuDomainRemoveHostDevice(driver, vm, virDomainNetGetActualHostdev(net));
        return;
    }

    VIR_DEBUG("Removing network interface %s from domain %p %s",
              net->info.alias, vm, vm->def->name);

    virDomainAuditNet(vm, net, NULL, "detach", true);

    event = virDomainEventDeviceRemovedNewFromObj(vm, net->info.alias);
    if (event)
        qemuDomainEventQueue(driver, event);

    for (i = 0; i < vm->def->nnets; i++) {
        if (vm->def->nets[i] == net) {
            virDomainNetRemove(vm->def, i);
            break;
        }
    }

    qemuDomainReleaseDeviceAddress(vm, &net->info, NULL);
    virDomainConfNWFilterTeardown(net);

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
        ignore_value(virNetDevMacVLanDeleteWithVPortProfile(
                         net->ifname, &net->mac,
                         virDomainNetGetActualDirectDev(net),
                         virDomainNetGetActualDirectMode(net),
                         virDomainNetGetActualVirtPortProfile(net),
                         cfg->stateDir));
        VIR_FREE(net->ifname);
    }

    if (cfg->macFilter && (net->ifname != NULL)) {
        if ((errno = networkDisallowMacOnPort(driver,
                                              net->ifname,
                                              &net->mac))) {
            virReportSystemError(errno,
             _("failed to remove ebtables rule on '%s'"),
                                 net->ifname);
        }
    }

    vport = virDomainNetGetActualVirtPortProfile(net);
    if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
        ignore_value(virNetDevOpenvswitchRemovePort(
                        virDomainNetGetActualBridgeName(net),
                        net->ifname));

    networkReleaseActualDevice(net);
    virDomainNetDefFree(net);
    virObjectUnref(cfg);
}


static void
qemuDomainRemoveChrDevice(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          virDomainChrDefPtr chr)
{
    virDomainEventPtr event;

    VIR_DEBUG("Removing character device %s from domain %p %s",
              chr->info.alias, vm, vm->def->name);

    event = virDomainEventDeviceRemovedNewFromObj(vm, chr->info.alias);
    if (event)
        qemuDomainEventQueue(driver, event);

    qemuDomainChrRemove(vm->def, chr);
    virDomainChrDefFree(chr);
}


void
qemuDomainRemoveDevice(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       virDomainDeviceDefPtr dev)
{
    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        qemuDomainRemoveDiskDevice(driver, vm, dev->data.disk);
        break;
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        qemuDomainRemoveControllerDevice(driver, vm, dev->data.controller);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        qemuDomainRemoveNetDevice(driver, vm, dev->data.net);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        qemuDomainRemoveHostDevice(driver, vm, dev->data.hostdev);
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        qemuDomainRemoveChrDevice(driver, vm, dev->data.chr);
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
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("don't know how to remove a %s device"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }
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
 *   1 when device removal finished
 *   2 device removal did not finish in QEMU_REMOVAL_WAIT_TIME
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

void
qemuDomainSignalDeviceRemoval(virDomainObjPtr vm,
                              const char *devAlias)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (STREQ_NULLABLE(priv->unpluggingDevice, devAlias)) {
        qemuDomainResetDeviceRemoval(vm);
        virCondSignal(&priv->unplugFinished);
    }
}


static int
qemuDomainDetachVirtioDiskDevice(virQEMUDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainDiskDefPtr detach)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *drivestr = NULL;

    if (qemuIsMultiFunctionDevice(vm->def, &detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %s"),
                       detach->dst);
        goto cleanup;
    }

    if (STREQLEN(vm->def->os.machine, "s390-ccw", 8) &&
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

    /* build the actual drive id string as the disk->info.alias doesn't
     * contain the QEMU_DRIVE_HOST_PREFIX that is passed to qemu */
    if (virAsprintf(&drivestr, "%s%s",
                    QEMU_DRIVE_HOST_PREFIX, detach->info.alias) < 0)
        goto cleanup;

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
            goto cleanup;
        }
    }

    /* disconnect guest from host device */
    qemuMonitorDriveDel(priv->mon, drivestr);

    qemuDomainObjExitMonitor(driver, vm);

    if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveDiskDevice(driver, vm, detach);
    ret = 0;

cleanup:
    qemuDomainResetDeviceRemoval(vm);
    VIR_FREE(drivestr);
    return ret;
}

static int
qemuDomainDetachDiskDevice(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virDomainDiskDefPtr detach)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *drivestr = NULL;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Underlying qemu does not support %s disk removal"),
                       virDomainDiskBusTypeToString(detach->bus));
        goto cleanup;
    }

    if (detach->mirror) {
        virReportError(VIR_ERR_BLOCK_COPY_ACTIVE,
                       _("disk '%s' is in an active block copy job"),
                       detach->dst);
        goto cleanup;
    }

    /* build the actual drive id string as the disk->info.alias doesn't
     * contain the QEMU_DRIVE_HOST_PREFIX that is passed to qemu */
    if (virAsprintf(&drivestr, "%s%s",
                    QEMU_DRIVE_HOST_PREFIX, detach->info.alias) < 0)
        goto cleanup;

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        virDomainAuditDisk(vm, detach->src, NULL, "detach", false);
        goto cleanup;
    }

    /* disconnect guest from host device */
    qemuMonitorDriveDel(priv->mon, drivestr);

    qemuDomainObjExitMonitor(driver, vm);

    if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveDiskDevice(driver, vm, detach);
    ret = 0;

cleanup:
    qemuDomainResetDeviceRemoval(vm);
    VIR_FREE(drivestr);
    return ret;
}

static int
qemuFindDisk(virDomainDefPtr def, const char *dst)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ(def->disks[i]->dst, dst)) {
            return i;
        }
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

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuAssignDeviceControllerAlias(detach) < 0)
            goto cleanup;
    }

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias)) {
            qemuDomainObjExitMonitor(driver, vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

    if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveControllerDevice(driver, vm, detach);

    ret = 0;

cleanup:
    qemuDomainResetDeviceRemoval(vm);
    return ret;
}

static int
qemuDomainDetachHostPciDevice(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainHostdevSubsysPtr subsys = &detach->source.subsys;
    int ret;

    if (qemuIsMultiFunctionDevice(vm->def, detach->info)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("cannot hot unplug multifunction PCI device: %.4x:%.2x:%.2x.%.1x"),
                       subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                       subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
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
    qemuDomainObjExitMonitor(driver, vm);

    return ret;
}

static int
qemuDomainDetachHostUsbDevice(virQEMUDriverPtr driver,
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
    qemuDomainObjExitMonitor(driver, vm);

    return ret;
}

static int
qemuDomainDetachHostScsiDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr detach)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *drvstr = NULL;
    char *devstr = NULL;
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

    if (!(drvstr = qemuBuildSCSIHostdevDrvStr(detach, priv->qemuCaps,
                                              &buildCommandLineCallbacks)))
        goto cleanup;
    if (!(devstr = qemuBuildSCSIHostdevDevStr(vm->def, detach, priv->qemuCaps)))
        goto cleanup;

    qemuDomainMarkDeviceForRemoval(vm, detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if ((ret = qemuMonitorDelDevice(priv->mon, detach->info->alias)) == 0) {
        if ((ret = qemuMonitorDriveDel(priv->mon, drvstr)) < 0) {
            virErrorPtr orig_err = virSaveLastError();
            if (qemuMonitorAddDevice(priv->mon, devstr) < 0)
                VIR_WARN("Unable to add device %s (%s) after failed "
                         "qemuMonitorDriveDel",
                         drvstr, devstr);
            if (orig_err) {
                virSetError(orig_err);
                virFreeError(orig_err);
            }
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

cleanup:
    VIR_FREE(drvstr);
    VIR_FREE(devstr);
    return ret;
}

static int
qemuDomainDetachThisHostDevice(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr detach)
{
    int ret = -1;

    switch (detach->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        ret = qemuDomainDetachHostPciDevice(driver, vm, detach);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        ret = qemuDomainDetachHostUsbDevice(driver, vm, detach);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
        ret = qemuDomainDetachHostScsiDevice(driver, vm, detach);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hostdev subsys type '%s' not supported"),
                       virDomainHostdevSubsysTypeToString(detach->source.subsys.type));
        return -1;
    }

    if (ret < 0)
        virDomainAuditHostdev(vm, detach, "detach", false);
    else if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveHostDevice(driver, vm, detach);

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
                           subsys->u.pci.addr.domain, subsys->u.pci.addr.bus,
                           subsys->u.pci.addr.slot, subsys->u.pci.addr.function);
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (subsys->u.usb.bus && subsys->u.usb.device) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("host usb device %03d.%03d not found"),
                               subsys->u.usb.bus, subsys->u.usb.device);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("host usb device vendor=0x%.4x product=0x%.4x not found"),
                               subsys->u.usb.vendor, subsys->u.usb.product);
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("host scsi device %s:%d:%d.%d not found"),
                           subsys->u.scsi.adapter, subsys->u.scsi.bus,
                           subsys->u.scsi.target, subsys->u.scsi.unit);
            break;
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
    int vlan;
    char *hostnet_name = NULL;
    char mac[VIR_MAC_STRING_BUFLEN];

    detachidx = virDomainNetFindIdx(vm->def, dev->data.net);
    if (detachidx == -2) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("multiple devices matching mac address %s found"),
                       virMacAddrFormat(&dev->data.net->mac, mac));
        goto cleanup;
    }
    else if (detachidx < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("network device %s not found"),
                       virMacAddrFormat(&dev->data.net->mac, mac));
        goto cleanup;
    }
    detach = vm->def->nets[detachidx];

    if (virDomainNetGetActualType(detach) == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* coverity[negative_returns] */
        ret = qemuDomainDetachThisHostDevice(driver, vm,
                                             virDomainNetGetActualHostdev(detach));
        goto cleanup;
    }
    if (STREQLEN(vm->def->os.machine, "s390-ccw", 8) &&
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

    if ((vlan = qemuDomainNetVLAN(detach)) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("unable to determine original VLAN"));
        goto cleanup;
    }

    if (virAsprintf(&hostnet_name, "host%s", detach->info.alias) < 0)
        goto cleanup;

    qemuDomainMarkDeviceForRemoval(vm, &detach->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    }

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NETDEV) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE)) {
        if (qemuMonitorRemoveNetdev(priv->mon, hostnet_name) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0) {
            qemuDomainObjExitMonitor(driver, vm);
            virDomainAuditNet(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitor(driver, vm);

    if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveNetDevice(driver, vm, detach);

    ret = 0;

cleanup:
    qemuDomainResetDeviceRemoval(vm);
    VIR_FREE(hostnet_name);
    return ret;
}

int
qemuDomainChangeGraphicsPasswords(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  int type,
                                  virDomainGraphicsAuthDefPtr auth,
                                  const char *defaultPasswd)
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

    qemuDomainObjEnterMonitor(driver, vm);
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
    qemuDomainObjExitMonitor(driver, vm);
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
    char *charAlias = NULL;
    char *devstr = NULL;

    if (!(tmpChr = virDomainChrFind(vmdef, chr))) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("device not present in domain configuration"));
        return ret;
    }

    if (qemuBuildChrDeviceStr(&devstr, vm->def, chr, priv->qemuCaps) < 0)
        return ret;

    if (virAsprintf(&charAlias, "char%s", tmpChr->info.alias) < 0)
        goto cleanup;

    qemuDomainMarkDeviceForRemoval(vm, &tmpChr->info);

    qemuDomainObjEnterMonitor(driver, vm);
    if (devstr && qemuMonitorDelDevice(priv->mon, tmpChr->info.alias) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }

    if (qemuMonitorDetachCharDev(priv->mon, charAlias) < 0) {
        qemuDomainObjExitMonitor(driver, vm);
        goto cleanup;
    }
    qemuDomainObjExitMonitor(driver, vm);

    if (!qemuDomainWaitForDeviceRemoval(vm))
        qemuDomainRemoveChrDevice(driver, vm, tmpChr);
    ret = 0;

cleanup:
    qemuDomainResetDeviceRemoval(vm);
    VIR_FREE(devstr);
    VIR_FREE(charAlias);
    return ret;
}
