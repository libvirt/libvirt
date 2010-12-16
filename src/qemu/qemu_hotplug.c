/*
 * qemu_hotplug.h: QEMU device hotplug management
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#include <config.h>

#include "qemu_hotplug.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_command.h"
#include "qemu_bridge_filter.h"
#include "qemu_audit.h"
#include "qemu_hostdev.h"
#include "domain_nwfilter.h"
#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "pci.h"
#include "files.h"
#include "qemu_cgroup.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

int qemuDomainChangeEjectableMedia(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainDiskDefPtr disk,
                                   unsigned long long qemuCmdFlags,
                                   bool force)
{
    virDomainDiskDefPtr origdisk = NULL;
    int i;
    int ret;
    char *driveAlias = NULL;

    origdisk = NULL;
    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (vm->def->disks[i]->bus == disk->bus &&
            STREQ(vm->def->disks[i]->dst, disk->dst)) {
            origdisk = vm->def->disks[i];
            break;
        }
    }

    if (!origdisk) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("No device with bus '%s' and target '%s'"),
                        virDomainDiskBusTypeToString(disk->bus),
                        disk->dst);
        return -1;
    }

    if (!origdisk->info.alias) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing disk device alias name for %s"), origdisk->dst);
        return -1;
    }

    if (origdisk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        origdisk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Removable media not supported for %s device"),
                        virDomainDiskDeviceTypeToString(disk->device));
        return -1;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(driver->securityDriver,
                                                            vm, disk) < 0)
        return -1;

    if (!(driveAlias = qemuDeviceDriveHostAlias(origdisk, qemuCmdFlags)))
        goto error;

    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (disk->src) {
        const char *format = NULL;
        if (disk->type != VIR_DOMAIN_DISK_TYPE_DIR) {
            if (disk->driverType)
                format = disk->driverType;
            else if (origdisk->driverType)
                format = origdisk->driverType;
        }
        ret = qemuMonitorChangeMedia(priv->mon,
                                     driveAlias,
                                     disk->src, format);
    } else {
        ret = qemuMonitorEjectMedia(priv->mon, driveAlias, force);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, origdisk, disk, "update", ret >= 0);

    if (ret < 0)
        goto error;

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, origdisk) < 0)
        VIR_WARN("Unable to restore security label on ejected image %s", origdisk->src);

    VIR_FREE(origdisk->src);
    origdisk->src = disk->src;
    disk->src = NULL;
    origdisk->type = disk->type;

    VIR_FREE(driveAlias);

    virDomainDiskDefFree(disk);

    return ret;

error:
    VIR_FREE(driveAlias);
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, disk) < 0)
        VIR_WARN("Unable to restore security label on new media %s", disk->src);
    return -1;
}


int qemuDomainAttachPciDiskDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk,
                                  unsigned long long qemuCmdFlags)
{
    int i, ret;
    const char* type = virDomainDiskBusTypeToString(disk->bus);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;
    char *drivestr = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(driver->securityDriver,
                                                            vm, disk) < 0)
        return -1;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &disk->info) < 0)
            goto error;
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;

        if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
            goto error;

        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
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
        virDomainDevicePCIAddress guestAddr;
        ret = qemuMonitorAddPCIDisk(priv->mon,
                                    disk->src,
                                    type,
                                    &guestAddr);
        if (ret == 0) {
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            memcpy(&disk->info.addr.pci, &guestAddr, sizeof(guestAddr));
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, NULL, disk, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &disk->info) < 0)
        VIR_WARN("Unable to release PCI address on %s", disk->src);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


int qemuDomainAttachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainControllerDefPtr controller,
                                        unsigned long long qemuCmdFlags)
{
    int i;
    int ret = -1;
    const char* type = virDomainControllerTypeToString(controller->type);
    char *devstr = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if ((vm->def->controllers[i]->type == controller->type) &&
            (vm->def->controllers[i]->idx == controller->idx)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s:%d already exists"),
                            type, controller->idx);
            return -1;
        }
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &controller->info) < 0)
            goto cleanup;
        if (qemuAssignDeviceControllerAlias(controller) < 0)
            goto cleanup;

        if (!(devstr = qemuBuildControllerDevStr(controller))) {
            virReportOOMError();
            goto cleanup;
        }
    }

    if (VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    } else {
        ret = qemuMonitorAttachPCIDiskController(priv->mon,
                                                 type,
                                                 &controller->info.addr.pci);
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (ret == 0) {
        controller->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        virDomainControllerInsertPreAlloced(vm->def, controller);
    }

cleanup:
    if ((ret != 0) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (controller->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &controller->info) < 0)
        VIR_WARN0("Unable to release PCI address on controller");

    VIR_FREE(devstr);
    return ret;
}


static virDomainControllerDefPtr
qemuDomainFindOrCreateSCSIDiskController(struct qemud_driver *driver,
                                         virDomainObjPtr vm,
                                         int controller,
                                         unsigned long long qemuCmdFlags)
{
    int i;
    virDomainControllerDefPtr cont;
    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        cont = vm->def->controllers[i];

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            continue;

        if (cont->idx == controller)
            return cont;
    }

    /* No SCSI controller present, for backward compatibility we
     * now hotplug a controller */
    if (VIR_ALLOC(cont) < 0) {
        virReportOOMError();
        return NULL;
    }
    cont->type = VIR_DOMAIN_CONTROLLER_TYPE_SCSI;
    cont->idx = 0;
    cont->model = -1;

    VIR_INFO0("No SCSI controller present, hotplugging one");
    if (qemuDomainAttachPciControllerDevice(driver,
                                            vm, cont, qemuCmdFlags) < 0) {
        VIR_FREE(cont);
        return NULL;
    }

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        /* cont doesn't need freeing here, since the reference
         * now held in def->controllers */
        return NULL;
    }

    return cont;
}


int qemuDomainAttachSCSIDisk(struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk,
                             unsigned long long qemuCmdFlags)
{
    int i;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainControllerDefPtr cont = NULL;
    char *drivestr = NULL;
    char *devstr = NULL;
    int ret = -1;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }


    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(driver->securityDriver,
                                                            vm, disk) < 0)
        return -1;

    /* We should have an address already, so make sure */
    if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected disk address type %s"),
                        virDomainDeviceAddressTypeToString(disk->info.type));
        goto error;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
        goto error;

    for (i = 0 ; i <= disk->info.addr.drive.controller ; i++) {
        cont = qemuDomainFindOrCreateSCSIDiskController(driver, vm, i, qemuCmdFlags);
        if (!cont)
            goto error;
    }

    /* Tell clang that "cont" is non-NULL.
       This is because disk->info.addr.driver.controller is unsigned,
       and hence the above loop must iterate at least once.  */
    sa_assert (cont);

    if (cont->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("SCSI controller %d was missing its PCI address"), cont->idx);
        goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
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
        virDomainDeviceDriveAddress driveAddr;
        ret = qemuMonitorAttachDrive(priv->mon,
                                     drivestr,
                                     &cont->info.addr.pci,
                                     &driveAddr);
        if (ret == 0) {
            /* XXX we should probably validate that the addr matches
             * our existing defined addr instead of overwriting */
            disk->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
            memcpy(&disk->info.addr.drive, &driveAddr, sizeof(driveAddr));
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, NULL, disk, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


int qemuDomainAttachUsbMassstorageDevice(struct qemud_driver *driver,
                                         virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk,
                                         unsigned long long qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;
    char *drivestr = NULL;
    char *devstr = NULL;

    for (i = 0 ; i < vm->def->ndisks ; i++) {
        if (STREQ(vm->def->disks[i]->dst, disk->dst)) {
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                            _("target %s already exists"), disk->dst);
            return -1;
        }
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityImageLabel &&
        driver->securityDriver->domainSetSecurityImageLabel(driver->securityDriver,
                                                            vm, disk) < 0)
        return -1;

    if (!disk->src) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("disk source path is missing"));
        goto error;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceDiskAlias(disk, qemuCmdFlags) < 0)
            goto error;
        if (!(drivestr = qemuBuildDriveStr(disk, 0, qemuCmdFlags)))
            goto error;
        if (!(devstr = qemuBuildDriveDevStr(disk)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->disks, vm->def->ndisks+1) < 0) {
        virReportOOMError();
        goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
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
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, NULL, disk, "attach", ret >= 0);

    if (ret < 0)
        goto error;

    virDomainDiskInsertPreAlloced(vm->def, disk);

    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    return 0;

error:
    VIR_FREE(devstr);
    VIR_FREE(drivestr);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, disk) < 0)
        VIR_WARN("Unable to restore security label on %s", disk->src);

    return -1;
}


/* XXX conn required for network -> bridge resolution */
int qemuDomainAttachNetDevice(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainNetDefPtr net,
                              unsigned long long qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *tapfd_name = NULL;
    int tapfd = -1;
    char *nicstr = NULL;
    char *netstr = NULL;
    int ret = -1;
    virDomainDevicePCIAddress guestAddr;
    int vlan;

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_HOST_NET_ADD)) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("installed qemu version does not support host_net_add"));
        return -1;
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
        net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (priv->monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("network device type '%s' cannot be attached: "
                              "qemu is not using a unix socket monitor"),
                            virDomainNetTypeToString(net->type));
            return -1;
        }

        if ((tapfd = qemuNetworkIfaceConnect(conn, driver, net, qemuCmdFlags)) < 0)
            return -1;
    } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        if (priv->monConfig->type != VIR_DOMAIN_CHR_TYPE_UNIX) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("network device type '%s' cannot be attached: "
                            "qemu is not using a unix socket monitor"),
                            virDomainNetTypeToString(net->type));
            return -1;
        }

        if ((tapfd = qemuPhysIfaceConnect(conn, driver, net,
                                          qemuCmdFlags,
                                          vm->def->uuid,
                                          VIR_VM_OP_CREATE)) < 0)
            return -1;
    }

    if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets+1) < 0)
        goto no_memory;

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NET_NAME) ||
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (qemuAssignDeviceNetAlias(vm->def, net, -1) < 0)
            goto cleanup;
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &net->info) < 0)
        goto cleanup;

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        vlan = -1;
    } else {
        vlan = qemuDomainNetVLAN(net);

        if (vlan < 0) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("Unable to attach network devices without vlan"));
            goto cleanup;
        }
    }

    if (tapfd != -1) {
        if (virAsprintf(&tapfd_name, "fd-%s", net->info.alias) < 0)
            goto no_memory;

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorSendFileHandle(priv->mon, tapfd_name, tapfd) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            goto cleanup;
        }
        qemuDomainObjExitMonitorWithDriver(driver, vm);

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit"));
            goto cleanup;
        }
    }

    /* FIXME - need to support vhost-net here (5th arg) */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (!(netstr = qemuBuildHostNetStr(net, ',',
                                           -1, tapfd_name, 0)))
            goto try_tapfd_close;
    } else {
        if (!(netstr = qemuBuildHostNetStr(net, ' ',
                                           vlan, tapfd_name, 0)))
            goto try_tapfd_close;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (qemuMonitorAddNetdev(priv->mon, netstr) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, NULL, net, "attach", false);
            goto try_tapfd_close;
        }
    } else {
        if (qemuMonitorAddHostNetwork(priv->mon, netstr) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, NULL, net, "attach", false);
            goto try_tapfd_close;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    VIR_FORCE_CLOSE(tapfd);

    if (!virDomainObjIsActive(vm)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (!(nicstr = qemuBuildNicDevStr(net, vlan)))
            goto try_remove;
    } else {
        if (!(nicstr = qemuBuildNicStr(net, NULL, vlan)))
            goto try_remove;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorAddDevice(priv->mon, nicstr) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, NULL, net, "attach", false);
            goto try_remove;
        }
    } else {
        if (qemuMonitorAddPCINetwork(priv->mon, nicstr,
                                     &guestAddr) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, NULL, net, "attach", false);
            goto try_remove;
        }
        net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        memcpy(&net->info.addr.pci, &guestAddr, sizeof(guestAddr));
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainNetAudit(vm, NULL, net, "attach", true);

    ret = 0;

    vm->def->nets[vm->def->nnets++] = net;

cleanup:
    if ((ret != 0) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &net->info) < 0)
        VIR_WARN0("Unable to release PCI address on NIC");

    if (ret != 0)
        virDomainConfNWFilterTeardown(net);

    VIR_FREE(nicstr);
    VIR_FREE(netstr);
    VIR_FREE(tapfd_name);
    VIR_FORCE_CLOSE(tapfd);

    return ret;

try_remove:
    if (!virDomainObjIsActive(vm))
        goto cleanup;

    if (vlan < 0) {
        if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
            (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
            char *netdev_name;
            if (virAsprintf(&netdev_name, "host%s", net->info.alias) < 0)
                goto no_memory;
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            if (qemuMonitorRemoveNetdev(priv->mon, netdev_name) < 0)
                VIR_WARN("Failed to remove network backend for netdev %s",
                         netdev_name);
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            VIR_FREE(netdev_name);
        } else {
            VIR_WARN0("Unable to remove network backend");
        }
    } else {
        char *hostnet_name;
        if (virAsprintf(&hostnet_name, "host%s", net->info.alias) < 0)
            goto no_memory;
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0)
            VIR_WARN("Failed to remove network backend for vlan %d, net %s",
                     vlan, hostnet_name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        VIR_FREE(hostnet_name);
    }
    goto cleanup;

try_tapfd_close:
    if (!virDomainObjIsActive(vm))
        goto cleanup;

    if (tapfd_name) {
        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        if (qemuMonitorCloseFileHandle(priv->mon, tapfd_name) < 0)
            VIR_WARN("Failed to close tapfd with '%s'", tapfd_name);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    }

    goto cleanup;

no_memory:
    virReportOOMError();
    goto cleanup;
}


int qemuDomainAttachHostPciDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev,
                                  unsigned long long qemuCmdFlags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;
    char *devstr = NULL;
    int configfd = -1;
    char *configfd_name = NULL;

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError();
        return -1;
    }

    if (qemuPrepareHostdevPCIDevices(driver, &hostdev, 1) < 0)
        return -1;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (qemuDomainPCIAddressEnsureAddr(priv->pciaddrs, &hostdev->info) < 0)
            goto error;
        if (qemuCmdFlags & QEMUD_CMD_FLAG_PCI_CONFIGFD) {
            configfd = qemuOpenPCIConfig(hostdev);
            if (configfd >= 0) {
                if (virAsprintf(&configfd_name, "fd-%s",
                                hostdev->info.alias) < 0) {
                    virReportOOMError();
                    goto error;
                }

                qemuDomainObjEnterMonitorWithDriver(driver, vm);
                if (qemuMonitorSendFileHandle(priv->mon, configfd_name,
                                              configfd) < 0) {
                    qemuDomainObjExitMonitorWithDriver(driver, vm);
                    goto error;
                }
                qemuDomainObjExitMonitorWithDriver(driver, vm);
            }
        }

        if (!virDomainObjIsActive(vm)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("guest unexpectedly quit during hotplug"));
            goto error;
        }

        if (!(devstr = qemuBuildPCIHostdevDevStr(hostdev, configfd_name)))
            goto error;

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorAddDevice(priv->mon, devstr);
        qemuDomainObjExitMonitorWithDriver(driver, vm);
    } else {
        virDomainDevicePCIAddress guestAddr;

        qemuDomainObjEnterMonitorWithDriver(driver, vm);
        ret = qemuMonitorAddPCIHostDevice(priv->mon,
                                          &hostdev->source.subsys.u.pci,
                                          &guestAddr);
        qemuDomainObjExitMonitorWithDriver(driver, vm);

        hostdev->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        memcpy(&hostdev->info.addr.pci, &guestAddr, sizeof(guestAddr));
    }
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);

    return 0;

error:
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        (hostdev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &hostdev->info) < 0)
        VIR_WARN0("Unable to release PCI address on host device");

    qemuDomainReAttachHostdevDevices(driver, &hostdev, 1);

    VIR_FREE(devstr);
    VIR_FREE(configfd_name);
    VIR_FORCE_CLOSE(configfd);

    return -1;
}


int qemuDomainAttachHostUsbDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev,
                                  unsigned long long qemuCmdFlags)
{
    int ret;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *devstr = NULL;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceHostdevAlias(vm->def, hostdev, -1) < 0)
            goto error;
        if (!(devstr = qemuBuildUSBHostdevDevStr(hostdev)))
            goto error;
    }

    if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs+1) < 0) {
        virReportOOMError();
        goto error;
    }

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        virCgroupPtr cgroup = NULL;
        usbDevice *usb;

        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) !=0 ) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s\n"),
                            vm->def->name);
            goto error;
        }

        if ((usb = usbGetDevice(hostdev->source.subsys.u.usb.bus,
                                hostdev->source.subsys.u.usb.device)) == NULL)
            goto error;

        if (usbDeviceFileIterate(usb, qemuSetupHostUsbDeviceCgroup, cgroup) < 0 )
            goto error;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)
        ret = qemuMonitorAddDevice(priv->mon, devstr);
    else
        ret = qemuMonitorAddUSBDeviceExact(priv->mon,
                                           hostdev->source.subsys.u.usb.bus,
                                           hostdev->source.subsys.u.usb.device);
    qemuDomainObjExitMonitorWithDriver(driver, vm);
    if (ret < 0)
        goto error;

    vm->def->hostdevs[vm->def->nhostdevs++] = hostdev;

    VIR_FREE(devstr);

    return 0;

error:
    VIR_FREE(devstr);
    return -1;
}


int qemuDomainAttachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev,
                               unsigned long long qemuCmdFlags)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("hostdev mode '%s' not supported"),
                        virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    /* Resolve USB product/vendor to bus/device */
    if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
        hostdev->source.subsys.u.usb.vendor) {
        usbDevice *usb
            = usbFindDevice(hostdev->source.subsys.u.usb.vendor,
                            hostdev->source.subsys.u.usb.product);

        if (!usb)
            return -1;

        hostdev->source.subsys.u.usb.bus = usbDeviceGetBus(usb);
        hostdev->source.subsys.u.usb.device = usbDeviceGetDevno(usb);

        usbFreeDevice(usb);
    }


    if (driver->securityDriver &&
        driver->securityDriver->domainSetSecurityHostdevLabel &&
        driver->securityDriver->domainSetSecurityHostdevLabel(driver->securityDriver,
                                                              vm, hostdev) < 0)
        return -1;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        if (qemuDomainAttachHostPciDevice(driver, vm,
                                          hostdev, qemuCmdFlags) < 0)
            goto error;
        break;

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        if (qemuDomainAttachHostUsbDevice(driver, vm,
                                          hostdev, qemuCmdFlags) < 0)
            goto error;
        break;

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("hostdev subsys type '%s' not supported"),
                        virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        goto error;
    }

    return 0;

error:
    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel(driver->securityDriver,
                                                                  vm, hostdev) < 0)
        VIR_WARN0("Unable to restore host device labelling on hotplug fail");

    return -1;
}


static virDomainGraphicsDefPtr qemuDomainFindGraphics(virDomainObjPtr vm,
                                                      virDomainGraphicsDefPtr dev)
{
    int i;

    for (i = 0 ; i < vm->def->ngraphics ; i++) {
        if (vm->def->graphics[i]->type == dev->type)
            return vm->def->graphics[i];
    }

    return NULL;
}


int
qemuDomainChangeGraphics(struct qemud_driver *driver,
                         virDomainObjPtr vm,
                         virDomainGraphicsDefPtr dev)
{
    virDomainGraphicsDefPtr olddev = qemuDomainFindGraphics(vm, dev);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (!olddev) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot find existing graphics device to modify"));
        return -1;
    }

    switch (dev->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        if ((olddev->data.vnc.autoport != dev->data.vnc.autoport) ||
            (!dev->data.vnc.autoport && (olddev->data.vnc.port != dev->data.vnc.port))) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot change port settings on vnc graphics"));
            return -1;
        }
        if (STRNEQ_NULLABLE(olddev->data.vnc.listenAddr, dev->data.vnc.listenAddr)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot change listen address setting on vnc graphics"));
            return -1;
        }
        if (STRNEQ_NULLABLE(olddev->data.vnc.keymap, dev->data.vnc.keymap)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot change keymap setting on vnc graphics"));
            return -1;
        }

        if (STRNEQ_NULLABLE(olddev->data.vnc.auth.passwd, dev->data.vnc.auth.passwd)) {
            VIR_DEBUG("Updating password on VNC server %p %p", dev->data.vnc.auth.passwd, driver->vncPassword);
            qemuDomainObjEnterMonitorWithDriver(driver, vm);
            ret = qemuMonitorSetVNCPassword(priv->mon,
                                            dev->data.vnc.auth.passwd ?
                                            dev->data.vnc.auth.passwd :
                                            driver->vncPassword);
            qemuDomainObjExitMonitorWithDriver(driver, vm);

            /* Steal the new dev's  char * reference */
            VIR_FREE(olddev->data.vnc.auth.passwd);
            olddev->data.vnc.auth.passwd = dev->data.vnc.auth.passwd;
            dev->data.vnc.auth.passwd = NULL;
        } else {
            ret = 0;
        }
        break;

    default:
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unable to change config on '%s' graphics type"),
                        virDomainGraphicsTypeToString(dev->type));
        break;
    }

    return ret;
}


static inline int qemuFindDisk(virDomainDefPtr def, const char *dst)
{
    int i;

    for (i = 0 ; i < def->ndisks ; i++) {
        if (STREQ(def->disks[i]->dst, dst)) {
            return i;
        }
    }

    return -1;
}


int qemuDomainDetachPciDiskDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainDiskDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup = NULL;
    char *drivestr = NULL;

    i = qemuFindDisk(vm->def, dev->data.disk->dst);

    if (i < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    detach = vm->def->disks[i];

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s\n"),
                            vm->def->name);
            goto cleanup;
        }
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    /* build the actual drive id string as the disk->info.alias doesn't
     * contain the QEMU_DRIVE_HOST_PREFIX that is passed to qemu */
    if (virAsprintf(&drivestr, "%s%s",
                    QEMU_DRIVE_HOST_PREFIX, detach->info.alias) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }

    /* disconnect guest from host device */
    qemuMonitorDriveDel(priv->mon, drivestr);

    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, detach, NULL, "detach", ret >= 0);

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &detach->info) < 0)
        VIR_WARN("Unable to release PCI address on %s", dev->data.disk->src);

    virDomainDiskRemove(vm->def, i);

    virDomainDiskDefFree(detach);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, dev->data.disk) < 0)
        VIR_WARN("Unable to restore security label on %s", dev->data.disk->src);

    if (cgroup != NULL) {
        if (qemuTeardownDiskCgroup(driver, cgroup, dev->data.disk) < 0)
            VIR_WARN("Failed to teardown cgroup for disk path %s",
                     NULLSTR(dev->data.disk->src));
    }

    ret = 0;

cleanup:
    VIR_FREE(drivestr);
    return ret;
}

int qemuDomainDetachSCSIDiskDevice(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainDeviceDefPtr dev,
                                   unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainDiskDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCgroupPtr cgroup = NULL;
    char *drivestr = NULL;

    i = qemuFindDisk(vm->def, dev->data.disk->dst);

    if (i < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("disk %s not found"), dev->data.disk->dst);
        goto cleanup;
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("Underlying qemu does not support SCSI disk removal"));
        goto cleanup;
    }

    detach = vm->def->disks[i];

    if (qemuCgroupControllerActive(driver, VIR_CGROUP_CONTROLLER_DEVICES)) {
        if (virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unable to find cgroup for %s\n"),
                            vm->def->name);
            goto cleanup;
        }
    }

    /* build the actual drive id string as the disk->info.alias doesn't
     * contain the QEMU_DRIVE_HOST_PREFIX that is passed to qemu */
    if (virAsprintf(&drivestr, "%s%s",
                    QEMU_DRIVE_HOST_PREFIX, detach->info.alias) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
        qemuDomainObjExitMonitor(vm);
        goto cleanup;
    }

    /* disconnect guest from host device */
    qemuMonitorDriveDel(priv->mon, drivestr);

    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainDiskAudit(vm, detach, NULL, "detach", ret >= 0);

    virDomainDiskRemove(vm->def, i);

    virDomainDiskDefFree(detach);

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityImageLabel &&
        driver->securityDriver->domainRestoreSecurityImageLabel(driver->securityDriver,
                                                                vm, dev->data.disk) < 0)
        VIR_WARN("Unable to restore security label on %s", dev->data.disk->src);

    if (cgroup != NULL) {
        if (qemuTeardownDiskCgroup(driver, cgroup, dev->data.disk) < 0)
            VIR_WARN("Failed to teardown cgroup for disk path %s",
                     NULLSTR(dev->data.disk->src));
    }

    ret = 0;

cleanup:
    VIR_FREE(drivestr);
    virCgroupFree(&cgroup);
    return ret;
}

int qemuDomainDetachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainDeviceDefPtr dev,
                                        unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainControllerDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    for (i = 0 ; i < vm->def->ncontrollers ; i++) {
        if ((vm->def->controllers[i]->type == dev->data.controller->type) &&
            (vm->def->controllers[i]->idx == dev->data.controller->idx)) {
            detach = vm->def->controllers[i];
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("disk controller %s:%d not found"),
                        virDomainControllerTypeToString(dev->data.controller->type),
                        dev->data.controller->idx);
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED, "%s",
                        _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuAssignDeviceControllerAlias(detach) < 0)
            goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias)) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    if (vm->def->ncontrollers > 1) {
        memmove(vm->def->controllers + i,
                vm->def->controllers + i + 1,
                sizeof(*vm->def->controllers) *
                (vm->def->ncontrollers - (i + 1)));
        vm->def->ncontrollers--;
        if (VIR_REALLOC_N(vm->def->controllers, vm->def->ncontrollers) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->controllers);
        vm->def->ncontrollers = 0;
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &detach->info) < 0)
        VIR_WARN0("Unable to release PCI address on controller");

    virDomainControllerDefFree(detach);

    ret = 0;

cleanup:
    return ret;
}

int qemuDomainDetachNetDevice(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev,
                              unsigned long long qemuCmdFlags)
{
    int i, ret = -1;
    virDomainNetDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int vlan;
    char *hostnet_name = NULL;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr net = vm->def->nets[i];

        if (!memcmp(net->mac, dev->data.net->mac,  sizeof(net->mac))) {
            detach = net;
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("network device %02x:%02x:%02x:%02x:%02x:%02x not found"),
                        dev->data.net->mac[0], dev->data.net->mac[1],
                        dev->data.net->mac[2], dev->data.net->mac[3],
                        dev->data.net->mac[4], dev->data.net->mac[5]);
        goto cleanup;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a PCI address"));
        goto cleanup;
    }

    if ((vlan = qemuDomainNetVLAN(detach)) < 0) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("unable to determine original VLAN"));
        goto cleanup;
    }

    if (virAsprintf(&hostnet_name, "host%s", detach->info.alias) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            qemuDomainNetAudit(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        if (qemuMonitorRemoveNetdev(priv->mon, hostnet_name) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    } else {
        if (qemuMonitorRemoveHostNetwork(priv->mon, vlan, hostnet_name) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            qemuDomainNetAudit(vm, detach, NULL, "detach", false);
            goto cleanup;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    qemuDomainNetAudit(vm, detach, NULL, "detach", true);

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &detach->info) < 0)
        VIR_WARN0("Unable to release PCI address on NIC");

    virDomainConfNWFilterTeardown(detach);

#if WITH_MACVTAP
    if (detach->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
        delMacvtap(detach->ifname, detach->mac, detach->data.direct.linkdev,
                   &detach->data.direct.virtPortProfile);
        VIR_FREE(detach->ifname);
    }
#endif

    if ((driver->macFilter) && (detach->ifname != NULL)) {
        if ((errno = networkDisallowMacOnPort(driver,
                                              detach->ifname,
                                              detach->mac))) {
            virReportSystemError(errno,
             _("failed to remove ebtables rule on  '%s'"),
                                 detach->ifname);
        }
    }

    if (vm->def->nnets > 1) {
        memmove(vm->def->nets + i,
                vm->def->nets + i + 1,
                sizeof(*vm->def->nets) *
                (vm->def->nnets - (i + 1)));
        vm->def->nnets--;
        if (VIR_REALLOC_N(vm->def->nets, vm->def->nnets) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->nets);
        vm->def->nnets = 0;
    }
    virDomainNetDefFree(detach);

    ret = 0;

cleanup:
    VIR_FREE(hostnet_name);
    return ret;
}

int qemuDomainDetachHostPciDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;
    pciDevice *pci;

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (vm->def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            vm->def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        unsigned domain   = vm->def->hostdevs[i]->source.subsys.u.pci.domain;
        unsigned bus      = vm->def->hostdevs[i]->source.subsys.u.pci.bus;
        unsigned slot     = vm->def->hostdevs[i]->source.subsys.u.pci.slot;
        unsigned function = vm->def->hostdevs[i]->source.subsys.u.pci.function;

        if (dev->data.hostdev->source.subsys.u.pci.domain   == domain &&
            dev->data.hostdev->source.subsys.u.pci.bus      == bus &&
            dev->data.hostdev->source.subsys.u.pci.slot     == slot &&
            dev->data.hostdev->source.subsys.u.pci.function == function) {
            detach = vm->def->hostdevs[i];
            break;
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("host pci device %.4x:%.2x:%.2x.%.1x not found"),
                        dev->data.hostdev->source.subsys.u.pci.domain,
                        dev->data.hostdev->source.subsys.u.pci.bus,
                        dev->data.hostdev->source.subsys.u.pci.slot,
                        dev->data.hostdev->source.subsys.u.pci.function);
        return -1;
    }

    if (!virDomainDeviceAddressIsValid(&detach->info,
                                       VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a PCI address"));
        return -1;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
            qemuDomainObjExitMonitor(vm);
            return -1;
        }
    } else {
        if (qemuMonitorRemovePCIDevice(priv->mon,
                                       &detach->info.addr.pci) < 0) {
            qemuDomainObjExitMonitorWithDriver(driver, vm);
            return -1;
        }
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = 0;

    pci = pciGetDevice(detach->source.subsys.u.pci.domain,
                       detach->source.subsys.u.pci.bus,
                       detach->source.subsys.u.pci.slot,
                       detach->source.subsys.u.pci.function);
    if (!pci)
        ret = -1;
    else {
        pciDeviceSetManaged(pci, detach->managed);
        pciDeviceListDel(driver->activePciHostdevs, pci);
        if (pciResetDevice(pci, driver->activePciHostdevs, NULL) < 0)
            ret = -1;
        qemuReattachPciDevice(pci, driver);
        pciFreeDevice(pci);
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
        qemuDomainPCIAddressReleaseAddr(priv->pciaddrs, &detach->info) < 0)
        VIR_WARN0("Unable to release PCI address on host device");

    if (vm->def->nhostdevs > 1) {
        memmove(vm->def->hostdevs + i,
                vm->def->hostdevs + i + 1,
                sizeof(*vm->def->hostdevs) *
                (vm->def->nhostdevs - (i + 1)));
        vm->def->nhostdevs--;
        if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->hostdevs);
        vm->def->nhostdevs = 0;
    }
    virDomainHostdevDefFree(detach);

    return ret;
}

int qemuDomainDetachHostUsbDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr detach = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int i, ret;

    for (i = 0 ; i < vm->def->nhostdevs ; i++) {
        if (vm->def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            vm->def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        unsigned bus = vm->def->hostdevs[i]->source.subsys.u.usb.bus;
        unsigned device = vm->def->hostdevs[i]->source.subsys.u.usb.device;
        unsigned product = vm->def->hostdevs[i]->source.subsys.u.usb.product;
        unsigned vendor = vm->def->hostdevs[i]->source.subsys.u.usb.vendor;

        if (dev->data.hostdev->source.subsys.u.usb.bus &&
            dev->data.hostdev->source.subsys.u.usb.device) {
            if (dev->data.hostdev->source.subsys.u.usb.bus == bus &&
                dev->data.hostdev->source.subsys.u.usb.device == device) {
                detach = vm->def->hostdevs[i];
                break;
            }
        } else {
            if (dev->data.hostdev->source.subsys.u.usb.product == product &&
                dev->data.hostdev->source.subsys.u.usb.vendor == vendor) {
                detach = vm->def->hostdevs[i];
                break;
            }
        }
    }

    if (!detach) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        _("host usb device %03d.%03d not found"),
                        dev->data.hostdev->source.subsys.u.usb.bus,
                        dev->data.hostdev->source.subsys.u.usb.device);
        return -1;
    }

    if (!detach->info.alias) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached without a device alias"));
        return -1;
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        qemuReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("device cannot be detached with this QEMU version"));
        return -1;
    }

    qemuDomainObjEnterMonitorWithDriver(driver, vm);
    if (qemuMonitorDelDevice(priv->mon, detach->info.alias) < 0) {
        qemuDomainObjExitMonitorWithDriver(driver, vm);
        return -1;
    }
    qemuDomainObjExitMonitorWithDriver(driver, vm);

    ret = 0;

    if (vm->def->nhostdevs > 1) {
        memmove(vm->def->hostdevs + i,
                vm->def->hostdevs + i + 1,
                sizeof(*vm->def->hostdevs) *
                (vm->def->nhostdevs - (i + 1)));
        vm->def->nhostdevs--;
        if (VIR_REALLOC_N(vm->def->hostdevs, vm->def->nhostdevs) < 0) {
            /* ignore, harmless */
        }
    } else {
        VIR_FREE(vm->def->hostdevs);
        vm->def->nhostdevs = 0;
    }
    virDomainHostdevDefFree(detach);

    return ret;
}

int qemuDomainDetachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev,
                               unsigned long long qemuCmdFlags)
{
    virDomainHostdevDefPtr hostdev = dev->data.hostdev;
    int ret;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("hostdev mode '%s' not supported"),
                        virDomainHostdevModeTypeToString(hostdev->mode));
        return -1;
    }

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        ret = qemuDomainDetachHostPciDevice(driver, vm, dev, qemuCmdFlags);
        break;
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        ret = qemuDomainDetachHostUsbDevice(driver, vm, dev, qemuCmdFlags);
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("hostdev subsys type '%s' not supported"),
                        virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
        return -1;
    }

    if (driver->securityDriver &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel &&
        driver->securityDriver->domainRestoreSecurityHostdevLabel(driver->securityDriver,
                                                                  vm, dev->data.hostdev) < 0)
        VIR_WARN0("Failed to restore host device labelling");

    return ret;
}
