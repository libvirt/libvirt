/*
 * qemu_alias.c: QEMU alias manipulation
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_alias.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_alias");

int
qemuDomainDeviceAliasIndex(const virDomainDeviceInfo *info,
                           const char *prefix)
{
    int idx;

    if (!info->alias)
        return -1;
    if (!STRPREFIX(info->alias, prefix))
        return -1;

    if (virStrToLong_i(info->alias + strlen(prefix), NULL, 10, &idx) < 0)
        return -1;

    return idx;
}


static ssize_t
qemuGetNextChrDevIndex(virDomainDefPtr def,
                       virDomainChrDefPtr chr,
                       const char *prefix)
{
    const virDomainChrDef **arrPtr;
    size_t cnt;
    size_t i;
    ssize_t idx = 0;
    const char *prefix2 = NULL;

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE)
        prefix2 = "serial";

    virDomainChrGetDomainPtrs(def, chr->deviceType, &arrPtr, &cnt);

    for (i = 0; i < cnt; i++) {
        ssize_t thisidx;
        if (((thisidx = qemuDomainDeviceAliasIndex(&arrPtr[i]->info, prefix)) < 0) &&
            (prefix2 &&
             (thisidx = qemuDomainDeviceAliasIndex(&arrPtr[i]->info, prefix2)) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to determine device index for character device"));
            return -1;
        }
        if (thisidx >= idx)
            idx = thisidx + 1;
    }

    return idx;
}


int
qemuAssignDeviceChrAlias(virDomainDefPtr def,
                         virDomainChrDefPtr chr,
                         ssize_t idx)
{
    const char *prefix = NULL;

    switch ((virDomainChrDeviceType) chr->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        prefix = "parallel";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        prefix = "serial";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        prefix = "console";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        prefix = "channel";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        return -1;
    }

    if (idx == -1 && (idx = qemuGetNextChrDevIndex(def, chr, prefix)) < 0)
        return -1;

    return virAsprintf(&chr->info.alias, "%s%zd", prefix, idx);
}


int
qemuAssignDeviceControllerAlias(virDomainDefPtr domainDef,
                                virQEMUCapsPtr qemuCaps,
                                virDomainControllerDefPtr controller)
{
    const char *prefix = virDomainControllerTypeToString(controller->type);

    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
        if (!virQEMUCapsHasPCIMultiBus(qemuCaps, domainDef)) {
            /* qemus that don't support multiple PCI buses have
             * hardcoded the name of their single PCI controller as
             * "pci".
             */
            return VIR_STRDUP(controller->info.alias, "pci");
        } else if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
            /* The pcie-root controller on Q35 machinetypes uses a
             * different naming convention ("pcie.0"), because it is
             * hardcoded that way in qemu.
             */
            return virAsprintf(&controller->info.alias, "pcie.%d", controller->idx);
        }
        /* All other PCI controllers use the consistent "pci.%u"
         * (including the hardcoded pci-root controller on
         * multibus-capable qemus).
         */
        return virAsprintf(&controller->info.alias, "pci.%d", controller->idx);
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE) {
        /* for any machine based on e.g. I440FX or G3Beige, the
         * first (and currently only) IDE controller is an integrated
         * controller hardcoded with id "ide"
         */
        if (qemuDomainMachineHasBuiltinIDE(domainDef) &&
            controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "ide");
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA) {
        /* for any Q35 machine, the first SATA controller is the
         * integrated one, and it too is hardcoded with id "ide"
         */
        if (qemuDomainMachineIsQ35(domainDef) && controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "ide");
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        /* first USB device is "usb", others are normal "usb%d" */
        if (controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "usb");
    }
    /* all other controllers use the default ${type}${index} naming
     * scheme for alias/id.
     */
    return virAsprintf(&controller->info.alias, "%s%d", prefix, controller->idx);
}


/* Names used before -drive supported the id= option */
static int
qemuAssignDeviceDiskAliasFixed(virDomainDiskDefPtr disk)
{
    int busid, devid;
    int ret;
    char *dev_name;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot convert disk '%s' to bus/device index"),
                       disk->dst);
        return -1;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "ide%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "ide%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "scsi%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "scsi%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_FDC:
        ret = virAsprintf(&dev_name, "floppy%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        ret = virAsprintf(&dev_name, "virtio%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_XEN:
        ret = virAsprintf(&dev_name, "xenblk%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SD:
        ret = virAsprintf(&dev_name, "sd%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_USB:
        ret = virAsprintf(&dev_name, "usb%d", devid);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported disk name mapping for bus '%s'"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (ret == -1)
        return -1;

    disk->info.alias = dev_name;

    return 0;
}


/* Our custom -drive naming scheme used with id= */
static int
qemuAssignDeviceDiskAliasCustom(virDomainDefPtr def,
                                virDomainDiskDefPtr disk,
                                virQEMUCapsPtr qemuCaps)
{
    const char *prefix = virDomainDiskBusTypeToString(disk->bus);
    int controllerModel = -1;

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            controllerModel =
                virDomainDeviceFindControllerModel(def, &disk->info,
                                                   VIR_DOMAIN_CONTROLLER_TYPE_SCSI);

            if ((qemuDomainSetSCSIControllerModel(def, qemuCaps,
                                                  &controllerModel)) < 0)
                return -1;
        }

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI ||
            controllerModel == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.unit) < 0)
                return -1;
        } else {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.target,
                            disk->info.addr.drive.unit) < 0)
                return -1;
        }
    } else {
        int idx = virDiskNameToIndex(disk->dst);
        if (virAsprintf(&disk->info.alias, "%s-disk%d", prefix, idx) < 0)
            return -1;
    }

    return 0;
}


int
qemuAssignDeviceDiskAlias(virDomainDefPtr vmdef,
                          virDomainDiskDefPtr def,
                          virQEMUCapsPtr qemuCaps)
{
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        return qemuAssignDeviceDiskAliasCustom(vmdef, def, qemuCaps);
    else
        return qemuAssignDeviceDiskAliasFixed(def);
}


int
qemuAssignDeviceHostdevAlias(virDomainDefPtr def,
                             virDomainHostdevDefPtr hostdev,
                             int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nhostdevs; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(def->hostdevs[i]->info, "hostdev")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for hostdev device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&hostdev->info->alias, "hostdev%d", idx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceNetAlias(virDomainDefPtr def,
                         virDomainNetDefPtr net,
                         int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nnets; i++) {
            int thisidx;

            if (virDomainNetGetActualType(def->nets[i])
                == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
                /* type='hostdev' interfaces have a hostdev%d alias */
               continue;
            }
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "net")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for network device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&net->info.alias, "net%d", idx) < 0)
        return -1;
    return 0;
}


int
qemuAssignDeviceRedirdevAlias(virDomainDefPtr def,
                              virDomainRedirdevDefPtr redirdev,
                              int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nredirdevs; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->redirdevs[i]->info, "redir")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for redirected device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&redirdev->info.alias, "redir%d", idx) < 0)
        return -1;
    return 0;
}


int
qemuAssignDeviceRNGAlias(virDomainRNGDefPtr rng,
                         size_t idx)
{
    if (virAsprintf(&rng->info.alias, "rng%zu", idx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceAliases(virDomainDefPtr def, virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (qemuAssignDeviceDiskAlias(def, def->disks[i], qemuCaps) < 0)
            return -1;
    }
    for (i = 0; i < def->nnets; i++) {
        /* type='hostdev' interfaces are also on the hostdevs list,
         * and will have their alias assigned with other hostdevs.
         */
        if (virDomainNetGetActualType(def->nets[i])
            != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            qemuAssignDeviceNetAlias(def, def->nets[i], i) < 0) {
            return -1;
        }
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        return 0;

    for (i = 0; i < def->nfss; i++) {
        if (virAsprintf(&def->fss[i]->info.alias, "fs%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nsounds; i++) {
        if (virAsprintf(&def->sounds[i]->info.alias, "sound%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nhostdevs; i++) {
        if (qemuAssignDeviceHostdevAlias(def, def->hostdevs[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nredirdevs; i++) {
        if (qemuAssignDeviceRedirdevAlias(def, def->redirdevs[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nvideos; i++) {
        if (virAsprintf(&def->videos[i]->info.alias, "video%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->ncontrollers; i++) {
        if (qemuAssignDeviceControllerAlias(def, qemuCaps, def->controllers[i]) < 0)
            return -1;
    }
    for (i = 0; i < def->ninputs; i++) {
        if (virAsprintf(&def->inputs[i]->info.alias, "input%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nparallels; i++) {
        if (qemuAssignDeviceChrAlias(def, def->parallels[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nserials; i++) {
        if (qemuAssignDeviceChrAlias(def, def->serials[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nchannels; i++) {
        if (qemuAssignDeviceChrAlias(def, def->channels[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nconsoles; i++) {
        if (qemuAssignDeviceChrAlias(def, def->consoles[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nhubs; i++) {
        if (virAsprintf(&def->hubs[i]->info.alias, "hub%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nshmems; i++) {
        if (virAsprintf(&def->shmems[i]->info.alias, "shmem%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nsmartcards; i++) {
        if (virAsprintf(&def->smartcards[i]->info.alias, "smartcard%zu", i) < 0)
            return -1;
    }
    if (def->watchdog) {
        if (virAsprintf(&def->watchdog->info.alias, "watchdog%d", 0) < 0)
            return -1;
    }
    if (def->memballoon) {
        if (virAsprintf(&def->memballoon->info.alias, "balloon%d", 0) < 0)
            return -1;
    }
    for (i = 0; i < def->nrngs; i++) {
        if (qemuAssignDeviceRNGAlias(def->rngs[i], i) < 0)
            return -1;
    }
    if (def->tpm) {
        if (virAsprintf(&def->tpm->info.alias, "tpm%d", 0) < 0)
            return -1;
    }
    for (i = 0; i < def->nmems; i++) {
        if (virAsprintf(&def->mems[i]->info.alias, "dimm%zu", i) < 0)
            return -1;
    }

    return 0;
}
