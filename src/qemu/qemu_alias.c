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
#include "network/bridge_driver.h"

#define QEMU_DRIVE_HOST_PREFIX "drive-"

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


/* Our custom -drive naming scheme used with id= */
int
qemuAssignDeviceDiskAlias(virDomainDefPtr def,
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
qemuAssignDeviceHostdevAlias(virDomainDefPtr def,
                             char **alias,
                             int idx)
{
    if (idx == -1) {
        size_t i;

        idx = 0;
        for (i = 0; i < def->nhostdevs; i++) {
            int thisidx;

            if ((thisidx = qemuDomainDeviceAliasIndex(def->hostdevs[i]->info, "hostdev")) < 0)
                continue; /* error just means the alias wasn't "hostdevN", but something else */
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
        /* network interfaces can also have a hostdevN alias */
        for (i = 0; i < def->nnets; i++) {
            int thisidx;

            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "hostdev")) < 0)
                continue;
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(alias, "hostdev%d", idx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceNetAlias(virDomainDefPtr def,
                         virDomainNetDefPtr net,
                         int idx)
{

    /* <interface type='hostdev'> uses "hostdevN" as the alias
     * We must use "-1" as the index because the caller doesn't know
     * that we're now looking for a unique hostdevN rather than netN
     */
    if (networkGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV)
        return qemuAssignDeviceHostdevAlias(def, &net->info.alias, -1);

    if (idx == -1) {
        size_t i;

        idx = 0;
        for (i = 0; i < def->nnets; i++) {
            int thisidx;

            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "net")) < 0)
                continue; /* failure could be due to "hostdevN" */
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
qemuAssignDeviceRNGAlias(virDomainDefPtr def,
                         virDomainRNGDefPtr rng)
{
    size_t i;
    int maxidx = 0;
    int idx;

    for (i = 0; i < def->nrngs; i++) {
        if ((idx = qemuDomainDeviceAliasIndex(&def->rngs[i]->info, "rng")) >= maxidx)
            maxidx = idx + 1;
    }

    if (virAsprintf(&rng->info.alias, "rng%d", maxidx) < 0)
        return -1;

    return 0;
}


/**
 * qemuAssignDeviceMemoryAlias:
 * @def: domain definition. Necessary only if @oldAlias is true.
 * @mem: memory device definition
 * @oldAlias: Generate the alias according to the order of the device in @def
 *            rather than according to the slot number for legacy reasons.
 *
 * Generates alias for a memory device according to slot number if @oldAlias is
 * false or according to order in @def->mems otherwise.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuAssignDeviceMemoryAlias(virDomainDefPtr def,
                            virDomainMemoryDefPtr mem,
                            bool oldAlias)
{
    size_t i;
    int maxidx = 0;
    int idx;

    if (oldAlias) {
        for (i = 0; i < def->nmems; i++) {
            if ((idx = qemuDomainDeviceAliasIndex(&def->mems[i]->info, "dimm")) >= maxidx)
                maxidx = idx + 1;
        }
    } else {
        maxidx = mem->info.addr.dimm.slot;
    }

    if (virAsprintf(&mem->info.alias, "dimm%d", maxidx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceShmemAlias(virDomainDefPtr def,
                           virDomainShmemDefPtr shmem,
                           int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nshmems; i++) {
            int thisidx;

            if ((thisidx = qemuDomainDeviceAliasIndex(&def->shmems[i]->info,
                                                      "shmem")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index "
                                 "for shmem device"));
                return -1;
            }

            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&shmem->info.alias, "shmem%d", idx) < 0)
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
        if (qemuAssignDeviceNetAlias(def, def->nets[i], -1) < 0)
            return -1;
    }

    for (i = 0; i < def->nfss; i++) {
        if (virAsprintf(&def->fss[i]->info.alias, "fs%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nsounds; i++) {
        if (virAsprintf(&def->sounds[i]->info.alias, "sound%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nhostdevs; i++) {
        /* we can't start assigning at 0, since netdevs may have used
         * up some hostdevN entries already. Also if the HostdevDef is
         * linked to a NetDef, they will share an info and the alias
         * will already be set, so don't try to set it again.
         */
        if (!def->hostdevs[i]->info->alias &&
            qemuAssignDeviceHostdevAlias(def, &def->hostdevs[i]->info->alias, -1) < 0)
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
        if (qemuAssignDeviceShmemAlias(def, def->shmems[i], i) < 0)
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
        if (virAsprintf(&def->rngs[i]->info.alias, "rng%zu", i) < 0)
            return -1;
    }
    if (def->tpm) {
        if (virAsprintf(&def->tpm->info.alias, "tpm%d", 0) < 0)
            return -1;
    }
    for (i = 0; i < def->nmems; i++) {
        if (qemuAssignDeviceMemoryAlias(NULL, def->mems[i], false) < 0)
            return -1;
    }

    return 0;
}


/* qemuAliasFromDisk
 * @disk: Pointer to a disk definition
 *
 * Generate and return an alias for the device disk '-drive'
 *
 * Returns NULL with error or a string containing the alias
 */
char *
qemuAliasFromDisk(const virDomainDiskDef *disk)
{
    char *ret;

    if (!disk->info.alias) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("disk does not have an alias"));
        return NULL;
    }

    ignore_value(virAsprintf(&ret, "%s%s", QEMU_DRIVE_HOST_PREFIX,
                             disk->info.alias));

    return ret;
}


/* qemuAliasDiskDriveSkipPrefix:
 * @dev_name: Pointer to a const char string
 *
 * If the QEMU_DRIVE_HOST_PREFIX exists in the input string, then
 * increment the pointer and return it
 */
const char *
qemuAliasDiskDriveSkipPrefix(const char *dev_name)
{
    if (STRPREFIX(dev_name, QEMU_DRIVE_HOST_PREFIX))
        dev_name += strlen(QEMU_DRIVE_HOST_PREFIX);
    return dev_name;
}


/* qemuAliasFromHostdev
 * @hostdev: Pointer to host device
 *
 * Generate and return a string containing a drive alias
 */
char *
qemuAliasFromHostdev(const virDomainHostdevDef *hostdev)
{
    char *ret;

    if (!hostdev->info->alias) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostdev does not have an alias"));
        return NULL;
    }

    ignore_value(virAsprintf(&ret, "%s-%s",
                 virDomainDeviceAddressTypeToString(hostdev->info->type),
                 hostdev->info->alias));
    return ret;
}


/* qemuDomainGetMasterKeyAlias:
 *
 * Generate and return the masterKey alias
 *
 * Returns NULL or a string containing the master key alias
 */
char *
qemuDomainGetMasterKeyAlias(void)
{
    char *alias;

    ignore_value(VIR_STRDUP(alias, "masterKey0"));

    return alias;
}


/* qemuDomainGetSecretAESAlias:
 * @srcalias: Source alias used to generate the secret alias
 * @isLuks: True when we are generating a secret for LUKS encrypt/decrypt
 *
 * Generate and return an alias for the encrypted secret
 *
 * Returns NULL or a string containing the alias
 */
char *
qemuDomainGetSecretAESAlias(const char *srcalias,
                            bool isLuks)
{
    char *alias;

    if (!srcalias) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("encrypted secret alias requires valid source alias"));
        return NULL;
    }

    if (isLuks)
        ignore_value(virAsprintf(&alias, "%s-luks-secret0", srcalias));
    else
        ignore_value(virAsprintf(&alias, "%s-secret0", srcalias));

    return alias;
}


/* qemuAliasTLSObjFromSrcAlias
 * @srcAlias: Pointer to a source alias string
 *
 * Generate and return a string to be used as the TLS object alias
 */
char *
qemuAliasTLSObjFromSrcAlias(const char *srcAlias)
{
    char *ret;

    ignore_value(virAsprintf(&ret, "obj%s_tls0", srcAlias));

    return ret;
}


/* qemuAliasChardevFromDevAlias:
 * @devAlias: pointer do device alias
 *
 * Generate and return a string to be used as chardev alias.
 */
char *
qemuAliasChardevFromDevAlias(const char *devAlias)
{
    char *ret;

    ignore_value(virAsprintf(&ret, "char%s", devAlias));

    return ret;
}
