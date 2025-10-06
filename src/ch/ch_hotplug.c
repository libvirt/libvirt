/*
 * ch_hotplug.c: CH device hotplug handling
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

#include "ch_hotplug.h"
#include "ch_alias.h"
#include "ch_domain.h"
#include "ch_process.h"
#include "domain_event.h"
#include "domain_validate.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_hotplug");

static int
chDomainAddDisk(virCHMonitor *mon,
                virDomainObj *vm,
                virDomainDiskDef *disk)
{
    if (chAssignDeviceDiskAlias(disk) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Assigning disk alias failed"));
        return -1;
    }

    if (virCHMonitorAddDisk(mon, disk) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Adding disk to domain failed"));
        return -1;
    }

    virDomainDiskInsert(vm->def, disk);

    return 0;
}

static int
chDomainAttachDeviceLive(virCHDriver *driver,
                         virDomainObj *vm,
                         virDomainDeviceDef *dev)
{
    int ret = -1;
    virCHDomainObjPrivate *priv = vm->privateData;
    virCHMonitor *mon = priv->monitor;
    const char *alias = NULL;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (chDomainAddDisk(mon, vm, dev->data.disk) < 0) {
            break;
        }

        alias = dev->data.disk->info.alias;
        dev->data.disk = NULL;
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NET:
        if (chProcessAddNetworkDevice(driver, mon, vm->def, dev->data.net,
                                      NULL, NULL) < 0) {
            break;
        }

        virDomainNetInsert(vm->def, dev->data.net);
        alias = dev->data.net->info.alias;
        dev->data.net = NULL;
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_VSOCK:
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
    case VIR_DOMAIN_DEVICE_PSTORE:
    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("live attach of device '%1$s' is not supported"),
                       virDomainDeviceTypeToString(dev->type));
        break;
    }

    if (alias) {
        virObjectEvent *event;

        event = virDomainEventDeviceAddedNewFromObj(vm, alias);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    return ret;
}

int
chDomainAttachDeviceLiveAndUpdateConfig(virDomainObj *vm,
                                        virCHDriver *driver,
                                        const char *xml,
                                        unsigned int flags)
{
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE |
                               VIR_DOMAIN_DEF_PARSE_ABI_UPDATE;
    g_autoptr(virDomainDeviceDef) devLive = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;
    g_autoptr(virCHDriverConfig) cfg = NULL;
    g_autoptr(virDomainDeviceDef) devConf = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virCHDriverGetConfig(driver);

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Persistent domain state changes are not supported"));
        return -1;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!(devLive = virDomainDeviceDefParse(xml, vm->def,
                                                driver->xmlopt, NULL,
                                                parse_flags))) {
            return -1;
        }

        if (virDomainDeviceValidateAliasForHotplug(vm, devLive,
                                                   VIR_DOMAIN_AFFECT_LIVE) < 0)
            return -1;

        if (virDomainDefCompatibleDevice(vm->def, devLive, NULL,
                                        VIR_DOMAIN_DEVICE_ACTION_ATTACH,
                                        true) < 0) {
            return -1;
        }

        if (chDomainAttachDeviceLive(driver, vm, devLive) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to add device"));
            return -1;
        }
    }

    return 0;
}

static int
chFindDiskId(virDomainDef *def, const char *dst)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (STREQ(def->disks[i]->dst, dst))
            return i;
    }

    return -1;
}


/**
 * chDomainFindDisk
 *
 * Helper function to find a disk device definition of a domain.
 *
 * Searches through the disk devices of a domain by comparing to 'match' and
 * returns any match via the 'detach' out parameter.
 */
static int
chDomainFindDisk(virDomainObj *vm,
                 virDomainDiskDef *match,
                 virDomainDiskDef **detach)
{
    int idx;

    if ((idx = chFindDiskId(vm->def, match->dst)) < 0) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("disk %1$s not found"), match->dst);
        return -1;
    }
    *detach = vm->def->disks[idx];

    return 0;
}


static int
chDomainRemoveDevice(virDomainObj *vm,
                     virDomainDeviceDef *device)
{
    size_t i;

    VIR_DEBUG("Removing device %s from domain %p %s",
              virDomainDeviceTypeToString(device->type), vm, vm->def->name);

    switch (device->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        for (i = 0; i < vm->def->ndisks; i++) {
            if (vm->def->disks[i] == device->data.disk) {
                virDomainDiskRemove(vm->def, i);
                g_clear_pointer(&device->data.disk, virDomainDiskDefFree);
                break;
            }
        }
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_PSTORE:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("don't know how to remove a %1$s device"),
                       virDomainDeviceTypeToString(device->type));
        return -1;
    }

    return 0;
}


static int
chDomainDetachDeviceLive(virCHDriver *driver,
                         virDomainObj *vm,
                         virDomainDeviceDef *match)
{
    virDomainDeviceDef detach = { .type = match->type };
    virDomainDeviceInfo *info = NULL;
    virCHDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event = NULL;
    g_autofree char *alias = NULL;

    switch (match->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        if (chDomainFindDisk(vm, match->data.disk,
                             &detach.data.disk) < 0) {
            return -1;
        }
        break;
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_PSTORE:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
    default:
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

    /* Save the alias to use when sending a DEVICE_REMOVED event after all
     * other tear down is complete.
     */
    alias = g_strdup(info->alias);

    if (virCHMonitorRemoveDevice(priv->monitor, info->alias) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid response from CH. Disk removal failed."));
        return -1;
    }

    if (chDomainRemoveDevice(vm, &detach) < 0)
        return -1;

    event = virDomainEventDeviceRemovedNewFromObj(vm, alias);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;
}

int
chDomainDetachDeviceLiveAndUpdateConfig(virCHDriver *driver,
                                        virDomainObj *vm,
                                        const char *xml,
                                        unsigned int flags)
{
    g_autoptr(virCHDriverConfig) cfg = NULL;
    g_autoptr(virDomainDeviceDef) dev_config = NULL;
    g_autoptr(virDomainDeviceDef) dev_live = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE;
    g_autoptr(virDomainDef) vmdef = NULL;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    cfg = virCHDriverGetConfig(driver);

    if ((flags & VIR_DOMAIN_AFFECT_CONFIG) &&
        !(flags & VIR_DOMAIN_AFFECT_LIVE))
        parse_flags |= VIR_DOMAIN_DEF_PARSE_INACTIVE;

    if (flags & VIR_DOMAIN_AFFECT_CONFIG) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Persistent domain state changes are not supported"));
        return -1;
    }

    if (flags & VIR_DOMAIN_AFFECT_LIVE) {
        if (!(dev_live = virDomainDeviceDefParse(xml, vm->def, driver->xmlopt,
                                                 NULL, parse_flags))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could not parse domain definition"));
            return -1;
        }

        if (chDomainDetachDeviceLive(driver, vm, dev_live) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Could detach device"));
            return -1;
        }
    }

    return 0;
}
