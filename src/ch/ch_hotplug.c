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
chDomainAttachDeviceLive(virDomainObj *vm,
                         virDomainDeviceDef *dev)
{
    int ret = -1;
    virCHDomainObjPrivate *priv = vm->privateData;
    virCHMonitor *mon = priv->monitor;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK: {
        if (chDomainAddDisk(mon, vm, dev->data.disk) < 0) {
            break;
        }

        dev->data.disk = NULL;
        ret = 0;
        break;
    }
    case VIR_DOMAIN_DEVICE_NET:
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

        if (chDomainAttachDeviceLive(vm, devLive) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to add device"));
            return -1;
        }
    }

    return 0;
}
