/*
 * ch_hostdev.c: Cloud Hypervisor hostdev management
 *
 * Copyright (C) 2021 Wei Liu <liuwe@microsoft.com>
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

#include "ch_hostdev.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_hostdev");

static int
virCHDomainPrepareHostdevPCI(virDomainHostdevDef *hostdev)
{
    bool supportsPassthroughVFIO = virHostdevHostSupportsPassthroughVFIO();
    virDeviceHostdevPCIDriverName *driverName = &hostdev->source.subsys.u.pci.driver.name;

    /* assign defaults for hostdev passthrough */
    switch (*driverName) {
    case VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_DEFAULT:
        if (supportsPassthroughVFIO) {
            *driverName = VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_VFIO;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("host doesn't support passthrough of host PCI devices"));
            return -1;
        }
        break;

    case VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_VFIO:
        if (!supportsPassthroughVFIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("host doesn't support VFIO PCI passthrough"));
            return false;
        }
        break;

    case VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_KVM:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("host doesn't support legacy PCI passthrough"));
        return false;

    case VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_XEN:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CH does not support device assignment mode '%1$s'"),
                       virDeviceHostdevPCIDriverNameTypeToString(*driverName));
        return false;

    default:
    case VIR_DEVICE_HOSTDEV_PCI_DRIVER_NAME_LAST:
        virReportEnumRangeError(virDeviceHostdevPCIDriverName, *driverName);
        break;
    }

    return true;
}

int
virCHDomainPrepareHostdev(virDomainHostdevDef *hostdev)
{
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
        return 0;

    switch (hostdev->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
        return virCHDomainPrepareHostdevPCI(hostdev);
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
        break;
    }

    return 0;
}
