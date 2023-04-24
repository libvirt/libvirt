/*
 * lxc_hostdev.c: VIRLXC hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2012 Red Hat, Inc.
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

#include "lxc_hostdev.h"
#include "virlog.h"
#include "virerror.h"
#include "virhostdev.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_hostdev");

int
virLXCUpdateActiveUSBHostdevs(virLXCDriver *driver,
                              virDomainDef *def)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUSBDevices(hostdev_mgr,
                                            def->hostdevs, def->nhostdevs,
                                            LXC_DRIVER_NAME, def->name);
}

static int
virLXCPrepareHostUSBDevices(virLXCDriver *driver,
                            virDomainDef *def)
{
    virDomainHostdevDef **hostdevs = def->hostdevs;
    int nhostdevs = def->nhostdevs;
    const char *dom_name = def->name;
    unsigned int flags = 0;
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, LXC_DRIVER_NAME, dom_name,
                                       hostdevs, nhostdevs, flags);
}


int virLXCPrepareHostDevices(virLXCDriver *driver,
                             virDomainDef *def)
{
    size_t i;

    if (!def->nhostdevs)
        return 0;

    /* Sanity check for supported configurations only */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *dev = def->hostdevs[i];

        switch (dev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            switch (dev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
                break;
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported hostdev type %1$s"),
                               virDomainHostdevSubsysTypeToString(dev->source.subsys.type));
                return -1;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
            switch (dev->source.caps.type) {
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
                break;
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported hostdev type %1$s"),
                               virDomainHostdevSubsysTypeToString(dev->source.caps.type));
                return -1;
            }
            break;


        default:
        case VIR_DOMAIN_HOSTDEV_MODE_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported hostdev mode %1$s"),
                           virDomainHostdevModeTypeToString(dev->mode));
            return -1;
        }
    }

    if (virLXCPrepareHostUSBDevices(driver, def) < 0)
        return -1;

    return 0;
}


static void
virLXCDomainReAttachHostUSBDevices(virLXCDriver *driver,
                                   const char *name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachUSBDevices(hostdev_mgr, LXC_DRIVER_NAME,
                                 name, hostdevs, nhostdevs);
}

void virLXCDomainReAttachHostDevices(virLXCDriver *driver,
                                     virDomainDef *def)
{
    if (!def->nhostdevs)
        return;

    virLXCDomainReAttachHostUSBDevices(driver, def->name, def->hostdevs,
                                       def->nhostdevs);
}
