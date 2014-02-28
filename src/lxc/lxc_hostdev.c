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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "lxc_hostdev.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virhostdev.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_hostdev");

int
virLXCUpdateActiveUsbHostdevs(virLXCDriverPtr driver,
                              virDomainDefPtr def)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUSBDevices(hostdev_mgr,
                                            def->hostdevs, def->nhostdevs,
                                            LXC_DRIVER_NAME, def->name);
}

static int
virLXCPrepareHostUSBDevices(virLXCDriverPtr driver,
                            virDomainDefPtr def)
{
    virDomainHostdevDefPtr *hostdevs = def->hostdevs;
    int nhostdevs = def->nhostdevs;
    const char *dom_name = def->name;
    unsigned int flags = 0;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, LXC_DRIVER_NAME, dom_name,
                                       hostdevs, nhostdevs, flags);
}


int virLXCPrepareHostDevices(virLXCDriverPtr driver,
                             virDomainDefPtr def)
{
    size_t i;

    if (!def->nhostdevs)
        return 0;

    /* Sanity check for supported configurations only */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr dev = def->hostdevs[i];

        switch (dev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            switch (dev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
                break;
            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported hostdev type %s"),
                               virDomainHostdevSubsysTypeToString(dev->source.subsys.type));
                return -1;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
            switch (dev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
            case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
                break;
            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Unsupported hostdev type %s"),
                               virDomainHostdevSubsysTypeToString(dev->source.subsys.type));
                return -1;
            }
            break;


        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported hostdev mode %s"),
                           virDomainHostdevModeTypeToString(dev->mode));
            return -1;
        }
    }

    if (virLXCPrepareHostUSBDevices(driver, def) < 0)
        return -1;

    return 0;
}


static void
virLXCDomainReAttachHostUsbDevices(virLXCDriverPtr driver,
                                   const char *name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachUSBDevices(hostdev_mgr, LXC_DRIVER_NAME,
                                 name, hostdevs, nhostdevs);
}

void virLXCDomainReAttachHostDevices(virLXCDriverPtr driver,
                                     virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    virLXCDomainReAttachHostUsbDevices(driver, def->name, def->hostdevs,
                                       def->nhostdevs);
}
