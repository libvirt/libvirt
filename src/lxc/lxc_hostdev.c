/*
 * virLXC_hostdev.c: VIRLXC hostdev management
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

#define VIR_FROM_THIS VIR_FROM_LXC

int
virLXCUpdateActiveUsbHostdevs(virLXCDriverPtr driver,
                              virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;

    if (!def->nhostdevs)
        return 0;

    for (i = 0; i < def->nhostdevs; i++) {
        virUSBDevicePtr usb = NULL;
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        usb = virUSBDeviceNew(hostdev->source.subsys.u.usb.bus,
                              hostdev->source.subsys.u.usb.device,
                              NULL);
        if (!usb) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     def->name);
            continue;
        }

        virUSBDeviceSetUsedBy(usb, LXC_DRIVER_NAME, def->name);

        virObjectLock(driver->activeUsbHostdevs);
        if (virUSBDeviceListAdd(driver->activeUsbHostdevs, usb) < 0) {
            virObjectUnlock(driver->activeUsbHostdevs);
            virUSBDeviceFree(usb);
            return -1;
        }
        virObjectUnlock(driver->activeUsbHostdevs);
    }

    return 0;
}


int
virLXCPrepareHostdevUSBDevices(virLXCDriverPtr driver,
                               const char *name,
                               virUSBDeviceList *list)
{
    size_t i, j;
    unsigned int count;
    virUSBDevicePtr tmp;

    count = virUSBDeviceListCount(list);

    virObjectLock(driver->activeUsbHostdevs);
    for (i = 0; i < count; i++) {
        virUSBDevicePtr usb = virUSBDeviceListGet(list, i);
        if ((tmp = virUSBDeviceListFind(driver->activeUsbHostdevs, usb))) {
            const char *other_drvname;
            const char *other_domname;

            virUSBDeviceGetUsedBy(tmp, &other_drvname, &other_domname);
            if (other_drvname && other_domname)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is in use by "
                                 "driver %s, domain %s"),
                               virUSBDeviceGetName(tmp),
                               other_drvname, other_domname);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is already in use"),
                               virUSBDeviceGetName(tmp));
            goto error;
        }

        virUSBDeviceSetUsedBy(usb, LXC_DRIVER_NAME, name);
        VIR_DEBUG("Adding %03d.%03d dom=%s to activeUsbHostdevs",
                  virUSBDeviceGetBus(usb), virUSBDeviceGetDevno(usb), name);
        /*
         * The caller is responsible to steal these usb devices
         * from the virUSBDeviceList that passed in on success,
         * perform rollback on failure.
         */
        if (virUSBDeviceListAdd(driver->activeUsbHostdevs, usb) < 0)
            goto error;
    }
    virObjectUnlock(driver->activeUsbHostdevs);
    return 0;

error:
    for (j = 0; j < i; j++) {
        tmp = virUSBDeviceListGet(list, i);
        virUSBDeviceListSteal(driver->activeUsbHostdevs, tmp);
    }
    virObjectUnlock(driver->activeUsbHostdevs);
    return -1;
}

int
virLXCFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
                           bool mandatory,
                           virUSBDevicePtr *usb)
{
    unsigned vendor = hostdev->source.subsys.u.usb.vendor;
    unsigned product = hostdev->source.subsys.u.usb.product;
    unsigned bus = hostdev->source.subsys.u.usb.bus;
    unsigned device = hostdev->source.subsys.u.usb.device;
    bool autoAddress = hostdev->source.subsys.u.usb.autoAddress;
    int rc;

    *usb = NULL;

    if (vendor && bus) {
        rc = virUSBDeviceFind(vendor, product, bus, device,
                              NULL,
                              autoAddress ? false : mandatory,
                              usb);
        if (rc < 0) {
            return -1;
        } else if (!autoAddress) {
            goto out;
        } else {
            VIR_INFO("USB device %x:%x could not be found at previous"
                     " address (bus:%u device:%u)",
                     vendor, product, bus, device);
        }
    }

    /* When vendor is specified, its USB address is either unspecified or the
     * device could not be found at the USB device where it had been
     * automatically found before.
     */
    if (vendor) {
        virUSBDeviceList *devs;

        rc = virUSBDeviceFindByVendor(vendor, product,
                                      NULL,
                                      mandatory, &devs);
        if (rc < 0)
            return -1;

        if (rc == 1) {
            *usb = virUSBDeviceListGet(devs, 0);
            virUSBDeviceListSteal(devs, *usb);
        }
        virObjectUnref(devs);

        if (rc == 0) {
            goto out;
        } else if (rc > 1) {
            if (autoAddress) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %x:%x were found,"
                                 " but none of them is at bus:%u device:%u"),
                               vendor, product, bus, device);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %x:%x, "
                                 "use <address> to specify one"),
                               vendor, product);
            }
            return -1;
        }

        hostdev->source.subsys.u.usb.bus = virUSBDeviceGetBus(*usb);
        hostdev->source.subsys.u.usb.device = virUSBDeviceGetDevno(*usb);
        hostdev->source.subsys.u.usb.autoAddress = true;

        if (autoAddress) {
            VIR_INFO("USB device %x:%x found at bus:%u device:%u (moved"
                     " from bus:%u device:%u)",
                     vendor, product,
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     bus, device);
        }
    } else if (!vendor && bus) {
        if (virUSBDeviceFindByBus(bus, device,
                                  NULL,
                                  mandatory, usb) < 0)
            return -1;
    }

out:
    if (!*usb)
        hostdev->missing = true;
    return 0;
}

static int
virLXCPrepareHostUSBDevices(virLXCDriverPtr driver,
                            virDomainDefPtr def)
{
    size_t i;
    int ret = -1;
    virUSBDeviceList *list;
    virUSBDevicePtr tmp;
    virDomainHostdevDefPtr *hostdevs = def->hostdevs;
    int nhostdevs = def->nhostdevs;

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virLXCPrepareHostdevPCIDevices()
     */
    if (!(list = virUSBDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        bool required = true;
        virUSBDevicePtr usb;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        if (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_OPTIONAL)
            required = false;

        if (virLXCFindHostdevUSBDevice(hostdev, required, &usb) < 0)
            goto cleanup;

        if (usb && virUSBDeviceListAdd(list, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }

    /* Mark devices in temporary list as used by @name
     * and add them do driver list. However, if something goes
     * wrong, perform rollback.
     */
    if (virLXCPrepareHostdevUSBDevices(driver, def->name, list) < 0)
        goto cleanup;

    /* Loop 2: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * in cleanup label.
     */
    while (virUSBDeviceListCount(list) > 0) {
        tmp = virUSBDeviceListGet(list, 0);
        virUSBDeviceListSteal(list, tmp);
    }

    ret = 0;

cleanup:
    virObjectUnref(list);
    return ret;
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
    size_t i;

    virObjectLock(driver->activeUsbHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virUSBDevicePtr usb, tmp;
        const char *usedby_domname = NULL;
        const char *usedby_drvname = NULL;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;
        if (hostdev->missing)
            continue;

        usb = virUSBDeviceNew(hostdev->source.subsys.u.usb.bus,
                              hostdev->source.subsys.u.usb.device,
                              NULL);

        if (!usb) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     name);
            continue;
        }

        /* Delete only those USB devices which belongs
         * to domain @name because virLXCProcessStart() might
         * have failed because USB device is already taken.
         * Therefore we want to steal only those devices from
         * the list which were taken by @name */

        tmp = virUSBDeviceListFind(driver->activeUsbHostdevs, usb);
        virUSBDeviceFree(usb);

        if (!tmp) {
            VIR_WARN("Unable to find device %03d.%03d "
                     "in list of active USB devices",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device);
            continue;
        }

        virUSBDeviceGetUsedBy(tmp, &usedby_drvname, &usedby_domname);
        if (STREQ_NULLABLE(LXC_DRIVER_NAME, usedby_drvname) &&
            STREQ_NULLABLE(name, usedby_domname)) {
            VIR_DEBUG("Removing %03d.%03d dom=%s from activeUsbHostdevs",
                      hostdev->source.subsys.u.usb.bus,
                      hostdev->source.subsys.u.usb.device,
                      name);

            virUSBDeviceListDel(driver->activeUsbHostdevs, tmp);
        }
    }
    virObjectUnlock(driver->activeUsbHostdevs);
}

void virLXCDomainReAttachHostDevices(virLXCDriverPtr driver,
                                     virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    virLXCDomainReAttachHostUsbDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);
}
