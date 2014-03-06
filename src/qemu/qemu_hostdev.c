/*
 * qemu_hostdev.c: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2013 Red Hat, Inc.
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

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "qemu_hostdev.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virnetdev.h"
#include "virfile.h"
#include "virhostdev.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static int
virHostdevUpdateActivePciHostdevs(virHostdevManagerPtr mgr,
                                  virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    virPCIDevicePtr dev = NULL;
    size_t i;
    int ret = -1;

    virObjectLock(mgr->activePciHostdevs);
    virObjectLock(mgr->inactivePciHostdevs);

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = virPCIDeviceNew(hostdev->source.subsys.u.pci.addr.domain,
                              hostdev->source.subsys.u.pci.addr.bus,
                              hostdev->source.subsys.u.pci.addr.slot,
                              hostdev->source.subsys.u.pci.addr.function);

        if (!dev)
            goto cleanup;

        virPCIDeviceSetManaged(dev, hostdev->managed);
        if (hostdev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            if (virPCIDeviceSetStubDriver(dev, "vfio-pci") < 0)
                goto cleanup;
        } else {
            if (virPCIDeviceSetStubDriver(dev, "pci-stub") < 0)
                goto cleanup;

        }
        virPCIDeviceSetUsedBy(dev, QEMU_DRIVER_NAME, def->name);

        /* Setup the original states for the PCI device */
        virPCIDeviceSetUnbindFromStub(dev, hostdev->origstates.states.pci.unbind_from_stub);
        virPCIDeviceSetRemoveSlot(dev, hostdev->origstates.states.pci.remove_slot);
        virPCIDeviceSetReprobe(dev, hostdev->origstates.states.pci.reprobe);

        if (virPCIDeviceListAdd(mgr->activePciHostdevs, dev) < 0)
            goto cleanup;
        dev = NULL;
    }

    ret = 0;
cleanup:
    virPCIDeviceFree(dev);
    virObjectUnlock(mgr->activePciHostdevs);
    virObjectUnlock(mgr->inactivePciHostdevs);
    return ret;
}

int
qemuUpdateActivePciHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActivePciHostdevs(mgr, def);
}

static int
virHostdevUpdateActiveUsbHostdevs(virHostdevManagerPtr mgr,
                                  virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;

    virObjectLock(mgr->activeUsbHostdevs);
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

        virUSBDeviceSetUsedBy(usb, QEMU_DRIVER_NAME, def->name);

        if (virUSBDeviceListAdd(mgr->activeUsbHostdevs, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }
    ret = 0;
cleanup:
    virObjectUnlock(mgr->activeUsbHostdevs);
    return ret;
}

int
qemuUpdateActiveUsbHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUsbHostdevs(mgr, def);
}

static int
virHostdevUpdateActiveScsiHostdevs(virHostdevManagerPtr mgr,
                                   virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;
    virSCSIDevicePtr scsi = NULL;
    virSCSIDevicePtr tmp = NULL;

    virObjectLock(mgr->activeScsiHostdevs);
    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable)))
            goto cleanup;

        if ((tmp = virSCSIDeviceListFind(mgr->activeScsiHostdevs, scsi))) {
            if (virSCSIDeviceSetUsedBy(tmp, QEMU_DRIVER_NAME, def->name) < 0) {
                virSCSIDeviceFree(scsi);
                goto cleanup;
            }
            virSCSIDeviceFree(scsi);
        } else {
            if (virSCSIDeviceSetUsedBy(scsi, QEMU_DRIVER_NAME, def->name) < 0 ||
                virSCSIDeviceListAdd(mgr->activeScsiHostdevs, scsi) < 0) {
                virSCSIDeviceFree(scsi);
                goto cleanup;
            }
        }
    }
    ret = 0;

cleanup:
    virObjectUnlock(mgr->activeScsiHostdevs);
    return ret;
}

int
qemuUpdateActiveScsiHostdevs(virQEMUDriverPtr driver,
                             virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveScsiHostdevs(mgr, def);
}


bool
qemuHostdevHostSupportsPassthroughVFIO(void)
{
    DIR *iommuDir = NULL;
    struct dirent *iommuGroup = NULL;
    bool ret = false;

    /* condition 1 - /sys/kernel/iommu_groups/ contains entries */
    if (!(iommuDir = opendir("/sys/kernel/iommu_groups/")))
        goto cleanup;

    while ((iommuGroup = readdir(iommuDir))) {
        /* skip ./ ../ */
        if (STRPREFIX(iommuGroup->d_name, "."))
            continue;

        /* assume we found a group */
        break;
    }

    if (!iommuGroup)
        goto cleanup;
    /* okay, iommu is on and recognizes groups */

    /* condition 2 - /dev/vfio/vfio exists */
    if (!virFileExists("/dev/vfio/vfio"))
        goto cleanup;

    ret = true;

cleanup:
    if (iommuDir)
        closedir(iommuDir);

    return ret;
}


#if HAVE_LINUX_KVM_H
# include <linux/kvm.h>
bool
qemuHostdevHostSupportsPassthroughLegacy(void)
{
    int kvmfd = -1;
    bool ret = false;

    if ((kvmfd = open("/dev/kvm", O_RDONLY)) < 0)
        goto cleanup;

# ifdef KVM_CAP_IOMMU
    if ((ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_IOMMU)) <= 0)
        goto cleanup;

    ret = true;
# endif

cleanup:
    VIR_FORCE_CLOSE(kvmfd);

    return ret;
}
#else
bool
qemuHostdevHostSupportsPassthroughLegacy(void)
{
    return false;
}
#endif


static bool
qemuPrepareHostdevPCICheckSupport(virDomainHostdevDefPtr *hostdevs,
                                  size_t nhostdevs,
                                  virQEMUCapsPtr qemuCaps)
{
    bool supportsPassthroughKVM = qemuHostdevHostSupportsPassthroughLegacy();
    bool supportsPassthroughVFIO = qemuHostdevHostSupportsPassthroughVFIO();
    size_t i;

    /* assign defaults for hostdev passthrough */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        int *backend = &hostdev->source.subsys.u.pci.backend;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        switch ((virDomainHostdevSubsysPciBackendType) *backend) {
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
            if (supportsPassthroughVFIO &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
            } else if (supportsPassthroughKVM &&
                       (virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCIDEVICE) ||
                        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support passthrough of "
                                 "host PCI devices"));
                return false;
            }

            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
            if (!supportsPassthroughVFIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support VFIO PCI passthrough"));
                return false;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
            if (!supportsPassthroughKVM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support legacy PCI passthrough"));
                return false;
            }

            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
            break;
        }
    }

    return true;
}

int
qemuPrepareHostdevPCIDevices(virQEMUDriverPtr driver,
                             const char *name,
                             const unsigned char *uuid,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             virQEMUCapsPtr qemuCaps,
                             unsigned int flags)
{
    int ret = -1;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (!qemuPrepareHostdevPCICheckSupport(hostdevs, nhostdevs, qemuCaps))
        goto out;

    ret = virHostdevPreparePCIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                      name, uuid, hostdevs,
                                      nhostdevs, flags);
out:
    return ret;
}


static int
qemuPrepareHostdevUSBDevices(virHostdevManagerPtr mgr,
                             const char *name,
                             virUSBDeviceListPtr list)
{
    size_t i, j;
    unsigned int count;
    virUSBDevicePtr tmp;

    virObjectLock(mgr->activeUsbHostdevs);
    count = virUSBDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virUSBDevicePtr usb = virUSBDeviceListGet(list, i);
        if ((tmp = virUSBDeviceListFind(mgr->activeUsbHostdevs, usb))) {
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

        virUSBDeviceSetUsedBy(usb, QEMU_DRIVER_NAME, name);
        VIR_DEBUG("Adding %03d.%03d dom=%s to activeUsbHostdevs",
                  virUSBDeviceGetBus(usb), virUSBDeviceGetDevno(usb), name);
        /*
         * The caller is responsible to steal these usb devices
         * from the virUSBDeviceList that passed in on success,
         * perform rollback on failure.
         */
        if (virUSBDeviceListAdd(mgr->activeUsbHostdevs, usb) < 0)
            goto error;
    }

    virObjectUnlock(mgr->activeUsbHostdevs);
    return 0;

error:
    for (j = 0; j < i; j++) {
        tmp = virUSBDeviceListGet(list, i);
        virUSBDeviceListSteal(mgr->activeUsbHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeUsbHostdevs);
    return -1;
}


static int
qemuFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
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
        virUSBDeviceListPtr devs;

        rc = virUSBDeviceFindByVendor(vendor, product, NULL, mandatory, &devs);
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
        if (virUSBDeviceFindByBus(bus, device, NULL, mandatory, usb) < 0)
            return -1;
    }

out:
    if (!*usb)
        hostdev->missing = true;
    return 0;
}


int
qemuPrepareHostUSBDevices(virQEMUDriverPtr driver,
                          const char *name,
                          virDomainHostdevDefPtr *hostdevs,
                          int nhostdevs,
                          unsigned int flags)
{
    size_t i;
    int ret = -1;
    virUSBDeviceListPtr list;
    virUSBDevicePtr tmp;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;
    bool coldBoot = !!(flags & VIR_HOSTDEV_COLD_BOOT);

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
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

        if (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_OPTIONAL ||
            (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE &&
             !coldBoot))
            required = false;

        if (qemuFindHostdevUSBDevice(hostdev, required, &usb) < 0)
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
    if (qemuPrepareHostdevUSBDevices(hostdev_mgr, name, list) < 0)
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


int
qemuPrepareHostdevSCSIDevices(virQEMUDriverPtr driver,
                              const char *name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    size_t i, j;
    int count;
    virSCSIDeviceListPtr list;
    virSCSIDevicePtr tmp;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    /* Loop 1: Add the shared scsi host device to shared device
     * table.
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainDeviceDef dev;

        dev.type = VIR_DOMAIN_DEVICE_HOSTDEV;
        dev.data.hostdev = hostdevs[i];

        if (qemuAddSharedDevice(driver, &dev, name) < 0)
            return -1;

        if (qemuSetUnprivSGIO(&dev) < 0)
            return -1;
    }

    /* To prevent situation where SCSI device is assigned to two domains
     * we need to keep a list of currently assigned SCSI devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIDeviceListNew()))
        goto cleanup;

    /* Loop 2: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virSCSIDevicePtr scsi;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (hostdev->managed) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("SCSI host device doesn't support managed mode"));
            goto cleanup;
        }

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable)))
            goto cleanup;

        if (scsi && virSCSIDeviceListAdd(list, scsi) < 0) {
            virSCSIDeviceFree(scsi);
            goto cleanup;
        }
    }

    /* Loop 3: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(hostdev_mgr->activeScsiHostdevs);
    count = virSCSIDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virSCSIDevicePtr scsi = virSCSIDeviceListGet(list, i);
        if ((tmp = virSCSIDeviceListFind(hostdev_mgr->activeScsiHostdevs,
                                         scsi))) {
            bool scsi_shareable = virSCSIDeviceGetShareable(scsi);
            bool tmp_shareable = virSCSIDeviceGetShareable(tmp);

            if (!(scsi_shareable && tmp_shareable)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("SCSI device %s is already in use by "
                                 "other domain(s) as '%s'"),
                               virSCSIDeviceGetName(tmp),
                               tmp_shareable ? "shareable" : "non-shareable");
                goto error;
            }

            if (virSCSIDeviceSetUsedBy(tmp, QEMU_DRIVER_NAME, name) < 0)
                goto error;
        } else {
            if (virSCSIDeviceSetUsedBy(scsi, QEMU_DRIVER_NAME, name) < 0)
                goto error;

            VIR_DEBUG("Adding %s to activeScsiHostdevs", virSCSIDeviceGetName(scsi));

            if (virSCSIDeviceListAdd(hostdev_mgr->activeScsiHostdevs, scsi) < 0)
                goto error;
        }
    }

    virObjectUnlock(hostdev_mgr->activeScsiHostdevs);

    /* Loop 4: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * when freeing temporary list.
     */
    while (virSCSIDeviceListCount(list) > 0) {
        tmp = virSCSIDeviceListGet(list, 0);
        virSCSIDeviceListSteal(list, tmp);
    }

    virObjectUnref(list);
    return 0;

error:
    for (j = 0; j < i; j++) {
        tmp = virSCSIDeviceListGet(list, i);
        virSCSIDeviceListSteal(hostdev_mgr->activeScsiHostdevs, tmp);
    }
    virObjectUnlock(hostdev_mgr->activeScsiHostdevs);
cleanup:
    virObjectUnref(list);
    return -1;
}


int
qemuPrepareHostDevices(virQEMUDriverPtr driver,
                       virDomainDefPtr def,
                       virQEMUCapsPtr qemuCaps,
                       unsigned int flags)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuPrepareHostdevPCIDevices(driver, def->name, def->uuid,
                                     def->hostdevs, def->nhostdevs,
                                     qemuCaps, flags) < 0)
        return -1;

    if (qemuPrepareHostUSBDevices(driver, def->name,
                                  def->hostdevs, def->nhostdevs, flags) < 0)
        return -1;

    if (qemuPrepareHostdevSCSIDevices(driver, def->name,
                                      def->hostdevs, def->nhostdevs) < 0)
        return -1;

    return 0;
}

void
qemuDomainReAttachHostdevDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    char *oldStateDir = cfg->stateDir;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachPCIDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                 hostdevs, nhostdevs, oldStateDir);

    virObjectUnref(cfg);
}


void
qemuDomainReAttachHostUsbDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    size_t i;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virObjectLock(hostdev_mgr->activeUsbHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virUSBDevicePtr usb, tmp;
        const char *usedby_drvname;
        const char *usedby_domname;

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
         * to domain @name because qemuProcessStart() might
         * have failed because USB device is already taken.
         * Therefore we want to steal only those devices from
         * the list which were taken by @name */

        tmp = virUSBDeviceListFind(hostdev_mgr->activeUsbHostdevs, usb);
        virUSBDeviceFree(usb);

        if (!tmp) {
            VIR_WARN("Unable to find device %03d.%03d "
                     "in list of active USB devices",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device);
            continue;
        }

        virUSBDeviceGetUsedBy(tmp, &usedby_drvname, &usedby_domname);
        if (STREQ_NULLABLE(QEMU_DRIVER_NAME, usedby_drvname) &&
            STREQ_NULLABLE(name, usedby_domname)) {
            VIR_DEBUG("Removing %03d.%03d dom=%s from activeUsbHostdevs",
                      hostdev->source.subsys.u.usb.bus,
                      hostdev->source.subsys.u.usb.device,
                      name);

            virUSBDeviceListDel(hostdev_mgr->activeUsbHostdevs, tmp);
        }
    }
    virObjectUnlock(hostdev_mgr->activeUsbHostdevs);
}


void
qemuDomainReAttachHostScsiDevices(virQEMUDriverPtr driver,
                                  const char *name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs)
{
    size_t i;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virObjectLock(hostdev_mgr->activeScsiHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virSCSIDevicePtr scsi;
        virSCSIDevicePtr tmp;
        virDomainDeviceDef dev;

        dev.type = VIR_DOMAIN_DEVICE_HOSTDEV;
        dev.data.hostdev = hostdev;

        ignore_value(qemuRemoveSharedDevice(driver, &dev, name));

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable))) {
            VIR_WARN("Unable to reattach SCSI device %s:%d:%d:%d on domain %s",
                     hostdev->source.subsys.u.scsi.adapter,
                     hostdev->source.subsys.u.scsi.bus,
                     hostdev->source.subsys.u.scsi.target,
                     hostdev->source.subsys.u.scsi.unit,
                     name);
            continue;
        }

        /* Only delete the devices which are marked as being used by @name,
         * because qemuProcessStart could fail on the half way. */

        if (!(tmp = virSCSIDeviceListFind(hostdev_mgr->activeScsiHostdevs, scsi))) {
            VIR_WARN("Unable to find device %s:%d:%d:%d "
                     "in list of active SCSI devices",
                     hostdev->source.subsys.u.scsi.adapter,
                     hostdev->source.subsys.u.scsi.bus,
                     hostdev->source.subsys.u.scsi.target,
                     hostdev->source.subsys.u.scsi.unit);
            virSCSIDeviceFree(scsi);
            continue;
        }

        VIR_DEBUG("Removing %s:%d:%d:%d dom=%s from activeScsiHostdevs",
                   hostdev->source.subsys.u.scsi.adapter,
                   hostdev->source.subsys.u.scsi.bus,
                   hostdev->source.subsys.u.scsi.target,
                   hostdev->source.subsys.u.scsi.unit,
                   name);

        virSCSIDeviceListDel(hostdev_mgr->activeScsiHostdevs, tmp, QEMU_DRIVER_NAME, name);
        virSCSIDeviceFree(scsi);
    }
    virObjectUnlock(hostdev_mgr->activeScsiHostdevs);
}

void
qemuDomainReAttachHostDevices(virQEMUDriverPtr driver,
                              virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    qemuDomainReAttachHostdevDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);

    qemuDomainReAttachHostUsbDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);

    qemuDomainReAttachHostScsiDevices(driver, def->name, def->hostdevs,
                                      def->nhostdevs);
}
