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

int
qemuUpdateActivePciHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActivePciHostdevs(mgr, QEMU_DRIVER_NAME, def);
}

int
qemuUpdateActiveUsbHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUsbHostdevs(mgr, QEMU_DRIVER_NAME, def);
}

int
qemuUpdateActiveScsiHostdevs(virQEMUDriverPtr driver,
                             virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveScsiHostdevs(mgr, QEMU_DRIVER_NAME, def);
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

int
qemuPrepareHostUSBDevices(virQEMUDriverPtr driver,
                          const char *name,
                          virDomainHostdevDefPtr *hostdevs,
                          int nhostdevs,
                          unsigned int flags)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                       hostdevs, nhostdevs, flags);
}

static int
virHostdevPrepareSCSIDevices(virHostdevManagerPtr hostdev_mgr,
                             const char *name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs)
{
    size_t i, j;
    int count;
    virSCSIDeviceListPtr list;
    virSCSIDevicePtr tmp;

    /* To prevent situation where SCSI device is assigned to two domains
     * we need to keep a list of currently assigned SCSI devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list */
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

    /* Loop 2: Mark devices in temporary list as used by @name
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

    /* Loop 3: Temporary list was successfully merged with
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
qemuPrepareHostdevSCSIDevices(virQEMUDriverPtr driver,
                              const char *name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    size_t i;
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

    return virHostdevPrepareSCSIDevices(hostdev_mgr, name,
                                        hostdevs, nhostdevs);
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
