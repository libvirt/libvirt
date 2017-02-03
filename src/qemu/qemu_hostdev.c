/*
 * qemu_hostdev.c: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2014 Red Hat, Inc.
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

VIR_LOG_INIT("qemu.qemu_hostdev");


int
qemuHostdevUpdateActivePCIDevices(virQEMUDriverPtr driver,
                                  virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActivePCIDevices(mgr, def->hostdevs, def->nhostdevs,
                                            QEMU_DRIVER_NAME, def->name);
}

int
qemuHostdevUpdateActiveUSBDevices(virQEMUDriverPtr driver,
                                  virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUSBDevices(mgr, def->hostdevs, def->nhostdevs,
                                            QEMU_DRIVER_NAME, def->name);
}

int
qemuHostdevUpdateActiveSCSIDevices(virQEMUDriverPtr driver,
                                   virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveSCSIDevices(mgr, def->hostdevs, def->nhostdevs,
                                             QEMU_DRIVER_NAME, def->name);
}


int
qemuHostdevUpdateActiveMediatedDevices(virQEMUDriverPtr driver,
                                       virDomainDefPtr def)
{
    virHostdevManagerPtr mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveMediatedDevices(mgr, def->hostdevs,
                                                 def->nhostdevs,
                                                 QEMU_DRIVER_NAME, def->name);
}


int
qemuHostdevUpdateActiveDomainDevices(virQEMUDriverPtr driver,
                                     virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuHostdevUpdateActivePCIDevices(driver, def) < 0)
        return -1;

    if (qemuHostdevUpdateActiveUSBDevices(driver, def) < 0)
        return -1;

    if (qemuHostdevUpdateActiveSCSIDevices(driver, def) < 0)
        return -1;

    if (qemuHostdevUpdateActiveMediatedDevices(driver, def) < 0)
        return -1;

    return 0;
}

bool
qemuHostdevHostSupportsPassthroughVFIO(void)
{
    DIR *iommuDir = NULL;
    struct dirent *iommuGroup = NULL;
    bool ret = false;
    int direrr;

    /* condition 1 - /sys/kernel/iommu_groups/ contains entries */
    if (virDirOpenQuiet(&iommuDir, "/sys/kernel/iommu_groups/") < 0)
        goto cleanup;

    while ((direrr = virDirRead(iommuDir, &iommuGroup, NULL)) > 0) {
        /* assume we found a group */
        break;
    }

    if (direrr < 0 || !iommuGroup)
        goto cleanup;
    /* okay, iommu is on and recognizes groups */

    /* condition 2 - /dev/vfio/vfio exists */
    if (!virFileExists("/dev/vfio/vfio"))
        goto cleanup;

    ret = true;

 cleanup:
    VIR_DIR_CLOSE(iommuDir);
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
qemuHostdevPreparePCIDevicesCheckSupport(virDomainHostdevDefPtr *hostdevs,
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

        switch ((virDomainHostdevSubsysPCIBackendType) *backend) {
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
            if (supportsPassthroughVFIO &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
            } else if (supportsPassthroughKVM) {
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

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN:
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
            break;
        }
    }

    return true;
}

int
qemuHostdevPreparePCIDevices(virQEMUDriverPtr driver,
                             const char *name,
                             const unsigned char *uuid,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             virQEMUCapsPtr qemuCaps,
                             unsigned int flags)
{
    int ret = -1;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (!qemuHostdevPreparePCIDevicesCheckSupport(hostdevs, nhostdevs, qemuCaps))
        goto out;

    ret = virHostdevPreparePCIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                      name, uuid, hostdevs,
                                      nhostdevs, flags);
 out:
    return ret;
}

int
qemuHostdevPrepareUSBDevices(virQEMUDriverPtr driver,
                             const char *name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             unsigned int flags)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                       hostdevs, nhostdevs, flags);
}

int
qemuHostdevPrepareSCSIDevices(virQEMUDriverPtr driver,
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

    return virHostdevPrepareSCSIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                        name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareSCSIVHostDevices(virQEMUDriverPtr driver,
                                   const char *name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareSCSIVHostDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                             name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareMediatedDevices(virQEMUDriverPtr driver,
                                  const char *name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    if (!qemuHostdevHostSupportsPassthroughVFIO()) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("host doesn't support VFIO PCI interface"));
        return -1;
    }

    return virHostdevPrepareMediatedDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                            name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareDomainDevices(virQEMUDriverPtr driver,
                                virDomainDefPtr def,
                                virQEMUCapsPtr qemuCaps,
                                unsigned int flags)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuHostdevPreparePCIDevices(driver, def->name, def->uuid,
                                     def->hostdevs, def->nhostdevs,
                                     qemuCaps, flags) < 0)
        return -1;

    if (qemuHostdevPrepareUSBDevices(driver, def->name,
                                     def->hostdevs, def->nhostdevs, flags) < 0)
        return -1;

    if (qemuHostdevPrepareSCSIDevices(driver, def->name,
                                      def->hostdevs, def->nhostdevs) < 0)
        return -1;

    if (qemuHostdevPrepareSCSIVHostDevices(driver, def->name,
                                           def->hostdevs, def->nhostdevs) < 0)
        return -1;

    if (qemuHostdevPrepareMediatedDevices(driver, def->name,
                                          def->hostdevs, def->nhostdevs) < 0)
        return -1;

    return 0;
}

void
qemuHostdevReAttachPCIDevices(virQEMUDriverPtr driver,
                              const char *name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *oldStateDir = cfg->stateDir;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachPCIDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                 hostdevs, nhostdevs, oldStateDir);

    virObjectUnref(cfg);
}

void
qemuHostdevReAttachUSBDevices(virQEMUDriverPtr driver,
                              const char *name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachUSBDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                  name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachSCSIDevices(virQEMUDriverPtr driver,
                               const char *name,
                               virDomainHostdevDefPtr *hostdevs,
                               int nhostdevs)
{
    size_t i;
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainDeviceDef dev;

        dev.type = VIR_DOMAIN_DEVICE_HOSTDEV;
        dev.data.hostdev = hostdev;

        ignore_value(qemuRemoveSharedDevice(driver, &dev, name));
    }

    virHostdevReAttachSCSIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                  name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachSCSIVHostDevices(virQEMUDriverPtr driver,
                                    const char *name,
                                    virDomainHostdevDefPtr *hostdevs,
                                    int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachSCSIVHostDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                       name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachMediatedDevices(virQEMUDriverPtr driver,
                                   const char *name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs)
{
    virHostdevManagerPtr hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachMediatedDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                      name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachDomainDevices(virQEMUDriverPtr driver,
                                 virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    qemuHostdevReAttachPCIDevices(driver, def->name, def->hostdevs,
                                  def->nhostdevs);

    qemuHostdevReAttachUSBDevices(driver, def->name, def->hostdevs,
                                  def->nhostdevs);

    qemuHostdevReAttachSCSIDevices(driver, def->name, def->hostdevs,
                                   def->nhostdevs);

    qemuHostdevReAttachSCSIVHostDevices(driver, def->name, def->hostdevs,
                                        def->nhostdevs);

    qemuHostdevReAttachMediatedDevices(driver, def->name, def->hostdevs,
                                       def->nhostdevs);
}
