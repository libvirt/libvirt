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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/ioctl.h>

#include "qemu_hostdev.h"
#include "qemu_domain.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virhostdev.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_hostdev");


int
qemuHostdevUpdateActivePCIDevices(virQEMUDriver *driver,
                                  virDomainDef *def)
{
    virHostdevManager *mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActivePCIDevices(mgr, def->hostdevs, def->nhostdevs,
                                            QEMU_DRIVER_NAME, def->name);
}

int
qemuHostdevUpdateActiveUSBDevices(virQEMUDriver *driver,
                                  virDomainDef *def)
{
    virHostdevManager *mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveUSBDevices(mgr, def->hostdevs, def->nhostdevs,
                                            QEMU_DRIVER_NAME, def->name);
}

int
qemuHostdevUpdateActiveSCSIDevices(virQEMUDriver *driver,
                                   virDomainDef *def)
{
    virHostdevManager *mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveSCSIDevices(mgr, def->hostdevs, def->nhostdevs,
                                             QEMU_DRIVER_NAME, def->name);
}


int
qemuHostdevUpdateActiveMediatedDevices(virQEMUDriver *driver,
                                       virDomainDef *def)
{
    virHostdevManager *mgr = driver->hostdevMgr;

    if (!def->nhostdevs)
        return 0;

    return virHostdevUpdateActiveMediatedDevices(mgr, def->hostdevs,
                                                 def->nhostdevs,
                                                 QEMU_DRIVER_NAME, def->name);
}


int
qemuHostdevUpdateActiveNVMeDisks(virQEMUDriver *driver,
                                 virDomainDef *def)
{
    return virHostdevUpdateActiveNVMeDevices(driver->hostdevMgr,
                                             QEMU_DRIVER_NAME,
                                             def->name,
                                             def->disks,
                                             def->ndisks);
}


int
qemuHostdevUpdateActiveDomainDevices(virQEMUDriver *driver,
                                     virDomainDef *def)
{
    if (!def->nhostdevs && !def->ndisks)
        return 0;

    if (qemuHostdevUpdateActiveNVMeDisks(driver, def) < 0)
        return -1;

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
qemuHostdevNeedsVFIO(const virDomainHostdevDef *hostdev)
{
    return virHostdevIsVFIODevice(hostdev) ||
        virHostdevIsMdevDevice(hostdev);
}


bool
qemuHostdevHostSupportsPassthroughVFIO(void)
{
    /* condition 1 - host has IOMMU */
    if (!virHostHasIOMMU())
        return false;

    /* condition 2 - /dev/vfio/vfio exists */
    if (!virFileExists(QEMU_DEV_VFIO))
        return false;

    return true;
}


int
qemuHostdevPrepareOneNVMeDisk(virQEMUDriver *driver,
                              const char *name,
                              virStorageSource *src)
{
    return virHostdevPrepareOneNVMeDevice(driver->hostdevMgr,
                                          QEMU_DRIVER_NAME,
                                          name,
                                          src);
}

int
qemuHostdevPrepareNVMeDisks(virQEMUDriver *driver,
                            const char *name,
                            virDomainDiskDef **disks,
                            size_t ndisks)
{
    return virHostdevPrepareNVMeDevices(driver->hostdevMgr,
                                        QEMU_DRIVER_NAME,
                                        name, disks, ndisks);
}

int
qemuHostdevPreparePCIDevices(virQEMUDriver *driver,
                             const char *name,
                             const unsigned char *uuid,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs,
                             unsigned int flags)
{
    return virHostdevPreparePCIDevices(driver->hostdevMgr,
                                       QEMU_DRIVER_NAME,
                                       name, uuid, hostdevs,
                                       nhostdevs, flags);
}

int
qemuHostdevPrepareUSBDevices(virQEMUDriver *driver,
                             const char *name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs,
                             unsigned int flags)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareUSBDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                       hostdevs, nhostdevs, flags);
}

int
qemuHostdevPrepareSCSIDevices(virQEMUDriver *driver,
                              const char *name,
                              virDomainHostdevDef **hostdevs,
                              int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareSCSIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                        name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareSCSIVHostDevices(virQEMUDriver *driver,
                                   const char *name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    return virHostdevPrepareSCSIVHostDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                             name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareMediatedDevices(virQEMUDriver *driver,
                                  const char *name,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;
    bool supportsVFIO;
    size_t i;

    /* Checking for VFIO only is fine with mdev, as IOMMU isolation is achieved
     * by the physical parent device.
     */
    supportsVFIO = virFileExists(QEMU_DEV_VFIO);

    for (i = 0; i < nhostdevs; i++) {
        if (virHostdevIsMdevDevice(hostdevs[i])) {
            if (!supportsVFIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Mediated host device assignment requires VFIO support"));
                return -1;
            }
            break;
        }
    }

    return virHostdevPrepareMediatedDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                            name, hostdevs, nhostdevs);
}

int
qemuHostdevPrepareDomainDevices(virQEMUDriver *driver,
                                virDomainDef *def,
                                unsigned int flags)
{
    if (!def->nhostdevs && !def->ndisks)
        return 0;

    if (qemuHostdevPrepareNVMeDisks(driver, def->name, def->disks, def->ndisks) < 0)
        return -1;

    if (qemuHostdevPreparePCIDevices(driver, def->name, def->uuid,
                                     def->hostdevs, def->nhostdevs, flags) < 0)
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
qemuHostdevReAttachOneNVMeDisk(virQEMUDriver *driver,
                               const char *name,
                               virStorageSource *src)
{
    virHostdevReAttachOneNVMeDevice(driver->hostdevMgr,
                                    QEMU_DRIVER_NAME,
                                    name,
                                    src);
}

void
qemuHostdevReAttachNVMeDisks(virQEMUDriver *driver,
                             const char *name,
                             virDomainDiskDef **disks,
                             size_t ndisks)
{
    virHostdevReAttachNVMeDevices(driver->hostdevMgr,
                                  QEMU_DRIVER_NAME,
                                  name, disks, ndisks);
}

void
qemuHostdevReAttachPCIDevices(virQEMUDriver *driver,
                              const char *name,
                              virDomainHostdevDef **hostdevs,
                              int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachPCIDevices(hostdev_mgr, QEMU_DRIVER_NAME, name,
                                 hostdevs, nhostdevs);
}

void
qemuHostdevReAttachUSBDevices(virQEMUDriver *driver,
                              const char *name,
                              virDomainHostdevDef **hostdevs,
                              int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachUSBDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                  name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachSCSIDevices(virQEMUDriver *driver,
                               const char *name,
                               virDomainHostdevDef **hostdevs,
                               int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachSCSIDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                  name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachSCSIVHostDevices(virQEMUDriver *driver,
                                    const char *name,
                                    virDomainHostdevDef **hostdevs,
                                    int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachSCSIVHostDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                       name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachMediatedDevices(virQEMUDriver *driver,
                                   const char *name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs)
{
    virHostdevManager *hostdev_mgr = driver->hostdevMgr;

    virHostdevReAttachMediatedDevices(hostdev_mgr, QEMU_DRIVER_NAME,
                                      name, hostdevs, nhostdevs);
}

void
qemuHostdevReAttachDomainDevices(virQEMUDriver *driver,
                                 virDomainDef *def)
{
    if (!def->nhostdevs && !def->ndisks)
        return;

    qemuHostdevReAttachNVMeDisks(driver, def->name, def->disks,
                                 def->ndisks);

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
