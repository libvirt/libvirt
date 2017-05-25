/*
 * node_device_linux_sysfs.c: Linux specific code to gather device data
 * that is available from sysfs (but not from UDEV or HAL).
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "dirname.h"
#include "node_device_driver.h"
#include "node_device_hal.h"
#include "node_device_linux_sysfs.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfcp.h"
#include "virlog.h"
#include "virfile.h"
#include "virscsihost.h"
#include "virstring.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

VIR_LOG_INIT("node_device.node_device_linux_sysfs");

int
nodeDeviceSysfsGetSCSIHostCaps(virNodeDevCapSCSIHostPtr scsi_host)
{
    return virNodeDeviceGetSCSIHostCaps(scsi_host);
}


int
nodeDeviceSysfsGetSCSITargetCaps(const char *sysfsPath,
                                 virNodeDevCapSCSITargetPtr scsi_target)
{
    int ret = -1;
    char *dir = NULL, *rport = NULL;

    VIR_DEBUG("Checking if '%s' is an FC remote port", scsi_target->name);

    /* /sys/devices/[...]/host0/rport-0:0-0/target0:0:0 -> rport-0:0-0 */
    if (!(dir = mdir_name(sysfsPath)))
        return -1;

    if (VIR_STRDUP(rport, last_component(dir)) < 0)
        goto cleanup;

    if (!virFCIsCapableRport(rport))
        goto cleanup;

    VIR_FREE(scsi_target->rport);
    VIR_STEAL_PTR(scsi_target->rport, rport);

    if (virFCReadRportValue(scsi_target->rport, "port_name",
                            &scsi_target->wwpn) < 0) {
        VIR_WARN("Failed to read port_name for '%s'", scsi_target->rport);
        goto cleanup;
    }

    scsi_target->flags |= VIR_NODE_DEV_CAP_FLAG_FC_RPORT;
    ret = 0;

 cleanup:
    if (ret < 0) {
        VIR_FREE(scsi_target->rport);
        VIR_FREE(scsi_target->wwpn);
        scsi_target->flags &= ~VIR_NODE_DEV_CAP_FLAG_FC_RPORT;
    }
    VIR_FREE(rport);
    VIR_FREE(dir);

    return ret;
}


static int
nodeDeviceSysfsGetPCISRIOVCaps(const char *sysfsPath,
                               virNodeDevCapPCIDevPtr pci_dev)
{
    size_t i;
    int ret;

    /* this could be a refresh, so clear out the old data */
    for (i = 0; i < pci_dev->num_virtual_functions; i++)
       VIR_FREE(pci_dev->virtual_functions[i]);
    VIR_FREE(pci_dev->virtual_functions);
    pci_dev->num_virtual_functions = 0;
    pci_dev->max_virtual_functions = 0;
    pci_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;
    pci_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    ret = virPCIGetPhysicalFunction(sysfsPath,
                                    &pci_dev->physical_function);
    if (ret < 0)
        goto cleanup;

    if (pci_dev->physical_function)
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    ret = virPCIGetVirtualFunctions(sysfsPath, &pci_dev->virtual_functions,
                                    &pci_dev->num_virtual_functions,
                                    &pci_dev->max_virtual_functions);
    if (ret < 0)
        goto cleanup;

    if (pci_dev->num_virtual_functions > 0 ||
        pci_dev->max_virtual_functions > 0)
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;

 cleanup:
    return ret;
}


static int
nodeDeviceSysfsGetPCIIOMMUGroupCaps(virNodeDevCapPCIDevPtr pci_dev)
{
    size_t i;
    int tmpGroup, ret = -1;
    virPCIDeviceAddress addr;

    /* this could be a refresh, so clear out the old data */
    for (i = 0; i < pci_dev->nIommuGroupDevices; i++)
       VIR_FREE(pci_dev->iommuGroupDevices[i]);
    VIR_FREE(pci_dev->iommuGroupDevices);
    pci_dev->nIommuGroupDevices = 0;
    pci_dev->iommuGroupNumber = 0;

    addr.domain = pci_dev->domain;
    addr.bus = pci_dev->bus;
    addr.slot = pci_dev->slot;
    addr.function = pci_dev->function;
    tmpGroup = virPCIDeviceAddressGetIOMMUGroupNum(&addr);
    if (tmpGroup == -1) {
        /* error was already reported */
        goto cleanup;
    }
    if (tmpGroup == -2) {
        /* -2 return means there is no iommu_group data */
        ret = 0;
        goto cleanup;
    }
    if (tmpGroup >= 0) {
        if (virPCIDeviceAddressGetIOMMUGroupAddresses(&addr, &pci_dev->iommuGroupDevices,
                                                      &pci_dev->nIommuGroupDevices) < 0)
            goto cleanup;
        pci_dev->iommuGroupNumber = tmpGroup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/* nodeDeviceSysfsGetPCIRelatedCaps() get info that is stored in sysfs
 * about devices related to this device, i.e. things that can change
 * without this device itself changing. These must be refreshed
 * anytime full XML of the device is requested, because they can
 * change with no corresponding notification from the kernel/udev.
 */
int
nodeDeviceSysfsGetPCIRelatedDevCaps(const char *sysfsPath,
                                    virNodeDevCapPCIDevPtr pci_dev)
{
    if (nodeDeviceSysfsGetPCISRIOVCaps(sysfsPath, pci_dev) < 0)
        return -1;
    if (nodeDeviceSysfsGetPCIIOMMUGroupCaps(pci_dev) < 0)
        return -1;
    return 0;
}


#else

int
nodeDeviceSysfsGetSCSIHostCaps(virNodeDevCapSCSIHostPtr scsi_host ATTRIBUTE_UNUSED)
{
    return -1;
}

int nodeDeviceSysfsGetSCSITargetCaps(const char *sysfsPath ATTRIBUTE_UNUSED,
                                     virNodeDevCapSCSITargetPtr scsi_target ATTRIBUTE_UNUSED)
{
    return -1;
}

int
nodeDeviceSysfsGetPCIRelatedDevCaps(const char *sysfsPath ATTRIBUTE_UNUSED,
                                    virNodeDevCapPCIDevPtr pci_dev ATTRIBUTE_UNUSED)
{
    return -1;
}

#endif /* __linux__ */
