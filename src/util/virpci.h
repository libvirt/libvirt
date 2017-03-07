/*
 * virpci.h: helper APIs for managing host PCI devices
 *
 * Copyright (C) 2009, 2011-2015 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __VIR_PCI_H__
# define __VIR_PCI_H__

# include "internal.h"
# include "virobject.h"
# include "virutil.h"

typedef struct _virPCIDevice virPCIDevice;
typedef virPCIDevice *virPCIDevicePtr;
typedef struct _virPCIDeviceAddress virPCIDeviceAddress;
typedef virPCIDeviceAddress *virPCIDeviceAddressPtr;
typedef struct _virPCIDeviceList virPCIDeviceList;
typedef virPCIDeviceList *virPCIDeviceListPtr;

struct _virPCIDeviceAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    int multi; /* virTristateSwitch */
};

typedef enum {
    VIR_PCI_STUB_DRIVER_NONE = 0,
    VIR_PCI_STUB_DRIVER_XEN,
    VIR_PCI_STUB_DRIVER_KVM,
    VIR_PCI_STUB_DRIVER_VFIO,
    VIR_PCI_STUB_DRIVER_LAST
} virPCIStubDriver;

VIR_ENUM_DECL(virPCIStubDriver);

typedef enum {
    VIR_PCIE_LINK_SPEED_NA = 0,
    VIR_PCIE_LINK_SPEED_25,
    VIR_PCIE_LINK_SPEED_5,
    VIR_PCIE_LINK_SPEED_8,
    VIR_PCIE_LINK_SPEED_LAST
} virPCIELinkSpeed;

VIR_ENUM_DECL(virPCIELinkSpeed)

typedef enum {
    VIR_PCI_HEADER_ENDPOINT = 0,
    VIR_PCI_HEADER_PCI_BRIDGE,
    VIR_PCI_HEADER_CARDBUS_BRIDGE,

    VIR_PCI_HEADER_LAST
} virPCIHeaderType;

VIR_ENUM_DECL(virPCIHeader)

typedef struct _virPCIELink virPCIELink;
typedef virPCIELink *virPCIELinkPtr;
struct _virPCIELink {
    int port;
    virPCIELinkSpeed speed;
    unsigned int width;
};

typedef struct _virPCIEDeviceInfo virPCIEDeviceInfo;
typedef virPCIEDeviceInfo *virPCIEDeviceInfoPtr;
struct _virPCIEDeviceInfo {
    /* Not all PCI Express devices have link. For example this 'Root Complex
     * Integrated Endpoint' and 'Root Complex Event Collector' don't have it. */
    virPCIELink *link_cap;   /* PCIe device link capabilities */
    virPCIELink *link_sta;   /* Actually negotiated capabilities */
};

virPCIDevicePtr virPCIDeviceNew(unsigned int domain,
                                unsigned int bus,
                                unsigned int slot,
                                unsigned int function);
virPCIDevicePtr virPCIDeviceCopy(virPCIDevicePtr dev);
void virPCIDeviceFree(virPCIDevicePtr dev);
const char *virPCIDeviceGetName(virPCIDevicePtr dev);
const char *virPCIDeviceGetConfigPath(virPCIDevicePtr dev);

int virPCIDeviceDetach(virPCIDevicePtr dev,
                       virPCIDeviceListPtr activeDevs,
                       virPCIDeviceListPtr inactiveDevs);
int virPCIDeviceReattach(virPCIDevicePtr dev,
                         virPCIDeviceListPtr activeDevs,
                         virPCIDeviceListPtr inactiveDevs);
int virPCIDeviceReset(virPCIDevicePtr dev,
                      virPCIDeviceListPtr activeDevs,
                      virPCIDeviceListPtr inactiveDevs);

void virPCIDeviceSetManaged(virPCIDevice *dev,
                            bool managed);
bool virPCIDeviceGetManaged(virPCIDevice *dev);
void virPCIDeviceSetStubDriver(virPCIDevicePtr dev,
                               virPCIStubDriver driver);
virPCIStubDriver virPCIDeviceGetStubDriver(virPCIDevicePtr dev);
virPCIDeviceAddressPtr virPCIDeviceGetAddress(virPCIDevicePtr dev);
int virPCIDeviceSetUsedBy(virPCIDevice *dev,
                          const char *drv_name,
                          const char *dom_name);
void virPCIDeviceGetUsedBy(virPCIDevice *dev,
                           const char **drv_name,
                           const char **dom_name);
bool virPCIDeviceGetUnbindFromStub(virPCIDevicePtr dev);
void  virPCIDeviceSetUnbindFromStub(virPCIDevice *dev,
                                    bool unbind);
bool virPCIDeviceGetRemoveSlot(virPCIDevicePtr dev);
void virPCIDeviceSetRemoveSlot(virPCIDevice *dev,
                               bool remove_slot);
bool virPCIDeviceGetReprobe(virPCIDevicePtr dev);
void virPCIDeviceSetReprobe(virPCIDevice *dev,
                            bool reprobe);


virPCIDeviceListPtr virPCIDeviceListNew(void);
int  virPCIDeviceListAdd(virPCIDeviceListPtr list,
                         virPCIDevicePtr dev);
int virPCIDeviceListAddCopy(virPCIDeviceListPtr list, virPCIDevicePtr dev);
virPCIDevicePtr virPCIDeviceListGet(virPCIDeviceListPtr list,
                                    int idx);
size_t virPCIDeviceListCount(virPCIDeviceListPtr list);
virPCIDevicePtr virPCIDeviceListSteal(virPCIDeviceListPtr list,
                                      virPCIDevicePtr dev);
virPCIDevicePtr virPCIDeviceListStealIndex(virPCIDeviceListPtr list,
                                           int idx);
void virPCIDeviceListDel(virPCIDeviceListPtr list,
                         virPCIDevicePtr dev);
virPCIDevicePtr virPCIDeviceListFind(virPCIDeviceListPtr list,
                                     virPCIDevicePtr dev);
virPCIDevicePtr
virPCIDeviceListFindByIDs(virPCIDeviceListPtr list,
                          unsigned int domain,
                          unsigned int bus,
                          unsigned int slot,
                          unsigned int function);
int virPCIDeviceListFindIndex(virPCIDeviceListPtr list,
                              virPCIDevicePtr dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for PCI host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virPCIDeviceFileActor)(virPCIDevicePtr dev,
                                     const char *path, void *opaque);
int virPCIDeviceFileIterate(virPCIDevicePtr dev,
                            virPCIDeviceFileActor actor,
                            void *opaque);

typedef int (*virPCIDeviceAddressActor)(virPCIDeviceAddressPtr addr,
                                        void *opaque);
int virPCIDeviceAddressIOMMUGroupIterate(virPCIDeviceAddressPtr orig,
                                         virPCIDeviceAddressActor actor,
                                         void *opaque);
virPCIDeviceListPtr virPCIDeviceGetIOMMUGroupList(virPCIDevicePtr dev);
int virPCIDeviceAddressGetIOMMUGroupAddresses(virPCIDeviceAddressPtr devAddr,
                                              virPCIDeviceAddressPtr **iommuGroupDevices,
                                              size_t *nIommuGroupDevices);
int virPCIDeviceAddressGetIOMMUGroupNum(virPCIDeviceAddressPtr addr);
char *virPCIDeviceGetIOMMUGroupDev(virPCIDevicePtr dev);

int virPCIDeviceIsAssignable(virPCIDevicePtr dev,
                             int strict_acs_check);
int virPCIDeviceWaitForCleanup(virPCIDevicePtr dev, const char *matcher);

virPCIDeviceAddressPtr
virPCIGetDeviceAddressFromSysfsLink(const char *device_link);

int virPCIGetPhysicalFunction(const char *vf_sysfs_path,
                              virPCIDeviceAddressPtr *pf);

int virPCIGetVirtualFunctions(const char *sysfs_path,
                              virPCIDeviceAddressPtr **virtual_functions,
                              size_t *num_virtual_functions,
                              unsigned int *max_virtual_functions);

int virPCIIsVirtualFunction(const char *vf_sysfs_device_link);

int virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link,
                                        const char *vf_sysfs_device_link,
                                        int *vf_index);

int virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr addr,
                                    char **pci_sysfs_device_link);

int virPCIGetNetName(char *device_link_sysfs_path, char **netname);

int virPCIGetSysfsFile(char *virPCIDeviceName,
                             char **pci_sysfs_device_link)
    ATTRIBUTE_RETURN_CHECK;

int virPCIGetAddrString(unsigned int domain,
                        unsigned int bus,
                        unsigned int slot,
                        unsigned int function,
                        char **pciConfigAddr)
    ATTRIBUTE_NONNULL(5) ATTRIBUTE_RETURN_CHECK;

int virPCIDeviceAddressParse(char *address, virPCIDeviceAddressPtr bdf);

int virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path,
                                 char **pfname, int *vf_index);

int virPCIDeviceUnbind(virPCIDevicePtr dev);
int virPCIDeviceRebind(virPCIDevicePtr dev);
int virPCIDeviceGetDriverPathAndName(virPCIDevicePtr dev,
                                     char **path,
                                     char **name);

int virPCIDeviceIsPCIExpress(virPCIDevicePtr dev);
int virPCIDeviceHasPCIExpressLink(virPCIDevicePtr dev);
int virPCIDeviceGetLinkCapSta(virPCIDevicePtr dev,
                              int *ca_port,
                              unsigned int *cap_speed,
                              unsigned int *cap_width,
                              unsigned int *sta_speed,
                              unsigned int *sta_width);

int virPCIGetHeaderType(virPCIDevicePtr dev, int *hdrType);

void virPCIEDeviceInfoFree(virPCIEDeviceInfoPtr dev);

#endif /* __VIR_PCI_H__ */
