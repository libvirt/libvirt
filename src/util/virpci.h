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
 */

#pragma once

#include "internal.h"
#include "virmdev.h"
#include "virobject.h"
#include "virenum.h"
#include "virpcivpd.h"

typedef struct _virPCIDevice virPCIDevice;
typedef struct _virPCIDeviceAddress virPCIDeviceAddress;
typedef struct _virPCIDeviceList virPCIDeviceList;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIDeviceList, virObjectUnref);


#define VIR_DOMAIN_DEVICE_ZPCI_MAX_UID UINT16_MAX
#define VIR_DOMAIN_DEVICE_ZPCI_MAX_FID UINT32_MAX

typedef struct _virZPCIDeviceAddressID virZPCIDeviceAddressID;
typedef struct _virZPCIDeviceAddress virZPCIDeviceAddress;

struct _virZPCIDeviceAddressID {
    unsigned int value;
    bool isSet;
};

struct _virZPCIDeviceAddress {
    virZPCIDeviceAddressID uid; /* exempt from syntax-check */
    virZPCIDeviceAddressID fid;
    /* Don't forget to update virPCIDeviceAddressCopy if needed. */
};

#define VIR_PCI_DEVICE_ADDRESS_FMT "%04x:%02x:%02x.%d"

/* Represents format of PF's phys_port_name in switchdev mode:
 * 'p%u' or 'p%us%u'. New line checked since value is read from sysfs file.
 */
#define VIR_PF_PHYS_PORT_NAME_REGEX  "(p[0-9]+$)|(p[0-9]+s[0-9]+$)"

struct _virPCIDeviceAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    virTristateSwitch multi;
    int extFlags; /* enum virPCIDeviceAddressExtensionFlags */
    virZPCIDeviceAddress zpci;
    /* Don't forget to update virPCIDeviceAddressCopy if needed. */
};

typedef enum {
    VIR_PCI_STUB_DRIVER_NONE = 0,
    VIR_PCI_STUB_DRIVER_XEN,
    VIR_PCI_STUB_DRIVER_VFIO,
    VIR_PCI_STUB_DRIVER_LAST
} virPCIStubDriver;

VIR_ENUM_DECL(virPCIStubDriver);

typedef enum {
    VIR_PCIE_LINK_SPEED_NA = 0,
    VIR_PCIE_LINK_SPEED_25,
    VIR_PCIE_LINK_SPEED_5,
    VIR_PCIE_LINK_SPEED_8,
    VIR_PCIE_LINK_SPEED_16,
    VIR_PCIE_LINK_SPEED_32,
    VIR_PCIE_LINK_SPEED_64,
    VIR_PCIE_LINK_SPEED_LAST
} virPCIELinkSpeed;

VIR_ENUM_DECL(virPCIELinkSpeed);

typedef enum {
    VIR_PCI_HEADER_ENDPOINT = 0,
    VIR_PCI_HEADER_PCI_BRIDGE,
    VIR_PCI_HEADER_CARDBUS_BRIDGE,

    VIR_PCI_HEADER_LAST
} virPCIHeaderType;

VIR_ENUM_DECL(virPCIHeader);

typedef struct _virPCIELink virPCIELink;
struct _virPCIELink {
    int port;
    virPCIELinkSpeed speed;
    unsigned int width;
};

typedef struct _virPCIEDeviceInfo virPCIEDeviceInfo;
struct _virPCIEDeviceInfo {
    /* Not all PCI Express devices have link. For example this 'Root Complex
     * Integrated Endpoint' and 'Root Complex Event Collector' don't have it. */
    virPCIELink *link_cap;   /* PCIe device link capabilities */
    virPCIELink *link_sta;   /* Actually negotiated capabilities */
};

virPCIDevice *virPCIDeviceNew(const virPCIDeviceAddress *address);
virPCIDevice *virPCIDeviceCopy(virPCIDevice *dev);
void virPCIDeviceFree(virPCIDevice *dev);
const char *virPCIDeviceGetName(virPCIDevice *dev);
const char *virPCIDeviceGetConfigPath(virPCIDevice *dev);

int virPCIDeviceDetach(virPCIDevice *dev,
                       virPCIDeviceList *activeDevs,
                       virPCIDeviceList *inactiveDevs);
int virPCIDeviceReattach(virPCIDevice *dev,
                         virPCIDeviceList *activeDevs,
                         virPCIDeviceList *inactiveDevs);
int virPCIDeviceReset(virPCIDevice *dev,
                      virPCIDeviceList *activeDevs,
                      virPCIDeviceList *inactiveDevs);

void virPCIDeviceSetManaged(virPCIDevice *dev,
                            bool managed);
bool virPCIDeviceGetManaged(virPCIDevice *dev);
void virPCIDeviceSetStubDriverType(virPCIDevice *dev,
                                   virPCIStubDriver driverType);
virPCIStubDriver virPCIDeviceGetStubDriverType(virPCIDevice *dev);
void virPCIDeviceSetStubDriverName(virPCIDevice *dev,
                                   const char *driverName);
const char *virPCIDeviceGetStubDriverName(virPCIDevice *dev);
virPCIDeviceAddress *virPCIDeviceGetAddress(virPCIDevice *dev);
int virPCIDeviceSetUsedBy(virPCIDevice *dev,
                          const char *drv_name,
                          const char *dom_name);
void virPCIDeviceGetUsedBy(virPCIDevice *dev,
                           const char **drv_name,
                           const char **dom_name);
bool virPCIDeviceGetUnbindFromStub(virPCIDevice *dev);
void  virPCIDeviceSetUnbindFromStub(virPCIDevice *dev,
                                    bool unbind);
bool virPCIDeviceGetRemoveSlot(virPCIDevice *dev);
void virPCIDeviceSetRemoveSlot(virPCIDevice *dev,
                               bool remove_slot);
bool virPCIDeviceGetReprobe(virPCIDevice *dev);
void virPCIDeviceSetReprobe(virPCIDevice *dev,
                            bool reprobe);


virPCIDeviceList *virPCIDeviceListNew(void);
int  virPCIDeviceListAdd(virPCIDeviceList *list,
                         virPCIDevice *dev);
int virPCIDeviceListAddCopy(virPCIDeviceList *list, virPCIDevice *dev);
virPCIDevice *virPCIDeviceListGet(virPCIDeviceList *list,
                                    int idx);
size_t virPCIDeviceListCount(virPCIDeviceList *list);
virPCIDevice *virPCIDeviceListSteal(virPCIDeviceList *list,
                                      virPCIDeviceAddress *devAddr);
virPCIDevice *virPCIDeviceListStealIndex(virPCIDeviceList *list,
                                           int idx);
void virPCIDeviceListDel(virPCIDeviceList *list,
                         virPCIDeviceAddress *devAddr);
virPCIDevice *virPCIDeviceListFind(virPCIDeviceList *list,
                                     virPCIDeviceAddress *devAddr);
virPCIDevice *
virPCIDeviceListFindByIDs(virPCIDeviceList *list,
                          unsigned int domain,
                          unsigned int bus,
                          unsigned int slot,
                          unsigned int function);
int virPCIDeviceListFindIndex(virPCIDeviceList *list,
                              virPCIDeviceAddress *devAddr);

/*
 * Callback that will be invoked once for each file
 * associated with / used for PCI host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virPCIDeviceFileActor)(virPCIDevice *dev,
                                     const char *path, void *opaque);
int virPCIDeviceFileIterate(virPCIDevice *dev,
                            virPCIDeviceFileActor actor,
                            void *opaque);

typedef int (*virPCIDeviceAddressActor)(virPCIDeviceAddress *addr,
                                        void *opaque);
int virPCIDeviceAddressIOMMUGroupIterate(virPCIDeviceAddress *orig,
                                         virPCIDeviceAddressActor actor,
                                         void *opaque);
virPCIDeviceList *virPCIDeviceGetIOMMUGroupList(virPCIDevice *dev);
int virPCIDeviceAddressGetIOMMUGroupAddresses(virPCIDeviceAddress *devAddr,
                                              virPCIDeviceAddress ***iommuGroupDevices,
                                              size_t *nIommuGroupDevices);
int virPCIDeviceAddressGetIOMMUGroupNum(virPCIDeviceAddress *addr);
char *virPCIDeviceAddressGetIOMMUGroupDev(const virPCIDeviceAddress *devAddr);
bool virPCIDeviceExists(const virPCIDeviceAddress *addr);
char *virPCIDeviceGetIOMMUGroupDev(virPCIDevice *dev);

int virPCIDeviceIsAssignable(virPCIDevice *dev,
                             int strict_acs_check);

virPCIDeviceAddress *
virPCIGetDeviceAddressFromSysfsLink(const char *device_link);

int virPCIGetPhysicalFunction(const char *vf_sysfs_path,
                              virPCIDeviceAddress **pf);

struct virPCIVirtualFunction {
    virPCIDeviceAddress *addr;
    char *ifname;
};

struct _virPCIVirtualFunctionList {
    struct virPCIVirtualFunction *functions;
    size_t nfunctions;
    size_t maxfunctions;
};
typedef struct _virPCIVirtualFunctionList virPCIVirtualFunctionList;

void virPCIVirtualFunctionListFree(virPCIVirtualFunctionList *list);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIVirtualFunctionList, virPCIVirtualFunctionListFree);

int virPCIGetVirtualFunctionsFull(const char *sysfs_path,
                                  virPCIVirtualFunctionList **vfs,
                                  const char *pfNetDevName);
int virPCIGetVirtualFunctions(const char *sysfs_path,
                              virPCIVirtualFunctionList **vfs);

int virPCIIsVirtualFunction(const char *vf_sysfs_device_link);

int virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link,
                                        const char *vf_sysfs_device_link,
                                        int *vf_index);

int virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddress *addr,
                                    char **pci_sysfs_device_link);

int virPCIGetNetName(const char *device_link_sysfs_path,
                     size_t idx,
                     const char *physPortNetDevName,
                     char **netname);

bool virPCIDeviceAddressIsValid(virPCIDeviceAddress *addr,
                                bool report);
bool virPCIDeviceAddressIsEmpty(const virPCIDeviceAddress *addr);

bool virPCIDeviceAddressEqual(const virPCIDeviceAddress *addr1,
                              const virPCIDeviceAddress *addr2);
void virPCIDeviceAddressCopy(virPCIDeviceAddress *dst,
                             const virPCIDeviceAddress *src);

char *virPCIDeviceAddressAsString(const virPCIDeviceAddress *addr)
      ATTRIBUTE_NONNULL(1);

int virPCIDeviceAddressParse(char *address, virPCIDeviceAddress *bdf);

bool virZPCIDeviceAddressIsIncomplete(const virZPCIDeviceAddress *addr);
bool virZPCIDeviceAddressIsPresent(const virZPCIDeviceAddress *addr);

int virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path,
                                 int pfNetDevIdx,
                                 char **pfname,
                                 int *vf_index);

bool virPCIDeviceHasVPD(virPCIDevice *dev);
virPCIVPDResource * virPCIDeviceGetVPD(virPCIDevice *dev);

int virPCIDeviceUnbind(virPCIDevice *dev);
int virPCIDeviceRebind(virPCIDevice *dev);
int virPCIDeviceGetCurrentDriverPathAndName(virPCIDevice *dev,
                                            char **path,
                                            char **name);
int virPCIDeviceGetCurrentDriverNameAndType(virPCIDevice *dev,
                                            char **drvName,
                                            virPCIStubDriver *drvType);

int virPCIDeviceIsPCIExpress(virPCIDevice *dev);
int virPCIDeviceHasPCIExpressLink(virPCIDevice *dev);
int virPCIDeviceGetLinkCapSta(virPCIDevice *dev,
                              int *ca_port,
                              unsigned int *cap_speed,
                              unsigned int *cap_width,
                              unsigned int *sta_speed,
                              unsigned int *sta_width);

int virPCIGetHeaderType(virPCIDevice *dev, int *hdrType);

void virPCIEDeviceInfoFree(virPCIEDeviceInfo *dev);

void virPCIDeviceAddressFree(virPCIDeviceAddress *address);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIDevice, virPCIDeviceFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIDeviceAddress, virPCIDeviceAddressFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIEDeviceInfo, virPCIEDeviceInfoFree);
