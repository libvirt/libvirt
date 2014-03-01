/*
 * virpci.h: helper APIs for managing host PCI devices
 *
 * Copyright (C) 2009, 2011-2013 Red Hat, Inc.
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
};

virPCIDevicePtr virPCIDeviceNew(unsigned int domain,
                                unsigned int bus,
                                unsigned int slot,
                                unsigned int function);
virPCIDevicePtr virPCIDeviceCopy(virPCIDevicePtr dev);
void virPCIDeviceFree(virPCIDevicePtr dev);
const char *virPCIDeviceGetName(virPCIDevicePtr dev);

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
unsigned int virPCIDeviceGetManaged(virPCIDevice *dev);
int virPCIDeviceSetStubDriver(virPCIDevicePtr dev,
                              const char *driver)
    ATTRIBUTE_NONNULL(2);
const char *virPCIDeviceGetStubDriver(virPCIDevicePtr dev);
int virPCIDeviceSetUsedBy(virPCIDevice *dev,
                          const char *drv_name,
                          const char *dom_name);
void virPCIDeviceGetUsedBy(virPCIDevice *dev,
                           const char **drv_name,
                           const char **dom_name);
unsigned int virPCIDeviceGetUnbindFromStub(virPCIDevicePtr dev);
void  virPCIDeviceSetUnbindFromStub(virPCIDevice *dev,
                                    bool unbind);
unsigned int virPCIDeviceGetRemoveSlot(virPCIDevicePtr dev);
void virPCIDeviceSetRemoveSlot(virPCIDevice *dev,
                               bool remove_slot);
unsigned int virPCIDeviceGetReprobe(virPCIDevicePtr dev);
void virPCIDeviceSetReprobe(virPCIDevice *dev,
                            bool reprobe);
void virPCIDeviceReattachInit(virPCIDevice *dev);


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

typedef int (*virPCIDeviceAddressActor)(virPCIDeviceAddress *addr,
                                        void *opaque);
int virPCIDeviceAddressIOMMUGroupIterate(virPCIDeviceAddressPtr orig,
                                         virPCIDeviceAddressActor actor,
                                         void *opaque);
virPCIDeviceListPtr virPCIDeviceGetIOMMUGroupList(virPCIDevicePtr dev);
int virPCIDeviceAddressGetIOMMUGroupAddresses(virPCIDeviceAddressPtr devAddr,
                                              virPCIDeviceAddressPtr **iommuGroupDevices,
                                              size_t *nIommuGroupDevices);
int virPCIDeviceAddressGetIOMMUGroupNum(virPCIDeviceAddressPtr dev);
char *virPCIDeviceGetIOMMUGroupDev(virPCIDevicePtr dev);

int virPCIDeviceIsAssignable(virPCIDevicePtr dev,
                             int strict_acs_check);
int virPCIDeviceWaitForCleanup(virPCIDevicePtr dev, const char *matcher);

int virPCIGetPhysicalFunction(const char *sysfs_path,
                              virPCIDeviceAddressPtr *phys_fn);

int virPCIGetVirtualFunctions(const char *sysfs_path,
                              virPCIDeviceAddressPtr **virtual_functions,
                              size_t *num_virtual_functions);

int virPCIIsVirtualFunction(const char *vf_sysfs_device_link);

int virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link,
                                        const char *vf_sysfs_device_link,
                                        int *vf_index);

int virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr dev,
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

int virPCIDeviceUnbind(virPCIDevicePtr dev, bool reprobe);
int virPCIDeviceGetDriverPathAndName(virPCIDevicePtr dev,
                                     char **path,
                                     char **name);

#endif /* __VIR_PCI_H__ */
