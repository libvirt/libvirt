/*
 * virnvme.h: helper APIs for managing NVMe devices
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

#include "virpci.h"

typedef struct _virNVMeDevice virNVMeDevice;
typedef virNVMeDevice *virNVMeDevicePtr;

/* Note that this list is lockable, and in fact, it is caller's
 * responsibility to acquire the lock and release it. The reason
 * is that in a lot of cases the list must be locked between two
 * API calls and therefore only caller knows when it is safe to
 * finally release the lock. */
typedef struct _virNVMeDeviceList virNVMeDeviceList;
typedef virNVMeDeviceList *virNVMeDeviceListPtr;

virNVMeDevicePtr
virNVMeDeviceNew(const virPCIDeviceAddress *address,
                 unsigned long namespace,
                 bool managed);

void
virNVMeDeviceFree(virNVMeDevicePtr dev);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNVMeDevice, virNVMeDeviceFree);

virNVMeDevicePtr
virNVMeDeviceCopy(const virNVMeDevice *dev);

const virPCIDeviceAddress *
virNVMeDeviceAddressGet(const virNVMeDevice *dev);

void
virNVMeDeviceUsedByClear(virNVMeDevicePtr dev);

void
virNVMeDeviceUsedByGet(const virNVMeDevice *dev,
                       const char **drv,
                       const char **dom);

void
virNVMeDeviceUsedBySet(virNVMeDevicePtr dev,
                       const char *drv,
                       const char *dom);

virNVMeDeviceListPtr
virNVMeDeviceListNew(void);

size_t
virNVMeDeviceListCount(const virNVMeDeviceList *list);

int
virNVMeDeviceListAdd(virNVMeDeviceListPtr list,
                     const virNVMeDevice *dev);

int
virNVMeDeviceListDel(virNVMeDeviceListPtr list,
                     const virNVMeDevice *dev);

virNVMeDevicePtr
virNVMeDeviceListGet(virNVMeDeviceListPtr list,
                     size_t i);

virNVMeDevicePtr
virNVMeDeviceListLookup(virNVMeDeviceListPtr list,
                        const virNVMeDevice *dev);

ssize_t
virNVMeDeviceListLookupIndex(virNVMeDeviceListPtr list,
                             const virNVMeDevice *dev);

virPCIDeviceListPtr
virNVMeDeviceListCreateDetachList(virNVMeDeviceListPtr activeList,
                                  virNVMeDeviceListPtr toDetachList);

virPCIDeviceListPtr
virNVMeDeviceListCreateReAttachList(virNVMeDeviceListPtr activeList,
                                    virNVMeDeviceListPtr toReAttachList);
