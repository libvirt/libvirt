/*
 * virscsi.h: helper APIs for managing host SCSI devices
 *
 * Copyright (C) 2013 Fujitsu, Inc.
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
#include "virobject.h"

typedef struct _virSCSIDevice virSCSIDevice;

typedef struct _virSCSIDeviceList virSCSIDeviceList;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSCSIDeviceList, virObjectUnref);


char *virSCSIDeviceGetSgName(const char *sysfs_prefix,
                             const char *adapter,
                             unsigned int bus,
                             unsigned int target,
                             unsigned long long unit) G_NO_INLINE;
char *virSCSIDeviceGetDevName(const char *sysfs_prefix,
                              const char *adapter,
                              unsigned int bus,
                              unsigned int target,
                              unsigned long long unit);

virSCSIDevice *virSCSIDeviceNew(const char *sysfs_prefix,
                                  const char *adapter,
                                  unsigned int bus,
                                  unsigned int target,
                                  unsigned long long unit,
                                  bool readonly,
                                  bool shareable);

void virSCSIDeviceFree(virSCSIDevice *dev);
int virSCSIDeviceSetUsedBy(virSCSIDevice *dev,
                           const char *drvname,
                           const char *domname);
bool virSCSIDeviceIsAvailable(virSCSIDevice *dev);
const char *virSCSIDeviceGetName(virSCSIDevice *dev);
const char *virSCSIDeviceGetPath(virSCSIDevice *dev);
unsigned int virSCSIDeviceGetAdapter(virSCSIDevice *dev);
unsigned int virSCSIDeviceGetBus(virSCSIDevice *dev);
unsigned int virSCSIDeviceGetTarget(virSCSIDevice *dev);
unsigned long long virSCSIDeviceGetUnit(virSCSIDevice *dev);
bool virSCSIDeviceGetReadonly(virSCSIDevice *dev);
bool virSCSIDeviceGetShareable(virSCSIDevice *dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for SCSI host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virSCSIDeviceFileActor)(virSCSIDevice *dev,
                                      const char *path, void *opaque);

int virSCSIDeviceFileIterate(virSCSIDevice *dev,
                             virSCSIDeviceFileActor actor,
                             void *opaque);

virSCSIDeviceList *virSCSIDeviceListNew(void);
int virSCSIDeviceListAdd(virSCSIDeviceList *list,
                         virSCSIDevice *dev);
virSCSIDevice *virSCSIDeviceListGet(virSCSIDeviceList *list,
                                      int idx);
size_t virSCSIDeviceListCount(virSCSIDeviceList *list);
virSCSIDevice *virSCSIDeviceListSteal(virSCSIDeviceList *list,
                                        virSCSIDevice *dev);
void virSCSIDeviceListDel(virSCSIDeviceList *list,
                          virSCSIDevice *dev,
                          const char *drvname,
                          const char *domname);
virSCSIDevice *virSCSIDeviceListFind(virSCSIDeviceList *list,
                                       virSCSIDevice *dev);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSCSIDevice, virSCSIDeviceFree);
