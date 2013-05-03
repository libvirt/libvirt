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
 *
 * Authors:
 *     Han Cheng <hanc.fnst@cn.fujitsu.com>
 */

#ifndef __VIR_SCSI_H__
# define __VIR_SCSI_H__

# include "internal.h"
# include "virobject.h"

typedef struct _virSCSIDevice virSCSIDevice;
typedef virSCSIDevice *virSCSIDevicePtr;

typedef struct _virSCSIDeviceList virSCSIDeviceList;
typedef virSCSIDeviceList *virSCSIDeviceListPtr;

char *virSCSIDeviceGetSgName(const char *adapter,
                             unsigned int bus,
                             unsigned int target,
                             unsigned int unit);
char *virSCSIDeviceGetDevName(const char *adapter,
                              unsigned int bus,
                              unsigned int target,
                              unsigned int unit);

virSCSIDevicePtr virSCSIDeviceNew(const char *adapter,
                                  unsigned int bus,
                                  unsigned int target,
                                  unsigned int unit,
                                  bool readonly);

void virSCSIDeviceFree(virSCSIDevicePtr dev);
void virSCSIDeviceSetUsedBy(virSCSIDevicePtr dev, const char *name);
const char *virSCSIDeviceGetUsedBy(virSCSIDevicePtr dev);
const char *virSCSIDeviceGetName(virSCSIDevicePtr dev);
unsigned int virSCSIDeviceGetAdapter(virSCSIDevicePtr dev);
unsigned int virSCSIDeviceGetBus(virSCSIDevicePtr dev);
unsigned int virSCSIDeviceGetTarget(virSCSIDevicePtr dev);
unsigned int virSCSIDeviceGetUnit(virSCSIDevicePtr dev);
bool virSCSIDeviceGetReadonly(virSCSIDevicePtr dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for SCSI host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virSCSIDeviceFileActor)(virSCSIDevicePtr dev,
                                      const char *path, void *opaque);

int virSCSIDeviceFileIterate(virSCSIDevicePtr dev,
                             virSCSIDeviceFileActor actor,
                             void *opaque);

virSCSIDeviceListPtr virSCSIDeviceListNew(void);
int virSCSIDeviceListAdd(virSCSIDeviceListPtr list,
                         virSCSIDevicePtr dev);
virSCSIDevicePtr virSCSIDeviceListGet(virSCSIDeviceListPtr list,
                                      int idx);
int virSCSIDeviceListCount(virSCSIDeviceListPtr list);
virSCSIDevicePtr virSCSIDeviceListSteal(virSCSIDeviceListPtr list,
                                        virSCSIDevicePtr dev);
void virSCSIDeviceListDel(virSCSIDeviceListPtr list,
                          virSCSIDevicePtr dev);
virSCSIDevicePtr virSCSIDeviceListFind(virSCSIDeviceListPtr list,
                                       virSCSIDevicePtr dev);

#endif /* __VIR_SCSI_H__ */
