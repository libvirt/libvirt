/*
 * virscsivhost.h: helper APIs for managing host scsi_host devices
 *
 * Copyright (C) 2016 IBM Corporation
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

typedef struct _virSCSIVHostDevice virSCSIVHostDevice;
typedef struct _virSCSIVHostDeviceList virSCSIVHostDeviceList;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSCSIVHostDeviceList, virObjectUnref);


typedef int (*virSCSIVHostDeviceFileActor)(virSCSIVHostDevice *dev,
                                           const char *name, void *opaque);

int virSCSIVHostDeviceFileIterate(virSCSIVHostDevice *dev,
                                  virSCSIVHostDeviceFileActor actor,
                                  void *opaque);
const char *virSCSIVHostDeviceGetName(virSCSIVHostDevice *dev);
const char *virSCSIVHostDeviceGetPath(virSCSIVHostDevice *dev);
virSCSIVHostDevice *virSCSIVHostDeviceListGet(virSCSIVHostDeviceList *list,
                                                int idx);
size_t virSCSIVHostDeviceListCount(virSCSIVHostDeviceList *list);
virSCSIVHostDevice *virSCSIVHostDeviceListSteal(virSCSIVHostDeviceList *list,
                                                  virSCSIVHostDevice *dev);
virSCSIVHostDevice *virSCSIVHostDeviceListFind(virSCSIVHostDeviceList *list,
                                                 virSCSIVHostDevice *dev);
int  virSCSIVHostDeviceListAdd(virSCSIVHostDeviceList *list,
                               virSCSIVHostDevice *dev);
void virSCSIVHostDeviceListDel(virSCSIVHostDeviceList *list,
                               virSCSIVHostDevice *dev);
virSCSIVHostDeviceList *virSCSIVHostDeviceListNew(void);
virSCSIVHostDevice *virSCSIVHostDeviceNew(const char *name);
int virSCSIVHostDeviceSetUsedBy(virSCSIVHostDevice *dev,
                                const char *drvname,
                                const char *domname);
void virSCSIVHostDeviceGetUsedBy(virSCSIVHostDevice *dev,
                                 const char **drv_name,
                                 const char **dom_name);
void virSCSIVHostDeviceFree(virSCSIVHostDevice *dev);
int virSCSIVHostOpenVhostSCSI(int *vhostfd) G_NO_INLINE;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSCSIVHostDevice, virSCSIVHostDeviceFree);
