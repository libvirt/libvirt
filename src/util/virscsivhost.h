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
 *
 * Authors:
 *     Eric Farman <farman@linux.vnet.ibm.com>
 */

#ifndef __VIR_SCSIHOST_H__
# define __VIR_SCSIHOST_H__

# include "internal.h"
# include "virobject.h"
# include "virutil.h"

typedef struct _virSCSIVHostDevice virSCSIVHostDevice;
typedef virSCSIVHostDevice *virSCSIVHostDevicePtr;
typedef struct _virSCSIVHostDeviceList virSCSIVHostDeviceList;
typedef virSCSIVHostDeviceList *virSCSIVHostDeviceListPtr;

typedef int (*virSCSIVHostDeviceFileActor)(virSCSIVHostDevicePtr dev,
                                           const char *name, void *opaque);

int virSCSIVHostDeviceFileIterate(virSCSIVHostDevicePtr dev,
                                  virSCSIVHostDeviceFileActor actor,
                                  void *opaque);
const char *virSCSIVHostDeviceGetName(virSCSIVHostDevicePtr dev);
const char *virSCSIVHostDeviceGetPath(virSCSIVHostDevicePtr dev);
virSCSIVHostDevicePtr virSCSIVHostDeviceListGet(virSCSIVHostDeviceListPtr list,
                                                int idx);
size_t virSCSIVHostDeviceListCount(virSCSIVHostDeviceListPtr list);
virSCSIVHostDevicePtr virSCSIVHostDeviceListSteal(virSCSIVHostDeviceListPtr list,
                                                  virSCSIVHostDevicePtr dev);
virSCSIVHostDevicePtr virSCSIVHostDeviceListFind(virSCSIVHostDeviceListPtr list,
                                                 virSCSIVHostDevicePtr dev);
int  virSCSIVHostDeviceListAdd(virSCSIVHostDeviceListPtr list,
                               virSCSIVHostDevicePtr dev);
void virSCSIVHostDeviceListDel(virSCSIVHostDeviceListPtr list,
                               virSCSIVHostDevicePtr dev);
virSCSIVHostDeviceListPtr virSCSIVHostDeviceListNew(void);
virSCSIVHostDevicePtr virSCSIVHostDeviceNew(const char *name);
int virSCSIVHostDeviceSetUsedBy(virSCSIVHostDevicePtr dev,
                                const char *drvname,
                                const char *domname);
void virSCSIVHostDeviceGetUsedBy(virSCSIVHostDevicePtr dev,
                                 const char **drv_name,
                                 const char **dom_name);
void virSCSIVHostDeviceFree(virSCSIVHostDevicePtr dev);
int virSCSIVHostOpenVhostSCSI(int *vhostfd) ATTRIBUTE_NOINLINE;

#endif /* __VIR_SCSIHOST_H__ */
