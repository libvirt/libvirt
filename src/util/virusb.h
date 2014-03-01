/*
 * virusb.h: helper APIs for managing host USB devices
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 *     Michal Privoznik <mprivozn@redhat.com>
 */

#ifndef __VIR_USB_H__
# define __VIR_USB_H__

# include "internal.h"
# include "virobject.h"

# define USB_DEVFS "/dev/bus/usb/"

typedef struct _virUSBDevice virUSBDevice;
typedef virUSBDevice *virUSBDevicePtr;
typedef struct _virUSBDeviceList virUSBDeviceList;
typedef virUSBDeviceList *virUSBDeviceListPtr;

virUSBDevicePtr virUSBDeviceNew(unsigned int bus,
                                unsigned int devno,
                                const char *vroot);

int virUSBDeviceFindByBus(unsigned int bus,
                          unsigned int devno,
                          const char *vroot,
                          bool mandatory,
                          virUSBDevicePtr *usb);

int virUSBDeviceFindByVendor(unsigned int vendor,
                             unsigned int product,
                             const char *vroot,
                             bool mandatory,
                             virUSBDeviceListPtr *devices);

int virUSBDeviceFind(unsigned int vendor,
                     unsigned int product,
                     unsigned int bus,
                     unsigned int devno,
                     const char *vroot,
                     bool mandatory,
                     virUSBDevicePtr *usb);

void virUSBDeviceFree(virUSBDevicePtr dev);
int virUSBDeviceSetUsedBy(virUSBDevicePtr dev,
                          const char *drv_name,
                          const char *dom_name);
void virUSBDeviceGetUsedBy(virUSBDevicePtr dev,
                           const char **drv_name,
                           const char **dom_name);
const char *virUSBDeviceGetName(virUSBDevicePtr dev);

unsigned int virUSBDeviceGetBus(virUSBDevicePtr dev);
unsigned int virUSBDeviceGetDevno(virUSBDevicePtr dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for USB host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virUSBDeviceFileActor)(virUSBDevicePtr dev,
                                     const char *path, void *opaque);

int virUSBDeviceFileIterate(virUSBDevicePtr dev,
                            virUSBDeviceFileActor actor,
                            void *opaque);

virUSBDeviceListPtr virUSBDeviceListNew(void);
int virUSBDeviceListAdd(virUSBDeviceListPtr list,
                        virUSBDevicePtr dev);
virUSBDevicePtr virUSBDeviceListGet(virUSBDeviceListPtr list,
                                    int idx);
size_t virUSBDeviceListCount(virUSBDeviceListPtr list);
virUSBDevicePtr virUSBDeviceListSteal(virUSBDeviceListPtr list,
                                      virUSBDevicePtr dev);
void virUSBDeviceListDel(virUSBDeviceListPtr list,
                         virUSBDevicePtr dev);
virUSBDevicePtr virUSBDeviceListFind(virUSBDeviceListPtr list,
                                     virUSBDevicePtr dev);

#endif /* __VIR_USB_H__ */
