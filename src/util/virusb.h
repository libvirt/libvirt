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
 */

#pragma once

#include "internal.h"
#include "virobject.h"

#define USB_DEVFS "/dev/bus/usb/"

typedef struct _virUSBDevice virUSBDevice;
typedef struct _virUSBDeviceList virUSBDeviceList;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virUSBDeviceList, virObjectUnref);


virUSBDevice *virUSBDeviceNew(unsigned int bus,
                                unsigned int devno,
                                const char *vroot);

int virUSBDeviceFindByBus(unsigned int bus,
                          unsigned int devno,
                          const char *vroot,
                          bool mandatory,
                          virUSBDevice **usb);

int virUSBDeviceFindByVendor(unsigned int vendor,
                             unsigned int product,
                             const char *vroot,
                             bool mandatory,
                             virUSBDeviceList **devices);

int virUSBDeviceFind(unsigned int vendor,
                     unsigned int product,
                     unsigned int bus,
                     unsigned int devno,
                     const char *vroot,
                     bool mandatory,
                     virUSBDevice **usb);

void virUSBDeviceFree(virUSBDevice *dev);
int virUSBDeviceSetUsedBy(virUSBDevice *dev,
                          const char *drv_name,
                          const char *dom_name);
void virUSBDeviceGetUsedBy(virUSBDevice *dev,
                           const char **drv_name,
                           const char **dom_name);
const char *virUSBDeviceGetName(virUSBDevice *dev);
const char *virUSBDeviceGetPath(virUSBDevice *usb);

unsigned int virUSBDeviceGetBus(virUSBDevice *dev);
unsigned int virUSBDeviceGetDevno(virUSBDevice *dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for USB host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*virUSBDeviceFileActor)(virUSBDevice *dev,
                                     const char *path, void *opaque);

int virUSBDeviceFileIterate(virUSBDevice *dev,
                            virUSBDeviceFileActor actor,
                            void *opaque);

virUSBDeviceList *virUSBDeviceListNew(void);
int virUSBDeviceListAdd(virUSBDeviceList *list,
                        virUSBDevice **dev);
virUSBDevice *virUSBDeviceListGet(virUSBDeviceList *list,
                                    int idx);
size_t virUSBDeviceListCount(virUSBDeviceList *list);
virUSBDevice *virUSBDeviceListSteal(virUSBDeviceList *list,
                                      virUSBDevice *dev);
void virUSBDeviceListDel(virUSBDeviceList *list,
                         virUSBDevice *dev);
virUSBDevice *virUSBDeviceListFind(virUSBDeviceList *list,
                                     virUSBDevice *dev);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virUSBDevice, virUSBDeviceFree);
