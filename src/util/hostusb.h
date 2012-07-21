/*
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 *     Michal Privoznik <mprivozn@redhat.com>
 */

#ifndef __VIR_USB_H__
# define __VIR_USB_H__

# include "internal.h"

typedef struct _usbDevice usbDevice;
typedef struct _usbDeviceList usbDeviceList;

usbDevice *usbGetDevice(unsigned int bus,
                        unsigned int devno);

usbDevice *usbFindDeviceByBus(unsigned int bus,
                              unsigned int devno);

usbDeviceList *usbFindDeviceByVendor(unsigned int vendor,
                                     unsigned int product);

usbDevice *usbFindDevice(unsigned int vendor,
                         unsigned int product,
                         unsigned int bus,
                         unsigned int devno);

void       usbFreeDevice (usbDevice *dev);
void       usbDeviceSetUsedBy(usbDevice *dev, const char *name);
const char *usbDeviceGetUsedBy(usbDevice *dev);
const char *usbDeviceGetName(usbDevice *dev);

unsigned int usbDeviceGetBus(usbDevice *dev);
unsigned int usbDeviceGetDevno(usbDevice *dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for USB host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*usbDeviceFileActor)(usbDevice *dev,
                                  const char *path, void *opaque);

int usbDeviceFileIterate(usbDevice *dev,
                         usbDeviceFileActor actor,
                         void *opaque);

usbDeviceList *usbDeviceListNew(void);
void           usbDeviceListFree(usbDeviceList *list);
int            usbDeviceListAdd(usbDeviceList *list,
                                usbDevice *dev);
usbDevice *    usbDeviceListGet(usbDeviceList *list,
                                int idx);
int            usbDeviceListCount(usbDeviceList *list);
usbDevice *    usbDeviceListSteal(usbDeviceList *list,
                                  usbDevice *dev);
void           usbDeviceListDel(usbDeviceList *list,
                                usbDevice *dev);
usbDevice *    usbDeviceListFind(usbDeviceList *list,
                                 usbDevice *dev);

#endif /* __VIR_USB_H__ */
