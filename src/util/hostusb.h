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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_USB_H__
#define __VIR_USB_H__

#include "internal.h"

typedef struct _usbDevice usbDevice;

usbDevice *usbGetDevice      (virConnectPtr  conn,
                              unsigned       bus,
                              unsigned       devno,
                              unsigned       vendor,
                              unsigned       product);
void       usbFreeDevice     (virConnectPtr  conn,
                              usbDevice     *dev);

/*
 * Callback that will be invoked once for each file
 * associated with / used for USB host device access.
 *
 * Should return 0 if successfully processed, or
 * -1 to indicate error and abort iteration
 */
typedef int (*usbDeviceFileActor)(virConnectPtr conn, usbDevice *dev,
                                  const char *path, void *opaque);

int usbDeviceFileIterate(virConnectPtr conn,
                         usbDevice *dev,
                         usbDeviceFileActor actor,
                         void *opaque);


#endif /* __VIR_USB_H__ */
