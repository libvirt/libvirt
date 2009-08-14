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

#include <config.h>

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hostusb.h"
#include "logging.h"
#include "memory.h"
#include "util.h"
#include "virterror_internal.h"

#define USB_DEVFS "/dev/bus/usb/"
#define USB_ID_LEN 10 /* "XXXX XXXX" */
#define USB_ADDR_LEN 8 /* "XXX:XXX" */

struct _usbDevice {
    unsigned      bus;
    unsigned      dev;

    char          name[USB_ADDR_LEN]; /* domain:bus:slot.function */
    char          id[USB_ID_LEN];     /* product vendor */
    char          path[PATH_MAX];
};

/* For virReportOOMError()  and virReportSystemError() */
#define VIR_FROM_THIS VIR_FROM_NONE

#define usbReportError(conn, code, fmt...)                     \
    virReportErrorHelper(conn, VIR_FROM_NONE, code, __FILE__,  \
                         __FUNCTION__, __LINE__, fmt)


usbDevice *
usbGetDevice(virConnectPtr conn,
             unsigned bus,
             unsigned devno)
{
    usbDevice *dev;

    if (VIR_ALLOC(dev) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    dev->bus     = bus;
    dev->dev     = devno;

    snprintf(dev->name, sizeof(dev->name), "%.3o:%.3o",
             dev->bus, dev->dev);
    snprintf(dev->path, sizeof(dev->path),
             USB_DEVFS "%03o/%03o", dev->bus, dev->dev);

    /* XXX fixme. this should be product/vendor */
    snprintf(dev->id, sizeof(dev->id), "%d %d", dev->bus, dev->dev);

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

    return dev;
}

void
usbFreeDevice(virConnectPtr conn ATTRIBUTE_UNUSED, usbDevice *dev)
{
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    VIR_FREE(dev);
}


int usbDeviceFileIterate(virConnectPtr conn,
                         usbDevice *dev,
                         usbDeviceFileActor actor,
                         void *opaque)
{
    return (actor)(conn, dev, dev->path, opaque);
}
