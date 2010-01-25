/*
 * Copyright (C) 2009-2010 Red Hat, Inc.
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

#define USB_SYSFS "/sys/bus/usb"
#define USB_DEVFS "/dev/bus/usb/"
#define USB_ID_LEN 10 /* "1234 5678" */
#define USB_ADDR_LEN 8 /* "123:456" */

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

static int usbSysReadFile(virConnectPtr conn,
                          const char *f_name, const char *d_name,
                          int base, unsigned *value)
{
    int ret = -1, tmp;
    char *buf = NULL;
    char *filename = NULL;
    char *ignore = NULL;

    tmp = virAsprintf(&filename, USB_SYSFS "/devices/%s/%s", d_name, f_name);
    if (tmp < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (virFileReadAll(filename, 1024, &buf) < 0)
        goto cleanup;

    if (virStrToLong_ui(buf, &ignore, base, value) < 0) {
        usbReportError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse usb file %s"), filename);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(filename);
    VIR_FREE(buf);
    return ret;
}

static int usbFindBusByVendor(virConnectPtr conn,
                              unsigned vendor, unsigned product,
                              unsigned *bus, unsigned *devno)
{
    DIR *dir = NULL;
    int ret = -1, found = 0;
    char *ignore = NULL;
    struct dirent *de;

    dir = opendir(USB_SYSFS "/devices");
    if (!dir) {
        virReportSystemError(conn, errno,
                             _("Could not open directory %s"),
                             USB_SYSFS "/devices");
        goto cleanup;
    }

    while ((de = readdir(dir))) {
        unsigned found_prod, found_vend;
        if (de->d_name[0] == '.' || strchr(de->d_name, ':'))
            continue;

        if (usbSysReadFile(conn, "idVendor", de->d_name,
                           16, &found_vend) < 0)
            goto cleanup;
        if (usbSysReadFile(conn, "idProduct", de->d_name,
                           16, &found_prod) < 0)
            goto cleanup;

        if (found_prod == product && found_vend == vendor) {
            /* Lookup bus.addr info */
            char *tmpstr = de->d_name;
            unsigned found_bus, found_addr;

            if (STREQ(de->d_name, "usb"))
                tmpstr += 3;

            if (virStrToLong_ui(tmpstr, &ignore, 10, &found_bus) < 0) {
                usbReportError(conn, VIR_ERR_INTERNAL_ERROR,
                               _("Failed to parse dir name '%s'"),
                               de->d_name);
                goto cleanup;
            }

            if (usbSysReadFile(conn, "devnum", de->d_name,
                               10, &found_addr) < 0)
                goto cleanup;

            *bus = found_bus;
            *devno = found_addr;
            found = 1;
            break;
        }
    }

    if (!found)
        usbReportError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("Did not find USB device %x:%x"), vendor, product);
    else
        ret = 0;

cleanup:
    if (dir) {
        int saved_errno = errno;
        closedir (dir);
        errno = saved_errno;
    }
    return ret;
}

usbDevice *
usbGetDevice(virConnectPtr conn,
             unsigned bus,
             unsigned devno,
             unsigned vendor,
             unsigned product)
{
    usbDevice *dev;

    if (VIR_ALLOC(dev) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (vendor) {
        /* Look up bus.dev by vendor:product */
        if (usbFindBusByVendor(conn, vendor, product, &bus, &devno) < 0) {
            VIR_FREE(dev);
            return NULL;
        }
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
