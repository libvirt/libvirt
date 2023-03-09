/*
 * virusb.c: helper APIs for managing host USB devices
 *
 * Copyright (C) 2009-2014 Red Hat, Inc.
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

#include <config.h>

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virusb.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "viralloc.h"

#define USB_SYSFS "/sys/bus/usb"
#define USB_ID_LEN 10 /* "1234 5678" */
#define USB_ADDR_LEN 8 /* "123:456" */

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.usb");

struct _virUSBDevice {
    unsigned int      bus;
    unsigned int      dev;

    char          name[USB_ADDR_LEN]; /* domain:bus:slot.function */
    char          id[USB_ID_LEN];     /* product vendor */
    char          *path;

    /* driver:domain using this dev */
    char          *used_by_drvname;
    char          *used_by_domname;
};

struct _virUSBDeviceList {
    virObjectLockable parent;
    size_t count;
    virUSBDevice **devs;
};

typedef enum {
    USB_DEVICE_ALL = 0,
    USB_DEVICE_FIND_BY_VENDOR = 1 << 0,
    USB_DEVICE_FIND_BY_BUS = 1 << 1,
} virUSBDeviceFindFlags;

static virClass *virUSBDeviceListClass;

static void virUSBDeviceListDispose(void *obj);

static int virUSBOnceInit(void)
{
    if (!VIR_CLASS_NEW(virUSBDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virUSB);

static int virUSBSysReadFile(const char *f_name, const char *d_name,
                             int base, unsigned int *value)
{
    g_autofree char *buf = NULL;
    g_autofree char *filename = NULL;
    char *ignore = NULL;

    filename = g_strdup_printf(USB_SYSFS "/devices/%s/%s", d_name, f_name);

    if (virFileReadAll(filename, 1024, &buf) < 0)
        return -1;

    if (virStrToLong_ui(buf, &ignore, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse usb file %1$s"), filename);
        return -1;
    }

    return 0;
}

static virUSBDeviceList *
virUSBDeviceSearch(unsigned int vendor,
                   unsigned int product,
                   unsigned int bus,
                   unsigned int devno,
                   const char *vroot,
                   unsigned int flags)
{
    g_autoptr(DIR) dir = NULL;
    bool found = false;
    char *ignore = NULL;
    struct dirent *de;
    virUSBDeviceList *list = NULL;
    virUSBDeviceList *ret = NULL;
    g_autoptr(virUSBDevice) usb = NULL;
    int direrr;

    if (!(list = virUSBDeviceListNew()))
        goto cleanup;

    if (virDirOpen(&dir, USB_SYSFS "/devices") < 0)
        goto cleanup;

    while ((direrr = virDirRead(dir, &de, USB_SYSFS "/devices")) > 0) {
        unsigned int found_prod, found_vend, found_bus, found_devno;
        char *tmpstr = de->d_name;

        if (strchr(de->d_name, ':'))
            continue;

        if (virUSBSysReadFile("idVendor", de->d_name,
                              16, &found_vend) < 0)
            goto cleanup;

        if (virUSBSysReadFile("idProduct", de->d_name,
                              16, &found_prod) < 0)
            goto cleanup;

        if (STRPREFIX(de->d_name, "usb"))
            tmpstr += 3;

        if (virStrToLong_ui(tmpstr, &ignore, 10, &found_bus) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to parse dir name '%1$s'"),
                           de->d_name);
            goto cleanup;
        }

        if (virUSBSysReadFile("devnum", de->d_name,
                              10, &found_devno) < 0)
            goto cleanup;

        if ((flags & USB_DEVICE_FIND_BY_VENDOR) &&
            (found_prod != product || found_vend != vendor))
            continue;

        if (flags & USB_DEVICE_FIND_BY_BUS) {
            if (found_bus != bus || found_devno != devno)
                continue;
            found = true;
        }

        usb = virUSBDeviceNew(found_bus, found_devno, vroot);

        if (!usb)
            goto cleanup;

        if (virUSBDeviceListAdd(list, &usb) < 0)
            goto cleanup;

        if (found)
            break;
    }
    if (direrr < 0)
        goto cleanup;
    ret = list;

 cleanup:
    if (!ret)
        virObjectUnref(list);
    return ret;
}

int
virUSBDeviceFindByVendor(unsigned int vendor,
                         unsigned int product,
                         const char *vroot,
                         bool mandatory,
                         virUSBDeviceList **devices)
{
    virUSBDeviceList *list;
    int count;

    if (!(list = virUSBDeviceSearch(vendor, product, 0, 0,
                                    vroot,
                                    USB_DEVICE_FIND_BY_VENDOR)))
        return -1;

    if (list->count == 0) {
        virObjectUnref(list);
        if (!mandatory) {
            VIR_DEBUG("Did not find USB device %04x:%04x",
                      vendor, product);
            if (devices)
                *devices = NULL;
            return 0;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Did not find USB device %1$04x:%2$04x"), vendor, product);
        return -1;
    }

    count = list->count;
    if (devices)
        *devices = list;
    else
        virObjectUnref(list);

    return count;
}

int
virUSBDeviceFindByBus(unsigned int bus,
                      unsigned int devno,
                      const char *vroot,
                      bool mandatory,
                      virUSBDevice **usb)
{
    virUSBDeviceList *list;

    if (!(list = virUSBDeviceSearch(0, 0, bus, devno,
                                    vroot,
                                    USB_DEVICE_FIND_BY_BUS)))
        return -1;

    if (list->count == 0) {
        virObjectUnref(list);
        if (!mandatory) {
            VIR_DEBUG("Did not find USB device bus:%u device:%u",
                      bus, devno);
            if (usb)
                *usb = NULL;
            return 0;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Did not find USB device bus:%1$u device:%2$u"),
                       bus, devno);
        return -1;
    }

    if (usb) {
        *usb = virUSBDeviceListGet(list, 0);
        virUSBDeviceListSteal(list, *usb);
    }
    virObjectUnref(list);

    return 0;
}

int
virUSBDeviceFind(unsigned int vendor,
                 unsigned int product,
                 unsigned int bus,
                 unsigned int devno,
                 const char *vroot,
                 bool mandatory,
                 virUSBDevice **usb)
{
    virUSBDeviceList *list;

    unsigned int flags = USB_DEVICE_FIND_BY_VENDOR|USB_DEVICE_FIND_BY_BUS;
    if (!(list = virUSBDeviceSearch(vendor, product, bus, devno,
                                    vroot, flags)))
        return -1;

    if (list->count == 0) {
        virObjectUnref(list);
        if (!mandatory) {
            VIR_DEBUG("Did not find USB device %04x:%04x bus:%u device:%u",
                      vendor, product, bus, devno);
            if (usb)
                *usb = NULL;
            return 0;
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Did not find USB device %1$04x:%2$04x bus:%3$u device:%4$u"),
                       vendor, product, bus, devno);
        return -1;
    }

    if (usb) {
        *usb = virUSBDeviceListGet(list, 0);
        virUSBDeviceListSteal(list, *usb);
    }
    virObjectUnref(list);

    return 0;
}

virUSBDevice *
virUSBDeviceNew(unsigned int bus,
                unsigned int devno,
                const char *vroot)
{
    virUSBDevice *dev;

    dev = g_new0(virUSBDevice, 1);

    dev->bus     = bus;
    dev->dev     = devno;

    if (g_snprintf(dev->name, sizeof(dev->name), "%.3d:%.3d",
                   dev->bus, dev->dev) >= sizeof(dev->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->name buffer overflow: %1$.3d:%2$.3d"),
                       dev->bus, dev->dev);
        virUSBDeviceFree(dev);
        return NULL;
    }

    if (vroot) {
        dev->path = g_strdup_printf("%s/%03d/%03d",
                                    vroot, dev->bus, dev->dev);
    } else {
        dev->path = g_strdup_printf(USB_DEVFS "%03d/%03d",
                                    dev->bus, dev->dev);
    }

    /* XXX fixme. this should be product/vendor */
    if (g_snprintf(dev->id, sizeof(dev->id), "%d %d", dev->bus,
                   dev->dev) >= sizeof(dev->id)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->id buffer overflow: %1$d %2$d"),
                       dev->bus, dev->dev);
        virUSBDeviceFree(dev);
        return NULL;
    }

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

    return dev;
}

void
virUSBDeviceFree(virUSBDevice *dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    g_free(dev->path);
    g_free(dev->used_by_drvname);
    g_free(dev->used_by_domname);
    g_free(dev);
}

int
virUSBDeviceSetUsedBy(virUSBDevice *dev,
                      const char *drv_name,
                      const char *dom_name)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    dev->used_by_drvname = g_strdup(drv_name);
    dev->used_by_domname = g_strdup(dom_name);

    return 0;
}

void
virUSBDeviceGetUsedBy(virUSBDevice *dev,
                      const char **drv_name,
                      const char **dom_name)
{
    *drv_name = dev->used_by_drvname;
    *dom_name = dev->used_by_domname;
}

const char *virUSBDeviceGetName(virUSBDevice *dev)
{
    return dev->name;
}

const char *virUSBDeviceGetPath(virUSBDevice *dev)
{
    return dev->path;
}

unsigned int virUSBDeviceGetBus(virUSBDevice *dev)
{
    return dev->bus;
}


unsigned int virUSBDeviceGetDevno(virUSBDevice *dev)
{
    return dev->dev;
}


int virUSBDeviceFileIterate(virUSBDevice *dev,
                            virUSBDeviceFileActor actor,
                            void *opaque)
{
    return (actor)(dev, dev->path, opaque);
}

virUSBDeviceList *
virUSBDeviceListNew(void)
{
    virUSBDeviceList *list;

    if (virUSBInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virUSBDeviceListClass)))
        return NULL;

    return list;
}

static void
virUSBDeviceListDispose(void *obj)
{
    virUSBDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++)
        virUSBDeviceFree(list->devs[i]);

    g_free(list->devs);
}

int
virUSBDeviceListAdd(virUSBDeviceList *list,
                    virUSBDevice **dev)
{
    if (virUSBDeviceListFind(list, *dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %1$s is already in use"),
                       (*dev)->name);
        return -1;
    }
    VIR_APPEND_ELEMENT(list->devs, list->count, *dev);

    return 0;
}

virUSBDevice *
virUSBDeviceListGet(virUSBDeviceList *list,
                    int idx)
{
    if (idx >= list->count ||
        idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virUSBDeviceListCount(virUSBDeviceList *list)
{
    return list->count;
}

virUSBDevice *
virUSBDeviceListSteal(virUSBDeviceList *list,
                      virUSBDevice *dev)
{
    virUSBDevice *ret = NULL;
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (list->devs[i]->bus == dev->bus &&
            list->devs[i]->dev == dev->dev) {
            ret = list->devs[i];
            VIR_DELETE_ELEMENT(list->devs, i, list->count);
            break;
        }
    }
    return ret;
}

void
virUSBDeviceListDel(virUSBDeviceList *list,
                    virUSBDevice *dev)
{
    virUSBDeviceFree(virUSBDeviceListSteal(list, dev));
}

virUSBDevice *
virUSBDeviceListFind(virUSBDeviceList *list,
                     virUSBDevice *dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (list->devs[i]->bus == dev->bus &&
            list->devs[i]->dev == dev->dev)
            return list->devs[i];
    }

    return NULL;
}
