/*
 * virscsivhost.c: helper APIs for managing scsi_host devices
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

#include <config.h>
#include <fcntl.h>

#include "virscsivhost.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.scsihost");

#define SYSFS_VHOST_SCSI_DEVICES "/sys/kernel/config/target/vhost/"
#define VHOST_SCSI_DEVICE "/dev/vhost-scsi"

struct _virSCSIVHostDevice {
    char *name; /* naa.<wwn> */
    char *path;
    char *used_by_drvname;
    char *used_by_domname;
};

struct _virSCSIVHostDeviceList {
    virObjectLockable parent;
    size_t count;
    virSCSIVHostDevice **devs;
};

static virClass *virSCSIVHostDeviceListClass;

static void
virSCSIVHostDeviceListDispose(void *obj)
{
    virSCSIVHostDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++)
        virSCSIVHostDeviceFree(list->devs[i]);

    g_free(list->devs);
}


static int
virSCSIVHostOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSCSIVHostDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virSCSIVHost);


int
virSCSIVHostOpenVhostSCSI(int *vhostfd)
{
    if (!virFileExists(VHOST_SCSI_DEVICE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("vhost-scsi device file '%1$s' cannot be found"),
                       VHOST_SCSI_DEVICE);
        return -1;
    }

    *vhostfd = open(VHOST_SCSI_DEVICE, O_RDWR);

    if (*vhostfd < 0) {
        virReportSystemError(errno, _("Failed to open %1$s"), VHOST_SCSI_DEVICE);
        return -1;
    }

    return 0;
}


void
virSCSIVHostDeviceListDel(virSCSIVHostDeviceList *list,
                          virSCSIVHostDevice *dev)
{
    virSCSIVHostDeviceFree(virSCSIVHostDeviceListSteal(list, dev));
}


static int
virSCSIVHostDeviceListFindIndex(virSCSIVHostDeviceList *list,
                                virSCSIVHostDevice *dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virSCSIVHostDevice *other = list->devs[i];
        if (STREQ_NULLABLE(other->name, dev->name))
            return i;
    }
    return -1;
}


virSCSIVHostDevice *
virSCSIVHostDeviceListGet(virSCSIVHostDeviceList *list, int idx)
{
    if (idx >= list->count || idx < 0)
        return NULL;

    return list->devs[idx];
}


size_t
virSCSIVHostDeviceListCount(virSCSIVHostDeviceList *list)
{
    return list->count;
}


virSCSIVHostDevice *
virSCSIVHostDeviceListSteal(virSCSIVHostDeviceList *list,
                            virSCSIVHostDevice *dev)
{
    virSCSIVHostDevice *ret = NULL;
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (STREQ_NULLABLE(list->devs[i]->name, dev->name)) {
            ret = list->devs[i];
            VIR_DELETE_ELEMENT(list->devs, i, list->count);
            break;
        }
    }

    return ret;
}


virSCSIVHostDevice *
virSCSIVHostDeviceListFind(virSCSIVHostDeviceList *list,
                           virSCSIVHostDevice *dev)
{
    int idx;

    if ((idx = virSCSIVHostDeviceListFindIndex(list, dev)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


int
virSCSIVHostDeviceListAdd(virSCSIVHostDeviceList *list,
                          virSCSIVHostDevice *dev)
{
    if (virSCSIVHostDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %1$s is already in use"), dev->name);
        return -1;
    }
    VIR_APPEND_ELEMENT(list->devs, list->count, dev);

    return 0;
}


virSCSIVHostDeviceList *
virSCSIVHostDeviceListNew(void)
{
    if (virSCSIVHostInitialize() < 0)
        return NULL;

    return virObjectLockableNew(virSCSIVHostDeviceListClass);
}


int
virSCSIVHostDeviceSetUsedBy(virSCSIVHostDevice *dev,
                            const char *drvname,
                            const char *domname)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    dev->used_by_drvname = g_strdup(drvname);
    dev->used_by_domname = g_strdup(domname);

    return 0;
}


void
virSCSIVHostDeviceGetUsedBy(virSCSIVHostDevice *dev,
                            const char **drv_name,
                            const char **dom_name)
{
    *drv_name = dev->used_by_drvname;
    *dom_name = dev->used_by_domname;
 }


int
virSCSIVHostDeviceFileIterate(virSCSIVHostDevice *dev,
                              virSCSIVHostDeviceFileActor actor,
                              void *opaque)
{
    return (actor)(dev, dev->path, opaque);
}


const char *
virSCSIVHostDeviceGetName(virSCSIVHostDevice *dev)
{
    return dev->name;
}


const char *
virSCSIVHostDeviceGetPath(virSCSIVHostDevice *dev)
{
    return dev->path;
}


virSCSIVHostDevice *
virSCSIVHostDeviceNew(const char *name)
{
    g_autoptr(virSCSIVHostDevice) dev = NULL;

    dev = g_new0(virSCSIVHostDevice, 1);

    dev->name = g_strdup(name);

    dev->path = g_strdup_printf("%s/%s", SYSFS_VHOST_SCSI_DEVICES, name);

    VIR_DEBUG("%s: initialized", dev->name);

    return g_steal_pointer(&dev);
}


void
virSCSIVHostDeviceFree(virSCSIVHostDevice *dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s: freeing", dev->name);
    g_free(dev->name);
    g_free(dev->path);
    g_free(dev->used_by_drvname);
    g_free(dev->used_by_domname);
    g_free(dev);
}
