/*
 * virscsi.c: helper APIs for managing host SCSI devices
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
 * Copyright (C) 2013 Fujitsu, Inc.
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

#include "virlog.h"
#include "virscsi.h"
#include "virfile.h"
#include "virstring.h"
#include "virerror.h"
#include "viralloc.h"

#define SYSFS_SCSI_DEVICES "/sys/bus/scsi/devices"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.scsi");

struct _virUsedByInfo {
    char *drvname; /* which driver */
    char *domname; /* which domain */
};
typedef struct _virUsedByInfo virUsedByInfo;

struct _virSCSIDevice {
    unsigned int adapter;
    unsigned int bus;
    unsigned int target;
    unsigned long long unit;

    char *name; /* adapter:bus:target:unit */
    char *id;   /* model:vendor */
    char *sg_path; /* e.g. /dev/sg2 */
    virUsedByInfo **used_by; /* driver:domain(s) using this dev */
    size_t n_used_by; /* how many domains are using this dev */

    bool readonly;
    bool shareable;
};

struct _virSCSIDeviceList {
    virObjectLockable parent;
    size_t count;
    virSCSIDevice **devs;
};

static virClass *virSCSIDeviceListClass;

static void virSCSIDeviceListDispose(void *obj);

static int
virSCSIOnceInit(void)
{
    if (!VIR_CLASS_NEW(virSCSIDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSCSI);

static int
virSCSIDeviceGetAdapterId(const char *adapter,
                          unsigned int *adapter_id)
{
    if (STRPREFIX(adapter, "scsi_host") &&
        virStrToLong_ui(adapter + strlen("scsi_host"),
                        NULL, 0, adapter_id) == 0)
        return 0;
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Cannot parse adapter '%1$s'"), adapter);
    return -1;
}

char *
virSCSIDeviceGetSgName(const char *sysfs_prefix,
                       const char *adapter,
                       unsigned int bus,
                       unsigned int target,
                       unsigned long long unit)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    g_autofree char *path = NULL;
    unsigned int adapter_id;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    path = g_strdup_printf("%s/%d:%u:%u:%llu/scsi_generic", prefix, adapter_id,
                           bus, target, unit);

    if (virDirOpen(&dir, path) < 0)
        return NULL;

    /* Assume a single directory entry */
    if (virDirRead(dir, &entry, path) > 0)
        return  g_strdup(entry->d_name);

    return NULL;
}

/* Returns device name (e.g. "sdc") on success, or NULL
 * on failure.
 */
char *
virSCSIDeviceGetDevName(const char *sysfs_prefix,
                        const char *adapter,
                        unsigned int bus,
                        unsigned int target,
                        unsigned long long unit)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    g_autofree char *path = NULL;
    unsigned int adapter_id;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    path = g_strdup_printf("%s/%d:%u:%u:%llu/block", prefix, adapter_id, bus,
                           target, unit);

    if (virDirOpen(&dir, path) < 0)
        return NULL;

    if (virDirRead(dir, &entry, path) > 0)
        return g_strdup(entry->d_name);

    return NULL;
}

virSCSIDevice *
virSCSIDeviceNew(const char *sysfs_prefix,
                 const char *adapter,
                 unsigned int bus,
                 unsigned int target,
                 unsigned long long unit,
                 bool readonly,
                 bool shareable)
{
    g_autoptr(virSCSIDevice) dev = NULL;
    g_autofree char *sg = NULL;
    g_autofree char *vendor_path = NULL;
    g_autofree char *model_path = NULL;
    g_autofree char *vendor = NULL;
    g_autofree char *model = NULL;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    dev = g_new0(virSCSIDevice, 1);

    dev->bus = bus;
    dev->target = target;
    dev->unit = unit;
    dev->readonly = readonly;
    dev->shareable = shareable;

    if (!(sg = virSCSIDeviceGetSgName(prefix, adapter, bus, target, unit)))
        return NULL;

    if (virSCSIDeviceGetAdapterId(adapter, &dev->adapter) < 0)
        return NULL;

    dev->name = g_strdup_printf("%d:%u:%u:%llu", dev->adapter,
                                dev->bus, dev->target, dev->unit);
    dev->sg_path = g_strdup_printf("%s/%s",
                                   sysfs_prefix ? sysfs_prefix : "/dev", sg);

    if (!virFileExists(dev->sg_path)) {
        virReportSystemError(errno,
                             _("SCSI device '%1$s': could not access %2$s"),
                             dev->name, dev->sg_path);
        return NULL;
    }

    vendor_path = g_strdup_printf("%s/%s/vendor", prefix, dev->name);
    model_path = g_strdup_printf("%s/%s/model", prefix, dev->name);

    if (virFileReadAll(vendor_path, 1024, &vendor) < 0)
        return NULL;

    if (virFileReadAll(model_path, 1024, &model) < 0)
        return NULL;

    virTrimSpaces(vendor, NULL);
    virTrimSpaces(model, NULL);

    dev->id = g_strdup_printf("%s:%s", vendor, model);

    return g_steal_pointer(&dev);
}

static void
virSCSIDeviceUsedByInfoFree(virUsedByInfo *used_by)
{
    g_free(used_by->drvname);
    g_free(used_by->domname);
    g_free(used_by);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virUsedByInfo, virSCSIDeviceUsedByInfoFree);

void
virSCSIDeviceFree(virSCSIDevice *dev)
{
    size_t i;

    if (!dev)
        return;

    g_free(dev->id);
    g_free(dev->name);
    g_free(dev->sg_path);
    for (i = 0; i < dev->n_used_by; i++)
        virSCSIDeviceUsedByInfoFree(dev->used_by[i]);
    g_free(dev->used_by);
    g_free(dev);
}

int
virSCSIDeviceSetUsedBy(virSCSIDevice *dev,
                       const char *drvname,
                       const char *domname)
{
    g_autoptr(virUsedByInfo) copy = NULL;

    copy = g_new0(virUsedByInfo, 1);
    copy->drvname = g_strdup(drvname);
    copy->domname = g_strdup(domname);

    VIR_APPEND_ELEMENT(dev->used_by, dev->n_used_by, copy);

    return 0;
}

bool
virSCSIDeviceIsAvailable(virSCSIDevice *dev)
{
    return dev->n_used_by == 0;
}

const char *
virSCSIDeviceGetName(virSCSIDevice *dev)
{
    return dev->name;
}

const char *
virSCSIDeviceGetPath(virSCSIDevice *dev)
{
    return dev->sg_path;
}

unsigned int
virSCSIDeviceGetAdapter(virSCSIDevice *dev)
{
    return dev->adapter;
}

unsigned int
virSCSIDeviceGetBus(virSCSIDevice *dev)
{
    return dev->bus;
}

unsigned int
virSCSIDeviceGetTarget(virSCSIDevice *dev)
{
    return dev->target;
}

unsigned long long
virSCSIDeviceGetUnit(virSCSIDevice *dev)
{
    return dev->unit;
}

bool
virSCSIDeviceGetReadonly(virSCSIDevice *dev)
{
    return dev->readonly;
}

bool
virSCSIDeviceGetShareable(virSCSIDevice *dev)
{
    return dev->shareable;
}

int
virSCSIDeviceFileIterate(virSCSIDevice *dev,
                         virSCSIDeviceFileActor actor,
                         void *opaque)
{
    return (actor)(dev, dev->sg_path, opaque);
}

virSCSIDeviceList *
virSCSIDeviceListNew(void)
{
    virSCSIDeviceList *list;

    if (virSCSIInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virSCSIDeviceListClass)))
        return NULL;

    return list;
}

static void
virSCSIDeviceListDispose(void *obj)
{
    virSCSIDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++)
        virSCSIDeviceFree(list->devs[i]);

    g_free(list->devs);
}

int
virSCSIDeviceListAdd(virSCSIDeviceList *list,
                     virSCSIDevice *dev)
{
    if (virSCSIDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %1$s already exists"),
                       dev->name);
        return -1;
    }

    VIR_APPEND_ELEMENT(list->devs, list->count, dev);

    return 0;
}

virSCSIDevice *
virSCSIDeviceListGet(virSCSIDeviceList *list, int idx)
{
    if (idx >= list->count || idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virSCSIDeviceListCount(virSCSIDeviceList *list)
{
    return list->count;
}

virSCSIDevice *
virSCSIDeviceListSteal(virSCSIDeviceList *list,
                       virSCSIDevice *dev)
{
    virSCSIDevice *ret = NULL;
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (list->devs[i]->adapter == dev->adapter &&
            list->devs[i]->bus == dev->bus &&
            list->devs[i]->target == dev->target &&
            list->devs[i]->unit == dev->unit) {
            ret = list->devs[i];
            VIR_DELETE_ELEMENT(list->devs, i, list->count);
            break;
        }
    }

    return ret;
}

void
virSCSIDeviceListDel(virSCSIDeviceList *list,
                     virSCSIDevice *dev,
                     const char *drvname,
                     const char *domname)
{
    size_t i;

    for (i = 0; i < dev->n_used_by; i++) {
        if (STREQ_NULLABLE(dev->used_by[i]->drvname, drvname) &&
            STREQ_NULLABLE(dev->used_by[i]->domname, domname)) {
            if (dev->n_used_by > 1) {
                virSCSIDeviceUsedByInfoFree(dev->used_by[i]);
                VIR_DELETE_ELEMENT(dev->used_by, i, dev->n_used_by);
            } else {
                virSCSIDeviceFree(virSCSIDeviceListSteal(list, dev));
            }
            break;
        }
    }
}

virSCSIDevice *
virSCSIDeviceListFind(virSCSIDeviceList *list,
                      virSCSIDevice *dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        if (list->devs[i]->adapter == dev->adapter &&
            list->devs[i]->bus == dev->bus &&
            list->devs[i]->target == dev->target &&
            list->devs[i]->unit == dev->unit)
            return list->devs[i];
    }

    return NULL;
}
