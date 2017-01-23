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
 *
 * Authors:
 *     Han Cheng <hanc.fnst@cn.fujitsu.com>
 *     Osier Yang <jyang@redhat.com>
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

#include "virlog.h"
#include "virscsi.h"
#include "viralloc.h"
#include "virfile.h"
#include "virutil.h"
#include "virstring.h"
#include "virerror.h"

#define SYSFS_SCSI_DEVICES "/sys/bus/scsi/devices"

/* For virReportOOMError()  and virReportSystemError() */
#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.scsi");

struct _virUsedByInfo {
    char *drvname; /* which driver */
    char *domname; /* which domain */
};
typedef struct _virUsedByInfo *virUsedByInfoPtr;

struct _virSCSIDevice {
    unsigned int adapter;
    unsigned int bus;
    unsigned int target;
    unsigned long long unit;

    char *name; /* adapter:bus:target:unit */
    char *id;   /* model:vendor */
    char *sg_path; /* e.g. /dev/sg2 */
    virUsedByInfoPtr *used_by; /* driver:domain(s) using this dev */
    size_t n_used_by; /* how many domains are using this dev */

    bool readonly;
    bool shareable;
};

struct _virSCSIDeviceList {
    virObjectLockable parent;
    size_t count;
    virSCSIDevicePtr *devs;
};

static virClassPtr virSCSIDeviceListClass;

static void virSCSIDeviceListDispose(void *obj);

static int
virSCSIOnceInit(void)
{
    if (!(virSCSIDeviceListClass = virClassNew(virClassForObjectLockable(),
                                               "virSCSIDeviceList",
                                               sizeof(virSCSIDeviceList),
                                               virSCSIDeviceListDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSCSI)

static int
virSCSIDeviceGetAdapterId(const char *adapter,
                          unsigned int *adapter_id)
{
    if (STRPREFIX(adapter, "scsi_host") &&
        virStrToLong_ui(adapter + strlen("scsi_host"),
                        NULL, 0, adapter_id) == 0)
        return 0;
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Cannot parse adapter '%s'"), adapter);
    return -1;
}

char *
virSCSIDeviceGetSgName(const char *sysfs_prefix,
                       const char *adapter,
                       unsigned int bus,
                       unsigned int target,
                       unsigned long long unit)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char *path = NULL;
    char *sg = NULL;
    unsigned int adapter_id;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    if (virAsprintf(&path,
                    "%s/%d:%u:%u:%llu/scsi_generic",
                    prefix, adapter_id, bus, target, unit) < 0)
        return NULL;

    if (virDirOpen(&dir, path) < 0)
        goto cleanup;

    while (virDirRead(dir, &entry, path) > 0) {
        /* Assume a single directory entry */
        ignore_value(VIR_STRDUP(sg, entry->d_name));
        break;
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(path);
    return sg;
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
    DIR *dir = NULL;
    struct dirent *entry;
    char *path = NULL;
    char *name = NULL;
    unsigned int adapter_id;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    if (virAsprintf(&path,
                    "%s/%d:%u:%u:%llu/block",
                    prefix, adapter_id, bus, target, unit) < 0)
        return NULL;

    if (virDirOpen(&dir, path) < 0)
        goto cleanup;

    while (virDirRead(dir, &entry, path) > 0) {
        ignore_value(VIR_STRDUP(name, entry->d_name));
        break;
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(path);
    return name;
}

virSCSIDevicePtr
virSCSIDeviceNew(const char *sysfs_prefix,
                 const char *adapter,
                 unsigned int bus,
                 unsigned int target,
                 unsigned long long unit,
                 bool readonly,
                 bool shareable)
{
    virSCSIDevicePtr dev, ret = NULL;
    char *sg = NULL;
    char *vendor_path = NULL;
    char *model_path = NULL;
    char *vendor = NULL;
    char *model = NULL;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SCSI_DEVICES;

    if (VIR_ALLOC(dev) < 0)
        return NULL;

    dev->bus = bus;
    dev->target = target;
    dev->unit = unit;
    dev->readonly = readonly;
    dev->shareable = shareable;

    if (!(sg = virSCSIDeviceGetSgName(prefix, adapter, bus, target, unit)))
        goto cleanup;

    if (virSCSIDeviceGetAdapterId(adapter, &dev->adapter) < 0)
        goto cleanup;

    if (virAsprintf(&dev->name, "%d:%u:%u:%llu", dev->adapter,
                    dev->bus, dev->target, dev->unit) < 0 ||
        virAsprintf(&dev->sg_path, "%s/%s",
                    sysfs_prefix ? sysfs_prefix : "/dev", sg) < 0)
        goto cleanup;

    if (!virFileExists(dev->sg_path)) {
        virReportSystemError(errno,
                             _("SCSI device '%s': could not access %s"),
                             dev->name, dev->sg_path);
        goto cleanup;
    }

    if (virAsprintf(&vendor_path,
                    "%s/%s/vendor", prefix, dev->name) < 0 ||
        virAsprintf(&model_path,
                    "%s/%s/model", prefix, dev->name) < 0)
        goto cleanup;

    if (virFileReadAll(vendor_path, 1024, &vendor) < 0)
        goto cleanup;

    if (virFileReadAll(model_path, 1024, &model) < 0)
        goto cleanup;

    virTrimSpaces(vendor, NULL);
    virTrimSpaces(model, NULL);

    if (virAsprintf(&dev->id, "%s:%s", vendor, model) < 0)
        goto cleanup;

    ret = dev;
 cleanup:
    VIR_FREE(sg);
    VIR_FREE(vendor);
    VIR_FREE(model);
    VIR_FREE(vendor_path);
    VIR_FREE(model_path);
    if (!ret)
        virSCSIDeviceFree(dev);
    return ret;
}

static void
virSCSIDeviceUsedByInfoFree(virUsedByInfoPtr used_by)
{
    VIR_FREE(used_by->drvname);
    VIR_FREE(used_by->domname);
    VIR_FREE(used_by);
}

void
virSCSIDeviceFree(virSCSIDevicePtr dev)
{
    size_t i;

    if (!dev)
        return;

    VIR_FREE(dev->id);
    VIR_FREE(dev->name);
    VIR_FREE(dev->sg_path);
    for (i = 0; i < dev->n_used_by; i++)
        virSCSIDeviceUsedByInfoFree(dev->used_by[i]);
    VIR_FREE(dev->used_by);
    VIR_FREE(dev);
}

int
virSCSIDeviceSetUsedBy(virSCSIDevicePtr dev,
                       const char *drvname,
                       const char *domname)
{
    virUsedByInfoPtr copy;
    if (VIR_ALLOC(copy) < 0)
        return -1;
    if (VIR_STRDUP(copy->drvname, drvname) < 0 ||
        VIR_STRDUP(copy->domname, domname) < 0)
        goto cleanup;

    if (VIR_APPEND_ELEMENT(dev->used_by, dev->n_used_by, copy) < 0)
        goto cleanup;

    return 0;

 cleanup:
    virSCSIDeviceUsedByInfoFree(copy);
    return -1;
}

bool
virSCSIDeviceIsAvailable(virSCSIDevicePtr dev)
{
    return dev->n_used_by == 0;
}

const char *
virSCSIDeviceGetName(virSCSIDevicePtr dev)
{
    return dev->name;
}

const char *
virSCSIDeviceGetPath(virSCSIDevicePtr dev)
{
    return dev->sg_path;
}

unsigned int
virSCSIDeviceGetAdapter(virSCSIDevicePtr dev)
{
    return dev->adapter;
}

unsigned int
virSCSIDeviceGetBus(virSCSIDevicePtr dev)
{
    return dev->bus;
}

unsigned int
virSCSIDeviceGetTarget(virSCSIDevicePtr dev)
{
    return dev->target;
}

unsigned long long
virSCSIDeviceGetUnit(virSCSIDevicePtr dev)
{
    return dev->unit;
}

bool
virSCSIDeviceGetReadonly(virSCSIDevicePtr dev)
{
    return dev->readonly;
}

bool
virSCSIDeviceGetShareable(virSCSIDevicePtr dev)
{
    return dev->shareable;
}

int
virSCSIDeviceFileIterate(virSCSIDevicePtr dev,
                         virSCSIDeviceFileActor actor,
                         void *opaque)
{
    return (actor)(dev, dev->sg_path, opaque);
}

virSCSIDeviceListPtr
virSCSIDeviceListNew(void)
{
    virSCSIDeviceListPtr list;

    if (virSCSIInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virSCSIDeviceListClass)))
        return NULL;

    return list;
}

static void
virSCSIDeviceListDispose(void *obj)
{
    virSCSIDeviceListPtr list = obj;
    size_t i;

    for (i = 0; i < list->count; i++)
        virSCSIDeviceFree(list->devs[i]);

    VIR_FREE(list->devs);
}

int
virSCSIDeviceListAdd(virSCSIDeviceListPtr list,
                     virSCSIDevicePtr dev)
{
    if (virSCSIDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %s already exists"),
                       dev->name);
        return -1;
    }

    return VIR_APPEND_ELEMENT(list->devs, list->count, dev);
}

virSCSIDevicePtr
virSCSIDeviceListGet(virSCSIDeviceListPtr list, int idx)
{
    if (idx >= list->count || idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virSCSIDeviceListCount(virSCSIDeviceListPtr list)
{
    return list->count;
}

virSCSIDevicePtr
virSCSIDeviceListSteal(virSCSIDeviceListPtr list,
                       virSCSIDevicePtr dev)
{
    virSCSIDevicePtr ret = NULL;
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
virSCSIDeviceListDel(virSCSIDeviceListPtr list,
                     virSCSIDevicePtr dev,
                     const char *drvname,
                     const char *domname)
{
    virSCSIDevicePtr tmp = NULL;
    size_t i;

    for (i = 0; i < dev->n_used_by; i++) {
        if (STREQ_NULLABLE(dev->used_by[i]->drvname, drvname) &&
            STREQ_NULLABLE(dev->used_by[i]->domname, domname)) {
            if (dev->n_used_by > 1) {
                virSCSIDeviceUsedByInfoFree(dev->used_by[i]);
                VIR_DELETE_ELEMENT(dev->used_by, i, dev->n_used_by);
            } else {
                tmp = virSCSIDeviceListSteal(list, dev);
                virSCSIDeviceFree(tmp);
            }
            break;
        }
    }
}

virSCSIDevicePtr
virSCSIDeviceListFind(virSCSIDeviceListPtr list,
                      virSCSIDevicePtr dev)
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
