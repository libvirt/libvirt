/*
 * virscsi.c: helper APIs for managing host SCSI devices
 *
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

#include "virscsi.h"
#include "virlog.h"
#include "viralloc.h"
#include "virfile.h"
#include "virutil.h"
#include "virstring.h"
#include "virerror.h"

#define SYSFS_SCSI_DEVICES "/sys/bus/scsi/devices"

/* For virReportOOMError()  and virReportSystemError() */
#define VIR_FROM_THIS VIR_FROM_NONE

struct _virSCSIDevice {
    unsigned int adapter;
    unsigned int bus;
    unsigned int target;
    unsigned int unit;

    char *name; /* adapter:bus:target:unit */
    char *id;   /* model:vendor */
    char *sg_path; /* e.g. /dev/sg2 */
    const char *used_by; /* name of the domain using this dev */

    bool readonly;
};

struct _virSCSIDeviceList {
    virObjectLockable parent;
    unsigned int count;
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
    if (STRPREFIX(adapter, "scsi_host")) {
        if (virStrToLong_ui(adapter + strlen("scsi_host"),
                            NULL, 0, adapter_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse adapter '%s'"), adapter);
            return -1;
        }
    }

    return 0;
}

char *
virSCSIDeviceGetSgName(const char *adapter,
                       unsigned int bus,
                       unsigned int target,
                       unsigned int unit)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char *path = NULL;
    char *sg = NULL;
    unsigned int adapter_id;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    if (virAsprintf(&path,
                    SYSFS_SCSI_DEVICES "/%d:%d:%d:%d/scsi_generic",
                    adapter_id, bus, target, unit) < 0)
        return NULL;

    if (!(dir = opendir(path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), path);
        goto cleanup;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;

        if (VIR_STRDUP(sg, entry->d_name) < 0)
            goto cleanup;
    }

cleanup:
    closedir(dir);
    VIR_FREE(path);
    return sg;
}

/* Returns device name (e.g. "sdc") on success, or NULL
 * on failure.
 */
char *
virSCSIDeviceGetDevName(const char *adapter,
                        unsigned int bus,
                        unsigned int target,
                        unsigned int unit)
{
    DIR *dir = NULL;
    struct dirent *entry;
    char *path = NULL;
    char *name = NULL;
    unsigned int adapter_id;

    if (virSCSIDeviceGetAdapterId(adapter, &adapter_id) < 0)
        return NULL;

    if (virAsprintf(&path,
                    SYSFS_SCSI_DEVICES "/%d:%d:%d:%d/block",
                    adapter_id, bus, target, unit) < 0)
        return NULL;

    if (!(dir = opendir(path))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to open %s"), path);
        goto cleanup;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;

        ignore_value(VIR_STRDUP(name, entry->d_name));
        break;
    }

cleanup:
    closedir(dir);
    VIR_FREE(path);
    return name;
}

virSCSIDevicePtr
virSCSIDeviceNew(const char *adapter,
                 unsigned int bus,
                 unsigned int target,
                 unsigned int unit,
                 bool readonly)
{
    virSCSIDevicePtr dev, ret = NULL;
    char *sg = NULL;
    char *vendor_path = NULL;
    char *model_path = NULL;
    char *vendor = NULL;
    char *model = NULL;

    if (VIR_ALLOC(dev) < 0)
        return NULL;

    dev->bus = bus;
    dev->target = target;
    dev->unit = unit;
    dev->readonly = readonly;

    if (!(sg = virSCSIDeviceGetSgName(adapter, bus, target, unit)))
        goto cleanup;

    if (virSCSIDeviceGetAdapterId(adapter, &dev->adapter) < 0)
        goto cleanup;

    if (virAsprintf(&dev->name, "%d:%d:%d:%d", dev->adapter,
                    dev->bus, dev->target, dev->unit) < 0 ||
        virAsprintf(&dev->sg_path, "/dev/%s", sg) < 0)
        goto cleanup;

    if (access(dev->sg_path, F_OK) != 0) {
        virReportSystemError(errno,
                             _("SCSI device '%s': could not access %s"),
                             dev->name, dev->sg_path);
        goto cleanup;
    }

    if (virAsprintf(&vendor_path,
                    SYSFS_SCSI_DEVICES "/%s/vendor", dev->name) < 0 ||
        virAsprintf(&model_path,
                    SYSFS_SCSI_DEVICES "/%s/model", dev->name) < 0)
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

void
virSCSIDeviceFree(virSCSIDevicePtr dev)
{
    if (!dev)
        return;

    VIR_FREE(dev->id);
    VIR_FREE(dev->name);
    VIR_FREE(dev->sg_path);
    VIR_FREE(dev);
}

void
virSCSIDeviceSetUsedBy(virSCSIDevicePtr dev,
                       const char *name)
{
    dev->used_by = name;
}

const char *
virSCSIDeviceGetUsedBy(virSCSIDevicePtr dev)
{
    return dev->used_by;
}

const char *
virSCSIDeviceGetName(virSCSIDevicePtr dev)
{
    return dev->name;
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

unsigned int
virSCSIDeviceGetUnit(virSCSIDevicePtr dev)
{
    return dev->unit;
}

bool
virSCSIDeviceGetReadonly(virSCSIDevicePtr dev)
{
    return dev->readonly;
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

    if (VIR_REALLOC_N(list->devs, list->count + 1) < 0)
        return -1;

    list->devs[list->count++] = dev;

    return 0;
}

virSCSIDevicePtr
virSCSIDeviceListGet(virSCSIDeviceListPtr list, int idx)
{
    if (idx >= list->count || idx < 0)
        return NULL;

    return list->devs[idx];
}

int
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
        if (list->devs[i]->adapter != dev->adapter ||
            list->devs[i]->bus != dev->bus ||
            list->devs[i]->target != dev->target ||
            list->devs[i]->unit != dev->unit)
            continue;

        ret = list->devs[i];

        if (i != list->count--)
            memmove(&list->devs[i],
                    &list->devs[i+1],
                    sizeof(*list->devs) * (list->count - i));

        if (VIR_REALLOC_N(list->devs, list->count) < 0) {
            ; /* not fatal */
        }

        break;
    }

    return ret;
}

void
virSCSIDeviceListDel(virSCSIDeviceListPtr list,
                     virSCSIDevicePtr dev)
{
    virSCSIDevicePtr ret = virSCSIDeviceListSteal(list, dev);
    virSCSIDeviceFree(ret);
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
