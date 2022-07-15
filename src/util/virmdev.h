/*
 * virmdev.h: helper APIs for managing host mediated devices
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
#include "virenum.h"

typedef enum {
    VIR_MDEV_MODEL_TYPE_VFIO_PCI = 0,
    VIR_MDEV_MODEL_TYPE_VFIO_CCW = 1,
    VIR_MDEV_MODEL_TYPE_VFIO_AP  = 2,

    VIR_MDEV_MODEL_TYPE_LAST
} virMediatedDeviceModelType;

VIR_ENUM_DECL(virMediatedDeviceModel);


typedef struct _virMediatedDevice virMediatedDevice;
typedef struct _virMediatedDeviceList virMediatedDeviceList;
typedef struct _virMediatedDeviceAttr virMediatedDeviceAttr;
struct _virMediatedDeviceAttr {
    char *name;
    char *value;
};

virMediatedDeviceAttr *virMediatedDeviceAttrNew(void);
void virMediatedDeviceAttrFree(virMediatedDeviceAttr *attr);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virMediatedDeviceAttr, virMediatedDeviceAttrFree);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virMediatedDeviceList, virObjectUnref);


typedef struct _virMediatedDeviceType virMediatedDeviceType;
struct _virMediatedDeviceType {
    char *id;
    char *name;
    char *device_api;
    unsigned int available_instances;
};

typedef int (*virMediatedDeviceCallback)(virMediatedDevice *dev,
                                         const char *path, void *opaque);

virMediatedDevice *
virMediatedDeviceNew(const char *uuidstr, virMediatedDeviceModelType model);

virMediatedDevice *
virMediatedDeviceCopy(virMediatedDevice *dev);

void
virMediatedDeviceFree(virMediatedDevice *dev);

const char *
virMediatedDeviceGetPath(virMediatedDevice *dev);

void
virMediatedDeviceGetUsedBy(virMediatedDevice *dev,
                           const char **drvname, const char **domname);

int
virMediatedDeviceSetUsedBy(virMediatedDevice *dev,
                           const char *drvname,
                           const char *domname);

char *
virMediatedDeviceGetIOMMUGroupDev(const char *uuidstr);

int
virMediatedDeviceGetIOMMUGroupNum(const char *uuidstr);

char *
virMediatedDeviceGetSysfsPath(const char *uuidstr);

bool
virMediatedDeviceIsUsed(virMediatedDevice *dev,
                        virMediatedDeviceList *list);

bool
virMediatedDeviceIsUsed(virMediatedDevice *dev,
                        virMediatedDeviceList *list);

virMediatedDeviceList *
virMediatedDeviceListNew(void);

int
virMediatedDeviceListAdd(virMediatedDeviceList *list,
                         virMediatedDevice **dev);

virMediatedDevice *
virMediatedDeviceListGet(virMediatedDeviceList *list,
                         ssize_t idx);

size_t
virMediatedDeviceListCount(virMediatedDeviceList *list);

virMediatedDevice *
virMediatedDeviceListSteal(virMediatedDeviceList *list,
                           virMediatedDevice *dev);

virMediatedDevice *
virMediatedDeviceListStealIndex(virMediatedDeviceList *list,
                                ssize_t idx);

void
virMediatedDeviceListDel(virMediatedDeviceList *list,
                         virMediatedDevice *dev);

virMediatedDevice *
virMediatedDeviceListFind(virMediatedDeviceList *list,
                          const char *sysfspath);

int
virMediatedDeviceListFindIndex(virMediatedDeviceList *list,
                               const char *sysfspath);

int
virMediatedDeviceListMarkDevices(virMediatedDeviceList *dst,
                                 virMediatedDeviceList *src,
                                 const char *drvname,
                                 const char *domname);

void
virMediatedDeviceTypeFree(virMediatedDeviceType *type);

int
virMediatedDeviceTypeReadAttrs(const char *sysfspath,
                               virMediatedDeviceType **type);

ssize_t
virMediatedDeviceGetMdevTypes(const char *sysfspath,
                              virMediatedDeviceType ***types,
                              size_t *ntypes);

int
virMediatedDeviceParentGetAddress(const char *sysfspath,
                                  char **address);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virMediatedDevice, virMediatedDeviceFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virMediatedDeviceType, virMediatedDeviceTypeFree);
