/*
 * virmdev.c: helper APIs for managing host mediated devices
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

#include "dirname.h"
#include "virmdev.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define MDEV_SYSFS_DEVICES "/sys/bus/mdev/devices/"

VIR_LOG_INIT("util.mdev");

struct _virMediatedDevice {
    char *path;                             /* sysfs path */
    virMediatedDeviceModelType model;

    char *used_by_drvname;
    char *used_by_domname;
};

struct _virMediatedDeviceList {
    virObjectLockable parent;

    size_t count;
    virMediatedDevicePtr *devs;
};

VIR_ENUM_IMPL(virMediatedDeviceModel, VIR_MDEV_MODEL_TYPE_LAST,
              "vfio-pci",
              "vfio-ccw",
              "vfio-ap",
);

static virClassPtr virMediatedDeviceListClass;

static void
virMediatedDeviceListDispose(void *obj);

static int
virMediatedOnceInit(void)
{
    if (!VIR_CLASS_NEW(virMediatedDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virMediated);

#ifdef __linux__

static int
virMediatedDeviceGetSysfsDeviceAPI(virMediatedDevicePtr dev,
                                   char **device_api)
{
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOFREE(char *) file = NULL;
    char *tmp = NULL;

    if (virAsprintf(&file, "%s/mdev_type/device_api", dev->path) < 0)
        return -1;

    /* TODO - make this a generic method to access sysfs files for various
     * kinds of devices
     */
    if (!virFileExists(file)) {
        virReportSystemError(errno, _("failed to read '%s'"), file);
        return -1;
    }

    if (virFileReadAll(file, 1024, &buf) < 0)
        return -1;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    *device_api = buf;
    buf = NULL;

    return 0;
}


static int
virMediatedDeviceCheckModel(virMediatedDevicePtr dev,
                            virMediatedDeviceModelType model)
{
    VIR_AUTOFREE(char *) dev_api = NULL;
    int actual_model;

    if (virMediatedDeviceGetSysfsDeviceAPI(dev, &dev_api) < 0)
        return -1;

    /* safeguard in case we've got an older libvirt which doesn't know newer
     * device_api models yet
     */
    if ((actual_model = virMediatedDeviceModelTypeFromString(dev_api)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device API '%s' not supported yet"),
                       dev_api);
        return -1;
    }

    if (actual_model != model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid device API '%s' for device %s: "
                         "device only supports '%s'"),
                       virMediatedDeviceModelTypeToString(model),
                       dev->path, dev_api);
        return -1;
    }

    return 0;
}


virMediatedDevicePtr
virMediatedDeviceNew(const char *uuidstr, virMediatedDeviceModelType model)
{
    virMediatedDevicePtr ret = NULL;
    VIR_AUTOPTR(virMediatedDevice) dev = NULL;
    VIR_AUTOFREE(char *) sysfspath = NULL;

    if (!(sysfspath = virMediatedDeviceGetSysfsPath(uuidstr)))
        return NULL;

    if (!virFileExists(sysfspath)) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("mediated device '%s' not found"), uuidstr);
        return NULL;
    }

    if (VIR_ALLOC(dev) < 0)
        return NULL;

    VIR_STEAL_PTR(dev->path, sysfspath);

    /* Check whether the user-provided model corresponds with the actually
     * supported mediated device's API.
     */
    if (virMediatedDeviceCheckModel(dev, model))
        return NULL;

    dev->model = model;
    VIR_STEAL_PTR(ret, dev);

    return ret;
}

#else

virMediatedDevicePtr
virMediatedDeviceNew(const char *uuidstr ATTRIBUTE_UNUSED,
                     virMediatedDeviceModelType model ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("mediated devices are not supported on non-linux "
                     "platforms"));
    return NULL;
}

#endif /* __linux__ */

void
virMediatedDeviceFree(virMediatedDevicePtr dev)
{
    if (!dev)
        return;
    VIR_FREE(dev->path);
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    VIR_FREE(dev);
}


const char *
virMediatedDeviceGetPath(virMediatedDevicePtr dev)
{
    return dev->path;
}


/* Returns an absolute canonicalized path to the device used to control the
 * mediated device's IOMMU group (e.g. "/dev/vfio/15"). Caller is responsible
 * for freeing the result.
 */
char *
virMediatedDeviceGetIOMMUGroupDev(const char *uuidstr)
{
    VIR_AUTOFREE(char *) result_path = NULL;
    VIR_AUTOFREE(char *) iommu_path = NULL;
    VIR_AUTOFREE(char *) dev_path = virMediatedDeviceGetSysfsPath(uuidstr);
    char *vfio_path = NULL;

    if (!dev_path)
        return NULL;

    if (virAsprintf(&iommu_path, "%s/iommu_group", dev_path) < 0)
        return NULL;

    if (!virFileExists(iommu_path)) {
        virReportSystemError(errno, _("failed to access '%s'"), iommu_path);
        return NULL;
    }

    if (virFileResolveLink(iommu_path, &result_path) < 0) {
        virReportSystemError(errno, _("failed to resolve '%s'"), iommu_path);
        return NULL;
    }

    if (virAsprintf(&vfio_path, "/dev/vfio/%s", last_component(result_path)) < 0)
        return NULL;

    return vfio_path;
}


int
virMediatedDeviceGetIOMMUGroupNum(const char *uuidstr)
{
    VIR_AUTOFREE(char *) vfio_path = NULL;
    char *group_num_str = NULL;
    unsigned int group_num = -1;

    if (!(vfio_path = virMediatedDeviceGetIOMMUGroupDev(uuidstr)))
        return -1;

    group_num_str = last_component(vfio_path);
    ignore_value(virStrToLong_ui(group_num_str, NULL, 10, &group_num));

    return group_num;
}


void
virMediatedDeviceGetUsedBy(virMediatedDevicePtr dev,
                           const char **drvname, const char **domname)
{
    *drvname = dev->used_by_drvname;
    *domname = dev->used_by_domname;
}


int
virMediatedDeviceSetUsedBy(virMediatedDevicePtr dev,
                           const char *drvname,
                           const char *domname)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    if (VIR_STRDUP(dev->used_by_drvname, drvname) < 0)
        return -1;
    if (VIR_STRDUP(dev->used_by_domname, domname) < 0)
        return -1;

    return 0;
}


virMediatedDeviceListPtr
virMediatedDeviceListNew(void)
{
    virMediatedDeviceListPtr list;

    if (virMediatedInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virMediatedDeviceListClass)))
        return NULL;

    return list;
}


static void
virMediatedDeviceListDispose(void *obj)
{
    virMediatedDeviceListPtr list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        virMediatedDeviceFree(list->devs[i]);
        list->devs[i] = NULL;
    }

    list->count = 0;
    VIR_FREE(list->devs);
}


/* The reason for @dev to be double pointer is that VIR_APPEND_ELEMENT clears
 * the pointer and we need to clear the original not a copy on the stack
 */
int
virMediatedDeviceListAdd(virMediatedDeviceListPtr list,
                         virMediatedDevicePtr *dev)
{
    if (virMediatedDeviceListFind(list, *dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device %s is already in use"), (*dev)->path);
        return -1;
    }
    return VIR_APPEND_ELEMENT(list->devs, list->count, *dev);
}


virMediatedDevicePtr
virMediatedDeviceListGet(virMediatedDeviceListPtr list,
                         ssize_t idx)
{
    if (idx < 0 || idx >= list->count)
        return NULL;

    return list->devs[idx];
}


size_t
virMediatedDeviceListCount(virMediatedDeviceListPtr list)
{
    return list->count;
}


virMediatedDevicePtr
virMediatedDeviceListStealIndex(virMediatedDeviceListPtr list,
                                ssize_t idx)
{
    virMediatedDevicePtr ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}


virMediatedDevicePtr
virMediatedDeviceListSteal(virMediatedDeviceListPtr list,
                           virMediatedDevicePtr dev)
{
    int idx = virMediatedDeviceListFindIndex(list, dev);

    return virMediatedDeviceListStealIndex(list, idx);
}


void
virMediatedDeviceListDel(virMediatedDeviceListPtr list,
                         virMediatedDevicePtr dev)
{
    virMediatedDeviceFree(virMediatedDeviceListSteal(list, dev));
}


int
virMediatedDeviceListFindIndex(virMediatedDeviceListPtr list,
                               virMediatedDevicePtr dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virMediatedDevicePtr other = list->devs[i];
        if (STREQ(other->path, dev->path))
            return i;
    }
    return -1;
}


virMediatedDevicePtr
virMediatedDeviceListFind(virMediatedDeviceListPtr list,
                          virMediatedDevicePtr dev)
{
    int idx;

    if ((idx = virMediatedDeviceListFindIndex(list, dev)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


bool
virMediatedDeviceIsUsed(virMediatedDevicePtr dev,
                        virMediatedDeviceListPtr list)
{
    const char *drvname, *domname;
    virMediatedDevicePtr tmp = NULL;

    if ((tmp = virMediatedDeviceListFind(list, dev))) {
        virMediatedDeviceGetUsedBy(tmp, &drvname, &domname);
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("mediated device %s is in use by "
                         "driver %s, domain %s"),
                       tmp->path, drvname, domname);
    }

    return !!tmp;
}


char *
virMediatedDeviceGetSysfsPath(const char *uuidstr)
{
    char *ret = NULL;

    ignore_value(virAsprintf(&ret, MDEV_SYSFS_DEVICES "%s", uuidstr));
    return ret;
}


int
virMediatedDeviceListMarkDevices(virMediatedDeviceListPtr dst,
                                 virMediatedDeviceListPtr src,
                                 const char *drvname,
                                 const char *domname)
{
    int ret = -1;
    size_t count = virMediatedDeviceListCount(src);
    size_t i, j;

    virObjectLock(dst);
    for (i = 0; i < count; i++) {
        virMediatedDevicePtr mdev = virMediatedDeviceListGet(src, i);

        if (virMediatedDeviceIsUsed(mdev, dst) ||
            virMediatedDeviceSetUsedBy(mdev, drvname, domname) < 0)
            goto cleanup;

        /* Copy mdev references to the driver list:
         * - caller is responsible for NOT freeing devices in @src on success
         * - we're responsible for performing a rollback on failure
         */
        VIR_DEBUG("Add '%s' to list of active mediated devices used by '%s'",
                  mdev->path, domname);
        if (virMediatedDeviceListAdd(dst, &mdev) < 0)
            goto rollback;

    }

    ret = 0;
 cleanup:
    virObjectUnlock(dst);
    return ret;

 rollback:
    for (j = 0; j < i; j++) {
        virMediatedDevicePtr tmp = virMediatedDeviceListGet(src, j);
        virMediatedDeviceListSteal(dst, tmp);
    }
    goto cleanup;
}


void
virMediatedDeviceTypeFree(virMediatedDeviceTypePtr type)
{
    if (!type)
        return;

    VIR_FREE(type->id);
    VIR_FREE(type->name);
    VIR_FREE(type->device_api);
    VIR_FREE(type);
}


int
virMediatedDeviceTypeReadAttrs(const char *sysfspath,
                               virMediatedDeviceTypePtr *type)
{
    VIR_AUTOPTR(virMediatedDeviceType) tmp = NULL;

#define MDEV_GET_SYSFS_ATTR(attr, dst, cb, optional) \
    do { \
        int rc; \
        if ((rc = cb(dst, "%s/%s", sysfspath, attr)) < 0) { \
            if (rc != -2 || !optional) \
                return -1; \
        } \
    } while (0)

    if (VIR_ALLOC(tmp) < 0)
        return -1;

    if (VIR_STRDUP(tmp->id, last_component(sysfspath)) < 0)
        return -1;

    /* @name sysfs attribute is optional, so getting ENOENT is fine */
    MDEV_GET_SYSFS_ATTR("name", &tmp->name, virFileReadValueString, true);
    MDEV_GET_SYSFS_ATTR("device_api", &tmp->device_api,
                        virFileReadValueString, false);
    MDEV_GET_SYSFS_ATTR("available_instances", &tmp->available_instances,
                        virFileReadValueUint, false);

#undef MDEV_GET_SYSFS_ATTR

    VIR_STEAL_PTR(*type, tmp);

    return 0;
}
