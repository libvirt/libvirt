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

#include "virmdev.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "viralloc.h"

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
    virMediatedDevice **devs;
};

VIR_ENUM_IMPL(virMediatedDeviceModel,
              VIR_MDEV_MODEL_TYPE_LAST,
              "vfio-pci",
              "vfio-ccw",
              "vfio-ap",
);

static virClass *virMediatedDeviceListClass;

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
virMediatedDeviceGetSysfsDeviceAPI(virMediatedDevice *dev,
                                   char **device_api)
{
    g_autofree char *buf = NULL;
    g_autofree char *file = NULL;
    char *tmp = NULL;

    file = g_strdup_printf("%s/mdev_type/device_api", dev->path);

    /* TODO - make this a generic method to access sysfs files for various
     * kinds of devices
     */
    if (!virFileExists(file)) {
        virReportSystemError(errno, _("failed to read '%1$s'"), file);
        return -1;
    }

    if (virFileReadAll(file, 1024, &buf) < 0)
        return -1;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    *device_api = g_steal_pointer(&buf);

    return 0;
}


static int
virMediatedDeviceCheckModel(virMediatedDevice *dev,
                            virMediatedDeviceModelType model)
{
    g_autofree char *dev_api = NULL;
    int actual_model;

    if (virMediatedDeviceGetSysfsDeviceAPI(dev, &dev_api) < 0)
        return -1;

    /* safeguard in case we've got an older libvirt which doesn't know newer
     * device_api models yet
     */
    if ((actual_model = virMediatedDeviceModelTypeFromString(dev_api)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device API '%1$s' not supported yet"),
                       dev_api);
        return -1;
    }

    if (actual_model != model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid device API '%1$s' for device %2$s: device only supports '%3$s'"),
                       virMediatedDeviceModelTypeToString(model),
                       dev->path, dev_api);
        return -1;
    }

    return 0;
}


virMediatedDevice *
virMediatedDeviceNew(const char *uuidstr, virMediatedDeviceModelType model)
{
    g_autoptr(virMediatedDevice) dev = NULL;
    g_autofree char *sysfspath = NULL;

    sysfspath = virMediatedDeviceGetSysfsPath(uuidstr);
    if (!virFileExists(sysfspath)) {
        virReportError(VIR_ERR_DEVICE_MISSING,
                       _("mediated device '%1$s' not found"), uuidstr);
        return NULL;
    }

    dev = g_new0(virMediatedDevice, 1);

    dev->path = g_steal_pointer(&sysfspath);

    /* Check whether the user-provided model corresponds with the actually
     * supported mediated device's API.
     */
    if (virMediatedDeviceCheckModel(dev, model))
        return NULL;

    dev->model = model;
    return g_steal_pointer(&dev);
}

#else

virMediatedDevice *
virMediatedDeviceNew(const char *uuidstr G_GNUC_UNUSED,
                     virMediatedDeviceModelType model G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("mediated devices are not supported on non-linux platforms"));
    return NULL;
}

#endif /* __linux__ */

void
virMediatedDeviceFree(virMediatedDevice *dev)
{
    if (!dev)
        return;
    g_free(dev->path);
    g_free(dev->used_by_drvname);
    g_free(dev->used_by_domname);
    g_free(dev);
}


const char *
virMediatedDeviceGetPath(virMediatedDevice *dev)
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
    int group_num = virMediatedDeviceGetIOMMUGroupNum(uuidstr);

    if (group_num < 0)
        return NULL;

    return g_strdup_printf("/dev/vfio/%i", group_num);
}


int
virMediatedDeviceGetIOMMUGroupNum(const char *uuidstr)
{
    g_autofree char *result_path = NULL;
    g_autofree char *group_num_str = NULL;
    g_autofree char *iommu_path = NULL;
    g_autofree char *dev_path = virMediatedDeviceGetSysfsPath(uuidstr);
    unsigned int group_num = -1;

    iommu_path = g_strdup_printf("%s/iommu_group", dev_path);

    if (!virFileExists(iommu_path)) {
        virReportSystemError(errno, _("failed to access '%1$s'"), iommu_path);
        return -1;
    }

    if (virFileResolveLink(iommu_path, &result_path) < 0) {
        virReportSystemError(errno, _("failed to resolve '%1$s'"), iommu_path);
        return -1;
    }

    group_num_str = g_path_get_basename(result_path);
    ignore_value(virStrToLong_ui(group_num_str, NULL, 10, &group_num));
    return group_num;
}


void
virMediatedDeviceGetUsedBy(virMediatedDevice *dev,
                           const char **drvname, const char **domname)
{
    *drvname = dev->used_by_drvname;
    *domname = dev->used_by_domname;
}


int
virMediatedDeviceSetUsedBy(virMediatedDevice *dev,
                           const char *drvname,
                           const char *domname)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    dev->used_by_drvname = g_strdup(drvname);
    dev->used_by_domname = g_strdup(domname);

    return 0;
}


virMediatedDeviceList *
virMediatedDeviceListNew(void)
{
    virMediatedDeviceList *list;

    if (virMediatedInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virMediatedDeviceListClass)))
        return NULL;

    return list;
}


static void
virMediatedDeviceListDispose(void *obj)
{
    virMediatedDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        g_clear_pointer(&list->devs[i], virMediatedDeviceFree);
    }

    list->count = 0;
    g_free(list->devs);
}


/* The reason for @dev to be double pointer is that VIR_APPEND_ELEMENT clears
 * the pointer and we need to clear the original not a copy on the stack
 */
int
virMediatedDeviceListAdd(virMediatedDeviceList *list,
                         virMediatedDevice **dev)
{
    if (virMediatedDeviceListFind(list, (*dev)->path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device %1$s is already in use"), (*dev)->path);
        return -1;
    }
    VIR_APPEND_ELEMENT(list->devs, list->count, *dev);

    return 0;
}


virMediatedDevice *
virMediatedDeviceListGet(virMediatedDeviceList *list,
                         ssize_t idx)
{
    if (idx < 0 || idx >= list->count)
        return NULL;

    return list->devs[idx];
}


size_t
virMediatedDeviceListCount(virMediatedDeviceList *list)
{
    return list->count;
}


virMediatedDevice *
virMediatedDeviceListStealIndex(virMediatedDeviceList *list,
                                ssize_t idx)
{
    virMediatedDevice *ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}


virMediatedDevice *
virMediatedDeviceListSteal(virMediatedDeviceList *list,
                           virMediatedDevice *dev)
{
    int idx = -1;

    if (!dev)
        return NULL;

    idx = virMediatedDeviceListFindIndex(list, dev->path);

    return virMediatedDeviceListStealIndex(list, idx);
}


void
virMediatedDeviceListDel(virMediatedDeviceList *list,
                         virMediatedDevice *dev)
{
    virMediatedDeviceFree(virMediatedDeviceListSteal(list, dev));
}


int
virMediatedDeviceListFindIndex(virMediatedDeviceList *list,
                               const char *sysfspath)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virMediatedDevice *dev = list->devs[i];
        if (STREQ(sysfspath, dev->path))
            return i;
    }
    return -1;
}


virMediatedDevice *
virMediatedDeviceListFind(virMediatedDeviceList *list,
                          const char *sysfspath)
{
    int idx;

    if ((idx = virMediatedDeviceListFindIndex(list, sysfspath)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


bool
virMediatedDeviceIsUsed(virMediatedDevice *dev,
                        virMediatedDeviceList *list)
{
    const char *drvname, *domname;
    virMediatedDevice *tmp = NULL;

    if ((tmp = virMediatedDeviceListFind(list, dev->path))) {
        virMediatedDeviceGetUsedBy(tmp, &drvname, &domname);
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("mediated device %1$s is in use by driver %2$s, domain %3$s"),
                       tmp->path, drvname, domname);
    }

    return !!tmp;
}


char *
virMediatedDeviceGetSysfsPath(const char *uuidstr)
{
    return g_strdup_printf(MDEV_SYSFS_DEVICES "%s", uuidstr);
}


int
virMediatedDeviceListMarkDevices(virMediatedDeviceList *dst,
                                 virMediatedDeviceList *src,
                                 const char *drvname,
                                 const char *domname)
{
    int ret = -1;
    size_t count = virMediatedDeviceListCount(src);
    size_t i, j;

    virObjectLock(dst);
    for (i = 0; i < count; i++) {
        virMediatedDevice *mdev = virMediatedDeviceListGet(src, i);

        if (virMediatedDeviceIsUsed(mdev, dst) ||
            virMediatedDeviceSetUsedBy(mdev, drvname, domname) < 0)
            goto rollback;

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
        virMediatedDevice *tmp = virMediatedDeviceListGet(src, j);
        virMediatedDeviceListSteal(dst, tmp);
    }
    goto cleanup;
}


void
virMediatedDeviceTypeFree(virMediatedDeviceType *type)
{
    if (!type)
        return;

    g_free(type->id);
    g_free(type->name);
    g_free(type->device_api);
    g_free(type);
}


int
virMediatedDeviceTypeReadAttrs(const char *sysfspath,
                               virMediatedDeviceType **type)
{
    g_autoptr(virMediatedDeviceType) tmp = NULL;

#define MDEV_GET_SYSFS_ATTR(attr, dst, cb, optional) \
    do { \
        int rc; \
        if ((rc = cb(dst, "%s/%s", sysfspath, attr)) < 0) { \
            if (rc != -2 || !optional) \
                return -1; \
        } \
    } while (0)

    tmp = g_new0(virMediatedDeviceType, 1);

    tmp->id = g_path_get_basename(sysfspath);

    /* @name sysfs attribute is optional, so getting ENOENT is fine */
    MDEV_GET_SYSFS_ATTR("name", &tmp->name, virFileReadValueString, true);
    MDEV_GET_SYSFS_ATTR("device_api", &tmp->device_api,
                        virFileReadValueString, false);
    MDEV_GET_SYSFS_ATTR("available_instances", &tmp->available_instances,
                        virFileReadValueUint, false);

#undef MDEV_GET_SYSFS_ATTR

    *type = g_steal_pointer(&tmp);

    return 0;
}

virMediatedDeviceAttr *virMediatedDeviceAttrNew(void)
{
    return g_new0(virMediatedDeviceAttr, 1);
}

void virMediatedDeviceAttrFree(virMediatedDeviceAttr *attr)
{
    g_free(attr->name);
    g_free(attr->value);
    g_free(attr);
}


#define MDEV_BUS_DIR "/sys/class/mdev_bus"


int
virMediatedDeviceParentGetAddress(const char *sysfspath,
                                  char **address)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    if (virDirOpen(&dir, MDEV_BUS_DIR) < 0)
        return -1;

    /* check if one of the links in /sys/class/mdev_bus/ points at the sysfs
     * path for this device. If so, the link name is treated as the 'address'
     * for the mdev parent */
    while (virDirRead(dir, &entry, MDEV_BUS_DIR) > 0) {
        g_autofree char *tmppath = g_strdup_printf("%s/%s", MDEV_BUS_DIR,
                                                   entry->d_name);

        if (virFileLinkPointsTo(tmppath, sysfspath)) {
            *address = g_strdup(entry->d_name);
            return 0;
        }
    }

    return -1;
}

#ifdef __linux__

ssize_t
virMediatedDeviceGetMdevTypes(const char *sysfspath,
                              virMediatedDeviceType ***types,
                              size_t *ntypes)
{
    ssize_t ret = -1;
    int dirret = -1;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    g_autofree char *types_path = NULL;
    g_autoptr(virMediatedDeviceType) mdev_type = NULL;
    virMediatedDeviceType **mdev_types = NULL;
    size_t nmdev_types = 0;
    size_t i;

    types_path = g_strdup_printf("%s/mdev_supported_types", sysfspath);

    if ((dirret = virDirOpenIfExists(&dir, types_path)) < 0)
        goto cleanup;

    if (dirret == 0) {
        ret = 0;
        goto cleanup;
    }

    while ((dirret = virDirRead(dir, &entry, types_path)) > 0) {
        g_autofree char *tmppath = NULL;
        /* append the type id to the path and read the attributes from there */
        tmppath = g_strdup_printf("%s/%s", types_path, entry->d_name);

        if (virMediatedDeviceTypeReadAttrs(tmppath, &mdev_type) < 0)
            goto cleanup;

        VIR_APPEND_ELEMENT(mdev_types, nmdev_types, mdev_type);
    }

    if (dirret < 0)
        goto cleanup;

    *types = g_steal_pointer(&mdev_types);
    *ntypes = nmdev_types;
    nmdev_types = 0;
    ret = 0;
 cleanup:
    for (i = 0; i < nmdev_types; i++)
        virMediatedDeviceTypeFree(mdev_types[i]);
    VIR_FREE(mdev_types);
    return ret;
}

#else
static const char *unsupported = N_("not supported on non-linux platforms");

ssize_t
virMediatedDeviceGetMdevTypes(const char *sysfspath G_GNUC_UNUSED,
                              virMediatedDeviceType ***types G_GNUC_UNUSED,
                              size_t *ntypes G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

#endif /* __linux__ */
