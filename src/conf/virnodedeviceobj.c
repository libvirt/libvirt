/*
 * virnodedeviceobj.c: node device object handling
 *                     (derived from node_device_conf.c)
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

#include "datatypes.h"
#include "node_device_conf.h"

#include "viralloc.h"
#include "virnodedeviceobj.h"
#include "virerror.h"
#include "virhash.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("conf.virnodedeviceobj");

struct _virNodeDeviceObj {
    virObjectLockable parent;

    virNodeDeviceDefPtr def;            /* device definition */
    bool skipUpdateCaps;                /* whether to skip checking host caps,
                                           used by testdriver */
};

struct _virNodeDeviceObjList {
    virObjectRWLockable parent;

    /* name string -> virNodeDeviceObj mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objs;

};


static virClassPtr virNodeDeviceObjClass;
static virClassPtr virNodeDeviceObjListClass;
static void virNodeDeviceObjDispose(void *opaque);
static void virNodeDeviceObjListDispose(void *opaque);
static bool virNodeDeviceObjHasCap(const virNodeDeviceObj *obj, int type);

static int
virNodeDeviceObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNodeDeviceObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virNodeDeviceObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNodeDeviceObj);


static void
virNodeDeviceObjDispose(void *opaque)
{
    virNodeDeviceObjPtr obj = opaque;

    virNodeDeviceDefFree(obj->def);
}


static virNodeDeviceObjPtr
virNodeDeviceObjNew(void)
{
    virNodeDeviceObjPtr obj;

    if (virNodeDeviceObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virNodeDeviceObjClass)))
        return NULL;

    virObjectLock(obj);

    return obj;
}


void
virNodeDeviceObjEndAPI(virNodeDeviceObjPtr *obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    virObjectUnref(*obj);
    *obj = NULL;
}


virNodeDeviceDefPtr
virNodeDeviceObjGetDef(virNodeDeviceObjPtr obj)
{
    return obj->def;
}


static bool
virNodeDeviceObjHasCapStr(const virNodeDeviceObj *obj,
                          const char *cap)
{
    int type;

    if ((type = virNodeDevCapTypeFromString(cap)) < 0)
        return false;

    return virNodeDeviceObjHasCap(obj, type);
}


/* virNodeDeviceFindFCCapDef:
 * @obj: Pointer to current device
 *
 * Search the device object 'caps' array for fc_host capability.
 *
 * Returns:
 * Pointer to the caps or NULL if not found
 */
static virNodeDevCapsDefPtr
virNodeDeviceFindFCCapDef(const virNodeDeviceObj *obj)
{
    virNodeDevCapsDefPtr caps = obj->def->caps;

    while (caps) {
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST))
            break;

        caps = caps->next;
    }
    return caps;
}


/* virNodeDeviceFindVPORTCapDef:
 * @obj: Pointer to current device
 *
 * Search the device object 'caps' array for vport_ops capability.
 *
 * Returns:
 * Pointer to the caps or NULL if not found
 */
static virNodeDevCapsDefPtr
virNodeDeviceFindVPORTCapDef(const virNodeDeviceObj *obj)
{
    virNodeDevCapsDefPtr caps = obj->def->caps;

    while (caps) {
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS))
            break;

        caps = caps->next;
    }
    return caps;
}


static virNodeDeviceObjPtr
virNodeDeviceObjListSearch(virNodeDeviceObjListPtr devs,
                           virHashSearcher callback,
                           const void *data)
{
    virNodeDeviceObjPtr obj;

    virObjectRWLockRead(devs);
    obj = virHashSearch(devs->objs, callback, data, NULL);
    virObjectRef(obj);
    virObjectRWUnlock(devs);

    if (obj)
        virObjectLock(obj);

    return obj;
}


static int
virNodeDeviceObjListFindBySysfsPathCallback(const void *payload,
                                            const void *name G_GNUC_UNUSED,
                                            const void *opaque)
{
    virNodeDeviceObjPtr obj = (virNodeDeviceObjPtr) payload;
    const char *sysfs_path = opaque;
    int want = 0;

    virObjectLock(obj);
    if (obj->def->sysfs_path &&
        STREQ_NULLABLE(obj->def->sysfs_path, sysfs_path))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


virNodeDeviceObjPtr
virNodeDeviceObjListFindBySysfsPath(virNodeDeviceObjListPtr devs,
                                    const char *sysfs_path)
{
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindBySysfsPathCallback,
                                      sysfs_path);
}


static virNodeDeviceObjPtr
virNodeDeviceObjListFindByNameLocked(virNodeDeviceObjListPtr devs,
                                     const char *name)
{
    return virObjectRef(virHashLookup(devs->objs, name));
}


virNodeDeviceObjPtr
virNodeDeviceObjListFindByName(virNodeDeviceObjListPtr devs,
                               const char *name)
{
    virNodeDeviceObjPtr obj;

    virObjectRWLockRead(devs);
    obj = virNodeDeviceObjListFindByNameLocked(devs, name);
    virObjectRWUnlock(devs);
    if (obj)
        virObjectLock(obj);

    return obj;
}


struct virNodeDeviceObjListFindByWWNsData {
    const char *parent_wwnn;
    const char *parent_wwpn;
};

static int
virNodeDeviceObjListFindByWWNsCallback(const void *payload,
                                       const void *name G_GNUC_UNUSED,
                                       const void *opaque)
{
    virNodeDeviceObjPtr obj = (virNodeDeviceObjPtr) payload;
    struct virNodeDeviceObjListFindByWWNsData *data =
        (struct virNodeDeviceObjListFindByWWNsData *) opaque;
    virNodeDevCapsDefPtr cap;
    int want = 0;

    virObjectLock(obj);
    if ((cap = virNodeDeviceFindFCCapDef(obj)) &&
        STREQ_NULLABLE(cap->data.scsi_host.wwnn, data->parent_wwnn) &&
        STREQ_NULLABLE(cap->data.scsi_host.wwpn, data->parent_wwpn) &&
        virNodeDeviceFindVPORTCapDef(obj))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNodeDeviceObjPtr
virNodeDeviceObjListFindByWWNs(virNodeDeviceObjListPtr devs,
                               const char *parent_wwnn,
                               const char *parent_wwpn)
{
    struct virNodeDeviceObjListFindByWWNsData data = {
        .parent_wwnn = parent_wwnn, .parent_wwpn = parent_wwpn };

    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindByWWNsCallback,
                                      &data);
}


static int
virNodeDeviceObjListFindByFabricWWNCallback(const void *payload,
                                            const void *name G_GNUC_UNUSED,
                                            const void *opaque)
{
    virNodeDeviceObjPtr obj = (virNodeDeviceObjPtr) payload;
    const char *matchstr = opaque;
    virNodeDevCapsDefPtr cap;
    int want = 0;

    virObjectLock(obj);
    if ((cap = virNodeDeviceFindFCCapDef(obj)) &&
        STREQ_NULLABLE(cap->data.scsi_host.fabric_wwn, matchstr) &&
        virNodeDeviceFindVPORTCapDef(obj))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNodeDeviceObjPtr
virNodeDeviceObjListFindByFabricWWN(virNodeDeviceObjListPtr devs,
                                    const char *parent_fabric_wwn)
{
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindByFabricWWNCallback,
                                      parent_fabric_wwn);
}


static int
virNodeDeviceObjListFindByCapCallback(const void *payload,
                                      const void *name G_GNUC_UNUSED,
                                      const void *opaque)
{
    virNodeDeviceObjPtr obj = (virNodeDeviceObjPtr) payload;
    const char *matchstr = opaque;
    int want = 0;

    virObjectLock(obj);
    if (virNodeDeviceObjHasCapStr(obj, matchstr))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNodeDeviceObjPtr
virNodeDeviceObjListFindByCap(virNodeDeviceObjListPtr devs,
                              const char *cap)
{
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindByCapCallback,
                                      cap);
}


struct virNodeDeviceObjListFindSCSIHostByWWNsData {
    const char *wwnn;
    const char *wwpn;
};

static int
virNodeDeviceObjListFindSCSIHostByWWNsCallback(const void *payload,
                                               const void *name G_GNUC_UNUSED,
                                               const void *opaque)
{
    virNodeDeviceObjPtr obj = (virNodeDeviceObjPtr) payload;
    struct virNodeDeviceObjListFindSCSIHostByWWNsData *data =
        (struct virNodeDeviceObjListFindSCSIHostByWWNsData *) opaque;
    virNodeDevCapsDefPtr cap;
    int want = 0;

    virObjectLock(obj);
    cap = obj->def->caps;

    while (cap) {
        if (cap->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            virNodeDeviceGetSCSIHostCaps(&cap->data.scsi_host);
            if (cap->data.scsi_host.flags &
                VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                if (STREQ(cap->data.scsi_host.wwnn, data->wwnn) &&
                    STREQ(cap->data.scsi_host.wwpn, data->wwpn)) {
                    want = 1;
                    break;
                }
            }
        }
        cap = cap->next;
     }

    virObjectUnlock(obj);
    return want;
}


virNodeDeviceObjPtr
virNodeDeviceObjListFindSCSIHostByWWNs(virNodeDeviceObjListPtr devs,
                                       const char *wwnn,
                                       const char *wwpn)
{
    struct virNodeDeviceObjListFindSCSIHostByWWNsData data = {
        .wwnn = wwnn, .wwpn = wwpn };

    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindSCSIHostByWWNsCallback,
                                      &data);
}


static void
virNodeDeviceObjListDispose(void *obj)
{
    virNodeDeviceObjListPtr devs = obj;

    virHashFree(devs->objs);
}


virNodeDeviceObjListPtr
virNodeDeviceObjListNew(void)
{
    virNodeDeviceObjListPtr devs;

    if (virNodeDeviceObjInitialize() < 0)
        return NULL;

    if (!(devs = virObjectRWLockableNew(virNodeDeviceObjListClass)))
        return NULL;

    if (!(devs->objs = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(devs);
        return NULL;
    }

    return devs;
}


void
virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs)
{
    virObjectUnref(devs);
}


virNodeDeviceObjPtr
virNodeDeviceObjListAssignDef(virNodeDeviceObjListPtr devs,
                              virNodeDeviceDefPtr def)
{
    virNodeDeviceObjPtr obj;

    virObjectRWLockWrite(devs);

    if ((obj = virNodeDeviceObjListFindByNameLocked(devs, def->name))) {
        virObjectLock(obj);
        virNodeDeviceDefFree(obj->def);
        obj->def = def;
    } else {
        if (!(obj = virNodeDeviceObjNew()))
            goto cleanup;

        if (virHashAddEntry(devs->objs, def->name, obj) < 0) {
            virNodeDeviceObjEndAPI(&obj);
            goto cleanup;
        }

        obj->def = def;
        virObjectRef(obj);
    }

 cleanup:
    virObjectRWUnlock(devs);
    return obj;
}


void
virNodeDeviceObjListRemove(virNodeDeviceObjListPtr devs,
                           virNodeDeviceObjPtr obj)
{
    virNodeDeviceDefPtr def;

    if (!obj)
        return;
    def = obj->def;

    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(devs);
    virObjectLock(obj);
    virHashRemoveEntry(devs->objs, def->name);
    virObjectUnlock(obj);
    virObjectUnref(obj);
    virObjectRWUnlock(devs);
}


/*
 * Return the NPIV dev's parent device name
 */
/* virNodeDeviceFindFCParentHost:
 * @obj: Pointer to node device object
 *
 * Search the capabilities for the device to find the FC capabilities
 * in order to set the parent_host value.
 *
 * Returns:
 *   parent_host value on success (>= 0), -1 otherwise.
 */
static int
virNodeDeviceFindFCParentHost(virNodeDeviceObjPtr obj)
{
    virNodeDevCapsDefPtr cap = virNodeDeviceFindVPORTCapDef(obj);

    if (!cap) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parent device %s is not capable "
                         "of vport operations"),
                       obj->def->name);
        return -1;
    }

    return cap->data.scsi_host.host;
}


static int
virNodeDeviceObjListGetParentHostByParent(virNodeDeviceObjListPtr devs,
                                          const char *dev_name,
                                          const char *parent_name)
{
    virNodeDeviceObjPtr obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByName(devs, parent_name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListGetParentHostByWWNs(virNodeDeviceObjListPtr devs,
                                        const char *dev_name,
                                        const char *parent_wwnn,
                                        const char *parent_wwpn)
{
    virNodeDeviceObjPtr obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByWWNs(devs, parent_wwnn,
                                               parent_wwpn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListGetParentHostByFabricWWN(virNodeDeviceObjListPtr devs,
                                             const char *dev_name,
                                             const char *parent_fabric_wwn)
{
    virNodeDeviceObjPtr obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByFabricWWN(devs, parent_fabric_wwn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListFindVportParentHost(virNodeDeviceObjListPtr devs)
{
    virNodeDeviceObjPtr obj = NULL;
    const char *cap = virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_VPORTS);
    int ret;

    if (!(obj = virNodeDeviceObjListFindByCap(devs, cap))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any vport capable device"));
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


int
virNodeDeviceObjListGetParentHost(virNodeDeviceObjListPtr devs,
                                  virNodeDeviceDefPtr def)
{
    int parent_host = -1;

    if (def->parent) {
        parent_host = virNodeDeviceObjListGetParentHostByParent(devs, def->name,
                                                                def->parent);
    } else if (def->parent_wwnn && def->parent_wwpn) {
        parent_host = virNodeDeviceObjListGetParentHostByWWNs(devs, def->name,
                                                              def->parent_wwnn,
                                                              def->parent_wwpn);
    } else if (def->parent_fabric_wwn) {
        parent_host =
            virNodeDeviceObjListGetParentHostByFabricWWN(devs, def->name,
                                                         def->parent_fabric_wwn);
    } else {
        /* Try to find a vport capable scsi_host when no parent supplied */
        parent_host = virNodeDeviceObjListFindVportParentHost(devs);
    }

    return parent_host;
}


static bool
virNodeDeviceObjHasCap(const virNodeDeviceObj *obj,
                       int type)
{
    virNodeDevCapsDefPtr cap = NULL;

    for (cap = obj->def->caps; cap; cap = cap->next) {
        if (type == cap->data.type)
            return true;

        switch (cap->data.type) {
        case VIR_NODE_DEV_CAP_PCI_DEV:
            if (type == VIR_NODE_DEV_CAP_MDEV_TYPES &&
                (cap->data.pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_MDEV))
                return true;
            break;

        case VIR_NODE_DEV_CAP_SCSI_HOST:
            if (type == VIR_NODE_DEV_CAP_FC_HOST &&
                (cap->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST))
                return true;

            if (type == VIR_NODE_DEV_CAP_VPORTS &&
                (cap->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS))
                return true;
            break;

        case VIR_NODE_DEV_CAP_SYSTEM:
        case VIR_NODE_DEV_CAP_USB_DEV:
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
        case VIR_NODE_DEV_CAP_NET:
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
        case VIR_NODE_DEV_CAP_SCSI:
        case VIR_NODE_DEV_CAP_STORAGE:
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        case VIR_NODE_DEV_CAP_DRM:
        case VIR_NODE_DEV_CAP_MDEV_TYPES:
        case VIR_NODE_DEV_CAP_MDEV:
        case VIR_NODE_DEV_CAP_CCW_DEV:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }
    }

    return false;
}


struct virNodeDeviceCountData {
    virConnectPtr conn;
    virNodeDeviceObjListFilter filter;
    const char *matchstr;
    int count;
};

static int
virNodeDeviceObjListNumOfDevicesCallback(void *payload,
                                         const void *name G_GNUC_UNUSED,
                                         void *opaque)
{
    virNodeDeviceObjPtr obj = payload;
    virNodeDeviceDefPtr def;
    struct virNodeDeviceCountData *data = opaque;
    virNodeDeviceObjListFilter filter = data->filter;

    virObjectLock(obj);
    def = obj->def;
    if ((!filter || filter(data->conn, def)) &&
        (!data->matchstr || virNodeDeviceObjHasCapStr(obj, data->matchstr)))
        data->count++;

    virObjectUnlock(obj);
    return 0;
}


int
virNodeDeviceObjListNumOfDevices(virNodeDeviceObjListPtr devs,
                                 virConnectPtr conn,
                                 const char *cap,
                                 virNodeDeviceObjListFilter filter)
{
    struct virNodeDeviceCountData data = {
        .conn = conn, .filter = filter, .matchstr = cap, .count = 0 };

    virObjectRWLockRead(devs);
    virHashForEach(devs->objs, virNodeDeviceObjListNumOfDevicesCallback, &data);
    virObjectRWUnlock(devs);

    return data.count;
}


struct virNodeDeviceGetNamesData {
    virConnectPtr conn;
    virNodeDeviceObjListFilter filter;
    const char *matchstr;
    int nnames;
    char **names;
    int maxnames;
    bool error;
};

static int
virNodeDeviceObjListGetNamesCallback(void *payload,
                                     const void *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virNodeDeviceObjPtr obj = payload;
    virNodeDeviceDefPtr def;
    struct virNodeDeviceGetNamesData *data = opaque;
    virNodeDeviceObjListFilter filter = data->filter;

    if (data->error)
        return 0;

    if (data->nnames >= data->maxnames)
        return 0;

    virObjectLock(obj);
    def = obj->def;

    if ((!filter || filter(data->conn, def)) &&
        (!data->matchstr || virNodeDeviceObjHasCapStr(obj, data->matchstr))) {
        if (VIR_STRDUP(data->names[data->nnames], def->name) < 0) {
            data->error = true;
            goto cleanup;
        }
        data->nnames++;
     }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virNodeDeviceObjListGetNames(virNodeDeviceObjListPtr devs,
                             virConnectPtr conn,
                             virNodeDeviceObjListFilter filter,
                             const char *cap,
                             char **const names,
                             int maxnames)
{
    struct virNodeDeviceGetNamesData data = {
        .conn = conn, .filter = filter, .matchstr = cap, .names = names,
        .nnames = 0, .maxnames = maxnames, .error = false };

    virObjectRWLockRead(devs);
    virHashForEach(devs->objs, virNodeDeviceObjListGetNamesCallback, &data);
    virObjectRWUnlock(devs);

    if (data.error)
        goto error;

    return data.nnames;

 error:
    while (--data.nnames)
        VIR_FREE(data.names[data.nnames]);
    return -1;
}


#define MATCH(FLAG) ((flags & (VIR_CONNECT_LIST_NODE_DEVICES_CAP_ ## FLAG)) && \
                     virNodeDeviceObjHasCap(obj, VIR_NODE_DEV_CAP_ ## FLAG))
static bool
virNodeDeviceObjMatch(virNodeDeviceObjPtr obj,
                      unsigned int flags)
{
    /* Refresh the capabilities first, e.g. due to a driver change */
    if (!obj->skipUpdateCaps &&
        virNodeDeviceUpdateCaps(obj->def) < 0)
        return false;

    /* filter by cap type */
    if (flags & VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP) {
        if (!(MATCH(SYSTEM)        ||
              MATCH(PCI_DEV)       ||
              MATCH(USB_DEV)       ||
              MATCH(USB_INTERFACE) ||
              MATCH(NET)           ||
              MATCH(SCSI_HOST)     ||
              MATCH(SCSI_TARGET)   ||
              MATCH(SCSI)          ||
              MATCH(STORAGE)       ||
              MATCH(FC_HOST)       ||
              MATCH(VPORTS)        ||
              MATCH(SCSI_GENERIC)  ||
              MATCH(DRM)           ||
              MATCH(MDEV_TYPES)    ||
              MATCH(MDEV)          ||
              MATCH(CCW_DEV)))
            return false;
    }

    return true;
}
#undef MATCH


typedef struct _virNodeDeviceObjListExportData virNodeDeviceObjListExportData;
typedef virNodeDeviceObjListExportData *virNodeDeviceObjListExportDataPtr;
struct _virNodeDeviceObjListExportData {
    virConnectPtr conn;
    virNodeDeviceObjListFilter filter;
    unsigned int flags;
    virNodeDevicePtr *devices;
    int ndevices;
    bool error;
};

static int
virNodeDeviceObjListExportCallback(void *payload,
                                   const void *name G_GNUC_UNUSED,
                                   void *opaque)
{
    virNodeDeviceObjPtr obj = payload;
    virNodeDeviceDefPtr def;
    virNodeDeviceObjListExportDataPtr data = opaque;
    virNodeDevicePtr device = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);
    def = obj->def;

    if ((!data->filter || data->filter(data->conn, def)) &&
        virNodeDeviceObjMatch(obj, data->flags)) {
        if (data->devices) {
            if (!(device = virGetNodeDevice(data->conn, def->name)) ||
                VIR_STRDUP(device->parentName, def->parent) < 0) {
                virObjectUnref(device);
                data->error = true;
                goto cleanup;
            }
            data->devices[data->ndevices] = device;
        }
        data->ndevices++;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virNodeDeviceObjListExport(virConnectPtr conn,
                           virNodeDeviceObjListPtr devs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter filter,
                           unsigned int flags)
{
    virNodeDeviceObjListExportData data = {
        .conn = conn, .filter = filter, .flags = flags,
        .devices = NULL, .ndevices = 0, .error = false };

    virObjectRWLockRead(devs);
    if (devices &&
        VIR_ALLOC_N(data.devices, virHashSize(devs->objs) + 1) < 0) {
        virObjectRWUnlock(devs);
        return -1;
    }

    virHashForEach(devs->objs, virNodeDeviceObjListExportCallback, &data);
    virObjectRWUnlock(devs);

    if (data.error)
        goto cleanup;

    if (data.devices) {
        ignore_value(VIR_REALLOC_N(data.devices, data.ndevices + 1));
        *devices = data.devices;
     }

    return data.ndevices;

 cleanup:
    virObjectListFree(data.devices);
    return -1;
}


void
virNodeDeviceObjSetSkipUpdateCaps(virNodeDeviceObjPtr obj,
                                  bool skipUpdateCaps)
{
    obj->skipUpdateCaps = skipUpdateCaps;
}
