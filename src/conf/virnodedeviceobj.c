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

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("conf.virnodedeviceobj");

struct _virNodeDeviceObj {
    virObjectLockable parent;

    virNodeDeviceDef *def;            /* device definition */
    bool skipUpdateCaps;                /* whether to skip checking host caps,
                                           used by testdriver */
    bool active;
    bool persistent;
    bool autostart;
};

struct _virNodeDeviceObjList {
    virObjectRWLockable parent;

    /* name string -> virNodeDeviceObj mapping
     * for O(1), lookup-by-name */
    GHashTable *objs;

};


static virClass *virNodeDeviceObjClass;
static virClass *virNodeDeviceObjListClass;
static void virNodeDeviceObjDispose(void *opaque);
static void virNodeDeviceObjListDispose(void *opaque);

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
    virNodeDeviceObj *obj = opaque;

    virNodeDeviceDefFree(obj->def);
}


static virNodeDeviceObj *
virNodeDeviceObjNew(void)
{
    virNodeDeviceObj *obj;

    if (virNodeDeviceObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virNodeDeviceObjClass)))
        return NULL;

    virObjectLock(obj);

    return obj;
}


void
virNodeDeviceObjEndAPI(virNodeDeviceObj **obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    g_clear_pointer(obj, virObjectUnref);
}


virNodeDeviceDef *
virNodeDeviceObjGetDef(virNodeDeviceObj *obj)
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
static virNodeDevCapsDef *
virNodeDeviceFindFCCapDef(const virNodeDeviceObj *obj)
{
    virNodeDevCapsDef *caps = obj->def->caps;

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
static virNodeDevCapsDef *
virNodeDeviceFindVPORTCapDef(const virNodeDeviceObj *obj)
{
    virNodeDevCapsDef *caps = obj->def->caps;

    while (caps) {
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS))
            break;

        caps = caps->next;
    }
    return caps;
}


static virNodeDeviceObj *
virNodeDeviceObjListSearch(virNodeDeviceObjList *devs,
                           virHashSearcher callback,
                           const void *data)
{
    virNodeDeviceObj *obj;

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
                                            const char *name G_GNUC_UNUSED,
                                            const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    const char *sysfs_path = opaque;
    int want = 0;

    virObjectLock(obj);
    if (obj->def->sysfs_path &&
        STREQ_NULLABLE(obj->def->sysfs_path, sysfs_path))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


virNodeDeviceObj *
virNodeDeviceObjListFindBySysfsPath(virNodeDeviceObjList *devs,
                                    const char *sysfs_path)
{
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindBySysfsPathCallback,
                                      sysfs_path);
}


static virNodeDeviceObj *
virNodeDeviceObjListFindByNameLocked(virNodeDeviceObjList *devs,
                                     const char *name)
{
    return virObjectRef(virHashLookup(devs->objs, name));
}


virNodeDeviceObj *
virNodeDeviceObjListFindByName(virNodeDeviceObjList *devs,
                               const char *name)
{
    virNodeDeviceObj *obj;

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
                                       const char *name G_GNUC_UNUSED,
                                       const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    struct virNodeDeviceObjListFindByWWNsData *data =
        (struct virNodeDeviceObjListFindByWWNsData *) opaque;
    virNodeDevCapsDef *cap;
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


static virNodeDeviceObj *
virNodeDeviceObjListFindByWWNs(virNodeDeviceObjList *devs,
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
                                            const char *name G_GNUC_UNUSED,
                                            const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    const char *matchstr = opaque;
    virNodeDevCapsDef *cap;
    int want = 0;

    virObjectLock(obj);
    if ((cap = virNodeDeviceFindFCCapDef(obj)) &&
        STREQ_NULLABLE(cap->data.scsi_host.fabric_wwn, matchstr) &&
        virNodeDeviceFindVPORTCapDef(obj))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNodeDeviceObj *
virNodeDeviceObjListFindByFabricWWN(virNodeDeviceObjList *devs,
                                    const char *parent_fabric_wwn)
{
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindByFabricWWNCallback,
                                      parent_fabric_wwn);
}


static int
virNodeDeviceObjListFindByCapCallback(const void *payload,
                                      const char *name G_GNUC_UNUSED,
                                      const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    const char *matchstr = opaque;
    int want = 0;

    virObjectLock(obj);
    if (virNodeDeviceObjHasCapStr(obj, matchstr))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNodeDeviceObj *
virNodeDeviceObjListFindByCap(virNodeDeviceObjList *devs,
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
                                               const char *name G_GNUC_UNUSED,
                                               const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    struct virNodeDeviceObjListFindSCSIHostByWWNsData *data =
        (struct virNodeDeviceObjListFindSCSIHostByWWNsData *) opaque;
    virNodeDevCapsDef *cap;
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


virNodeDeviceObj *
virNodeDeviceObjListFindSCSIHostByWWNs(virNodeDeviceObjList *devs,
                                       const char *wwnn,
                                       const char *wwpn)
{
    struct virNodeDeviceObjListFindSCSIHostByWWNsData data = {
        .wwnn = wwnn, .wwpn = wwpn };

    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindSCSIHostByWWNsCallback,
                                      &data);
}


typedef struct _FindMediatedDeviceData FindMediatedDeviceData;
struct _FindMediatedDeviceData {
    const char *uuid;
    const char *parent_addr;
};


static int
virNodeDeviceObjListFindMediatedDeviceByUUIDCallback(const void *payload,
                                                     const char *name G_GNUC_UNUSED,
                                                     const void *opaque)
{
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;
    const FindMediatedDeviceData* data = opaque;
    virNodeDevCapsDef *cap;
    int want = 0;

    virObjectLock(obj);

    for (cap = obj->def->caps; cap != NULL; cap = cap->next) {
        if (cap->data.type == VIR_NODE_DEV_CAP_MDEV) {
            if (STREQ(cap->data.mdev.uuid, data->uuid) &&
                STREQ(cap->data.mdev.parent_addr, data->parent_addr)) {
                want = 1;
                break;
            }
        }
     }

    virObjectUnlock(obj);
    return want;
}


virNodeDeviceObj *
virNodeDeviceObjListFindMediatedDeviceByUUID(virNodeDeviceObjList *devs,
                                             const char *uuid,
                                             const char *parent_addr)
{
    const FindMediatedDeviceData data = {uuid, parent_addr};
    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindMediatedDeviceByUUIDCallback,
                                      &data);
}

static void
virNodeDeviceObjListDispose(void *obj)
{
    virNodeDeviceObjList *devs = obj;

    g_clear_pointer(&devs->objs, g_hash_table_unref);
}


virNodeDeviceObjList *
virNodeDeviceObjListNew(void)
{
    virNodeDeviceObjList *devs;

    if (virNodeDeviceObjInitialize() < 0)
        return NULL;

    if (!(devs = virObjectRWLockableNew(virNodeDeviceObjListClass)))
        return NULL;

    devs->objs = virHashNew(virObjectUnref);

    return devs;
}


void
virNodeDeviceObjListFree(virNodeDeviceObjList *devs)
{
    virObjectUnref(devs);
}


virNodeDeviceObj *
virNodeDeviceObjListAssignDef(virNodeDeviceObjList *devs,
                              virNodeDeviceDef *def)
{
    virNodeDeviceObj *obj;

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
virNodeDeviceObjListRemove(virNodeDeviceObjList *devs,
                           virNodeDeviceObj *obj)
{
    if (!obj)
        return;

    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(devs);
    virObjectLock(obj);
    virNodeDeviceObjListRemoveLocked(devs, obj);
    virObjectUnref(obj);
    virObjectRWUnlock(devs);
}


/* The caller must hold lock on 'devs' */
void
virNodeDeviceObjListRemoveLocked(virNodeDeviceObjList *devs,
                                 virNodeDeviceObj *dev)
{
    virHashRemoveEntry(devs->objs, dev->def->name);
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
virNodeDeviceFindFCParentHost(virNodeDeviceObj *obj)
{
    virNodeDevCapsDef *cap = virNodeDeviceFindVPORTCapDef(obj);

    if (!cap) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parent device %1$s is not capable of vport operations"),
                       obj->def->name);
        return -1;
    }

    return cap->data.scsi_host.host;
}


static int
virNodeDeviceObjListGetParentHostByParent(virNodeDeviceObjList *devs,
                                          const char *dev_name,
                                          const char *parent_name)
{
    virNodeDeviceObj *obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByName(devs, parent_name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%1$s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListGetParentHostByWWNs(virNodeDeviceObjList *devs,
                                        const char *dev_name,
                                        const char *parent_wwnn,
                                        const char *parent_wwpn)
{
    virNodeDeviceObj *obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByWWNs(devs, parent_wwnn,
                                               parent_wwpn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%1$s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListGetParentHostByFabricWWN(virNodeDeviceObjList *devs,
                                             const char *dev_name,
                                             const char *parent_fabric_wwn)
{
    virNodeDeviceObj *obj = NULL;
    int ret;

    if (!(obj = virNodeDeviceObjListFindByFabricWWN(devs, parent_fabric_wwn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%1$s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(obj);

    virNodeDeviceObjEndAPI(&obj);

    return ret;
}


static int
virNodeDeviceObjListFindVportParentHost(virNodeDeviceObjList *devs)
{
    virNodeDeviceObj *obj = NULL;
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
virNodeDeviceObjListGetParentHost(virNodeDeviceObjList *devs,
                                  virNodeDeviceDef *def)
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


bool
virNodeDeviceObjHasCap(const virNodeDeviceObj *obj,
                       int type)
{
    virNodeDevCapsDef *cap = NULL;

    for (cap = obj->def->caps; cap; cap = cap->next) {
        if (type == cap->data.type)
            return true;

        switch (cap->data.type) {
        case VIR_NODE_DEV_CAP_PCI_DEV:
            if (type == VIR_NODE_DEV_CAP_MDEV_TYPES &&
                (cap->data.pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_MDEV))
                return true;
            if (type == VIR_NODE_DEV_CAP_VPD &&
                (cap->data.pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_VPD))
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

        case VIR_NODE_DEV_CAP_CSS_DEV:
            if (type == VIR_NODE_DEV_CAP_MDEV_TYPES &&
                (cap->data.ccw_dev.flags & VIR_NODE_DEV_CAP_FLAG_CSS_MDEV))
                return true;
            break;

        case VIR_NODE_DEV_CAP_AP_MATRIX:
            if (type == VIR_NODE_DEV_CAP_MDEV_TYPES &&
                (cap->data.ap_matrix.flags & VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV))
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
        case VIR_NODE_DEV_CAP_VDPA:
        case VIR_NODE_DEV_CAP_AP_CARD:
        case VIR_NODE_DEV_CAP_AP_QUEUE:
        case VIR_NODE_DEV_CAP_VPD:
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
                                         const char *name G_GNUC_UNUSED,
                                         void *opaque)
{
    virNodeDeviceObj *obj = payload;
    virNodeDeviceDef *def;
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
virNodeDeviceObjListNumOfDevices(virNodeDeviceObjList *devs,
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
                                     const char *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virNodeDeviceObj *obj = payload;
    virNodeDeviceDef *def;
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
        data->names[data->nnames] = g_strdup(def->name);
        data->nnames++;
     }

    virObjectUnlock(obj);
    return 0;
}


int
virNodeDeviceObjListGetNames(virNodeDeviceObjList *devs,
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


#define MATCH_CAP(FLAG) ((flags & (VIR_CONNECT_LIST_NODE_DEVICES_CAP_ ## FLAG)) && \
                         virNodeDeviceObjHasCap(obj, VIR_NODE_DEV_CAP_ ## FLAG))
#define MATCH(FLAG) (flags & (FLAG))

static bool
virNodeDeviceObjMatch(virNodeDeviceObj *obj,
                      unsigned int flags)
{
    /* Refresh the capabilities first, e.g. due to a driver change */
    if (!obj->skipUpdateCaps &&
        virNodeDeviceUpdateCaps(obj->def) < 0)
        return false;

    /* filter by cap type */
    if (flags & VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP) {
        if (!(MATCH_CAP(SYSTEM)        ||
              MATCH_CAP(PCI_DEV)       ||
              MATCH_CAP(USB_DEV)       ||
              MATCH_CAP(USB_INTERFACE) ||
              MATCH_CAP(NET)           ||
              MATCH_CAP(SCSI_HOST)     ||
              MATCH_CAP(SCSI_TARGET)   ||
              MATCH_CAP(SCSI)          ||
              MATCH_CAP(STORAGE)       ||
              MATCH_CAP(FC_HOST)       ||
              MATCH_CAP(VPORTS)        ||
              MATCH_CAP(SCSI_GENERIC)  ||
              MATCH_CAP(DRM)           ||
              MATCH_CAP(MDEV_TYPES)    ||
              MATCH_CAP(MDEV)          ||
              MATCH_CAP(CCW_DEV)       ||
              MATCH_CAP(CSS_DEV)       ||
              MATCH_CAP(VDPA)          ||
              MATCH_CAP(AP_CARD)       ||
              MATCH_CAP(AP_QUEUE)      ||
              MATCH_CAP(AP_MATRIX)     ||
              MATCH_CAP(VPD)))
            return false;
    }

    if (flags & (VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_ACTIVE)) {
        if (!((MATCH(VIR_CONNECT_LIST_NODE_DEVICES_ACTIVE) &&
              virNodeDeviceObjIsActive(obj)) ||
              (MATCH(VIR_CONNECT_LIST_NODE_DEVICES_INACTIVE) &&
               !virNodeDeviceObjIsActive(obj))))
            return false;
    }

    return true;
}
#undef MATCH
#undef MATCH_CAP


typedef struct _virNodeDeviceObjListExportData virNodeDeviceObjListExportData;
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
                                   const char *name G_GNUC_UNUSED,
                                   void *opaque)
{
    virNodeDeviceObj *obj = payload;
    virNodeDeviceDef *def;
    virNodeDeviceObjListExportData *data = opaque;
    virNodeDevicePtr device = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);
    def = obj->def;

    if ((!data->filter || data->filter(data->conn, def)) &&
        virNodeDeviceObjMatch(obj, data->flags)) {
        if (data->devices) {
            if (!(device = virGetNodeDevice(data->conn, def->name))) {
                virObjectUnref(device);
                data->error = true;
                goto cleanup;
            }
            device->parentName = g_strdup(def->parent);
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
                           virNodeDeviceObjList *devs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter filter,
                           unsigned int flags)
{
    virNodeDeviceObjListExportData data = {
        .conn = conn, .filter = filter, .flags = flags,
        .devices = NULL, .ndevices = 0, .error = false };

    virObjectRWLockRead(devs);
    if (devices)
        data.devices = g_new0(virNodeDevicePtr, virHashSize(devs->objs) + 1);

    virHashForEach(devs->objs, virNodeDeviceObjListExportCallback, &data);
    virObjectRWUnlock(devs);

    if (data.error)
        goto cleanup;

    if (data.devices) {
        VIR_REALLOC_N(data.devices, data.ndevices + 1);
        *devices = data.devices;
     }

    return data.ndevices;

 cleanup:
    virObjectListFree(data.devices);
    return -1;
}


void
virNodeDeviceObjSetSkipUpdateCaps(virNodeDeviceObj *obj,
                                  bool skipUpdateCaps)
{
    obj->skipUpdateCaps = skipUpdateCaps;
}


bool
virNodeDeviceObjIsActive(virNodeDeviceObj *obj)
{
    return obj->active;
}


void
virNodeDeviceObjSetActive(virNodeDeviceObj *obj,
                          bool active)
{
    obj->active = active;
}


bool
virNodeDeviceObjIsPersistent(virNodeDeviceObj *obj)
{
    return obj->persistent;
}


void
virNodeDeviceObjSetPersistent(virNodeDeviceObj *obj,
                              bool persistent)
{
    obj->persistent = persistent;
}


bool
virNodeDeviceObjIsAutostart(virNodeDeviceObj *obj)
{
    return obj->autostart;
}


void
virNodeDeviceObjSetAutostart(virNodeDeviceObj *obj,
                             bool autostart)
{
    obj->autostart = autostart;
}


typedef struct _PredicateHelperData PredicateHelperData;
struct _PredicateHelperData {
    virNodeDeviceObjListPredicate predicate;
    void *opaque;
};

static int virNodeDeviceObjListRemoveHelper(void *key G_GNUC_UNUSED,
                                            void *value,
                                            void *opaque)
{
    PredicateHelperData *data = opaque;

    return data->predicate(value, data->opaque);
}


/**
 * virNodeDeviceObjListForEachRemove
 * @devs: Pointer to object list
 * @callback: function to call for each device object
 * @opaque: Opaque data to use as argument to helper
 *
 * For each object in @devs, call the @callback helper using @opaque as
 * an argument. If @callback returns true, that item will be removed from the
 * object list.
 */
void
virNodeDeviceObjListForEachRemove(virNodeDeviceObjList *devs,
                                  virNodeDeviceObjListPredicate callback,
                                  void *opaque)
{
    PredicateHelperData data = {
        .predicate = callback,
        .opaque = opaque
    };

    virObjectRWLockWrite(devs);
    g_hash_table_foreach_remove(devs->objs,
                                virNodeDeviceObjListRemoveHelper,
                                &data);
    virObjectRWUnlock(devs);
}


static int virNodeDeviceObjListFindHelper(const void *payload,
                                          const char *name G_GNUC_UNUSED,
                                          const void *opaque)
{
    PredicateHelperData *data = (PredicateHelperData *) opaque;
    virNodeDeviceObj *obj = (virNodeDeviceObj *) payload;

    return data->predicate(obj, data->opaque);
}


/**
 * virNodeDeviceObjListFind
 * @devs: Pointer to object list
 * @predicate: function to test the device for a certain property
 * @opaque: Opaque data to use as argument to helper
 *
 * For each object in @devs, call the @predicate helper using @opaque as
 * an argument until it returns TRUE. The list may not be modified while
 * iterating.
 */
virNodeDeviceObj *
virNodeDeviceObjListFind(virNodeDeviceObjList *devs,
                         virNodeDeviceObjListPredicate predicate,
                         void *opaque)
{
    PredicateHelperData data = {
        .predicate = predicate,
        .opaque = opaque
    };

    return virNodeDeviceObjListSearch(devs,
                                      virNodeDeviceObjListFindHelper,
                                      &data);
}
