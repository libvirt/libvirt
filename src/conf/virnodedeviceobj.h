/*
 * virnodedeviceobj.h: node device object handling for node devices
 *                     (derived from node_device_conf.h)
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

#ifndef LIBVIRT_VIRNODEDEVICEOBJ_H
# define LIBVIRT_VIRNODEDEVICEOBJ_H

# include "internal.h"
# include "virthread.h"

# include "node_device_conf.h"
# include "object_event.h"


typedef struct _virNodeDeviceObj virNodeDeviceObj;
typedef virNodeDeviceObj *virNodeDeviceObjPtr;

typedef struct _virNodeDeviceObjList virNodeDeviceObjList;
typedef virNodeDeviceObjList *virNodeDeviceObjListPtr;

typedef struct _virNodeDeviceDriverState virNodeDeviceDriverState;
typedef virNodeDeviceDriverState *virNodeDeviceDriverStatePtr;
struct _virNodeDeviceDriverState {
    virMutex lock;

    virNodeDeviceObjListPtr devs;       /* currently-known devices */
    void *privateData;                  /* driver-specific private data */
    bool privileged;                    /* whether we run in privileged mode */

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr nodeDeviceEventState;
};

void
virNodeDeviceObjEndAPI(virNodeDeviceObjPtr *obj);

virNodeDeviceDefPtr
virNodeDeviceObjGetDef(virNodeDeviceObjPtr obj);

virNodeDeviceObjPtr
virNodeDeviceObjListFindByName(virNodeDeviceObjListPtr devs,
                               const char *name);

virNodeDeviceObjPtr
virNodeDeviceObjListFindBySysfsPath(virNodeDeviceObjListPtr devs,
                                    const char *sysfs_path)
    ATTRIBUTE_NONNULL(2);

virNodeDeviceObjPtr
virNodeDeviceObjListFindSCSIHostByWWNs(virNodeDeviceObjListPtr devs,
                                       const char *wwnn,
                                       const char *wwpn);

virNodeDeviceObjPtr
virNodeDeviceObjListAssignDef(virNodeDeviceObjListPtr devs,
                              virNodeDeviceDefPtr def);

void
virNodeDeviceObjListRemove(virNodeDeviceObjListPtr devs,
                           virNodeDeviceObjPtr dev);

int
virNodeDeviceObjListGetParentHost(virNodeDeviceObjListPtr devs,
                                  virNodeDeviceDefPtr def);

virNodeDeviceObjListPtr
virNodeDeviceObjListNew(void);

void
virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs);

typedef bool
(*virNodeDeviceObjListFilter)(virConnectPtr conn,
                              virNodeDeviceDefPtr def);

int
virNodeDeviceObjListNumOfDevices(virNodeDeviceObjListPtr devs,
                                 virConnectPtr conn,
                                 const char *cap,
                                 virNodeDeviceObjListFilter filter);

int
virNodeDeviceObjListGetNames(virNodeDeviceObjListPtr devs,
                             virConnectPtr conn,
                             virNodeDeviceObjListFilter filter,
                             const char *cap,
                             char **const names,
                             int maxnames);

int
virNodeDeviceObjListExport(virConnectPtr conn,
                           virNodeDeviceObjListPtr devobjs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter filter,
                           unsigned int flags);

void
virNodeDeviceObjSetSkipUpdateCaps(virNodeDeviceObjPtr obj,
                                  bool skipUpdateCaps);

#endif /* LIBVIRT_VIRNODEDEVICEOBJ_H */
