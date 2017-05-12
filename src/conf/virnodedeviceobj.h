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

#ifndef __VIRNODEDEVICEOBJ_H__
# define __VIRNODEDEVICEOBJ_H__

# include "internal.h"
# include "virthread.h"

# include "node_device_conf.h"
# include "object_event.h"


typedef struct _virNodeDeviceDriverState virNodeDeviceDriverState;
typedef virNodeDeviceDriverState *virNodeDeviceDriverStatePtr;
struct _virNodeDeviceDriverState {
    virMutex lock;

    virNodeDeviceObjListPtr devs;	/* currently-known devices */
    void *privateData;			/* driver-specific private data */

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr nodeDeviceEventState;
};


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
virNodeDeviceObjListAssignDef(virNodeDeviceObjListPtr devs,
                              virNodeDeviceDefPtr def);

void
virNodeDeviceObjListRemove(virNodeDeviceObjListPtr devs,
                           virNodeDeviceObjPtr dev);

int
virNodeDeviceObjListGetParentHost(virNodeDeviceObjListPtr devs,
                                  virNodeDeviceDefPtr def,
                              int create);

void
virNodeDeviceObjFree(virNodeDeviceObjPtr dev);

virNodeDeviceObjListPtr
virNodeDeviceObjListNew(void);

void
virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs);

void
virNodeDeviceObjLock(virNodeDeviceObjPtr obj);

void
virNodeDeviceObjUnlock(virNodeDeviceObjPtr obj);

typedef bool
(*virNodeDeviceObjListFilter)(virConnectPtr conn,
                              virNodeDeviceDefPtr def);

int
virNodeDeviceObjListNumOfDevices(virNodeDeviceObjListPtr devs,
                                 virConnectPtr conn,
                                 const char *cap,
                                 virNodeDeviceObjListFilter aclfilter);

int
virNodeDeviceObjListGetNames(virNodeDeviceObjListPtr devs,
                             virConnectPtr conn,
                             virNodeDeviceObjListFilter aclfilter,
                             const char *cap,
                             char **const names,
                             int maxnames);

int
virNodeDeviceObjListExport(virConnectPtr conn,
                           virNodeDeviceObjListPtr devobjs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter aclfilter,
                           unsigned int flags);

#endif /* __VIRNODEDEVICEOBJ_H__ */
