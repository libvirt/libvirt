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

#pragma once

#include "internal.h"
#include "virthread.h"

#include "node_device_conf.h"
#include "object_event.h"


typedef struct _virNodeDeviceObj virNodeDeviceObj;

typedef struct _virNodeDeviceObjList virNodeDeviceObjList;

typedef struct _virNodeDeviceDriverState virNodeDeviceDriverState;
struct _virNodeDeviceDriverState {
    virMutex lock;
    virCond initCond;
    bool initialized;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    char *stateDir;

    virNodeDeviceObjList *devs;       /* currently-known devices */
    void *privateData;                  /* driver-specific private data */
    bool privileged;                    /* whether we run in privileged mode */

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *nodeDeviceEventState;
    virNodeDeviceDefParserCallbacks parserCallbacks;
};

void
virNodeDeviceObjEndAPI(virNodeDeviceObj **obj);

virNodeDeviceDef *
virNodeDeviceObjGetDef(virNodeDeviceObj *obj);

virNodeDeviceObj *
virNodeDeviceObjListFindByName(virNodeDeviceObjList *devs,
                               const char *name);

virNodeDeviceObj *
virNodeDeviceObjListFindBySysfsPath(virNodeDeviceObjList *devs,
                                    const char *sysfs_path)
    ATTRIBUTE_NONNULL(2);

virNodeDeviceObj *
virNodeDeviceObjListFindSCSIHostByWWNs(virNodeDeviceObjList *devs,
                                       const char *wwnn,
                                       const char *wwpn);

virNodeDeviceObj *
virNodeDeviceObjListAssignDef(virNodeDeviceObjList *devs,
                              virNodeDeviceDef *def);

void
virNodeDeviceObjListRemove(virNodeDeviceObjList *devs,
                           virNodeDeviceObj *dev);

void
virNodeDeviceObjListRemoveLocked(virNodeDeviceObjList *devs,
                                 virNodeDeviceObj *dev);

int
virNodeDeviceObjListGetParentHost(virNodeDeviceObjList *devs,
                                  virNodeDeviceDef *def);

bool
virNodeDeviceObjHasCap(const virNodeDeviceObj *obj,
                       int type);

virNodeDeviceObjList *
virNodeDeviceObjListNew(void);

void
virNodeDeviceObjListFree(virNodeDeviceObjList *devs);

typedef bool
(*virNodeDeviceObjListFilter)(virConnectPtr conn,
                              virNodeDeviceDef *def);

int
virNodeDeviceObjListNumOfDevices(virNodeDeviceObjList *devs,
                                 virConnectPtr conn,
                                 const char *cap,
                                 virNodeDeviceObjListFilter filter);

int
virNodeDeviceObjListGetNames(virNodeDeviceObjList *devs,
                             virConnectPtr conn,
                             virNodeDeviceObjListFilter filter,
                             const char *cap,
                             char **const names,
                             int maxnames);

int
virNodeDeviceObjListExport(virConnectPtr conn,
                           virNodeDeviceObjList *devobjs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter filter,
                           unsigned int flags);

void
virNodeDeviceObjSetSkipUpdateCaps(virNodeDeviceObj *obj,
                                  bool skipUpdateCaps);
virNodeDeviceObj *
virNodeDeviceObjListFindMediatedDeviceByUUID(virNodeDeviceObjList *devs,
                                             const char *uuid,
                                             const char *parent_addr);

bool
virNodeDeviceObjIsActive(virNodeDeviceObj *obj);

void
virNodeDeviceObjSetActive(virNodeDeviceObj *obj,
                          bool active);
bool
virNodeDeviceObjIsPersistent(virNodeDeviceObj *obj);

void
virNodeDeviceObjSetPersistent(virNodeDeviceObj *obj,
                              bool persistent);
bool
virNodeDeviceObjIsAutostart(virNodeDeviceObj *obj);

void
virNodeDeviceObjSetAutostart(virNodeDeviceObj *obj,
                             bool autostart);

typedef bool (*virNodeDeviceObjListPredicate)(virNodeDeviceObj *obj,
                                              const void *opaque);

void virNodeDeviceObjListForEachRemove(virNodeDeviceObjList *devs,
                                       virNodeDeviceObjListPredicate callback,
                                       void *opaque);

virNodeDeviceObj *
virNodeDeviceObjListFind(virNodeDeviceObjList *devs,
                         virNodeDeviceObjListPredicate callback,
                         void *opaque);
