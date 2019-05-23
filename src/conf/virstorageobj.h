/*
 * virstorageobj.h: internal storage pool and volume objects handling
 *                  (derived from storage_conf.h)
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

#include "storage_conf.h"

#include "capabilities.h"

typedef struct _virStoragePoolObj virStoragePoolObj;
typedef virStoragePoolObj *virStoragePoolObjPtr;

typedef struct _virStoragePoolObjList virStoragePoolObjList;
typedef virStoragePoolObjList *virStoragePoolObjListPtr;

typedef struct _virStorageDriverState virStorageDriverState;
typedef virStorageDriverState *virStorageDriverStatePtr;

struct _virStorageDriverState {
    virMutex lock;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virStoragePoolObjListPtr pools;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    bool privileged;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr storageEventState;

    /* Immutable pointer, read only after initialized */
    virCapsPtr caps;
};

typedef bool
(*virStoragePoolObjListFilter)(virConnectPtr conn,
                               virStoragePoolDefPtr def);

virStoragePoolObjPtr
virStoragePoolObjNew(void);

void
virStoragePoolObjEndAPI(virStoragePoolObjPtr *obj);

virStoragePoolDefPtr
virStoragePoolObjGetDef(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetDef(virStoragePoolObjPtr obj,
                        virStoragePoolDefPtr def);

virStoragePoolDefPtr
virStoragePoolObjGetNewDef(virStoragePoolObjPtr obj);

void
virStoragePoolObjDefUseNewDef(virStoragePoolObjPtr obj);

const char *
virStoragePoolObjGetConfigFile(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetConfigFile(virStoragePoolObjPtr obj,
                               char *configFile);

const char *
virStoragePoolObjGetAutostartLink(virStoragePoolObjPtr obj);

bool
virStoragePoolObjIsActive(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetActive(virStoragePoolObjPtr obj,
                           bool active);

bool
virStoragePoolObjIsAutostart(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetAutostart(virStoragePoolObjPtr obj,
                              bool autostart);

unsigned int
virStoragePoolObjGetAsyncjobs(virStoragePoolObjPtr obj);

void
virStoragePoolObjIncrAsyncjobs(virStoragePoolObjPtr obj);

void
virStoragePoolObjDecrAsyncjobs(virStoragePoolObjPtr obj);

int
virStoragePoolObjLoadAllConfigs(virStoragePoolObjListPtr pools,
                                const char *configDir,
                                const char *autostartDir);

int
virStoragePoolObjLoadAllState(virStoragePoolObjListPtr pools,
                              const char *stateDir);

virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                            const unsigned char *uuid);

virStoragePoolObjPtr
virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
                            const char *name);

int
virStoragePoolObjAddVol(virStoragePoolObjPtr obj,
                        virStorageVolDefPtr voldef);

void
virStoragePoolObjRemoveVol(virStoragePoolObjPtr obj,
                           virStorageVolDefPtr voldef);

size_t
virStoragePoolObjGetVolumesCount(virStoragePoolObjPtr obj);

typedef int
(*virStorageVolObjListIterator)(virStorageVolDefPtr voldef,
                                const void *opaque);

int
virStoragePoolObjForEachVolume(virStoragePoolObjPtr obj,
                               virStorageVolObjListIterator iter,
                               const void *opaque);

typedef bool
(*virStorageVolObjListSearcher)(virStorageVolDefPtr voldef,
                                const void *opaque);

virStorageVolDefPtr
virStoragePoolObjSearchVolume(virStoragePoolObjPtr obj,
                              virStorageVolObjListSearcher iter,
                              const void *opaque);

virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr obj,
                          const char *key);

virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr obj,
                           const char *path);

virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr obj,
                           const char *name);

void
virStoragePoolObjClearVols(virStoragePoolObjPtr obj);

typedef bool
(*virStoragePoolVolumeACLFilter)(virConnectPtr conn,
                                 virStoragePoolDefPtr pool,
                                 virStorageVolDefPtr def);

int
virStoragePoolObjNumOfVolumes(virStoragePoolObjPtr obj,
                              virConnectPtr conn,
                              virStoragePoolVolumeACLFilter filter);

int
virStoragePoolObjVolumeGetNames(virStoragePoolObjPtr obj,
                                virConnectPtr conn,
                                virStoragePoolVolumeACLFilter filter,
                                char **const names,
                                int maxnames);

int
virStoragePoolObjVolumeListExport(virConnectPtr conn,
                                  virStoragePoolObjPtr obj,
                                  virStorageVolPtr **vols,
                                  virStoragePoolVolumeACLFilter filter);

virStoragePoolObjPtr
virStoragePoolObjAssignDef(virStoragePoolObjListPtr pools,
                           virStoragePoolDefPtr def,
                           bool check_active);

int
virStoragePoolObjSaveDef(virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr obj,
                         virStoragePoolDefPtr def);

int
virStoragePoolObjDeleteDef(virStoragePoolObjPtr obj);

typedef bool (*virStoragePoolObjListACLFilter)(virConnectPtr conn,
                                               virStoragePoolDefPtr def);

int
virStoragePoolObjNumOfStoragePools(virStoragePoolObjListPtr pools,
                                   virConnectPtr conn,
                                   bool wantActive,
                                   virStoragePoolObjListACLFilter filter);

int
virStoragePoolObjGetNames(virStoragePoolObjListPtr pools,
                          virConnectPtr conn,
                          bool wantActive,
                          virStoragePoolObjListACLFilter filter,
                          char **const names,
                          int maxnames);

void
virStoragePoolObjFree(virStoragePoolObjPtr obj);

typedef void
(*virStoragePoolObjListIterator)(virStoragePoolObjPtr obj,
                                 const void *opaque);

void
virStoragePoolObjListForEach(virStoragePoolObjListPtr pools,
                             virStoragePoolObjListIterator iter,
                             const void *opaque);

typedef bool
(*virStoragePoolObjListSearcher)(virStoragePoolObjPtr obj,
                                 const void *opaque);

virStoragePoolObjPtr
virStoragePoolObjListSearch(virStoragePoolObjListPtr pools,
                            virStoragePoolObjListSearcher searcher,
                            const void *opaque);

virStoragePoolObjListPtr
virStoragePoolObjListNew(void);

void
virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                        virStoragePoolObjPtr obj);

int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjListPtr poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags);
