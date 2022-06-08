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

typedef struct _virStoragePoolObj virStoragePoolObj;

typedef struct _virStoragePoolObjList virStoragePoolObjList;

typedef struct _virStorageDriverState virStorageDriverState;
struct _virStorageDriverState {
    virMutex lock;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virStoragePoolObjList *pools;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    bool privileged;

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *storageEventState;

    /* Immutable pointer, read only after initialized */
    virCaps *caps;
};

typedef bool
(*virStoragePoolObjListFilter)(virConnectPtr conn,
                               virStoragePoolDef *def);

virStoragePoolObj *
virStoragePoolObjNew(void);

void
virStoragePoolObjEndAPI(virStoragePoolObj **obj);

virStoragePoolDef *
virStoragePoolObjGetDef(virStoragePoolObj *obj);

void
virStoragePoolObjSetDef(virStoragePoolObj *obj,
                        virStoragePoolDef *def);

virStoragePoolDef *
virStoragePoolObjGetNewDef(virStoragePoolObj *obj);

void
virStoragePoolObjDefUseNewDef(virStoragePoolObj *obj);

const char *
virStoragePoolObjGetConfigFile(virStoragePoolObj *obj);

void
virStoragePoolObjSetConfigFile(virStoragePoolObj *obj,
                               char *configFile);

const char *
virStoragePoolObjGetAutostartLink(virStoragePoolObj *obj);

bool
virStoragePoolObjIsActive(virStoragePoolObj *obj);

void
virStoragePoolObjSetActive(virStoragePoolObj *obj,
                           bool active);

void
virStoragePoolObjSetStarting(virStoragePoolObj *obj,
                             bool starting);
bool
virStoragePoolObjIsStarting(virStoragePoolObj *obj);

bool
virStoragePoolObjIsAutostart(virStoragePoolObj *obj);

void
virStoragePoolObjSetAutostart(virStoragePoolObj *obj,
                              bool autostart);

unsigned int
virStoragePoolObjGetAsyncjobs(virStoragePoolObj *obj);

void
virStoragePoolObjIncrAsyncjobs(virStoragePoolObj *obj);

void
virStoragePoolObjDecrAsyncjobs(virStoragePoolObj *obj);

int
virStoragePoolObjLoadAllConfigs(virStoragePoolObjList *pools,
                                const char *configDir,
                                const char *autostartDir);

int
virStoragePoolObjLoadAllState(virStoragePoolObjList *pools,
                              const char *stateDir);

virStoragePoolObj *
virStoragePoolObjFindByUUID(virStoragePoolObjList *pools,
                            const unsigned char *uuid);

virStoragePoolObj *
virStoragePoolObjFindByName(virStoragePoolObjList *pools,
                            const char *name);

int
virStoragePoolObjAddVol(virStoragePoolObj *obj,
                        virStorageVolDef *voldef);

void
virStoragePoolObjRemoveVol(virStoragePoolObj *obj,
                           virStorageVolDef *voldef);

size_t
virStoragePoolObjGetVolumesCount(virStoragePoolObj *obj);

typedef int
(*virStorageVolObjListIterator)(virStorageVolDef *voldef,
                                const void *opaque);

int
virStoragePoolObjForEachVolume(virStoragePoolObj *obj,
                               virStorageVolObjListIterator iter,
                               const void *opaque);

typedef bool
(*virStorageVolObjListSearcher)(virStorageVolDef *voldef,
                                const void *opaque);

virStorageVolDef *
virStoragePoolObjSearchVolume(virStoragePoolObj *obj,
                              virStorageVolObjListSearcher iter,
                              const void *opaque);

virStorageVolDef *
virStorageVolDefFindByKey(virStoragePoolObj *obj,
                          const char *key);

virStorageVolDef *
virStorageVolDefFindByPath(virStoragePoolObj *obj,
                           const char *path);

virStorageVolDef *
virStorageVolDefFindByName(virStoragePoolObj *obj,
                           const char *name);

void
virStoragePoolObjClearVols(virStoragePoolObj *obj);

typedef bool
(*virStoragePoolVolumeACLFilter)(virConnectPtr conn,
                                 virStoragePoolDef *pool,
                                 virStorageVolDef *def);

int
virStoragePoolObjNumOfVolumes(virStoragePoolObj *obj,
                              virConnectPtr conn,
                              virStoragePoolVolumeACLFilter filter);

int
virStoragePoolObjVolumeGetNames(virStoragePoolObj *obj,
                                virConnectPtr conn,
                                virStoragePoolVolumeACLFilter filter,
                                char **const names,
                                int maxnames);

int
virStoragePoolObjVolumeListExport(virConnectPtr conn,
                                  virStoragePoolObj *obj,
                                  virStorageVolPtr **vols,
                                  virStoragePoolVolumeACLFilter filter);

typedef enum {
    VIR_STORAGE_POOL_OBJ_LIST_ADD_LIVE = (1 << 0),
    VIR_STORAGE_POOL_OBJ_LIST_ADD_CHECK_LIVE = (1 << 1),
} virStoragePoolObjListFlags;

virStoragePoolObj *
virStoragePoolObjListAdd(virStoragePoolObjList *pools,
                         virStoragePoolDef **def,
                         unsigned int flags);

int
virStoragePoolObjSaveDef(virStorageDriverState *driver,
                         virStoragePoolObj *obj,
                         virStoragePoolDef *def);

int
virStoragePoolObjDeleteDef(virStoragePoolObj *obj);

typedef bool (*virStoragePoolObjListACLFilter)(virConnectPtr conn,
                                               virStoragePoolDef *def);

int
virStoragePoolObjNumOfStoragePools(virStoragePoolObjList *pools,
                                   virConnectPtr conn,
                                   bool wantActive,
                                   virStoragePoolObjListACLFilter filter);

int
virStoragePoolObjGetNames(virStoragePoolObjList *pools,
                          virConnectPtr conn,
                          bool wantActive,
                          virStoragePoolObjListACLFilter filter,
                          char **const names,
                          int maxnames);

void
virStoragePoolObjFree(virStoragePoolObj *obj);

typedef void
(*virStoragePoolObjListIterator)(virStoragePoolObj *obj,
                                 const void *opaque);

void
virStoragePoolObjListForEach(virStoragePoolObjList *pools,
                             virStoragePoolObjListIterator iter,
                             const void *opaque);

typedef bool
(*virStoragePoolObjListSearcher)(virStoragePoolObj *obj,
                                 const void *opaque);

virStoragePoolObj *
virStoragePoolObjListSearch(virStoragePoolObjList *pools,
                            virStoragePoolObjListSearcher searcher,
                            const void *opaque);

virStoragePoolObjList *
virStoragePoolObjListNew(void);

void
virStoragePoolObjRemove(virStoragePoolObjList *pools,
                        virStoragePoolObj *obj);

int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjList *poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags);
