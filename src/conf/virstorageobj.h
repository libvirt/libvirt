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

#ifndef __VIRSTORAGEOBJ_H__
# define __VIRSTORAGEOBJ_H__

# include "internal.h"

# include "storage_conf.h"

typedef struct _virStoragePoolObj virStoragePoolObj;
typedef virStoragePoolObj *virStoragePoolObjPtr;

struct _virStoragePoolObj {
    virMutex lock;

    char *configFile;
    char *autostartLink;
    bool active;
    bool autostart;
    unsigned int asyncjobs;

    virStoragePoolDefPtr def;
    virStoragePoolDefPtr newDef;

    virStorageVolDefList volumes;
};

typedef struct _virStoragePoolObjList virStoragePoolObjList;
typedef virStoragePoolObjList *virStoragePoolObjListPtr;
struct _virStoragePoolObjList {
    size_t count;
    virStoragePoolObjPtr *objs;
};

typedef struct _virStorageDriverState virStorageDriverState;
typedef virStorageDriverState *virStorageDriverStatePtr;

struct _virStorageDriverState {
    virMutex lock;

    virStoragePoolObjList pools;

    char *configDir;
    char *autostartDir;
    char *stateDir;
    bool privileged;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr storageEventState;
};

typedef bool
(*virStoragePoolObjListFilter)(virConnectPtr conn,
                               virStoragePoolDefPtr def);

virStoragePoolObjPtr
virStoragePoolObjNew(void);

virStoragePoolDefPtr
virStoragePoolObjGetDef(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetDef(virStoragePoolObjPtr obj,
                        virStoragePoolDefPtr def);

virStoragePoolDefPtr
virStoragePoolObjGetNewDef(virStoragePoolObjPtr obj);

void
virStoragePoolObjDefUseNewDef(virStoragePoolObjPtr obj);

char *
virStoragePoolObjGetConfigFile(virStoragePoolObjPtr obj);

void
virStoragePoolObjSetConfigFile(virStoragePoolObjPtr obj,
                               char *configFile);

char *
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
                           virStoragePoolDefPtr def);

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

void
virStoragePoolObjListFree(virStoragePoolObjListPtr pools);

void
virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                        virStoragePoolObjPtr obj);

int
virStoragePoolObjIsDuplicate(virStoragePoolObjListPtr pools,
                             virStoragePoolDefPtr def,
                             unsigned int check_active);

int
virStoragePoolObjSourceFindDuplicate(virConnectPtr conn,
                                     virStoragePoolObjListPtr pools,
                                     virStoragePoolDefPtr def);

void
virStoragePoolObjLock(virStoragePoolObjPtr obj);

void
virStoragePoolObjUnlock(virStoragePoolObjPtr obj);

int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjListPtr poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags);

#endif /* __VIRSTORAGEOBJ_H__ */
