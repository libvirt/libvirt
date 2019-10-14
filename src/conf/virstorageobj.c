/*
 * virstorageobj.c: internal storage pool and volume objects handling
 *                  (derived from storage_conf.c)
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
#include <dirent.h>

#include "datatypes.h"
#include "node_device_conf.h"
#include "node_device_util.h"
#include "virstorageobj.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"
#include "virscsihost.h"
#include "virstring.h"
#include "virvhba.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("conf.virstorageobj");

static virClassPtr virStoragePoolObjClass;
static virClassPtr virStoragePoolObjListClass;
static virClassPtr virStorageVolObjClass;
static virClassPtr virStorageVolObjListClass;

static void
virStoragePoolObjDispose(void *opaque);
static void
virStoragePoolObjListDispose(void *opaque);
static void
virStorageVolObjDispose(void *opaque);
static void
virStorageVolObjListDispose(void *opaque);



typedef struct _virStorageVolObj virStorageVolObj;
typedef virStorageVolObj *virStorageVolObjPtr;
struct _virStorageVolObj {
    virObjectLockable parent;

    virStorageVolDefPtr voldef;
};

typedef struct _virStorageVolObjList virStorageVolObjList;
typedef virStorageVolObjList *virStorageVolObjListPtr;
struct _virStorageVolObjList {
    virObjectRWLockable parent;

    /* key string -> virStorageVolObj mapping
     * for (1), lockless lookup-by-key */
    virHashTable *objsKey;

    /* name string -> virStorageVolObj mapping
     * for (1), lockless lookup-by-name */
    virHashTable *objsName;

    /* path string -> virStorageVolObj mapping
     * for (1), lockless lookup-by-path */
    virHashTable *objsPath;
};

struct _virStoragePoolObj {
    virObjectLockable parent;

    char *configFile;
    char *autostartLink;
    bool active;
    bool starting;
    bool autostart;
    unsigned int asyncjobs;

    virStoragePoolDefPtr def;
    virStoragePoolDefPtr newDef;

    virStorageVolObjListPtr volumes;
};

struct _virStoragePoolObjList {
    virObjectRWLockable parent;

    /* uuid string -> virStoragePoolObj mapping
     * for (1), lockless lookup-by-uuid */
    virHashTable *objs;

    /* name string -> virStoragePoolObj mapping
     * for (1), lockless lookup-by-name */
    virHashTable *objsName;
};


static int
virStorageVolObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virStorageVolObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virStorageVolObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStorageVolObj);


static virStorageVolObjPtr
virStorageVolObjNew(void)
{
    virStorageVolObjPtr obj;

    if (virStorageVolObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virStorageVolObjClass)))
        return NULL;

    virObjectLock(obj);
    return obj;
}


static void
virStorageVolObjEndAPI(virStorageVolObjPtr *obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    virObjectUnref(*obj);
    *obj = NULL;
}


static void
virStorageVolObjDispose(void *opaque)
{
    virStorageVolObjPtr obj = opaque;

    virStorageVolDefFree(obj->voldef);
}


static virStorageVolObjListPtr
virStorageVolObjListNew(void)
{
    virStorageVolObjListPtr vols;

    if (virStorageVolObjInitialize() < 0)
        return NULL;

    if (!(vols = virObjectRWLockableNew(virStorageVolObjListClass)))
        return NULL;

    if (!(vols->objsKey = virHashCreate(10, virObjectFreeHashData)) ||
        !(vols->objsName = virHashCreate(10, virObjectFreeHashData)) ||
        !(vols->objsPath = virHashCreate(10, virObjectFreeHashData))) {
        virObjectUnref(vols);
        return NULL;
    }

    return vols;
}


static void
virStorageVolObjListDispose(void *opaque)
{
    virStorageVolObjListPtr vols = opaque;

    virHashFree(vols->objsKey);
    virHashFree(vols->objsName);
    virHashFree(vols->objsPath);
}


static int
virStoragePoolObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virStoragePoolObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virStoragePoolObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStoragePoolObj);


virStoragePoolObjPtr
virStoragePoolObjNew(void)
{
    virStoragePoolObjPtr obj;

    if (virStoragePoolObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virStoragePoolObjClass)))
        return NULL;

    if (!(obj->volumes = virStorageVolObjListNew())) {
        virObjectUnref(obj);
        return NULL;
    }

    virObjectLock(obj);
    obj->active = false;
    return obj;
}


void
virStoragePoolObjEndAPI(virStoragePoolObjPtr *obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    virObjectUnref(*obj);
    *obj = NULL;
}


virStoragePoolDefPtr
virStoragePoolObjGetDef(virStoragePoolObjPtr obj)
{
    return obj->def;
}


void
virStoragePoolObjSetDef(virStoragePoolObjPtr obj,
                        virStoragePoolDefPtr def)
{
    virStoragePoolDefFree(obj->def);
    obj->def = def;
}


virStoragePoolDefPtr
virStoragePoolObjGetNewDef(virStoragePoolObjPtr obj)
{
    return obj->newDef;
}


void
virStoragePoolObjDefUseNewDef(virStoragePoolObjPtr obj)
{
    virStoragePoolDefFree(obj->def);
    obj->def = obj->newDef;
    obj->newDef = NULL;
}


const char *
virStoragePoolObjGetConfigFile(virStoragePoolObjPtr obj)
{
    return obj->configFile;
}


void
virStoragePoolObjSetConfigFile(virStoragePoolObjPtr obj,
                               char *configFile)
{
    VIR_FREE(obj->configFile);
    obj->configFile = configFile;
}


const char *
virStoragePoolObjGetAutostartLink(virStoragePoolObjPtr obj)
{
    return obj->autostartLink;
}


bool
virStoragePoolObjIsActive(virStoragePoolObjPtr obj)
{
    return obj->active;
}


void
virStoragePoolObjSetActive(virStoragePoolObjPtr obj,
                           bool active)
{
    obj->active = active;
}


void
virStoragePoolObjSetStarting(virStoragePoolObjPtr obj,
                             bool starting)
{
    obj->starting = starting;
}


bool
virStoragePoolObjIsStarting(virStoragePoolObjPtr obj)
{
    return obj->starting;
}


bool
virStoragePoolObjIsAutostart(virStoragePoolObjPtr obj)
{
    if (!obj->configFile)
        return 0;

    return obj->autostart;
}


void
virStoragePoolObjSetAutostart(virStoragePoolObjPtr obj,
                              bool autostart)
{
    obj->autostart = autostart;
}


unsigned int
virStoragePoolObjGetAsyncjobs(virStoragePoolObjPtr obj)
{
    return obj->asyncjobs;
}


void
virStoragePoolObjIncrAsyncjobs(virStoragePoolObjPtr obj)
{
    obj->asyncjobs++;
}


void
virStoragePoolObjDecrAsyncjobs(virStoragePoolObjPtr obj)
{
    obj->asyncjobs--;
}


void
virStoragePoolObjDispose(void *opaque)
{
    virStoragePoolObjPtr obj = opaque;

    virStoragePoolObjClearVols(obj);
    virObjectUnref(obj->volumes);

    virStoragePoolDefFree(obj->def);
    virStoragePoolDefFree(obj->newDef);

    VIR_FREE(obj->configFile);
    VIR_FREE(obj->autostartLink);
}


void
virStoragePoolObjListDispose(void *opaque)
{
    virStoragePoolObjListPtr pools = opaque;

    virHashFree(pools->objs);
    virHashFree(pools->objsName);
}


virStoragePoolObjListPtr
virStoragePoolObjListNew(void)
{
    virStoragePoolObjListPtr pools;

    if (virStoragePoolObjInitialize() < 0)
        return NULL;

    if (!(pools = virObjectRWLockableNew(virStoragePoolObjListClass)))
        return NULL;

    if (!(pools->objs = virHashCreate(20, virObjectFreeHashData)) ||
        !(pools->objsName = virHashCreate(20, virObjectFreeHashData))) {
        virObjectUnref(pools);
        return NULL;
    }

    return pools;
}


struct _virStoragePoolObjListForEachData {
    virStoragePoolObjListIterator iter;
    const void *opaque;
};

static int
virStoragePoolObjListForEachCb(void *payload,
                               const void *name G_GNUC_UNUSED,
                               void *opaque)
{
    virStoragePoolObjPtr obj = payload;
    struct _virStoragePoolObjListForEachData *data = opaque;

    /* Grab a reference so that we don't rely only on references grabbed by
     * hash table earlier. Remember, an iterator can remove object from the
     * hash table. */
    virObjectRef(obj);
    virObjectLock(obj);
    data->iter(obj, data->opaque);
    virStoragePoolObjEndAPI(&obj);

    return 0;
}


/**
 * virStoragePoolObjListForEach
 * @pools: Pointer to pools object
 * @iter: Callback iteration helper
 * @opaque: Opaque data to use as argument to helper
 *
 * For each object in @pools, call the @iter helper using @opaque as
 * an argument.  This function doesn't care whether the @iter fails or
 * not as it's being used for Autostart and UpdateAllState callers
 * that want to iterate over all the @pools objects not stopping if
 * one happens to fail.
 *
 * NB: We cannot take the Storage Pool lock here because it's possible
 *     that some action as part of Autostart or UpdateAllState will need
 *     to modify/destroy a transient pool. Since these paths only occur
 *     during periods in which the storageDriverLock is held (Initialization,
 *     AutoStart, or Reload) this is OK.
 */
void
virStoragePoolObjListForEach(virStoragePoolObjListPtr pools,
                             virStoragePoolObjListIterator iter,
                             const void *opaque)
{
    struct _virStoragePoolObjListForEachData data = { .iter = iter,
                                                      .opaque = opaque };

    virHashForEach(pools->objs, virStoragePoolObjListForEachCb, &data);
}


struct _virStoragePoolObjListSearchData {
    virStoragePoolObjListSearcher searcher;
    const void *opaque;
};


static int
virStoragePoolObjListSearchCb(const void *payload,
                              const void *name G_GNUC_UNUSED,
                              const void *opaque)
{
    virStoragePoolObjPtr obj = (virStoragePoolObjPtr) payload;
    struct _virStoragePoolObjListSearchData *data =
        (struct _virStoragePoolObjListSearchData *)opaque;

    virObjectLock(obj);
    if (data->searcher(obj, data->opaque))
        return 1;
    virObjectUnlock(obj);
    return 0;
}


/**
 * virStoragePoolObjListSearch
 * @pools: Pointer to pools object
 * @search: Callback searcher helper
 * @opaque: Opaque data to use as argument to helper
 *
 * Search through the @pools objects calling the @search helper using
 * the @opaque data in order to find an object that matches some criteria
 * and return that object locked.
 *
 * Returns a locked and reffed object when found and NULL when not found
 */
virStoragePoolObjPtr
virStoragePoolObjListSearch(virStoragePoolObjListPtr pools,
                            virStoragePoolObjListSearcher searcher,
                            const void *opaque)
{
    virStoragePoolObjPtr obj = NULL;
    struct _virStoragePoolObjListSearchData data = { .searcher = searcher,
                                                     .opaque = opaque };

    virObjectRWLockRead(pools);
    obj = virHashSearch(pools->objs, virStoragePoolObjListSearchCb, &data, NULL);
    virObjectRWUnlock(pools);

    return virObjectRef(obj);
}


void
virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                        virStoragePoolObjPtr obj)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(obj->def->uuid, uuidstr);
    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(pools);
    virObjectLock(obj);
    virHashRemoveEntry(pools->objs, uuidstr);
    virHashRemoveEntry(pools->objsName, obj->def->name);
    virObjectUnref(obj);
    virObjectRWUnlock(pools);
}


static virStoragePoolObjPtr
virStoragePoolObjFindByUUIDLocked(virStoragePoolObjListPtr pools,
                                  const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    return virObjectRef(virHashLookup(pools->objs, uuidstr));
}


/**
 * virStoragePoolObjFindByUUID
 * @pools: Storage pool object list pointer
 * @uuid: Storage object uuid to find
 *
 * Lock the @pools and lookup the object by @uuid
 *
 * Returns: Locked and reffed storage pool object or NULL if not found
 */
virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                            const unsigned char *uuid)
{
    virStoragePoolObjPtr obj;

    virObjectRWLockRead(pools);
    obj = virStoragePoolObjFindByUUIDLocked(pools, uuid);
    virObjectRWUnlock(pools);
    if (obj)
        virObjectLock(obj);

    return obj;
}


static virStoragePoolObjPtr
virStoragePoolObjFindByNameLocked(virStoragePoolObjListPtr pools,
                                  const char *name)
{
    return virObjectRef(virHashLookup(pools->objsName, name));
}


/**
 * virStoragePoolObjFindByName
 * @pools: Storage pool object list pointer
 * @name: Storage object name to find
 *
 * Lock the @pools and lookup the object by @name
 *
 * Returns: Locked and reffed storage pool object or NULL if not found
 */
virStoragePoolObjPtr
virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
                            const char *name)
{
    virStoragePoolObjPtr obj;

    virObjectRWLockRead(pools);
    obj = virStoragePoolObjFindByNameLocked(pools, name);
    virObjectRWUnlock(pools);
    if (obj)
        virObjectLock(obj);

    return obj;
}


static virStoragePoolObjPtr
virStoragePoolSourceFindDuplicateDevices(virStoragePoolObjPtr obj,
                                         virStoragePoolDefPtr def)
{
    size_t i, j;

    for (i = 0; i < obj->def->source.ndevice; i++) {
        for (j = 0; j < def->source.ndevice; j++) {
            if (STREQ(obj->def->source.devices[i].path, def->source.devices[j].path))
                return obj;
        }
    }

    return NULL;
}


void
virStoragePoolObjClearVols(virStoragePoolObjPtr obj)
{
    if (!obj->volumes)
        return;

    virHashRemoveAll(obj->volumes->objsKey);
    virHashRemoveAll(obj->volumes->objsName);
    virHashRemoveAll(obj->volumes->objsPath);
}


int
virStoragePoolObjAddVol(virStoragePoolObjPtr obj,
                        virStorageVolDefPtr voldef)
{
    virStorageVolObjPtr volobj = NULL;
    virStorageVolObjListPtr volumes = obj->volumes;

    virObjectRWLockWrite(volumes);

    if (!(volobj = virStorageVolObjNew()))
        goto error;

    if (virHashAddEntry(volumes->objsKey, voldef->key, volobj) < 0)
        goto error;
    virObjectRef(volobj);

    if (virHashAddEntry(volumes->objsName, voldef->name, volobj) < 0) {
        virHashRemoveEntry(volumes->objsKey, voldef->key);
        goto error;
    }
    virObjectRef(volobj);

    if (virHashAddEntry(volumes->objsPath, voldef->target.path, volobj) < 0) {
        virHashRemoveEntry(volumes->objsKey, voldef->key);
        virHashRemoveEntry(volumes->objsName, voldef->name);
        goto error;
    }
    virObjectRef(volobj);

    volobj->voldef = voldef;
    virObjectRWUnlock(volumes);
    virStorageVolObjEndAPI(&volobj);
    return 0;

 error:
    virStorageVolObjEndAPI(&volobj);
    virObjectRWUnlock(volumes);
    return -1;
}


void
virStoragePoolObjRemoveVol(virStoragePoolObjPtr obj,
                           virStorageVolDefPtr voldef)
{
    virStorageVolObjListPtr volumes = obj->volumes;
    virStorageVolObjPtr volobj;

    virObjectRWLockWrite(volumes);
    volobj = virHashLookup(volumes->objsName, voldef->name);
    if (!volobj) {
        VIR_INFO("Cannot find volume '%s' from storage pool '%s'",
                 voldef->name, obj->def->name);
        virObjectRWUnlock(volumes);
        return;
    }
    VIR_INFO("Deleting volume '%s' from storage pool '%s'",
             voldef->name, obj->def->name);

    virObjectRef(volobj);
    virObjectLock(volobj);
    virHashRemoveEntry(volumes->objsKey, voldef->key);
    virHashRemoveEntry(volumes->objsName, voldef->name);
    virHashRemoveEntry(volumes->objsPath, voldef->target.path);
    virStorageVolObjEndAPI(&volobj);

    virObjectRWUnlock(volumes);
}


size_t
virStoragePoolObjGetVolumesCount(virStoragePoolObjPtr obj)
{
    size_t nbElems;

    virObjectRWLockRead(obj->volumes);
    nbElems = virHashSize(obj->volumes->objsKey);
    virObjectRWUnlock(obj->volumes);

    return nbElems;
}


struct _virStoragePoolObjForEachVolData {
    virStorageVolObjListIterator iter;
    const void *opaque;
};

static int
virStoragePoolObjForEachVolumeCb(void *payload,
                                 const void *name G_GNUC_UNUSED,
                                 void *opaque)
{
    int ret = 0;
    virStorageVolObjPtr volobj = payload;
    struct _virStoragePoolObjForEachVolData *data = opaque;

    virObjectLock(volobj);
    if (data->iter(volobj->voldef, data->opaque) < 0)
        ret = -1;
    virObjectUnlock(volobj);

    return ret;
}


int
virStoragePoolObjForEachVolume(virStoragePoolObjPtr obj,
                               virStorageVolObjListIterator iter,
                               const void *opaque)
{
    struct _virStoragePoolObjForEachVolData data = {
        .iter = iter, .opaque = opaque };

    virObjectRWLockRead(obj->volumes);
    virHashForEach(obj->volumes->objsKey, virStoragePoolObjForEachVolumeCb,
                   &data);
    virObjectRWUnlock(obj->volumes);
    return 0;
}


struct _virStoragePoolObjSearchVolData {
    virStorageVolObjListSearcher iter;
    const void *opaque;
};

static int
virStoragePoolObjSearchVolumeCb(const void *payload,
                                const void *name G_GNUC_UNUSED,
                                const void *opaque)
{
    virStorageVolObjPtr volobj = (virStorageVolObjPtr) payload;
    struct _virStoragePoolObjSearchVolData *data =
        (struct _virStoragePoolObjSearchVolData *) opaque;
    int found = 0;

    virObjectLock(volobj);
    if (data->iter(volobj->voldef, data->opaque))
        found = 1;
    virObjectUnlock(volobj);

    return found;
}


virStorageVolDefPtr
virStoragePoolObjSearchVolume(virStoragePoolObjPtr obj,
                              virStorageVolObjListSearcher iter,
                              const void *opaque)
{
    virStorageVolObjPtr volobj;
    struct _virStoragePoolObjSearchVolData data = {
        .iter = iter, .opaque = opaque };

    virObjectRWLockRead(obj->volumes);
    volobj = virHashSearch(obj->volumes->objsKey,
                           virStoragePoolObjSearchVolumeCb,
                           &data, NULL);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;

    return NULL;
}


virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr obj,
                          const char *key)
{
    virStorageVolObjPtr volobj;

    virObjectRWLockRead(obj->volumes);
    volobj = virHashLookup(obj->volumes->objsKey, key);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;
    return NULL;
}


virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr obj,
                           const char *path)
{
    virStorageVolObjPtr volobj;

    virObjectRWLockRead(obj->volumes);
    volobj = virHashLookup(obj->volumes->objsPath, path);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;
    return NULL;
}


virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr obj,
                           const char *name)
{
    virStorageVolObjPtr volobj;

    virObjectRWLockRead(obj->volumes);
    volobj = virHashLookup(obj->volumes->objsName, name);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;
    return NULL;
}


struct _virStorageVolObjCountData {
    virConnectPtr conn;
    virStoragePoolVolumeACLFilter filter;
    virStoragePoolDefPtr pooldef;
    int count;
};


static int
virStoragePoolObjNumOfVolumesCb(void *payload,
                                const void *name G_GNUC_UNUSED,
                                void *opaque)
{
    virStorageVolObjPtr volobj = payload;
    struct _virStorageVolObjCountData *data = opaque;

    virObjectLock(volobj);

    if (data->filter &&
        !data->filter(data->conn, data->pooldef, volobj->voldef))
        goto cleanup;

    data->count++;

 cleanup:
    virObjectUnlock(volobj);
    return 0;
}


int
virStoragePoolObjNumOfVolumes(virStoragePoolObjPtr obj,
                              virConnectPtr conn,
                              virStoragePoolVolumeACLFilter filter)
{
    virStorageVolObjListPtr volumes = obj->volumes;
    struct _virStorageVolObjCountData data = {
        .conn = conn, .filter = filter, .pooldef = obj->def, .count = 0 };

    virObjectRWLockRead(volumes);
    virHashForEach(volumes->objsName, virStoragePoolObjNumOfVolumesCb, &data);
    virObjectRWUnlock(volumes);

    return data.count;
}


struct _virStorageVolObjNameData {
    virConnectPtr conn;
    virStoragePoolVolumeACLFilter filter;
    virStoragePoolDefPtr pooldef;
    bool error;
    int nnames;
    int maxnames;
    char **const names;
};

static int
virStoragePoolObjVolumeGetNamesCb(void *payload,
                                  const void *name G_GNUC_UNUSED,
                                  void *opaque)
{
    virStorageVolObjPtr volobj = payload;
    struct _virStorageVolObjNameData *data = opaque;

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    virObjectLock(volobj);

    if (data->filter &&
        !data->filter(data->conn, data->pooldef, volobj->voldef))
        goto cleanup;

    if (data->names) {
        if (VIR_STRDUP(data->names[data->nnames], volobj->voldef->name) < 0) {
            data->error = true;
            goto cleanup;
        }
    }

    data->nnames++;

 cleanup:
    virObjectUnlock(volobj);
    return 0;
}


int
virStoragePoolObjVolumeGetNames(virStoragePoolObjPtr obj,
                                virConnectPtr conn,
                                virStoragePoolVolumeACLFilter filter,
                                char **const names,
                                int maxnames)
{
    virStorageVolObjListPtr volumes = obj->volumes;
    struct _virStorageVolObjNameData data = {
        .conn = conn, .filter = filter, .pooldef = obj->def, .error = false,
        .nnames = 0, .maxnames = maxnames, .names = names };

    virObjectRWLockRead(volumes);
    virHashForEach(volumes->objsName, virStoragePoolObjVolumeGetNamesCb, &data);
    virObjectRWUnlock(volumes);

    if (data.error)
        goto error;

    return data.nnames;

 error:
    while (--data.nnames)
        VIR_FREE(data.names[data.nnames]);
    return -1;
}


typedef struct _virStoragePoolObjVolumeListExportData virStoragePoolObjVolumeListExportData;
typedef virStoragePoolObjVolumeListExportData *virStoragePoolObjVolumeListExportDataPtr;
struct _virStoragePoolObjVolumeListExportData {
    virConnectPtr conn;
    virStoragePoolVolumeACLFilter filter;
    virStoragePoolDefPtr pooldef;
    bool error;
    int nvols;
    virStorageVolPtr *vols;
};

static int
virStoragePoolObjVolumeListExportCallback(void *payload,
                                          const void *name G_GNUC_UNUSED,
                                          void *opaque)
{
    virStorageVolObjPtr volobj = payload;
    virStoragePoolObjVolumeListExportDataPtr data = opaque;
    virStorageVolPtr vol = NULL;

    if (data->error)
        return 0;

    virObjectLock(volobj);

    if (data->filter &&
        !data->filter(data->conn, data->pooldef, volobj->voldef))
        goto cleanup;

    if (data->vols) {
        if (!(vol = virGetStorageVol(data->conn, data->pooldef->name,
                                     volobj->voldef->name, volobj->voldef->key,
                                     NULL, NULL))) {
            data->error = true;
            goto cleanup;
        }
        data->vols[data->nvols] = vol;
    }

    data->nvols++;

 cleanup:
    virObjectUnlock(volobj);
    return 0;
}


int
virStoragePoolObjVolumeListExport(virConnectPtr conn,
                                  virStoragePoolObjPtr obj,
                                  virStorageVolPtr **vols,
                                  virStoragePoolVolumeACLFilter filter)
{
    virStorageVolObjListPtr volumes = obj->volumes;
    virStoragePoolObjVolumeListExportData data = {
        .conn = conn, .filter = filter, .pooldef = obj->def, .error = false,
        .nvols = 0, .vols = NULL };

    virObjectRWLockRead(volumes);

    if (!vols) {
        int ret = virHashSize(volumes->objsName);
        virObjectRWUnlock(volumes);
        return ret;
    }

    if (VIR_ALLOC_N(data.vols, virHashSize(volumes->objsName) + 1) < 0) {
        virObjectRWUnlock(volumes);
        return -1;
    }

    virHashForEach(volumes->objsName, virStoragePoolObjVolumeListExportCallback, &data);
    virObjectRWUnlock(volumes);

    if (data.error)
        goto error;

    *vols = data.vols;

    return data.nvols;

 error:
    virObjectListFree(data.vols);
    return -1;
}


/*
 * virStoragePoolObjIsDuplicate:
 * @doms : virStoragePoolObjListPtr to search
 * @def  : virStoragePoolDefPtr definition of pool to lookup
 * @check_active: If true, ensure that pool is not active
 * @objRet: returned pool object
 *
 * Assumes @pools is locked by caller already.
 *
 * Returns: -1 on error (name/uuid mismatch or check_active failure)
 *          0 if pool is new
 *          1 if pool is a duplicate (name and UUID match)
 */
static int
virStoragePoolObjIsDuplicate(virStoragePoolObjListPtr pools,
                             virStoragePoolDefPtr def,
                             bool check_active,
                             virStoragePoolObjPtr *objRet)
{
    int ret = -1;
    virStoragePoolObjPtr obj = NULL;

    /* See if a Pool with matching UUID already exists */
    obj = virStoragePoolObjFindByUUIDLocked(pools, def->uuid);
    if (obj) {
        virObjectLock(obj);

        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(obj->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%s' is already defined with uuid %s"),
                           obj->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if Pool is already active, refuse it */
            if (virStoragePoolObjIsActive(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("pool is already active as '%s'"),
                               obj->def->name);
                goto cleanup;
            }

            if (virStoragePoolObjIsStarting(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("pool '%s' is starting up"),
                               obj->def->name);
                goto cleanup;
            }
        }

        VIR_STEAL_PTR(*objRet, obj);
        ret = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        obj = virStoragePoolObjFindByNameLocked(pools, def->name);
        if (obj) {
            virObjectLock(obj);

            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto cleanup;
        }
        ret = 0;
    }

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
getSCSIHostNumber(virStorageAdapterSCSIHostPtr scsi_host,
                  unsigned int *hostnum)
{
    int ret = -1;
    unsigned int num;
    char *name = NULL;

    if (scsi_host->has_parent) {
        virPCIDeviceAddressPtr addr = &scsi_host->parentaddr;
        unsigned int unique_id = scsi_host->unique_id;

        if (!(name = virSCSIHostGetNameByParentaddr(addr->domain,
                                                    addr->bus,
                                                    addr->slot,
                                                    addr->function,
                                                    unique_id)))
            goto cleanup;
        if (virSCSIHostGetNumber(name, &num) < 0)
            goto cleanup;
    } else {
        if (virSCSIHostGetNumber(scsi_host->name, &num) < 0)
            goto cleanup;
    }

    *hostnum = num;
    ret = 0;

 cleanup:
    VIR_FREE(name);
    return ret;
}


static bool
virStorageIsSameHostnum(const char *name,
                        unsigned int scsi_hostnum)
{
    unsigned int fc_hostnum;

    if (virSCSIHostGetNumber(name, &fc_hostnum) == 0 &&
        scsi_hostnum == fc_hostnum)
        return true;

    return false;
}


/*
 * matchFCHostToSCSIHost:
 *
 * @fchost: fc_host adapter ptr (either def or pool->def)
 * @scsi_hostnum: Already determined "scsi_pool" hostnum
 *
 * Returns true/false whether there is a match between the incoming
 *         fc_adapter host# and the scsi_host host#
 */
static bool
matchFCHostToSCSIHost(virStorageAdapterFCHostPtr fchost,
                      unsigned int scsi_hostnum)
{
    virConnectPtr conn = NULL;
    bool ret = false;
    char *name = NULL;
    char *scsi_host_name = NULL;
    char *parent_name = NULL;

    /* If we have a parent defined, get its hostnum, and compare to the
     * scsi_hostnum. If they are the same, then we have a match
     */
    if (fchost->parent &&
        virStorageIsSameHostnum(fchost->parent, scsi_hostnum))
        return true;

    /* If we find an fc adapter name, then either libvirt created a vHBA
     * for this fc_host or a 'virsh nodedev-create' generated a vHBA.
     */
    if ((name = virVHBAGetHostByWWN(NULL, fchost->wwnn, fchost->wwpn))) {

        /* Get the scsi_hostN for the vHBA in order to see if it
         * matches our scsi_hostnum
         */
        if (virStorageIsSameHostnum(name, scsi_hostnum)) {
            ret = true;
            goto cleanup;
        }

        /* We weren't provided a parent, so we have to query the node
         * device driver in order to ascertain the parent of the vHBA.
         * If the parent fc_hostnum is the same as the scsi_hostnum, we
         * have a match.
         */
        if (!fchost->parent &&
            (conn = virGetConnectNodeDev())) {
            if (virAsprintf(&scsi_host_name, "scsi_%s", name) < 0)
                goto cleanup;
            if ((parent_name = virNodeDeviceGetParentName(conn,
                                                          scsi_host_name))) {
                if (virStorageIsSameHostnum(parent_name, scsi_hostnum)) {
                    ret = true;
                    goto cleanup;
                }
            } else {
                /* Throw away the error and fall through */
                virResetLastError();
                VIR_DEBUG("Could not determine parent vHBA");
            }
        }
    }

    /* NB: Lack of a name means that this vHBA hasn't yet been created,
     *     which means our scsi_host cannot be using the vHBA. Furthermore,
     *     lack of a provided parent means libvirt is going to choose the
     *     "best" fc_host capable adapter based on availability. That could
     *     conflict with an existing scsi_host definition, but there's no
     *     way to know that now.
     */

 cleanup:
    VIR_FREE(name);
    VIR_FREE(parent_name);
    VIR_FREE(scsi_host_name);
    virConnectClose(conn);
    return ret;
}


static bool
matchSCSIAdapterParent(virStorageAdapterSCSIHostPtr pool_scsi_host,
                       virStorageAdapterSCSIHostPtr def_scsi_host)
{
    virPCIDeviceAddressPtr pooladdr = &pool_scsi_host->parentaddr;
    virPCIDeviceAddressPtr defaddr = &def_scsi_host->parentaddr;

    if (pooladdr->domain == defaddr->domain &&
        pooladdr->bus == defaddr->bus &&
        pooladdr->slot == defaddr->slot &&
        pooladdr->function == defaddr->function &&
        pool_scsi_host->unique_id == def_scsi_host->unique_id)
        return true;

    return false;
}


static bool
virStoragePoolSourceMatchSingleHost(virStoragePoolSourcePtr poolsrc,
                                    virStoragePoolSourcePtr defsrc)
{
    if (poolsrc->nhost != 1 && defsrc->nhost != 1)
        return false;

    if (defsrc->hosts[0].port &&
        poolsrc->hosts[0].port != defsrc->hosts[0].port)
        return false;

    return STREQ(poolsrc->hosts[0].name, defsrc->hosts[0].name);
}


static bool
virStoragePoolSourceISCSIMatch(virStoragePoolObjPtr obj,
                               virStoragePoolDefPtr def)
{
    virStoragePoolSourcePtr poolsrc = &obj->def->source;
    virStoragePoolSourcePtr defsrc = &def->source;

    /* NB: Do not check the source host name */
    if (STRNEQ_NULLABLE(poolsrc->initiator.iqn, defsrc->initiator.iqn))
        return false;

    return true;
}


static virStoragePoolObjPtr
virStoragePoolObjSourceMatchTypeDIR(virStoragePoolObjPtr obj,
                                    virStoragePoolDefPtr def)
{
    if (obj->def->type == VIR_STORAGE_POOL_DIR) {
        if (STREQ(obj->def->target.path, def->target.path))
            return obj;
    } else if (obj->def->type == VIR_STORAGE_POOL_GLUSTER) {
        if (STREQ(obj->def->source.name, def->source.name) &&
            STREQ_NULLABLE(obj->def->source.dir, def->source.dir) &&
            virStoragePoolSourceMatchSingleHost(&obj->def->source,
                                                &def->source))
            return obj;
    } else if (obj->def->type == VIR_STORAGE_POOL_NETFS) {
        if (STREQ(obj->def->source.dir, def->source.dir) &&
            virStoragePoolSourceMatchSingleHost(&obj->def->source,
                                                &def->source))
            return obj;
    }

    return NULL;
}


static virStoragePoolObjPtr
virStoragePoolObjSourceMatchTypeISCSI(virStoragePoolObjPtr obj,
                                      virStoragePoolDefPtr def)
{
    virStorageAdapterPtr pool_adapter = &obj->def->source.adapter;
    virStorageAdapterPtr def_adapter = &def->source.adapter;
    virStorageAdapterSCSIHostPtr pool_scsi_host;
    virStorageAdapterSCSIHostPtr def_scsi_host;
    virStorageAdapterFCHostPtr pool_fchost;
    virStorageAdapterFCHostPtr def_fchost;
    unsigned int pool_hostnum;
    unsigned int def_hostnum;
    unsigned int scsi_hostnum;

    if (pool_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST &&
        def_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
        pool_fchost = &pool_adapter->data.fchost;
        def_fchost = &def_adapter->data.fchost;

        if (STREQ(pool_fchost->wwnn, def_fchost->wwnn) &&
            STREQ(pool_fchost->wwpn, def_fchost->wwpn))
            return obj;
    } else if (pool_adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST &&
               def_adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) {
        pool_scsi_host = &pool_adapter->data.scsi_host;
        def_scsi_host = &def_adapter->data.scsi_host;

        if (pool_scsi_host->has_parent &&
            def_scsi_host->has_parent &&
            matchSCSIAdapterParent(pool_scsi_host, def_scsi_host))
            return obj;

        if (getSCSIHostNumber(pool_scsi_host, &pool_hostnum) < 0 ||
            getSCSIHostNumber(def_scsi_host, &def_hostnum) < 0)
            return NULL;
        if (pool_hostnum == def_hostnum)
            return obj;
    } else if (pool_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST &&
               def_adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) {
        pool_fchost = &pool_adapter->data.fchost;
        def_scsi_host = &def_adapter->data.scsi_host;

        /* Get the scsi_hostN for the scsi_host source adapter def */
        if (getSCSIHostNumber(def_scsi_host, &scsi_hostnum) < 0)
            return NULL;

        if (matchFCHostToSCSIHost(pool_fchost, scsi_hostnum))
            return obj;

    } else if (pool_adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST &&
               def_adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) {
        pool_scsi_host = &pool_adapter->data.scsi_host;
        def_fchost = &def_adapter->data.fchost;

        if (getSCSIHostNumber(pool_scsi_host, &scsi_hostnum) < 0)
            return NULL;

        if (matchFCHostToSCSIHost(def_fchost, scsi_hostnum))
            return obj;
    }

    return NULL;
}


static virStoragePoolObjPtr
virStoragePoolObjSourceMatchTypeDEVICE(virStoragePoolObjPtr obj,
                                       virStoragePoolDefPtr def)
{
    virStoragePoolObjPtr matchobj = NULL;

    if (obj->def->type == VIR_STORAGE_POOL_ISCSI) {
        if (def->type != VIR_STORAGE_POOL_ISCSI)
            return NULL;

        if ((matchobj = virStoragePoolSourceFindDuplicateDevices(obj, def))) {
            if (!virStoragePoolSourceISCSIMatch(matchobj, def))
                return NULL;
        }
        return matchobj;
    }

    if (def->type == VIR_STORAGE_POOL_ISCSI)
        return NULL;

    /* VIR_STORAGE_POOL_FS
     * VIR_STORAGE_POOL_LOGICAL
     * VIR_STORAGE_POOL_DISK
     * VIR_STORAGE_POOL_ZFS */
    return virStoragePoolSourceFindDuplicateDevices(obj, def);
}


struct _virStoragePoolObjFindDuplicateData {
    virStoragePoolDefPtr def;
};

static int
virStoragePoolObjSourceFindDuplicateCb(const void *payload,
                                       const void *name G_GNUC_UNUSED,
                                       const void *opaque)
{
    virStoragePoolObjPtr obj = (virStoragePoolObjPtr) payload;
    struct _virStoragePoolObjFindDuplicateData *data =
        (struct _virStoragePoolObjFindDuplicateData *) opaque;

    /* Don't match against ourself if re-defining existing pool ! */
    if (STREQ(obj->def->name, data->def->name))
        return 0;

    switch ((virStoragePoolType)obj->def->type) {
    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_GLUSTER:
    case VIR_STORAGE_POOL_NETFS:
        if (data->def->type == obj->def->type &&
            virStoragePoolObjSourceMatchTypeDIR(obj, data->def))
            return 1;
        break;

    case VIR_STORAGE_POOL_SCSI:
        if (data->def->type == obj->def->type &&
            virStoragePoolObjSourceMatchTypeISCSI(obj, data->def))
            return 1;
        break;

    case VIR_STORAGE_POOL_ISCSI:
    case VIR_STORAGE_POOL_ISCSI_DIRECT:
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_LOGICAL:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_ZFS:
        if ((data->def->type == VIR_STORAGE_POOL_ISCSI ||
             data->def->type == VIR_STORAGE_POOL_ISCSI_DIRECT ||
             data->def->type == VIR_STORAGE_POOL_FS ||
             data->def->type == VIR_STORAGE_POOL_LOGICAL ||
             data->def->type == VIR_STORAGE_POOL_DISK ||
             data->def->type == VIR_STORAGE_POOL_ZFS) &&
            virStoragePoolObjSourceMatchTypeDEVICE(obj, data->def))
            return 1;
        break;

    case VIR_STORAGE_POOL_SHEEPDOG:
        if (data->def->type == obj->def->type &&
            virStoragePoolSourceMatchSingleHost(&obj->def->source,
                                                &data->def->source))
            return 1;
        break;

    case VIR_STORAGE_POOL_MPATH:
        /* Only one mpath pool is valid per host */
        if (data->def->type == obj->def->type)
            return 1;
        break;

    case VIR_STORAGE_POOL_VSTORAGE:
        if (data->def->type == obj->def->type &&
            STREQ(obj->def->source.name, data->def->source.name))
            return 1;
        break;

    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_LAST:
        break;
    }

    return 0;
}


static int
virStoragePoolObjSourceFindDuplicate(virStoragePoolObjListPtr pools,
                                     virStoragePoolDefPtr def)
{
    struct _virStoragePoolObjFindDuplicateData data = {.def = def};
    virStoragePoolObjPtr obj = NULL;

    obj = virHashSearch(pools->objs, virStoragePoolObjSourceFindDuplicateCb,
                        &data, NULL);

    if (obj) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Storage source conflict with pool: '%s'"),
                       obj->def->name);
        return -1;
    }

    return 0;
}


static void
virStoragePoolObjAssignDef(virStoragePoolObjPtr obj,
                           virStoragePoolDefPtr def,
                           unsigned int flags)
{
    if (virStoragePoolObjIsActive(obj) ||
        virStoragePoolObjIsStarting(obj)) {
        virStoragePoolDefFree(obj->newDef);
        obj->newDef = def;
    } else {
        if (!obj->newDef &&
            flags & VIR_STORAGE_POOL_OBJ_LIST_ADD_LIVE)
            VIR_STEAL_PTR(obj->newDef, obj->def);

        virStoragePoolDefFree(obj->def);
        obj->def = def;
    }
}


/**
 * virStoragePoolObjListAdd:
 * @pools: Storage Pool object list pointer
 * @def: Storage pool definition to add or update
 * @flags: bitwise-OR of VIR_STORAGE_POOL_OBJ_LIST_* flags
 *
 * Lookup the @def to see if it already exists in the @pools in order
 * to either update or add if it does not exist.
 *
 * Use VIR_STORAGE_POOL_OBJ_LIST_ADD_LIVE to denote that @def
 * refers to an active definition and thus any possible inactive
 * definition found should be saved to ->newDef (in case of
 * future restore).
 *
 * If VIR_STORAGE_POOL_OBJ_LIST_ADD_CHECK_LIVE is set in @flags
 * then this will fail if the pool exists and is active.
 *
 * Returns locked and reffed object pointer or NULL on error
 */
virStoragePoolObjPtr
virStoragePoolObjListAdd(virStoragePoolObjListPtr pools,
                         virStoragePoolDefPtr def,
                         unsigned int flags)
{
    virStoragePoolObjPtr obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int rc;

    virObjectRWLockWrite(pools);

    if (virStoragePoolObjSourceFindDuplicate(pools, def) < 0)
        goto error;

    rc = virStoragePoolObjIsDuplicate(pools, def,
                                      !!(flags & VIR_STORAGE_POOL_OBJ_LIST_ADD_CHECK_LIVE),
                                      &obj);

    if (rc < 0)
        goto error;
    if (rc > 0) {
        virStoragePoolObjAssignDef(obj, def, flags);
        virObjectRWUnlock(pools);
        return obj;
    }

    if (!(obj = virStoragePoolObjNew()))
        goto error;

    virUUIDFormat(def->uuid, uuidstr);
    if (virHashAddEntry(pools->objs, uuidstr, obj) < 0)
        goto error;
    virObjectRef(obj);

    if (virHashAddEntry(pools->objsName, def->name, obj) < 0) {
        virHashRemoveEntry(pools->objs, uuidstr);
        goto error;
    }
    virObjectRef(obj);
    obj->def = def;
    virObjectRWUnlock(pools);
    return obj;

 error:
    virStoragePoolObjEndAPI(&obj);
    virObjectRWUnlock(pools);
    return NULL;
}


static virStoragePoolObjPtr
virStoragePoolObjLoad(virStoragePoolObjListPtr pools,
                      const char *file,
                      const char *path,
                      const char *autostartLink)
{
    virStoragePoolObjPtr obj;
    VIR_AUTOPTR(virStoragePoolDef) def = NULL;

    if (!(def = virStoragePoolDefParseFile(path)))
        return NULL;

    if (!virStringMatchesNameSuffix(file, def->name, ".xml")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Storage pool config filename '%s' does "
                         "not match pool name '%s'"),
                       path, def->name);
        return NULL;
    }

    if (!(obj = virStoragePoolObjListAdd(pools, def, 0)))
        return NULL;
    def = NULL;

    VIR_FREE(obj->configFile);  /* for driver reload */
    if (VIR_STRDUP(obj->configFile, path) < 0) {
        virStoragePoolObjRemove(pools, obj);
        virStoragePoolObjEndAPI(&obj);
        return NULL;
    }
    VIR_FREE(obj->autostartLink); /* for driver reload */
    if (VIR_STRDUP(obj->autostartLink, autostartLink) < 0) {
        virStoragePoolObjRemove(pools, obj);
        virStoragePoolObjEndAPI(&obj);
        return NULL;
    }

    obj->autostart = virFileLinkPointsTo(obj->autostartLink,
                                         obj->configFile);

    return obj;
}


static virStoragePoolObjPtr
virStoragePoolObjLoadState(virStoragePoolObjListPtr pools,
                           const char *stateDir,
                           const char *name)
{
    char *stateFile = NULL;
    virStoragePoolObjPtr obj = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr node = NULL;
    VIR_AUTOPTR(virStoragePoolDef) def = NULL;

    if (!(stateFile = virFileBuildPath(stateDir, name, ".xml")))
        return NULL;

    if (!(xml = virXMLParseCtxt(stateFile, NULL, _("(pool state)"), &ctxt)))
        goto cleanup;

    if (!(node = virXPathNode("//pool", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any 'pool' element in state file"));
        goto cleanup;
    }

    ctxt->node = node;
    if (!(def = virStoragePoolDefParseXML(ctxt)))
        goto cleanup;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Storage pool state file '%s' does not match "
                         "pool name '%s'"),
                       stateFile, def->name);
        goto cleanup;
    }

    /* create the object */
    if (!(obj = virStoragePoolObjListAdd(pools, def,
                                         VIR_STORAGE_POOL_OBJ_LIST_ADD_CHECK_LIVE)))
        goto cleanup;
    def = NULL;

    /* XXX: future handling of some additional useful status data,
     * for now, if a status file for a pool exists, the pool will be marked
     * as active
     */

    obj->active = true;

 cleanup:
    VIR_FREE(stateFile);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return obj;
}


int
virStoragePoolObjLoadAllState(virStoragePoolObjListPtr pools,
                              const char *stateDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virStoragePoolObjPtr obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        if (!(obj = virStoragePoolObjLoadState(pools, stateDir, entry->d_name)))
            continue;
        virStoragePoolObjEndAPI(&obj);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virStoragePoolObjLoadAllConfigs(virStoragePoolObjListPtr pools,
                                const char *configDir,
                                const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        char *path;
        char *autostartLink;
        virStoragePoolObjPtr obj;

        if (!virStringHasSuffix(entry->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(configDir, entry->d_name, NULL)))
            continue;

        if (!(autostartLink = virFileBuildPath(autostartDir, entry->d_name,
                                               NULL))) {
            VIR_FREE(path);
            continue;
        }

        obj = virStoragePoolObjLoad(pools, entry->d_name, path, autostartLink);
        virStoragePoolObjEndAPI(&obj);

        VIR_FREE(path);
        VIR_FREE(autostartLink);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virStoragePoolObjSaveDef(virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr obj,
                         virStoragePoolDefPtr def)
{
    if (!obj->configFile) {
        if (virFileMakePath(driver->configDir) < 0) {
            virReportSystemError(errno,
                                 _("cannot create config directory %s"),
                                 driver->configDir);
            return -1;
        }

        if (!(obj->configFile = virFileBuildPath(driver->configDir,
                                                 def->name, ".xml"))) {
            return -1;
        }

        if (!(obj->autostartLink = virFileBuildPath(driver->autostartDir,
                                                    def->name, ".xml"))) {
            VIR_FREE(obj->configFile);
            return -1;
        }
    }

    return virStoragePoolSaveConfig(obj->configFile, def);
}


int
virStoragePoolObjDeleteDef(virStoragePoolObjPtr obj)
{
    if (!obj->configFile) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no config file for %s"), obj->def->name);
        return -1;
    }

    if (unlink(obj->configFile) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot remove config for %s"),
                       obj->def->name);
        return -1;
    }

    return 0;
}


struct _virStoragePoolCountData {
    virConnectPtr conn;
    virStoragePoolObjListACLFilter filter;
    bool wantActive;
    int count;
};


static int
virStoragePoolObjNumOfStoragePoolsCb(void *payload,
                                     const void *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virStoragePoolObjPtr obj = payload;
    struct _virStoragePoolCountData *data = opaque;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    if (data->wantActive != virStoragePoolObjIsActive(obj))
        goto cleanup;

    data->count++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virStoragePoolObjNumOfStoragePools(virStoragePoolObjListPtr pools,
                                   virConnectPtr conn,
                                   bool wantActive,
                                   virStoragePoolObjListACLFilter filter)
{
    struct _virStoragePoolCountData data = {
        .conn = conn, .filter = filter, .wantActive = wantActive, .count = 0 };

    virObjectRWLockRead(pools);
    virHashForEach(pools->objs, virStoragePoolObjNumOfStoragePoolsCb, &data);
    virObjectRWUnlock(pools);

    return data.count;
}


struct _virStoragePoolNameData {
    virConnectPtr conn;
    virStoragePoolObjListACLFilter filter;
    bool wantActive;
    bool error;
    int nnames;
    int maxnames;
    char **const names;
};


static int
virStoragePoolObjGetNamesCb(void *payload,
                            const void *name G_GNUC_UNUSED,
                            void *opaque)
{
    virStoragePoolObjPtr obj = payload;
    struct _virStoragePoolNameData *data = opaque;

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    if (data->wantActive != virStoragePoolObjIsActive(obj))
        goto cleanup;

    if (data->names) {
        if (VIR_STRDUP(data->names[data->nnames], obj->def->name) < 0) {
            data->error = true;
            goto cleanup;
        }
    }

    data->nnames++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virStoragePoolObjGetNames(virStoragePoolObjListPtr pools,
                          virConnectPtr conn,
                          bool wantActive,
                          virStoragePoolObjListACLFilter filter,
                          char **const names,
                          int maxnames)
{
    struct _virStoragePoolNameData data = {
        .conn = conn, .filter = filter, .wantActive = wantActive,
        .error = false, .nnames = 0, .maxnames = maxnames, .names = names };

    virObjectRWLockRead(pools);
    virHashForEach(pools->objs, virStoragePoolObjGetNamesCb, &data);
    virObjectRWUnlock(pools);

    if (data.error)
        goto error;

    return data.nnames;

 error:
    while (data.nnames)
        VIR_FREE(data.names[--data.nnames]);
    return -1;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virStoragePoolObjMatch(virStoragePoolObjPtr obj,
                       unsigned int flags)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE) &&
           virStoragePoolObjIsActive(obj)) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE) &&
           !virStoragePoolObjIsActive(obj))))
        return false;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT) &&
           obj->configFile) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT) &&
           !obj->configFile)))
        return false;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART) &&
           obj->autostart) ||
          (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART) &&
           !obj->autostart)))
        return false;

    /* filter by pool type */
    if (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE)) {
        if (!((MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_DIR) &&
               (obj->def->type == VIR_STORAGE_POOL_DIR))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_FS) &&
               (obj->def->type == VIR_STORAGE_POOL_FS))      ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_NETFS) &&
               (obj->def->type == VIR_STORAGE_POOL_NETFS))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL) &&
               (obj->def->type == VIR_STORAGE_POOL_LOGICAL)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_DISK) &&
               (obj->def->type == VIR_STORAGE_POOL_DISK))    ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI) &&
               (obj->def->type == VIR_STORAGE_POOL_ISCSI))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_SCSI) &&
               (obj->def->type == VIR_STORAGE_POOL_SCSI))    ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_MPATH) &&
               (obj->def->type == VIR_STORAGE_POOL_MPATH))   ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_RBD) &&
               (obj->def->type == VIR_STORAGE_POOL_RBD))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG) &&
               (obj->def->type == VIR_STORAGE_POOL_SHEEPDOG)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER) &&
               (obj->def->type == VIR_STORAGE_POOL_GLUSTER)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ZFS) &&
               (obj->def->type == VIR_STORAGE_POOL_ZFS))     ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE) &&
               (obj->def->type == VIR_STORAGE_POOL_VSTORAGE)) ||
              (MATCH(VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI_DIRECT) &&
               (obj->def->type == VIR_STORAGE_POOL_ISCSI_DIRECT))))
            return false;
    }

    return true;
}
#undef MATCH


typedef struct _virStoragePoolObjListExportData virStoragePoolObjListExportData;
typedef virStoragePoolObjListExportData *virStoragePoolObjListExportDataPtr;
struct _virStoragePoolObjListExportData {
    virConnectPtr conn;
    virStoragePoolObjListACLFilter filter;
    bool checkActive;
    bool wantActive;
    bool checkMatch;
    unsigned int flags;
    bool error;
    int nPools;
    virStoragePoolPtr *pools;
};


static int
virStoragePoolObjListExportCallback(void *payload,
                                    const void *name G_GNUC_UNUSED,
                                    void *opaque)
{
    virStoragePoolObjPtr obj = payload;
    virStoragePoolObjListExportDataPtr data = opaque;
    virStoragePoolPtr pool = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        goto cleanup;

    if (!virStoragePoolObjMatch(obj, data->flags))
        goto cleanup;

    if (data->pools) {
        if (!(pool = virGetStoragePool(data->conn, obj->def->name,
                                       obj->def->uuid, NULL, NULL))) {
            data->error = true;
            goto cleanup;
        }
        data->pools[data->nPools] = pool;
    }

    data->nPools++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjListPtr poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags)
{
    virStoragePoolObjListExportData data = {
        .conn = conn, .filter = filter, .flags = flags, .error = false,
        .nPools = 0, .pools = NULL };

    virObjectRWLockRead(poolobjs);

    if (pools && VIR_ALLOC_N(data.pools, virHashSize(poolobjs->objs) + 1) < 0)
        goto error;

    virHashForEach(poolobjs->objs, virStoragePoolObjListExportCallback, &data);
    virObjectRWUnlock(poolobjs);

    if (data.error)
        goto error;

    if (data.pools) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.pools, data.nPools + 1));
        *pools = data.pools;
    }

    return data.nPools;

 error:
    virObjectListFree(data.pools);
    return -1;
}
