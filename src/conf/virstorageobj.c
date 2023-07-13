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

static virClass *virStoragePoolObjClass;
static virClass *virStoragePoolObjListClass;
static virClass *virStorageVolObjClass;
static virClass *virStorageVolObjListClass;

static void
virStoragePoolObjDispose(void *opaque);
static void
virStoragePoolObjListDispose(void *opaque);
static void
virStorageVolObjDispose(void *opaque);
static void
virStorageVolObjListDispose(void *opaque);



typedef struct _virStorageVolObj virStorageVolObj;
struct _virStorageVolObj {
    virObjectLockable parent;

    virStorageVolDef *voldef;
};

typedef struct _virStorageVolObjList virStorageVolObjList;
struct _virStorageVolObjList {
    virObjectRWLockable parent;

    /* key string -> virStorageVolObj mapping
     * for (1), lookup-by-key */
    GHashTable *objsKey;

    /* name string -> virStorageVolObj mapping
     * for (1), lookup-by-name */
    GHashTable *objsName;

    /* path string -> virStorageVolObj mapping
     * for (1), lookup-by-path */
    GHashTable *objsPath;
};

struct _virStoragePoolObj {
    virObjectLockable parent;

    char *configFile;
    char *autostartLink;
    bool active;
    bool starting;
    bool autostart;
    unsigned int asyncjobs;

    virStoragePoolDef *def;
    virStoragePoolDef *newDef;

    virStorageVolObjList *volumes;
};

struct _virStoragePoolObjList {
    virObjectRWLockable parent;

    /* uuid string -> virStoragePoolObj mapping
     * for (1), lookup-by-uuid */
    GHashTable *objs;

    /* name string -> virStoragePoolObj mapping
     * for (1), lookup-by-name */
    GHashTable *objsName;
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


static virStorageVolObj *
virStorageVolObjNew(void)
{
    if (virStorageVolObjInitialize() < 0)
        return NULL;

    return virObjectLockableNew(virStorageVolObjClass);
}


static void
virStorageVolObjDispose(void *opaque)
{
    virStorageVolObj *obj = opaque;

    virStorageVolDefFree(obj->voldef);
}


static virStorageVolObjList *
virStorageVolObjListNew(void)
{
    virStorageVolObjList *vols;

    if (virStorageVolObjInitialize() < 0)
        return NULL;

    if (!(vols = virObjectRWLockableNew(virStorageVolObjListClass)))
        return NULL;

    vols->objsKey = virHashNew(virObjectUnref);
    vols->objsName = virHashNew(virObjectUnref);
    vols->objsPath = virHashNew(virObjectUnref);

    return vols;
}


static void
virStorageVolObjListDispose(void *opaque)
{
    virStorageVolObjList *vols = opaque;

    g_clear_pointer(&vols->objsKey, g_hash_table_unref);
    g_clear_pointer(&vols->objsName, g_hash_table_unref);
    g_clear_pointer(&vols->objsPath, g_hash_table_unref);
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


virStoragePoolObj *
virStoragePoolObjNew(void)
{
    virStoragePoolObj *obj;

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
virStoragePoolObjEndAPI(virStoragePoolObj **obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    g_clear_pointer(obj, virObjectUnref);
}


virStoragePoolDef *
virStoragePoolObjGetDef(virStoragePoolObj *obj)
{
    return obj->def;
}


void
virStoragePoolObjSetDef(virStoragePoolObj *obj,
                        virStoragePoolDef *def)
{
    virStoragePoolDefFree(obj->def);
    obj->def = def;
}


virStoragePoolDef *
virStoragePoolObjGetNewDef(virStoragePoolObj *obj)
{
    return obj->newDef;
}


void
virStoragePoolObjDefUseNewDef(virStoragePoolObj *obj)
{
    virStoragePoolDefFree(obj->def);
    obj->def = g_steal_pointer(&obj->newDef);
}


const char *
virStoragePoolObjGetConfigFile(virStoragePoolObj *obj)
{
    return obj->configFile;
}


void
virStoragePoolObjSetConfigFile(virStoragePoolObj *obj,
                               char *configFile)
{
    VIR_FREE(obj->configFile);
    obj->configFile = configFile;
}


const char *
virStoragePoolObjGetAutostartLink(virStoragePoolObj *obj)
{
    return obj->autostartLink;
}


bool
virStoragePoolObjIsActive(virStoragePoolObj *obj)
{
    return obj->active;
}


void
virStoragePoolObjSetActive(virStoragePoolObj *obj,
                           bool active)
{
    obj->active = active;
}


void
virStoragePoolObjSetStarting(virStoragePoolObj *obj,
                             bool starting)
{
    obj->starting = starting;
}


bool
virStoragePoolObjIsStarting(virStoragePoolObj *obj)
{
    return obj->starting;
}


bool
virStoragePoolObjIsAutostart(virStoragePoolObj *obj)
{
    if (!obj->configFile)
        return false;

    return obj->autostart;
}


void
virStoragePoolObjSetAutostart(virStoragePoolObj *obj,
                              bool autostart)
{
    obj->autostart = autostart;
}


unsigned int
virStoragePoolObjGetAsyncjobs(virStoragePoolObj *obj)
{
    return obj->asyncjobs;
}


void
virStoragePoolObjIncrAsyncjobs(virStoragePoolObj *obj)
{
    obj->asyncjobs++;
}


void
virStoragePoolObjDecrAsyncjobs(virStoragePoolObj *obj)
{
    obj->asyncjobs--;
}


void
virStoragePoolObjDispose(void *opaque)
{
    virStoragePoolObj *obj = opaque;

    virStoragePoolObjClearVols(obj);
    virObjectUnref(obj->volumes);

    virStoragePoolDefFree(obj->def);
    virStoragePoolDefFree(obj->newDef);

    g_free(obj->configFile);
    g_free(obj->autostartLink);
}


void
virStoragePoolObjListDispose(void *opaque)
{
    virStoragePoolObjList *pools = opaque;

    g_clear_pointer(&pools->objs, g_hash_table_unref);
    g_clear_pointer(&pools->objsName, g_hash_table_unref);
}


virStoragePoolObjList *
virStoragePoolObjListNew(void)
{
    virStoragePoolObjList *pools;

    if (virStoragePoolObjInitialize() < 0)
        return NULL;

    if (!(pools = virObjectRWLockableNew(virStoragePoolObjListClass)))
        return NULL;

    pools->objs = virHashNew(virObjectUnref);
    pools->objsName = virHashNew(virObjectUnref);

    return pools;
}


struct _virStoragePoolObjListForEachData {
    virStoragePoolObjListIterator iter;
    const void *opaque;
};

static int
virStoragePoolObjListForEachCb(void *payload,
                               const char *name G_GNUC_UNUSED,
                               void *opaque)
{
    virStoragePoolObj *obj = payload;
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
virStoragePoolObjListForEach(virStoragePoolObjList *pools,
                             virStoragePoolObjListIterator iter,
                             const void *opaque)
{
    struct _virStoragePoolObjListForEachData data = { .iter = iter,
                                                      .opaque = opaque };

    virHashForEachSafe(pools->objs, virStoragePoolObjListForEachCb, &data);
}


struct _virStoragePoolObjListSearchData {
    virStoragePoolObjListSearcher searcher;
    const void *opaque;
};


static int
virStoragePoolObjListSearchCb(const void *payload,
                              const char *name G_GNUC_UNUSED,
                              const void *opaque)
{
    virStoragePoolObj *obj = (virStoragePoolObj *) payload;
    struct _virStoragePoolObjListSearchData *data =
        (struct _virStoragePoolObjListSearchData *)opaque;

    virObjectLock(obj);

    /* If we find the matching pool object we must return while the object is
     * locked as the caller wants to return a locked object. */
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
virStoragePoolObj *
virStoragePoolObjListSearch(virStoragePoolObjList *pools,
                            virStoragePoolObjListSearcher searcher,
                            const void *opaque)
{
    virStoragePoolObj *obj = NULL;
    struct _virStoragePoolObjListSearchData data = { .searcher = searcher,
                                                     .opaque = opaque };

    virObjectRWLockRead(pools);
    obj = virHashSearch(pools->objs, virStoragePoolObjListSearchCb, &data, NULL);
    virObjectRWUnlock(pools);

    return virObjectRef(obj);
}


void
virStoragePoolObjRemove(virStoragePoolObjList *pools,
                        virStoragePoolObj *obj)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(obj->def->uuid, uuidstr);
    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(pools);
    virObjectLock(obj);
    g_hash_table_remove(pools->objs, uuidstr);
    g_hash_table_remove(pools->objsName, obj->def->name);
    virObjectUnref(obj);
    virObjectRWUnlock(pools);
}


static virStoragePoolObj *
virStoragePoolObjFindByUUIDLocked(virStoragePoolObjList *pools,
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
virStoragePoolObj *
virStoragePoolObjFindByUUID(virStoragePoolObjList *pools,
                            const unsigned char *uuid)
{
    virStoragePoolObj *obj;

    virObjectRWLockRead(pools);
    obj = virStoragePoolObjFindByUUIDLocked(pools, uuid);
    virObjectRWUnlock(pools);
    if (obj)
        virObjectLock(obj);

    return obj;
}


static virStoragePoolObj *
virStoragePoolObjFindByNameLocked(virStoragePoolObjList *pools,
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
virStoragePoolObj *
virStoragePoolObjFindByName(virStoragePoolObjList *pools,
                            const char *name)
{
    virStoragePoolObj *obj;

    virObjectRWLockRead(pools);
    obj = virStoragePoolObjFindByNameLocked(pools, name);
    virObjectRWUnlock(pools);
    if (obj)
        virObjectLock(obj);

    return obj;
}


static virStoragePoolObj *
virStoragePoolSourceFindDuplicateDevices(virStoragePoolObj *obj,
                                         virStoragePoolDef *def)
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
virStoragePoolObjClearVols(virStoragePoolObj *obj)
{
    if (!obj->volumes)
        return;

    g_hash_table_remove_all(obj->volumes->objsKey);
    g_hash_table_remove_all(obj->volumes->objsName);
    g_hash_table_remove_all(obj->volumes->objsPath);
}


int
virStoragePoolObjAddVol(virStoragePoolObj *obj,
                        virStorageVolDef *voldef)
{
    virStorageVolObj *volobj = NULL;
    virStorageVolObjList *volumes = obj->volumes;

    virObjectRWLockWrite(volumes);

    if (!voldef->key || !voldef->name || !voldef->target.path ||
        g_hash_table_contains(volumes->objsKey, voldef->key) ||
        g_hash_table_contains(volumes->objsName, voldef->name) ||
        g_hash_table_contains(volumes->objsPath, voldef->target.path)) {
        virObjectRWUnlock(volumes);
        return -1;
    }

    if (!(volobj = virStorageVolObjNew())) {
        virObjectRWUnlock(volumes);
        return -1;
    }

    VIR_WITH_OBJECT_LOCK_GUARD(volobj) {
        g_hash_table_insert(volumes->objsKey, g_strdup(voldef->key), volobj);
        virObjectRef(volobj);

        g_hash_table_insert(volumes->objsName, g_strdup(voldef->name), volobj);
        virObjectRef(volobj);

        g_hash_table_insert(volumes->objsPath, g_strdup(voldef->target.path), volobj);
        virObjectRef(volobj);

        volobj->voldef = voldef;
    }

    virObjectUnref(volobj);
    virObjectRWUnlock(volumes);
    return 0;
}


void
virStoragePoolObjRemoveVol(virStoragePoolObj *obj,
                           virStorageVolDef *voldef)
{
    virStorageVolObjList *volumes = obj->volumes;
    virStorageVolObj *volobj;

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
    VIR_WITH_OBJECT_LOCK_GUARD(volobj) {
        g_hash_table_remove(volumes->objsKey, voldef->key);
        g_hash_table_remove(volumes->objsName, voldef->name);
        g_hash_table_remove(volumes->objsPath, voldef->target.path);
    }
    virObjectUnref(volobj);
    virObjectRWUnlock(volumes);
}


size_t
virStoragePoolObjGetVolumesCount(virStoragePoolObj *obj)
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
                                 const char *name G_GNUC_UNUSED,
                                 void *opaque)
{
    virStorageVolObj *volobj = payload;
    struct _virStoragePoolObjForEachVolData *data = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(volobj);

    if (data->iter(volobj->voldef, data->opaque) < 0)
        return -1;

    return 0;
}


int
virStoragePoolObjForEachVolume(virStoragePoolObj *obj,
                               virStorageVolObjListIterator iter,
                               const void *opaque)
{
    struct _virStoragePoolObjForEachVolData data = {
        .iter = iter, .opaque = opaque };

    virObjectRWLockRead(obj->volumes);
    virHashForEachSafe(obj->volumes->objsKey, virStoragePoolObjForEachVolumeCb,
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
                                const char *name G_GNUC_UNUSED,
                                const void *opaque)
{
    virStorageVolObj *volobj = (virStorageVolObj *) payload;
    struct _virStoragePoolObjSearchVolData *data =
        (struct _virStoragePoolObjSearchVolData *) opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(volobj);

    if (data->iter(volobj->voldef, data->opaque))
        return 1;

    return 0;
}


virStorageVolDef *
virStoragePoolObjSearchVolume(virStoragePoolObj *obj,
                              virStorageVolObjListSearcher iter,
                              const void *opaque)
{
    virStorageVolObj *volobj;
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


virStorageVolDef *
virStorageVolDefFindByKey(virStoragePoolObj *obj,
                          const char *key)
{
    virStorageVolObj *volobj;

    virObjectRWLockRead(obj->volumes);
    volobj = virHashLookup(obj->volumes->objsKey, key);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;
    return NULL;
}


virStorageVolDef *
virStorageVolDefFindByPath(virStoragePoolObj *obj,
                           const char *path)
{
    virStorageVolObj *volobj;

    virObjectRWLockRead(obj->volumes);
    volobj = virHashLookup(obj->volumes->objsPath, path);
    virObjectRWUnlock(obj->volumes);

    if (volobj)
        return volobj->voldef;
    return NULL;
}


virStorageVolDef *
virStorageVolDefFindByName(virStoragePoolObj *obj,
                           const char *name)
{
    virStorageVolObj *volobj;

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
    virStoragePoolDef *pooldef;
    int count;
};


static int
virStoragePoolObjNumOfVolumesCb(void *payload,
                                const char *name G_GNUC_UNUSED,
                                void *opaque)
{
    virStorageVolObj *volobj = payload;
    struct _virStorageVolObjCountData *data = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(volobj);

    if (data->filter && !data->filter(data->conn, data->pooldef, volobj->voldef))
        return 0;

    data->count++;
    return 0;
}


int
virStoragePoolObjNumOfVolumes(virStoragePoolObj *obj,
                              virConnectPtr conn,
                              virStoragePoolVolumeACLFilter filter)
{
    virStorageVolObjList *volumes = obj->volumes;
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
    virStoragePoolDef *pooldef;
    bool error;
    int nnames;
    int maxnames;
    char **const names;
};

static int
virStoragePoolObjVolumeGetNamesCb(void *payload,
                                  const char *name G_GNUC_UNUSED,
                                  void *opaque)
{
    virStorageVolObj *volobj = payload;
    struct _virStorageVolObjNameData *data = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(volobj);

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    if (data->filter && !data->filter(data->conn, data->pooldef, volobj->voldef))
        return 0;

    if (data->names)
        data->names[data->nnames] = g_strdup(volobj->voldef->name);

    data->nnames++;
    return 0;
}


int
virStoragePoolObjVolumeGetNames(virStoragePoolObj *obj,
                                virConnectPtr conn,
                                virStoragePoolVolumeACLFilter filter,
                                char **const names,
                                int maxnames)
{
    virStorageVolObjList *volumes = obj->volumes;
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
struct _virStoragePoolObjVolumeListExportData {
    virConnectPtr conn;
    virStoragePoolVolumeACLFilter filter;
    virStoragePoolDef *pooldef;
    bool error;
    int nvols;
    virStorageVolPtr *vols;
};

static int
virStoragePoolObjVolumeListExportCallback(void *payload,
                                          const char *name G_GNUC_UNUSED,
                                          void *opaque)
{
    virStorageVolObj *volobj = payload;
    virStoragePoolObjVolumeListExportData *data = opaque;
    virStorageVolPtr vol = NULL;
    VIR_LOCK_GUARD lock = virObjectLockGuard(volobj);

    if (data->error)
        return 0;

    if (data->filter && !data->filter(data->conn, data->pooldef, volobj->voldef))
        return 0;

    if (data->vols) {
        if (!(vol = virGetStorageVol(data->conn, data->pooldef->name,
                                     volobj->voldef->name, volobj->voldef->key,
                                     NULL, NULL))) {
            data->error = true;
            return 0;
        }
        data->vols[data->nvols] = vol;
    }

    data->nvols++;
    return 0;
}


int
virStoragePoolObjVolumeListExport(virConnectPtr conn,
                                  virStoragePoolObj *obj,
                                  virStorageVolPtr **vols,
                                  virStoragePoolVolumeACLFilter filter)
{
    virStorageVolObjList *volumes = obj->volumes;
    virStoragePoolObjVolumeListExportData data = {
        .conn = conn, .filter = filter, .pooldef = obj->def, .error = false,
        .nvols = 0, .vols = NULL };

    virObjectRWLockRead(volumes);

    if (!vols) {
        int ret = virHashSize(volumes->objsName);
        virObjectRWUnlock(volumes);
        return ret;
    }

    data.vols = g_new0(virStorageVolPtr, virHashSize(volumes->objsName) + 1);

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
 * @doms : virStoragePoolObjList * to search
 * @def  : virStoragePoolDef * definition of pool to lookup
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
virStoragePoolObjIsDuplicate(virStoragePoolObjList *pools,
                             virStoragePoolDef *def,
                             bool check_active,
                             virStoragePoolObj **objRet)
{
    int ret = -1;
    virStoragePoolObj *obj = NULL;

    /* See if a Pool with matching UUID already exists */
    obj = virStoragePoolObjFindByUUIDLocked(pools, def->uuid);
    if (obj) {
        virObjectLock(obj);

        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(obj->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%1$s' is already defined with uuid %2$s"),
                           obj->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if Pool is already active, refuse it */
            if (virStoragePoolObjIsActive(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("pool is already active as '%1$s'"),
                               obj->def->name);
                goto cleanup;
            }

            if (virStoragePoolObjIsStarting(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("pool '%1$s' is starting up"),
                               obj->def->name);
                goto cleanup;
            }
        }

        *objRet = g_steal_pointer(&obj);
        ret = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        obj = virStoragePoolObjFindByNameLocked(pools, def->name);
        if (obj) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            virObjectLock(obj);

            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("pool '%1$s' already exists with uuid %2$s"),
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
getSCSIHostNumber(virStorageAdapterSCSIHost *scsi_host,
                  unsigned int *hostnum)
{
    unsigned int num;
    g_autofree char *name = NULL;

    if (scsi_host->has_parent) {
        virPCIDeviceAddress *addr = &scsi_host->parentaddr;
        unsigned int unique_id = scsi_host->unique_id;

        if (!(name = virSCSIHostGetNameByParentaddr(addr->domain,
                                                    addr->bus,
                                                    addr->slot,
                                                    addr->function,
                                                    unique_id)))
            return -1;
        if (virSCSIHostGetNumber(name, &num) < 0)
            return -1;
    } else {
        if (virSCSIHostGetNumber(scsi_host->name, &num) < 0)
            return -1;
    }

    *hostnum = num;

    return 0;
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
matchFCHostToSCSIHost(virStorageAdapterFCHost *fchost,
                      unsigned int scsi_hostnum)
{
    virConnectPtr conn = NULL;
    bool ret = false;
    g_autofree char *name = NULL;
    g_autofree char *scsi_host_name = NULL;
    g_autofree char *parent_name = NULL;

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
            scsi_host_name = g_strdup_printf("scsi_%s", name);
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
    virConnectClose(conn);
    return ret;
}


static bool
matchSCSIAdapterParent(virStorageAdapterSCSIHost *pool_scsi_host,
                       virStorageAdapterSCSIHost *def_scsi_host)
{
    virPCIDeviceAddress *pooladdr = &pool_scsi_host->parentaddr;
    virPCIDeviceAddress *defaddr = &def_scsi_host->parentaddr;

    if (pooladdr->domain == defaddr->domain &&
        pooladdr->bus == defaddr->bus &&
        pooladdr->slot == defaddr->slot &&
        pooladdr->function == defaddr->function &&
        pool_scsi_host->unique_id == def_scsi_host->unique_id)
        return true;

    return false;
}


static bool
virStoragePoolSourceMatchSingleHost(virStoragePoolSource *poolsrc,
                                    virStoragePoolSource *defsrc)
{
    if (poolsrc->nhost != 1 && defsrc->nhost != 1)
        return false;

    if (defsrc->hosts[0].port &&
        poolsrc->hosts[0].port != defsrc->hosts[0].port)
        return false;

    return STREQ(poolsrc->hosts[0].name, defsrc->hosts[0].name);
}


static bool
virStoragePoolSourceISCSIMatch(virStoragePoolObj *obj,
                               virStoragePoolDef *def)
{
    virStoragePoolSource *poolsrc = &obj->def->source;
    virStoragePoolSource *defsrc = &def->source;

    /* NB: Do not check the source host name */
    if (STRNEQ_NULLABLE(poolsrc->initiator.iqn, defsrc->initiator.iqn))
        return false;

    return true;
}


static virStoragePoolObj *
virStoragePoolObjSourceMatchTypeDIR(virStoragePoolObj *obj,
                                    virStoragePoolDef *def)
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


static virStoragePoolObj *
virStoragePoolObjSourceMatchTypeISCSI(virStoragePoolObj *obj,
                                      virStoragePoolDef *def)
{
    virStorageAdapter *pool_adapter = &obj->def->source.adapter;
    virStorageAdapter *def_adapter = &def->source.adapter;
    virStorageAdapterSCSIHost *pool_scsi_host;
    virStorageAdapterSCSIHost *def_scsi_host;
    virStorageAdapterFCHost *pool_fchost;
    virStorageAdapterFCHost *def_fchost;
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


static virStoragePoolObj *
virStoragePoolObjSourceMatchTypeDEVICE(virStoragePoolObj *obj,
                                       virStoragePoolDef *def)
{
    virStoragePoolObj *matchobj = NULL;

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
    virStoragePoolDef *def;
};

static int
virStoragePoolObjSourceFindDuplicateCb(const void *payload,
                                       const char *name G_GNUC_UNUSED,
                                       const void *opaque)
{
    virStoragePoolObj *obj = (virStoragePoolObj *) payload;
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
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_LOGICAL:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_ZFS:
        if ((data->def->type == VIR_STORAGE_POOL_ISCSI ||
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

    case VIR_STORAGE_POOL_ISCSI_DIRECT:
    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_LAST:
        break;
    }

    return 0;
}


static int
virStoragePoolObjSourceFindDuplicate(virStoragePoolObjList *pools,
                                     virStoragePoolDef *def)
{
    struct _virStoragePoolObjFindDuplicateData data = {.def = def};
    virStoragePoolObj *obj = NULL;

    obj = virHashSearch(pools->objs, virStoragePoolObjSourceFindDuplicateCb,
                        &data, NULL);

    if (obj) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Storage source conflict with pool: '%1$s'"),
                       obj->def->name);
        return -1;
    }

    return 0;
}


static void
virStoragePoolObjAssignDef(virStoragePoolObj *obj,
                           virStoragePoolDef **def,
                           unsigned int flags)
{
    if (virStoragePoolObjIsActive(obj) ||
        virStoragePoolObjIsStarting(obj)) {
        virStoragePoolDefFree(obj->newDef);
        obj->newDef = g_steal_pointer(def);
    } else {
        if (!obj->newDef &&
            flags & VIR_STORAGE_POOL_OBJ_LIST_ADD_LIVE)
            obj->newDef = g_steal_pointer(&obj->def);

        virStoragePoolDefFree(obj->def);
        obj->def = g_steal_pointer(def);
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
 * Upon successful return the virStoragePool object is the owner
 * of @def and callers should use virStoragePoolObjGetDef() or
 * virStoragePoolObjGetNewDef() if they need to access the
 * definition as @def is set to NULL.
 *
 * Returns locked and reffed object pointer or NULL on error
 */
virStoragePoolObj *
virStoragePoolObjListAdd(virStoragePoolObjList *pools,
                         virStoragePoolDef **def,
                         unsigned int flags)
{
    virStoragePoolObj *obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int rc;

    virObjectRWLockWrite(pools);

    if (virStoragePoolObjSourceFindDuplicate(pools, *def) < 0)
        goto error;

    rc = virStoragePoolObjIsDuplicate(pools, *def,
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

    virUUIDFormat((*def)->uuid, uuidstr);

    if (!(*def)->name ||
        g_hash_table_contains(pools->objs, uuidstr) ||
        g_hash_table_contains(pools->objsName, (*def)->name))
        goto error;

    g_hash_table_insert(pools->objs, g_strdup(uuidstr), obj);
    virObjectRef(obj);

    g_hash_table_insert(pools->objsName, g_strdup((*def)->name), obj);
    virObjectRef(obj);

    obj->def = g_steal_pointer(def);
    virObjectRWUnlock(pools);
    return obj;

 error:
    virStoragePoolObjEndAPI(&obj);
    virObjectRWUnlock(pools);
    return NULL;
}


static virStoragePoolObj *
virStoragePoolObjLoad(virStoragePoolObjList *pools,
                      const char *file,
                      const char *path,
                      const char *autostartLink)
{
    virStoragePoolObj *obj;
    g_autoptr(virStoragePoolDef) def = NULL;

    VIR_DEBUG("loading storage pool config XML '%s'", path);

    if (!(def = virStoragePoolDefParse(NULL, path, 0)))
        return NULL;

    if (!virStringMatchesNameSuffix(file, def->name, ".xml")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Storage pool config filename '%1$s' does not match pool name '%2$s'"),
                       path, def->name);
        return NULL;
    }

    if (!(obj = virStoragePoolObjListAdd(pools, &def, 0)))
        return NULL;

    VIR_FREE(obj->configFile);  /* for driver reload */
    obj->configFile = g_strdup(path);
    VIR_FREE(obj->autostartLink); /* for driver reload */
    obj->autostartLink = g_strdup(autostartLink);

    obj->autostart = virFileLinkPointsTo(obj->autostartLink,
                                         obj->configFile);

    return obj;
}


static virStoragePoolObj *
virStoragePoolObjLoadState(virStoragePoolObjList *pools,
                           const char *stateDir,
                           const char *name)
{
    g_autofree char *stateFile = NULL;
    virStoragePoolObj *obj = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    xmlNodePtr node = NULL;
    g_autoptr(virStoragePoolDef) def = NULL;

    if (!(stateFile = virFileBuildPath(stateDir, name, ".xml")))
        return NULL;

    VIR_DEBUG("loading storage pool state XML '%s'", stateFile);

    if (!(xml = virXMLParseFileCtxt(stateFile, &ctxt)))
        return NULL;

    if (!(node = virXPathNode("//pool", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any 'pool' element in state file"));
        return NULL;
    }

    ctxt->node = node;
    if (!(def = virStoragePoolDefParseXML(ctxt)))
        return NULL;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Storage pool state file '%1$s' does not match pool name '%2$s'"),
                       stateFile, def->name);
        return NULL;
    }

    /* create the object */
    if (!(obj = virStoragePoolObjListAdd(pools, &def,
                                         VIR_STORAGE_POOL_OBJ_LIST_ADD_CHECK_LIVE)))
        return NULL;

    /* XXX: future handling of some additional useful status data,
     * for now, if a status file for a pool exists, the pool will be marked
     * as active
     */

    obj->active = true;
    return obj;
}


int
virStoragePoolObjLoadAllState(virStoragePoolObjList *pools,
                              const char *stateDir)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virStoragePoolObj *obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        if (!(obj = virStoragePoolObjLoadState(pools, stateDir, entry->d_name)))
            continue;
        virStoragePoolObjEndAPI(&obj);
    }

    return ret;
}


int
virStoragePoolObjLoadAllConfigs(virStoragePoolObjList *pools,
                                const char *configDir,
                                const char *autostartDir)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        g_autofree char *path = virFileBuildPath(configDir, entry->d_name, NULL);
        g_autofree char *autostartLink = virFileBuildPath(autostartDir, entry->d_name, NULL);
        virStoragePoolObj *obj;

        if (!virStringHasSuffix(entry->d_name, ".xml"))
            continue;

        obj = virStoragePoolObjLoad(pools, entry->d_name, path, autostartLink);
        virStoragePoolObjEndAPI(&obj);
    }

    return ret;
}


int
virStoragePoolObjSaveDef(virStorageDriverState *driver,
                         virStoragePoolObj *obj,
                         virStoragePoolDef *def)
{
    if (!obj->configFile) {
        if (g_mkdir_with_parents(driver->configDir, 0777) < 0) {
            virReportSystemError(errno,
                                 _("cannot create config directory %1$s"),
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
virStoragePoolObjDeleteDef(virStoragePoolObj *obj)
{
    if (!obj->configFile) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no config file for %1$s"), obj->def->name);
        return -1;
    }

    if (unlink(obj->configFile) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot remove config for %1$s"),
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
                                     const char *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virStoragePoolObj *obj = payload;
    struct _virStoragePoolCountData *data = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);

    if (data->filter && !data->filter(data->conn, obj->def))
        return 0;

    if (data->wantActive != virStoragePoolObjIsActive(obj))
        return 0;

    data->count++;
    return 0;
}


int
virStoragePoolObjNumOfStoragePools(virStoragePoolObjList *pools,
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
                            const char *name G_GNUC_UNUSED,
                            void *opaque)
{
    virStoragePoolObj *obj = payload;
    struct _virStoragePoolNameData *data = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    if (data->filter && !data->filter(data->conn, obj->def))
        return 0;

    if (data->wantActive != virStoragePoolObjIsActive(obj))
        return 0;

    if (data->names)
        data->names[data->nnames] = g_strdup(obj->def->name);

    data->nnames++;
    return 0;
}


int
virStoragePoolObjGetNames(virStoragePoolObjList *pools,
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
virStoragePoolObjMatch(virStoragePoolObj *obj,
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
                                    const char *name G_GNUC_UNUSED,
                                    void *opaque)
{
    virStoragePoolObj *obj = payload;
    virStoragePoolObjListExportData *data = opaque;
    virStoragePoolPtr pool = NULL;
    VIR_LOCK_GUARD lock = virObjectLockGuard(obj);

    if (data->error)
        return 0;

    if (data->filter && !data->filter(data->conn, obj->def))
        return 0;

    if (!virStoragePoolObjMatch(obj, data->flags))
        return 0;

    if (data->pools) {
        if (!(pool = virGetStoragePool(data->conn, obj->def->name,
                                       obj->def->uuid, NULL, NULL))) {
            data->error = true;
            return 0;
        }
        data->pools[data->nPools] = pool;
    }

    data->nPools++;
    return 0;
}


int
virStoragePoolObjListExport(virConnectPtr conn,
                            virStoragePoolObjList *poolobjs,
                            virStoragePoolPtr **pools,
                            virStoragePoolObjListFilter filter,
                            unsigned int flags)
{
    virStoragePoolObjListExportData data = {
        .conn = conn, .filter = filter, .flags = flags, .error = false,
        .nPools = 0, .pools = NULL };

    virObjectRWLockRead(poolobjs);

    if (!pools) {
        int ret = virHashSize(poolobjs->objs);
        virObjectRWUnlock(poolobjs);
        return ret;
    }

    data.pools = g_new0(virStoragePoolPtr, virHashSize(poolobjs->objs) + 1);

    virHashForEach(poolobjs->objs, virStoragePoolObjListExportCallback, &data);
    virObjectRWUnlock(poolobjs);

    if (data.error)
        goto error;

    if (data.pools) {
        /* trim the array to the final size */
        VIR_REALLOC_N(data.pools, data.nPools + 1);
        *pools = data.pools;
    }

    return data.nPools;

 error:
    virObjectListFree(data.pools);
    return -1;
}
