/*
 * parallels_storage.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 *
 */

#include <config.h>

#include <stdlib.h>
#include <dirent.h>
#include <sys/statvfs.h>

#include "datatypes.h"
#include "memory.h"
#include "configmake.h"
#include "storage_file.h"
#include "virterror_internal.h"

#include "parallels_utils.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

#define parallelsPoolNotFoundError(pool_name)                    \
    virReportError(VIR_ERR_INVALID_ARG,                          \
                   _("pool '%s' not found"), pool_name);

static virStorageVolDefPtr
parallelsStorageVolumeDefine(virStoragePoolObjPtr pool, const char *xmldesc,
                             const char *xmlfile, bool is_new);
static virStorageVolPtr
parallelsStorageVolumeLookupByPath(virConnectPtr conn, const char *path);

static int
parallelsStoragePoolGetAlloc(virStoragePoolDefPtr def);

static void
parallelsStorageLock(virStorageDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
parallelsStorageUnlock(virStorageDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

static int
parallelsStorageClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    virStorageDriverStatePtr storageState = conn->storagePrivateData;
    conn->storagePrivateData = NULL;

    parallelsStorageLock(storageState);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(storageState->configDir);
    VIR_FREE(storageState->autostartDir);
    parallelsStorageUnlock(storageState);
    virMutexDestroy(&storageState->lock);
    VIR_FREE(storageState);

    return 0;
}

static int
parallelsFindVolumes(virStoragePoolObjPtr pool)
{
    DIR *dir;
    struct dirent *ent;
    char *path;

    if (!(dir = opendir(pool->def->target.path))) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (!virFileHasSuffix(ent->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(pool->def->target.path,
                                      ent->d_name, NULL)))
            goto no_memory;
        if (!parallelsStorageVolumeDefine(pool, NULL, path, false))
            goto cleanup;
        VIR_FREE(path);
    }

    return 0;
no_memory:
    virReportOOMError();
cleanup:
    return -1;

}

static virDrvOpenStatus
parallelsStorageOpen(virConnectPtr conn,
                     virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    char *base = NULL;
    virStorageDriverStatePtr storageState;
    int privileged = (geteuid() == 0);
    parallelsConnPtr privconn = conn->privateData;
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "Parallels"))
        return VIR_DRV_OPEN_DECLINED;

    if (VIR_ALLOC(storageState) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }

    if (virMutexInit(&storageState->lock) < 0) {
        VIR_FREE(storageState);
        return VIR_DRV_OPEN_ERROR;
    }
    parallelsStorageLock(storageState);

    if (privileged) {
        if ((base = strdup(SYSCONFDIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        char *userdir = virGetUserDirectory();

        if (!userdir)
            goto error;

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);
    }

    /* Configuration paths are either ~/.libvirt/storage/... (session) or
     * /etc/libvirt/storage/... (system).
     */
    if (virAsprintf(&storageState->configDir,
                    "%s/parallels-storage", base) == -1)
        goto out_of_memory;

    if (virAsprintf(&storageState->autostartDir,
                    "%s/parallels-storage/autostart", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if (virStoragePoolLoadAllConfigs(&privconn->pools,
                                     storageState->configDir,
                                     storageState->autostartDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to load pool configs"));
        goto error;
    }

    for (size_t i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        virStoragePoolObjPtr pool;

        pool = privconn->pools.objs[i];
        pool->active = 1;

        if (parallelsStoragePoolGetAlloc(pool->def) < 0)
            goto error;

        if (parallelsFindVolumes(pool) < 0)
            goto error;

        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }

    parallelsStorageUnlock(storageState);

    conn->storagePrivateData = storageState;

    return VIR_DRV_OPEN_SUCCESS;

out_of_memory:
    virReportOOMError();
error:
    VIR_FREE(base);
    parallelsStorageUnlock(storageState);
    parallelsStorageClose(conn);
    return -1;
}

static int
parallelsStorageNumPools(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int numActive = 0;
    size_t i;

    parallelsDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numActive++;
    parallelsDriverUnlock(privconn);

    return numActive;
}

static int
parallelsStorageListPools(virConnectPtr conn, char **const names, int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    parallelsDriverLock(privconn);
    memset(names, 0, sizeof(*names) * nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name))) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto no_memory;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    parallelsDriverUnlock(privconn);
    return -1;
}

static int
parallelsStorageNumDefinedPools(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    int numInactive = 0;
    size_t i;

    parallelsDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numInactive++;
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return numInactive;
}

static int
parallelsStorageListDefinedPools(virConnectPtr conn,
                           char **const names, int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    parallelsDriverLock(privconn);
    memset(names, 0, sizeof(*names) * nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name))) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto no_memory;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    parallelsDriverUnlock(privconn);
    return -1;
}


static int
parallelsStoragePoolIsActive(virStoragePoolPtr pool)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    parallelsDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    parallelsDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = virStoragePoolObjIsActive(obj);

cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}

static int
parallelsStoragePoolIsPersistent(virStoragePoolPtr pool ATTRIBUTE_UNUSED)
{
    return 1;
}

static virStoragePoolPtr
parallelsStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    parallelsDriverLock(privconn);
    pool = virStoragePoolObjFindByUUID(&privconn->pools, uuid);
    parallelsDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
parallelsStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    parallelsDriverLock(privconn);
    pool = virStoragePoolObjFindByName(&privconn->pools, name);
    parallelsDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
parallelsStoragePoolLookupByVolume(virStorageVolPtr vol)
{
    return parallelsStoragePoolLookupByName(vol->conn, vol->pool);
}

/*
 * Fill capacity, available and allocation
 * fields in pool definition.
 */
static int
parallelsStoragePoolGetAlloc(virStoragePoolDefPtr def)
{
    struct statvfs sb;

    if (statvfs(def->target.path, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot statvfs path '%s'"),
                             def->target.path);
        return -1;
    }

    def->capacity = ((unsigned long long)sb.f_frsize *
                     (unsigned long long)sb.f_blocks);
    def->available = ((unsigned long long)sb.f_bfree *
                            (unsigned long long)sb.f_bsize);
    def->allocation = def->capacity - def->available;

    return 0;
}

static virStoragePoolPtr
parallelsStoragePoolDefine(virConnectPtr conn,
                           const char *xml, unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    virCheckFlags(0, NULL);

    parallelsDriverLock(privconn);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (def->type != VIR_STORAGE_POOL_DIR) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("Only local directories are supported"));
        goto cleanup;
    }

    if (virStoragePoolObjIsDuplicate(&privconn->pools, def, 0) < 0)
        goto cleanup;

    if (virStoragePoolSourceFindDuplicate(&privconn->pools, def) < 0)
        goto cleanup;

    if (parallelsStoragePoolGetAlloc(def))
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&privconn->pools, def)))
        goto cleanup;

    if (virStoragePoolObjSaveDef(conn->storagePrivateData, pool, def) < 0) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    pool->configFile = strdup("\0");
    if (!pool->configFile) {
        virReportOOMError();
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsStoragePoolUndefine(virStoragePoolPtr pool)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is still active"), pool->name);
        goto cleanup;
    }

    if (virStoragePoolObjDeleteDef(privpool) < 0)
        goto cleanup;

    VIR_FREE(privpool->configFile);

    virStoragePoolObjRemove(&privconn->pools, privpool);
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsStoragePoolStart(virStoragePoolPtr pool, unsigned int flags)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    privpool->active = 1;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStoragePoolDestroy(virStoragePoolPtr pool)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    if (privpool->configFile == NULL) {
        virStoragePoolObjRemove(&privconn->pools, privpool);
        privpool = NULL;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    parallelsDriverUnlock(privconn);
    return ret;
}

static int
parallelsStoragePoolRefresh(virStoragePoolPtr pool, unsigned int flags)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
parallelsStoragePoolGetInfo(virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (privpool->active)
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = privpool->def->capacity;
    info->allocation = privpool->def->allocation;
    info->available = privpool->def->available;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
parallelsStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    ret = virStoragePoolDefFormat(privpool->def);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStoragePoolGetAutostart(virStoragePoolPtr pool, int *autostart)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!privpool->configFile) {
        *autostart = 0;
    } else {
        *autostart = privpool->autostart;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStoragePoolSetAutostart(virStoragePoolPtr pool, int autostart)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!privpool->configFile) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("pool has no config file"));
        goto cleanup;
    }

    privpool->autostart = (autostart != 0);
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStoragePoolNumVolumes(virStoragePoolPtr pool)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    ret = privpool->volumes.count;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStoragePoolListVolumes(virStoragePoolPtr pool,
                                char **const names, int maxnames)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int n = 0;
    size_t i = 0;

    memset(names, 0, maxnames * sizeof(*names));

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto error;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                 _("storage pool '%s' is not active"), pool->name);
        goto error;
    }

    for (i = 0; i < privpool->volumes.count && n < maxnames; i++) {
        if ((names[n++] = strdup(privpool->volumes.objs[i]->name)) == NULL) {
            virReportOOMError();
            goto error;
        }
    }

    virStoragePoolObjUnlock(privpool);
    return n;

error:
    for (n = 0; n < maxnames; n++)
        VIR_FREE(names[i]);

    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return -1;
}

static virStorageVolPtr
parallelsStorageVolumeLookupByName(virStoragePoolPtr pool,
                                   const char *name)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    virStorageVolPtr ret = NULL;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, name);

    if (!privvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static virStorageVolPtr
parallelsStorageVolumeLookupByKey(virConnectPtr conn, const char *key)
{
    parallelsConnPtr privconn = conn->privateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    parallelsDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByKey(privconn->pools.objs[i], key);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name, privvol->key);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching key '%s'"), key);

    return ret;
}

virStorageVolPtr
parallelsStorageVolumeLookupByPathLocked(virConnectPtr conn, const char *path)
{
    parallelsConnPtr privconn = conn->privateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByPath(privconn->pools.objs[i], path);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name, privvol->key);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching path '%s'"), path);

    return ret;
}

static virStorageVolPtr
parallelsStorageVolumeLookupByPath(virConnectPtr conn, const char *path)
{
    parallelsConnPtr privconn = conn->privateData;
    virStorageVolPtr ret = NULL;

    parallelsDriverLock(privconn);
    ret = parallelsStorageVolumeLookupByPathLocked(conn, path);
    parallelsDriverUnlock(privconn);

    return ret;
}

static virStorageVolDefPtr
parallelsStorageVolumeDefine(virStoragePoolObjPtr pool,
                             const char *xmldesc,
                             const char *xmlfile, bool is_new)
{
    virStorageVolDefPtr privvol = NULL;
    virStorageVolDefPtr ret = NULL;
    char *xml_path = NULL;

    if (xmlfile)
        privvol = virStorageVolDefParseFile(pool->def, xmlfile);
    else
        privvol = virStorageVolDefParseString(pool->def, xmldesc);

    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, privvol->name)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("storage vol already exists"));
        goto cleanup;
    }

    if (is_new) {
        /* Make sure enough space */
        if ((pool->def->allocation + privvol->allocation) >
            pool->def->capacity) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Not enough free space in pool for volume '%s'"),
                           privvol->name);
            goto cleanup;
        }
    }

    if (VIR_REALLOC_N(pool->volumes.objs, pool->volumes.count + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    pool->def->target.path, privvol->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    if (is_new) {
        xml_path = parallelsAddFileExt(privvol->target.path, ".xml");
        if (!xml_path)
            goto cleanup;

        if (virXMLSaveFile(xml_path, privvol->name,
                           "volume-create", xmldesc)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Can't create file with volume description"));
            goto cleanup;
        }

        pool->def->allocation += privvol->allocation;
        pool->def->available = (pool->def->capacity -
                                pool->def->allocation);
    }

    pool->volumes.objs[pool->volumes.count++] = privvol;

    ret = privvol;
    privvol = NULL;

cleanup:
    virStorageVolDefFree(privvol);
    VIR_FREE(xml_path);
    return ret;
}

static virStorageVolPtr
parallelsStorageVolumeCreateXML(virStoragePoolPtr pool,
                                const char *xmldesc, unsigned int flags)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolPtr ret = NULL;
    virStorageVolDefPtr privvol = NULL;

    virCheckFlags(0, NULL);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = parallelsStorageVolumeDefine(privpool, xmldesc, NULL, true);
    if (!privvol)
        goto cleanup;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);
cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static virStorageVolPtr
parallelsStorageVolumeCreateXMLFrom(virStoragePoolPtr pool,
                                    const char *xmldesc,
                                    virStorageVolPtr clonevol,
                                    unsigned int flags)
{
    parallelsConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL, origvol = NULL;
    virStorageVolPtr ret = NULL;

    virCheckFlags(0, NULL);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("storage vol already exists"));
        goto cleanup;
    }

    origvol = virStorageVolDefFindByName(privpool, clonevol->name);
    if (!origvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       clonevol->name);
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->allocation) >
        privpool->def->capacity) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not enough free space in pool for volume '%s'"),
                       privvol->name);
        goto cleanup;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path, privvol->name) == -1) {
        virReportOOMError();
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    privpool->def->allocation += privvol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    privpool->volumes.objs[privpool->volumes.count++] = privvol;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);
    privvol = NULL;

cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
parallelsStorageVolumeDelete(virStorageVolPtr vol, unsigned int flags)
{
    parallelsConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    size_t i;
    int ret = -1;
    char *xml_path = NULL;

    virCheckFlags(0, -1);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(vol->pool);
        goto cleanup;
    }


    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }


    privpool->def->allocation -= privvol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    for (i = 0; i < privpool->volumes.count; i++) {
        if (privpool->volumes.objs[i] == privvol) {
            xml_path = parallelsAddFileExt(privvol->target.path, ".xml");
            if (!xml_path)
                goto cleanup;

            if (unlink(xml_path)) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Can't remove file '%s'"), xml_path);
                goto cleanup;
            }

            virStorageVolDefFree(privvol);

            if (i < (privpool->volumes.count - 1))
                memmove(privpool->volumes.objs + i,
                        privpool->volumes.objs + i + 1,
                        sizeof(*(privpool->volumes.objs)) *
                        (privpool->volumes.count - (i + 1)));

            if (VIR_REALLOC_N(privpool->volumes.objs,
                              privpool->volumes.count - 1) < 0) {
                ;   /* Failure to reduce memory allocation isn't fatal */
            }
            privpool->volumes.count--;

            break;
        }
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    VIR_FREE(xml_path);
    return ret;
}


static int
parallelsStorageVolumeTypeForPool(int pooltype)
{

    switch (pooltype) {
        case VIR_STORAGE_POOL_DIR:
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_NETFS:
            return VIR_STORAGE_VOL_FILE;
default:
            return VIR_STORAGE_VOL_BLOCK;
    }
}

static int
parallelsStorageVolumeGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    parallelsConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int ret = -1;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(vol->pool);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    memset(info, 0, sizeof(*info));
    info->type = parallelsStorageVolumeTypeForPool(privpool->def->type);
    info->capacity = privvol->capacity;
    info->allocation = privvol->allocation;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
parallelsStorageVolumeGetXMLDesc(virStorageVolPtr vol, unsigned int flags)
{
    parallelsConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(vol->pool);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = virStorageVolDefFormat(privpool->def, privvol);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
parallelsStorageVolumeGetPath(virStorageVolPtr vol)
{
    parallelsConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    parallelsDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    parallelsDriverUnlock(privconn);

    if (privpool == NULL) {
        parallelsPoolNotFoundError(vol->pool);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = strdup(privvol->target.path);
    if (ret == NULL)
        virReportOOMError();

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static virStorageDriver parallelsStorageDriver = {
    .name = "Parallels",
    .open = parallelsStorageOpen,     /* 0.10.0 */
    .close = parallelsStorageClose,   /* 0.10.0 */

    .numOfPools = parallelsStorageNumPools,   /* 0.10.0 */
    .listPools = parallelsStorageListPools,   /* 0.10.0 */
    .numOfDefinedPools = parallelsStorageNumDefinedPools,     /* 0.10.0 */
    .listDefinedPools = parallelsStorageListDefinedPools,     /* 0.10.0 */
    .poolLookupByName = parallelsStoragePoolLookupByName,     /* 0.10.0 */
    .poolLookupByUUID = parallelsStoragePoolLookupByUUID,     /* 0.10.0 */
    .poolLookupByVolume = parallelsStoragePoolLookupByVolume, /* 0.10.0 */
    .poolDefineXML = parallelsStoragePoolDefine,      /* 0.10.0 */
    .poolUndefine = parallelsStoragePoolUndefine,     /* 0.10.0 */
    .poolCreate = parallelsStoragePoolStart,  /* 0.10.0 */
    .poolDestroy = parallelsStoragePoolDestroy,       /* 0.10.0 */
    .poolRefresh = parallelsStoragePoolRefresh,       /* 0.10.0 */
    .poolGetInfo = parallelsStoragePoolGetInfo,       /* 0.10.0 */
    .poolGetXMLDesc = parallelsStoragePoolGetXMLDesc, /* 0.10.0 */
    .poolGetAutostart = parallelsStoragePoolGetAutostart,     /* 0.10.0 */
    .poolSetAutostart = parallelsStoragePoolSetAutostart,     /* 0.10.0 */
    .poolNumOfVolumes = parallelsStoragePoolNumVolumes,       /* 0.10.0 */
    .poolListVolumes = parallelsStoragePoolListVolumes,       /* 0.10.0 */

    .volLookupByName = parallelsStorageVolumeLookupByName,    /* 0.10.0 */
    .volLookupByKey = parallelsStorageVolumeLookupByKey,      /* 0.10.0 */
    .volLookupByPath = parallelsStorageVolumeLookupByPath,    /* 0.10.0 */
    .volCreateXML = parallelsStorageVolumeCreateXML,  /* 0.10.0 */
    .volCreateXMLFrom = parallelsStorageVolumeCreateXMLFrom,  /* 0.10.0 */
    .volDelete = parallelsStorageVolumeDelete,        /* 0.10.0 */
    .volGetInfo = parallelsStorageVolumeGetInfo,      /* 0.10.0 */
    .volGetXMLDesc = parallelsStorageVolumeGetXMLDesc,        /* 0.10.0 */
    .volGetPath = parallelsStorageVolumeGetPath,      /* 0.10.0 */
    .poolIsActive = parallelsStoragePoolIsActive,     /* 0.10.0 */
    .poolIsPersistent = parallelsStoragePoolIsPersistent,     /* 0.10.0 */
};

int
parallelsStorageRegister(void)
{
    if (virRegisterStorageDriver(&parallelsStorageDriver) < 0)
        return -1;

    return 0;
}
