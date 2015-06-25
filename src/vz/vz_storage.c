/*
 * vz_storage.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "datatypes.h"
#include "dirname.h"
#include "viralloc.h"
#include "configmake.h"
#include "virstoragefile.h"
#include "virerror.h"
#include "virfile.h"
#include "vz_utils.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

#define vzPoolNotFoundError(pool_name)                    \
    virReportError(VIR_ERR_INVALID_ARG,                          \
                   _("pool '%s' not found"), pool_name);

static virStorageVolDefPtr
vzStorageVolDefineXML(virStoragePoolObjPtr pool, const char *xmldesc,
                      const char *xmlfile, bool is_new);
static virStorageVolPtr
vzStorageVolLookupByPath(virConnectPtr conn, const char *path);

static int
vzStoragePoolGetAlloc(virStoragePoolDefPtr def);

static void
vzStorageLock(virStorageDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
vzStorageUnlock(virStorageDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

int
vzStorageClose(virConnectPtr conn)
{
    vzConnPtr privconn = conn->privateData;

    if (!privconn)
        return 0;

    virStorageDriverStatePtr storageState = privconn->storageState;
    privconn->storageState = NULL;

    if (!storageState)
        return 0;

    vzStorageLock(storageState);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(storageState->configDir);
    VIR_FREE(storageState->autostartDir);
    vzStorageUnlock(storageState);
    virMutexDestroy(&storageState->lock);
    VIR_FREE(storageState);

    return 0;
}

static int
vzFindVolumes(virStoragePoolObjPtr pool)
{
    DIR *dir;
    struct dirent *ent;
    char *path = NULL;
    int ret = -1;
    int direrr;

    if (!(dir = opendir(pool->def->target.path))) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             pool->def->target.path);
        return -1;
    }

    while ((direrr = virDirRead(dir, &ent, pool->def->target.path)) > 0) {
        if (!virFileHasSuffix(ent->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(pool->def->target.path,
                                      ent->d_name, NULL)))
            goto cleanup;
        if (!vzStorageVolDefineXML(pool, NULL, path, false))
            goto cleanup;

        VIR_FREE(path);
    }
    if (direrr < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(path);
    closedir(dir);
    return ret;

}

/*
 * Generate unique pool name by path
 */
static char *vzMakePoolName(virConnectPtr conn, const char *path)
{
    vzConnPtr privconn = conn->privateData;
    char *name;
    size_t i;

    for (i = 0; i < UINT_MAX; i++) {
        bool found = false;
        size_t j;

        if ((!i && VIR_STRDUP(name, path) < 0) ||
            (i && virAsprintf(&name, "%s-%zu", path, i) < 0))
            return NULL;

        for (j = 0; j < strlen(name); j++)
            if (name[j] == '/')
                name[j] = '-';

        for (j = 0; j < privconn->pools.count; j++) {
            if (STREQ(name, privconn->pools.objs[j]->def->name)) {
                found = true;
                break;
            }
        }

        if (!found)
            return name;

        VIR_FREE(name);
    }

    return NULL;
}

static virStoragePoolObjPtr
vzPoolCreateByPath(virConnectPtr conn, const char *path)
{
    vzConnPtr privconn = conn->privateData;
    virStoragePoolObjListPtr pools = &privconn->pools;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;

    if (VIR_ALLOC(def) < 0)
        goto error;

    if (!(def->name = vzMakePoolName(conn, path)))
        goto error;

    if (virUUIDGenerate(def->uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Can't generate UUID"));
        goto error;
    }

    def->type = VIR_STORAGE_POOL_DIR;
    if (VIR_STRDUP(def->target.path, path) < 0)
        goto error;

    if (!(pool = virStoragePoolObjAssignDef(pools, def)))
        goto error;

    if (virStoragePoolObjSaveDef(privconn->storageState, pool, def) < 0) {
        virStoragePoolObjRemove(pools, pool);
        goto error;
    }

    virStoragePoolObjUnlock(pool);

    return pool;
 error:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    return NULL;
}

/*
 * Create pool of type VIR_STORAGE_POOL_DIR with
 * path to the VM, if it does not exist.
 */
static virStoragePoolObjPtr
vzPoolAddByDomain(virConnectPtr conn, virDomainObjPtr dom)
{
    vzConnPtr privconn = conn->privateData;
    vzDomObjPtr pdom = dom->privateData;
    virStoragePoolObjListPtr pools = &privconn->pools;
    char *poolPath;
    virStoragePoolObjPtr pool = NULL;
    size_t j;

    poolPath = mdir_name(pdom->home);
    if (!poolPath) {
        virReportOOMError();
        return NULL;
    }

    for (j = 0; j < pools->count; j++) {
        if (STREQ(poolPath, pools->objs[j]->def->target.path)) {
            pool = pools->objs[j];
            break;
        }
    }

    if (!pool)
        pool = vzPoolCreateByPath(conn, poolPath);

    VIR_FREE(poolPath);
    return pool;
}

static int vzDiskDescParseNode(xmlDocPtr xml,
                               xmlNodePtr root,
                               virStorageVolDefPtr def)
{
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    if (STRNEQ((const char *)root->name, "Parallels_disk_image")) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("unknown root element for storage pool"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;

    if (virXPathULongLong("string(./Disk_Parameters/Disk_size)",
                          ctxt, &def->target.capacity) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("failed to get disk size from "
                               "the disk descriptor xml"));
        goto cleanup;
    }

    def->target.capacity <<= 9;
    def->target.allocation = def->target.capacity;
    ret = 0;
 cleanup:
    xmlXPathFreeContext(ctxt);
    return ret;

}

static int vzDiskDescParse(const char *path, virStorageVolDefPtr def)
{
    xmlDocPtr xml;
    int ret = -1;

    if (!(xml = virXMLParse(path, NULL, NULL)))
        return -1;

    ret = vzDiskDescParseNode(xml, xmlDocGetRootElement(xml), def);
    xmlFreeDoc(xml);
    return ret;
}

static int vzAddDiskVolume(virStoragePoolObjPtr pool,
                           virDomainObjPtr dom,
                           const char *diskName,
                           const char *diskPath,
                           const char *diskDescPath)
{
    virStorageVolDefPtr def = NULL;

    if (VIR_ALLOC(def))
        goto error;

    if (virAsprintf(&def->name, "%s-%s", dom->def->name, diskName) < 0)
        goto error;

    def->type = VIR_STORAGE_VOL_FILE;

    if (vzDiskDescParse(diskDescPath, def) < 0)
        goto error;

    if (!(def->target.path = realpath(diskPath, NULL)))
        goto no_memory;

    if (VIR_STRDUP(def->key, def->target.path) < 0)
        goto error;

    if (VIR_APPEND_ELEMENT(pool->volumes.objs, pool->volumes.count, def) < 0)
        goto error;

    return 0;
 no_memory:
    virReportOOMError();
 error:
    virStorageVolDefFree(def);
    return -1;
}

static int vzFindVmVolumes(virStoragePoolObjPtr pool,
                           virDomainObjPtr dom)
{
    vzDomObjPtr pdom = dom->privateData;
    DIR *dir;
    struct dirent *ent;
    char *diskPath = NULL, *diskDescPath = NULL;
    struct stat sb;
    int ret = -1;
    int direrr;

    if (!(dir = opendir(pdom->home))) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             pdom->home);
        return ret;
    }

    while ((direrr = virDirRead(dir, &ent, pdom->home)) > 0) {
        VIR_FREE(diskPath);
        VIR_FREE(diskDescPath);

        if (!(diskPath = virFileBuildPath(pdom->home, ent->d_name, NULL)))
            goto cleanup;

        if (lstat(diskPath, &sb) < 0) {
            virReportSystemError(errno,
                                 _("cannot stat path '%s'"),
                                 ent->d_name);
            goto cleanup;
        }

        if (!S_ISDIR(sb.st_mode))
            continue;

        if (!(diskDescPath = virFileBuildPath(diskPath,
                                              "DiskDescriptor", ".xml")))
            goto cleanup;

        if (!virFileExists(diskDescPath))
            continue;

        /* here we know, that ent->d_name is a disk image directory */

        if (vzAddDiskVolume(pool, dom, ent->d_name,
                            diskPath, diskDescPath))
            goto cleanup;
    }
    if (direrr < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(diskPath);
    VIR_FREE(diskDescPath);
    closedir(dir);
    return ret;

}

static int
vzPoolsAdd(virDomainObjPtr dom,
           void *opaque)
{
    virConnectPtr conn = opaque;
    virStoragePoolObjPtr pool;

    if (!(pool = vzPoolAddByDomain(conn, dom)))
        return -1;

    if (vzFindVmVolumes(pool, dom))
        return -1;

    return 0;
}

static int vzLoadPools(virConnectPtr conn)
{
    vzConnPtr privconn = conn->privateData;
    virStorageDriverStatePtr storageState = privconn->storageState;
    char *base = NULL;
    size_t i;

    if (VIR_STRDUP(base, SYSCONFDIR "/libvirt") < 0)
        goto error;

    /* Configuration path is /etc/libvirt/parallels-storage/... . */
    if (virAsprintf(&storageState->configDir,
                    "%s/parallels-storage", base) == -1)
        goto error;

    if (virAsprintf(&storageState->autostartDir,
                    "%s/parallels-storage/autostart", base) == -1)
        goto error;

    VIR_FREE(base);

    if (virStoragePoolLoadAllConfigs(&privconn->pools,
                                     storageState->configDir,
                                     storageState->autostartDir) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to load pool configs"));
        goto error;
    }

    if (virDomainObjListForEach(privconn->domains, vzPoolsAdd, conn) < 0)
        goto error;

    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        virStoragePoolObjPtr pool;

        pool = privconn->pools.objs[i];
        pool->active = 1;

        if (vzStoragePoolGetAlloc(pool->def) < 0)
            goto error;

        if (vzFindVolumes(pool) < 0)
            goto error;

        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }

    return 0;

 error:
    VIR_FREE(base);
    return -1;
}

virDrvOpenStatus
vzStorageOpen(virConnectPtr conn,
              unsigned int flags)
{
    vzConnPtr privconn = conn->privateData;
    virStorageDriverStatePtr storageState;
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "vz") &&
        STRNEQ(conn->driver->name, "Parallels"))
        return VIR_DRV_OPEN_DECLINED;

    if (VIR_ALLOC(storageState) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (virMutexInit(&storageState->lock) < 0) {
        VIR_FREE(storageState);
        return VIR_DRV_OPEN_ERROR;
    }

    privconn->storageState = storageState;
    vzStorageLock(storageState);

    if (vzLoadPools(conn))
        goto error;

    vzStorageUnlock(storageState);

    return VIR_DRV_OPEN_SUCCESS;

 error:
    vzStorageUnlock(storageState);
    vzStorageClose(conn);
    return VIR_DRV_OPEN_ERROR;
}

static int
vzConnectNumOfStoragePools(virConnectPtr conn)
{
    vzConnPtr privconn = conn->privateData;
    int numActive = 0;
    size_t i;

    vzDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numActive++;
    vzDriverUnlock(privconn);

    return numActive;
}

static int
vzConnectListStoragePools(virConnectPtr conn, char **const names, int nnames)
{
    vzConnPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    vzDriverLock(privconn);
    memset(names, 0, sizeof(*names) * nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            VIR_STRDUP(names[n++], privconn->pools.objs[i]->def->name) < 0) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto error;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    vzDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    vzDriverUnlock(privconn);
    return -1;
}

static int
vzConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    vzConnPtr privconn = conn->privateData;
    int numInactive = 0;
    size_t i;

    vzDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numInactive++;
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    vzDriverUnlock(privconn);

    return numInactive;
}

static int
vzConnectListDefinedStoragePools(virConnectPtr conn,
                                 char **const names, int nnames)
{
    vzConnPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    vzDriverLock(privconn);
    memset(names, 0, sizeof(*names) * nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            VIR_STRDUP(names[n++], privconn->pools.objs[i]->def->name) < 0) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto error;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    vzDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    vzDriverUnlock(privconn);
    return -1;
}


static int
vzStoragePoolIsActive(virStoragePoolPtr pool)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    vzDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    vzDriverUnlock(privconn);
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
vzStoragePoolIsPersistent(virStoragePoolPtr pool ATTRIBUTE_UNUSED)
{
    return 1;
}

static virStoragePoolPtr
vzStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    vzConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    vzDriverLock(privconn);
    pool = virStoragePoolObjFindByUUID(&privconn->pools, uuid);
    vzDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
vzStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    vzConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    vzDriverLock(privconn);
    pool = virStoragePoolObjFindByName(&privconn->pools, name);
    vzDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
vzStoragePoolLookupByVolume(virStorageVolPtr vol)
{
    return vzStoragePoolLookupByName(vol->conn, vol->pool);
}

/*
 * Fill capacity, available and allocation
 * fields in pool definition.
 */
static int
vzStoragePoolGetAlloc(virStoragePoolDefPtr def)
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
                      (unsigned long long)sb.f_frsize);
    def->allocation = def->capacity - def->available;

    return 0;
}

static virStoragePoolPtr
vzStoragePoolDefineXML(virConnectPtr conn,
                       const char *xml, unsigned int flags)
{
    vzConnPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    virCheckFlags(0, NULL);

    vzDriverLock(privconn);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (def->type != VIR_STORAGE_POOL_DIR) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("Only local directories are supported"));
        goto cleanup;
    }

    if (virStoragePoolObjIsDuplicate(&privconn->pools, def, 0) < 0)
        goto cleanup;

    if (virStoragePoolSourceFindDuplicate(conn, &privconn->pools, def) < 0)
        goto cleanup;

    if (vzStoragePoolGetAlloc(def))
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&privconn->pools, def)))
        goto cleanup;

    if (virStoragePoolObjSaveDef(privconn->storageState, pool, def) < 0) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    if (VIR_STRDUP(pool->configFile, "\0") < 0)
        goto cleanup;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    vzDriverUnlock(privconn);
    return ret;
}

static int
vzStoragePoolUndefine(virStoragePoolPtr pool)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
    vzDriverUnlock(privconn);
    return ret;
}

static int
vzStoragePoolCreate(virStoragePoolPtr pool, unsigned int flags)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolDestroy(virStoragePoolPtr pool)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
    vzDriverUnlock(privconn);
    return ret;
}

static int
vzStoragePoolRefresh(virStoragePoolPtr pool, unsigned int flags)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolGetInfo(virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
        goto cleanup;
    }

    ret = virStoragePoolDefFormat(privpool->def);

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
vzStoragePoolGetAutostart(virStoragePoolPtr pool, int *autostart)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolSetAutostart(virStoragePoolPtr pool, int autostart)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
vzStoragePoolListVolumes(virStoragePoolPtr pool,
                         char **const names, int maxnames)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int n = 0;
    size_t i = 0;

    memset(names, 0, maxnames * sizeof(*names));

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
        goto error;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto error;
    }

    for (i = 0; i < privpool->volumes.count && n < maxnames; i++) {
        if (VIR_STRDUP(names[n++], privpool->volumes.objs[i]->name) < 0)
            goto error;
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
vzStorageVolLookupByName(virStoragePoolPtr pool,
                         const char *name)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    virStorageVolPtr ret = NULL;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
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
                           privvol->name, privvol->key,
                           NULL, NULL);

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static virStorageVolPtr
vzStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    vzConnPtr privconn = conn->privateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    vzDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByKey(privconn->pools.objs[i], key);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name, privvol->key,
                                       NULL, NULL);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    vzDriverUnlock(privconn);

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching key '%s'"), key);

    return ret;
}

virStorageVolPtr
vzStorageVolLookupByPathLocked(virConnectPtr conn, const char *path)
{
    vzConnPtr privconn = conn->privateData;
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
                                       privvol->name, privvol->key,
                                       NULL, NULL);
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
vzStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    vzConnPtr privconn = conn->privateData;
    virStorageVolPtr ret = NULL;

    vzDriverLock(privconn);
    ret = vzStorageVolLookupByPathLocked(conn, path);
    vzDriverUnlock(privconn);

    return ret;
}

static virStorageVolDefPtr
vzStorageVolDefineXML(virStoragePoolObjPtr pool,
                      const char *xmldesc,
                      const char *xmlfile, bool is_new)
{
    virStorageVolDefPtr privvol = NULL;
    virStorageVolDefPtr ret = NULL;
    char *xml_path = NULL;

    if (xmlfile)
        privvol = virStorageVolDefParseFile(pool->def, xmlfile, 0);
    else
        privvol = virStorageVolDefParseString(pool->def, xmldesc, 0);

    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, privvol->name)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("storage vol already exists"));
        goto cleanup;
    }

    if (is_new) {
        /* Make sure enough space */
        if ((pool->def->allocation + privvol->target.allocation) >
            pool->def->capacity) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Not enough free space in pool for volume '%s'"),
                           privvol->name);
            goto cleanup;
        }
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    pool->def->target.path, privvol->name) < 0)
        goto cleanup;

    if (VIR_STRDUP(privvol->key, privvol->target.path) < 0)
        goto cleanup;

    if (is_new) {
        xml_path = vzAddFileExt(privvol->target.path, ".xml");
        if (!xml_path)
            goto cleanup;

        if (virXMLSaveFile(xml_path, NULL, "volume-create", xmldesc)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Can't create file with volume description"));
            goto cleanup;
        }

        pool->def->allocation += privvol->target.allocation;
        pool->def->available = (pool->def->capacity -
                                pool->def->allocation);
    }

    if (VIR_APPEND_ELEMENT_COPY(pool->volumes.objs,
                                pool->volumes.count, privvol) < 0)
        goto cleanup;

    ret = privvol;
    privvol = NULL;

 cleanup:
    virStorageVolDefFree(privvol);
    VIR_FREE(xml_path);
    return ret;
}

static virStorageVolPtr
vzStorageVolCreateXML(virStoragePoolPtr pool,
                      const char *xmldesc, unsigned int flags)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolPtr ret = NULL;
    virStorageVolDefPtr privvol = NULL;

    virCheckFlags(0, NULL);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = vzStorageVolDefineXML(privpool, xmldesc, NULL, true);
    if (!privvol)
        goto cleanup;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key,
                           NULL, NULL);
 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static virStorageVolPtr
vzStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                          const char *xmldesc,
                          virStorageVolPtr clonevol,
                          unsigned int flags)
{
    vzConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL, origvol = NULL;
    virStorageVolPtr ret = NULL;

    virCheckFlags(0, NULL);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, pool->name);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(pool->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc, 0);
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
    if ((privpool->def->allocation + privvol->target.allocation) >
        privpool->def->capacity) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not enough free space in pool for volume '%s'"),
                       privvol->name);
        goto cleanup;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path, privvol->name) == -1)
        goto cleanup;

    if (VIR_STRDUP(privvol->key, privvol->target.path) < 0)
        goto cleanup;

    privpool->def->allocation += privvol->target.allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (VIR_APPEND_ELEMENT_COPY(privpool->volumes.objs,
                                privpool->volumes.count, privvol) < 0)
        goto cleanup;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key,
                           NULL, NULL);
    privvol = NULL;

 cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

int vzStorageVolDefRemove(virStoragePoolObjPtr privpool,
                          virStorageVolDefPtr privvol)
{
    int ret = -1;
    char *xml_path = NULL;
    size_t i;

    privpool->def->allocation -= privvol->target.allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    for (i = 0; i < privpool->volumes.count; i++) {
        if (privpool->volumes.objs[i] == privvol) {
            xml_path = vzAddFileExt(privvol->target.path, ".xml");
            if (!xml_path)
                goto cleanup;

            if (unlink(xml_path)) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Can't remove file '%s'"), xml_path);
                goto cleanup;
            }

            virStorageVolDefFree(privvol);

            VIR_DELETE_ELEMENT(privpool->volumes.objs, i, privpool->volumes.count);
            break;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(xml_path);
    return ret;
}

static int
vzStorageVolDelete(virStorageVolPtr vol, unsigned int flags)
{
    vzConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int ret = -1;

    virCheckFlags(0, -1);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(vol->pool);
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


    if (vzStorageVolDefRemove(privpool, privvol))
        goto cleanup;

    ret = 0;

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
vzStorageVolTypeForPool(int pooltype)
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
vzStorageVolGetInfo(virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    vzConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int ret = -1;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(vol->pool);
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
    info->type = vzStorageVolTypeForPool(privpool->def->type);
    info->capacity = privvol->target.capacity;
    info->allocation = privvol->target.allocation;
    ret = 0;

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
vzStorageVolGetXMLDesc(virStorageVolPtr vol, unsigned int flags)
{
    vzConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(vol->pool);
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
vzStorageVolGetPath(virStorageVolPtr vol)
{
    vzConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    vzDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools, vol->pool);
    vzDriverUnlock(privconn);

    if (privpool == NULL) {
        vzPoolNotFoundError(vol->pool);
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

    ignore_value(VIR_STRDUP(ret, privvol->target.path));

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

virStorageDriver vzStorageDriver = {
    .name = "Parallels",

    .connectNumOfStoragePools = vzConnectNumOfStoragePools,   /* 0.10.0 */
    .connectListStoragePools = vzConnectListStoragePools,   /* 0.10.0 */
    .connectNumOfDefinedStoragePools = vzConnectNumOfDefinedStoragePools,     /* 0.10.0 */
    .connectListDefinedStoragePools = vzConnectListDefinedStoragePools,     /* 0.10.0 */
    .storagePoolLookupByName = vzStoragePoolLookupByName,     /* 0.10.0 */
    .storagePoolLookupByUUID = vzStoragePoolLookupByUUID,     /* 0.10.0 */
    .storagePoolLookupByVolume = vzStoragePoolLookupByVolume, /* 0.10.0 */
    .storagePoolDefineXML = vzStoragePoolDefineXML,      /* 0.10.0 */
    .storagePoolUndefine = vzStoragePoolUndefine,     /* 0.10.0 */
    .storagePoolCreate = vzStoragePoolCreate,  /* 0.10.0 */
    .storagePoolDestroy = vzStoragePoolDestroy,       /* 0.10.0 */
    .storagePoolRefresh = vzStoragePoolRefresh,       /* 0.10.0 */
    .storagePoolGetInfo = vzStoragePoolGetInfo,       /* 0.10.0 */
    .storagePoolGetXMLDesc = vzStoragePoolGetXMLDesc, /* 0.10.0 */
    .storagePoolGetAutostart = vzStoragePoolGetAutostart,     /* 0.10.0 */
    .storagePoolSetAutostart = vzStoragePoolSetAutostart,     /* 0.10.0 */
    .storagePoolNumOfVolumes = vzStoragePoolNumOfVolumes,       /* 0.10.0 */
    .storagePoolListVolumes = vzStoragePoolListVolumes,       /* 0.10.0 */

    .storageVolLookupByName = vzStorageVolLookupByName,    /* 0.10.0 */
    .storageVolLookupByKey = vzStorageVolLookupByKey,      /* 0.10.0 */
    .storageVolLookupByPath = vzStorageVolLookupByPath,    /* 0.10.0 */
    .storageVolCreateXML = vzStorageVolCreateXML,  /* 0.10.0 */
    .storageVolCreateXMLFrom = vzStorageVolCreateXMLFrom,  /* 0.10.0 */
    .storageVolDelete = vzStorageVolDelete,        /* 0.10.0 */
    .storageVolGetInfo = vzStorageVolGetInfo,      /* 0.10.0 */
    .storageVolGetXMLDesc = vzStorageVolGetXMLDesc,        /* 0.10.0 */
    .storageVolGetPath = vzStorageVolGetPath,      /* 0.10.0 */
    .storagePoolIsActive = vzStoragePoolIsActive,     /* 0.10.0 */
    .storagePoolIsPersistent = vzStoragePoolIsPersistent,     /* 0.10.0 */
};
