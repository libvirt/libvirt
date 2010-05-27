/*
 * storage_driver.c: core driver for storage APIs
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

#if HAVE_PWD_H
# include <pwd.h>
#endif
#include <errno.h>
#include <string.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "driver.h"
#include "util.h"
#include "storage_driver.h"
#include "storage_conf.h"
#include "memory.h"
#include "storage_backend.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static virStorageDriverStatePtr driverState;

static int storageDriverShutdown(void);

static void storageDriverLock(virStorageDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}
static void storageDriverUnlock(virStorageDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

static void
storageDriverAutostart(virStorageDriverStatePtr driver) {
    unsigned int i;

    for (i = 0 ; i < driver->pools.count ; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];

        virStoragePoolObjLock(pool);
        if (pool->autostart &&
            !virStoragePoolObjIsActive(pool)) {
            virStorageBackendPtr backend;
            if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
                VIR_ERROR(_("Missing backend %d"), pool->def->type);
                virStoragePoolObjUnlock(pool);
                continue;
            }

            if (backend->startPool &&
                backend->startPool(NULL, pool) < 0) {
                virErrorPtr err = virGetLastError();
                VIR_ERROR(_("Failed to autostart storage pool '%s': %s"),
                          pool->def->name, err ? err->message :
                          "no error message found");
                virStoragePoolObjUnlock(pool);
                continue;
            }

            if (backend->refreshPool(NULL, pool) < 0) {
                virErrorPtr err = virGetLastError();
                if (backend->stopPool)
                    backend->stopPool(NULL, pool);
                VIR_ERROR(_("Failed to autostart storage pool '%s': %s"),
                          pool->def->name, err ? err->message :
                          "no error message found");
                virStoragePoolObjUnlock(pool);
                continue;
            }
            pool->active = 1;
        }
        virStoragePoolObjUnlock(pool);
    }
}

/**
 * virStorageStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
storageDriverStartup(int privileged) {
    char *base = NULL;
    char driverConf[PATH_MAX];

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        return -1;
    }
    storageDriverLock(driverState);

    if (privileged) {
        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
        char *userdir = virGetUserDirectory(uid);

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
    if (snprintf (driverConf, sizeof(driverConf),
                  "%s/storage.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (virAsprintf(&driverState->configDir,
                    "%s/storage", base) == -1)
        goto out_of_memory;

    if (virAsprintf(&driverState->autostartDir,
                    "%s/storage/autostart", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    /*
    if (virStorageLoadDriverConfig(driver, driverConf) < 0) {
        virStorageDriverShutdown();
        return -1;
    }
    */

    if (virStoragePoolLoadAllConfigs(&driverState->pools,
                                     driverState->configDir,
                                     driverState->autostartDir) < 0)
        goto error;
    storageDriverAutostart(driverState);

    storageDriverUnlock(driverState);
    return 0;

out_of_memory:
    virReportOOMError();
error:
    VIR_FREE(base);
    storageDriverUnlock(driverState);
    storageDriverShutdown();
    return -1;
}

/**
 * virStorageReload:
 *
 * Function to restart the storage driver, it will recheck the configuration
 * files and update its state
 */
static int
storageDriverReload(void) {
    if (!driverState)
        return -1;

    storageDriverLock(driverState);
    virStoragePoolLoadAllConfigs(&driverState->pools,
                                 driverState->configDir,
                                 driverState->autostartDir);
    storageDriverAutostart(driverState);
    storageDriverUnlock(driverState);

    return 0;
}

/**
 * virStorageActive:
 *
 * Checks if the storage driver is active, i.e. has an active pool
 *
 * Returns 1 if active, 0 otherwise
 */
static int
storageDriverActive(void) {
    unsigned int i;
    int active = 0;

    if (!driverState)
        return 0;

    storageDriverLock(driverState);

    for (i = 0 ; i < driverState->pools.count ; i++) {
        virStoragePoolObjLock(driverState->pools.objs[i]);
        if (virStoragePoolObjIsActive(driverState->pools.objs[i]))
            active = 1;
        virStoragePoolObjUnlock(driverState->pools.objs[i]);
    }

    storageDriverUnlock(driverState);
    return active;
}

/**
 * virStorageShutdown:
 *
 * Shutdown the storage driver, it will stop all active storage pools
 */
static int
storageDriverShutdown(void) {
    if (!driverState)
        return -1;

    storageDriverLock(driverState);

    /* free inactive pools */
    virStoragePoolObjListFree(&driverState->pools);

    VIR_FREE(driverState->configDir);
    VIR_FREE(driverState->autostartDir);
    storageDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);
    VIR_FREE(driverState);

    return 0;
}



static virStoragePoolPtr
storagePoolLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByName(virConnectPtr conn,
                        const char *name) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, name);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              _("no pool with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByVolume(virStorageVolPtr vol) {
    return storagePoolLookupByName(vol->conn, vol->pool);
}

static virDrvOpenStatus
storageOpen(virConnectPtr conn,
            virConnectAuthPtr auth ATTRIBUTE_UNUSED,
            int flags ATTRIBUTE_UNUSED) {
    if (!driverState)
        return VIR_DRV_OPEN_DECLINED;

    conn->storagePrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}

static int
storageClose(virConnectPtr conn) {
    conn->storagePrivateData = NULL;
    return 0;
}

static int
storageNumPools(virConnectPtr conn) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    unsigned int i, nactive = 0;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i]))
            nactive++;
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }
    storageDriverUnlock(driver);

    return nactive;
}

static int
storageListPools(virConnectPtr conn,
                 char **const names,
                 int nnames) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    int got = 0, i;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count && got < nnames ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            if (!(names[got] = strdup(driver->pools.objs[i]->def->name))) {
                virStoragePoolObjUnlock(driver->pools.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }
    storageDriverUnlock(driver);
    return got;

 cleanup:
    storageDriverUnlock(driver);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

static int
storageNumDefinedPools(virConnectPtr conn) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    unsigned int i, nactive = 0;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (!virStoragePoolObjIsActive(driver->pools.objs[i]))
            nactive++;
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }
    storageDriverUnlock(driver);

    return nactive;
}

static int
storageListDefinedPools(virConnectPtr conn,
                        char **const names,
                        int nnames) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    int got = 0, i;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count && got < nnames ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (!virStoragePoolObjIsActive(driver->pools.objs[i])) {
            if (!(names[got] = strdup(driver->pools.objs[i]->def->name))) {
                virStoragePoolObjUnlock(driver->pools.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }
    storageDriverUnlock(driver);
    return got;

 cleanup:
    storageDriverUnlock(driver);
    for (i = 0 ; i < got ; i++) {
        VIR_FREE(names[i]);
    }
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

/* This method is required to be re-entrant / thread safe, so
   uses no driver lock */
static char *
storageFindPoolSources(virConnectPtr conn,
                       const char *type,
                       const char *srcSpec,
                       unsigned int flags)
{
    int backend_type;
    virStorageBackendPtr backend;
    char *ret = NULL;

    backend_type = virStoragePoolTypeFromString(type);
    if (backend_type < 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("unknown storage pool type %s"), type);
        goto cleanup;
    }

    backend = virStorageBackendForType(backend_type);
    if (backend == NULL)
        goto cleanup;

    if (!backend->findPoolSources) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              _("pool type '%s' does not support source "
                                "discovery"), type);
        goto cleanup;
    }

    ret = backend->findPoolSources(conn, srcSpec, flags);

cleanup:
    return ret;
}


static int storagePoolIsActive(virStoragePoolPtr pool)
{
    virStorageDriverStatePtr driver = pool->conn->storagePrivateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    storageDriverLock(driver);
    obj = virStoragePoolObjFindByUUID(&driver->pools, pool->uuid);
    storageDriverUnlock(driver);
    if (!obj) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = virStoragePoolObjIsActive(obj);

cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}

static int storagePoolIsPersistent(virStoragePoolPtr pool)
{
    virStorageDriverStatePtr driver = pool->conn->storagePrivateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    storageDriverLock(driver);
    obj = virStoragePoolObjFindByUUID(&driver->pools, pool->uuid);
    storageDriverUnlock(driver);
    if (!obj) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = obj->configFile ? 1 : 0;

cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}


static virStoragePoolPtr
storagePoolCreate(virConnectPtr conn,
                  const char *xml,
                  unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virStorageBackendPtr backend;

    storageDriverLock(driver);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 1) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&driver->pools, def)))
        goto cleanup;
    def = NULL;

    if (backend->startPool &&
        backend->startPool(conn, pool) < 0) {
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
        goto cleanup;
    }

    if (backend->refreshPool(conn, pool) < 0) {
        if (backend->stopPool)
            backend->stopPool(conn, pool);
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
        goto cleanup;
    }
    pool->active = 1;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}

static virStoragePoolPtr
storagePoolDefine(virConnectPtr conn,
                  const char *xml,
                  unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 0) < 0)
        goto cleanup;

    if (virStorageBackendForType(def->type) == NULL)
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&driver->pools, def)))
        goto cleanup;

    if (virStoragePoolObjSaveDef(driver, pool, def) < 0) {
        virStoragePoolObjRemove(&driver->pools, pool);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}

static int
storagePoolUndefine(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("pool is still active"));
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("pool '%s' has asynchronous jobs running."),
                              pool->def->name);
        goto cleanup;
    }

    if (virStoragePoolObjDeleteDef(pool) < 0)
        goto cleanup;

    if (unlink(pool->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to delete autostart link '%s': %s"),
                   pool->autostartLink, virStrerror(errno, ebuf, sizeof ebuf));
    }

    VIR_FREE(pool->configFile);
    VIR_FREE(pool->autostartLink);

    virStoragePoolObjRemove(&driver->pools, pool);
    pool = NULL;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}

static int
storagePoolStart(virStoragePoolPtr obj,
                 unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("pool already active"));
        goto cleanup;
    }
    if (backend->startPool &&
        backend->startPool(obj->conn, pool) < 0)
        goto cleanup;

    if (backend->refreshPool(obj->conn, pool) < 0) {
        if (backend->stopPool)
            backend->stopPool(obj->conn, pool);
        goto cleanup;
    }

    pool->active = 1;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolBuild(virStoragePoolPtr obj,
                 unsigned int flags) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is already active"));
        goto cleanup;
    }

    if (backend->buildPool &&
        backend->buildPool(obj->conn, pool, flags) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolDestroy(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("pool '%s' has asynchronous jobs running."),
                              pool->def->name);
        goto cleanup;
    }

    if (backend->stopPool &&
        backend->stopPool(obj->conn, pool) < 0)
        goto cleanup;

    virStoragePoolObjClearVols(pool);

    pool->active = 0;

    if (pool->configFile == NULL) {
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
    }
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}


static int
storagePoolDelete(virStoragePoolPtr obj,
                  unsigned int flags) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is still active"));
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("pool '%s' has asynchronous jobs running."),
                              pool->def->name);
        goto cleanup;
    }

    if (!backend->deletePool) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("pool does not support pool deletion"));
        goto cleanup;
    }
    if (backend->deletePool(obj->conn, pool, flags) < 0)
        goto cleanup;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolRefresh(virStoragePoolPtr obj,
                   unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("pool '%s' has asynchronous jobs running."),
                              pool->def->name);
        goto cleanup;
    }

    virStoragePoolObjClearVols(pool);
    if (backend->refreshPool(obj->conn, pool) < 0) {
        if (backend->stopPool)
            backend->stopPool(obj->conn, pool);

        pool->active = 0;

        if (pool->configFile == NULL) {
            virStoragePoolObjRemove(&driver->pools, pool);
            pool = NULL;
        }
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}


static int
storagePoolGetInfo(virStoragePoolPtr obj,
                   virStoragePoolInfoPtr info) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (virStorageBackendForType(pool->def->type) == NULL)
        goto cleanup;

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (pool->active)
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = pool->def->capacity;
    info->allocation = pool->def->allocation;
    info->available = pool->def->available;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static char *
storagePoolDumpXML(virStoragePoolPtr obj,
                   unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    char *ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    ret = virStoragePoolDefFormat(pool->def);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolGetAutostart(virStoragePoolPtr obj,
                        int *autostart) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        goto cleanup;
    }

    if (!pool->configFile) {
        *autostart = 0;
    } else {
        *autostart = pool->autostart;
    }
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolSetAutostart(virStoragePoolPtr obj,
                        int autostart) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        goto cleanup;
    }

    if (!pool->configFile) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("pool has no config file"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (pool->autostart != autostart) {
        if (autostart) {
            int err;

            if ((err = virFileMakePath(driver->autostartDir))) {
                virReportSystemError(err,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(pool->configFile, pool->autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s' to '%s'"),
                                     pool->autostartLink, pool->configFile);
                goto cleanup;
            }
        } else {
            if (unlink(pool->autostartLink) < 0 &&
                errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     pool->autostartLink);
                goto cleanup;
            }
        }
        pool->autostart = autostart;
    }
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}


static int
storagePoolNumVolumes(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }
    ret = pool->volumes.count;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolListVolumes(virStoragePoolPtr obj,
                       char **const names,
                       int maxnames) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int i, n = 0;

    memset(names, 0, maxnames * sizeof(*names));

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    for (i = 0 ; i < pool->volumes.count && n < maxnames ; i++) {
        if ((names[n++] = strdup(pool->volumes.objs[i]->name)) == NULL) {
            virReportOOMError();
            goto cleanup;
        }
    }

    virStoragePoolObjUnlock(pool);
    return n;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[n]);

    memset(names, 0, maxnames * sizeof(*names));
    return -1;
}


static virStorageVolPtr
storageVolumeLookupByName(virStoragePoolPtr obj,
                          const char *name) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    virStorageVolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, name);

    if (!vol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              _("no storage vol with matching name '%s'"),
                              name);
        goto cleanup;
    }

    ret = virGetStorageVol(obj->conn, pool->def->name, vol->name, vol->key);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static virStorageVolPtr
storageVolumeLookupByKey(virConnectPtr conn,
                         const char *key) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    unsigned int i;
    virStorageVolPtr ret = NULL;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count && !ret ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByKey(driver->pools.objs[i], key);

            if (vol)
                ret = virGetStorageVol(conn,
                                       driver->pools.objs[i]->def->name,
                                       vol->name,
                                       vol->key);
        }
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }
    storageDriverUnlock(driver);

    if (!ret)
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              "%s", _("no storage vol with matching key"));

    return ret;
}

static virStorageVolPtr
storageVolumeLookupByPath(virConnectPtr conn,
                          const char *path) {
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    unsigned int i;
    virStorageVolPtr ret = NULL;
    char *cleanpath;

    cleanpath = virFileSanitizePath(path);
    if (!cleanpath)
        return NULL;

    storageDriverLock(driver);
    for (i = 0 ; i < driver->pools.count && !ret ; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol;
            const char *stable_path;

            stable_path = virStorageBackendStablePath(driver->pools.objs[i],
                                                      cleanpath);
            /*
             * virStorageBackendStablePath already does
             * virStorageReportError if it fails; we just need to keep
             * propagating the return code
             */
            if (stable_path == NULL) {
                virStoragePoolObjUnlock(driver->pools.objs[i]);
                goto cleanup;
            }

            vol = virStorageVolDefFindByPath(driver->pools.objs[i],
                                             stable_path);
            VIR_FREE(stable_path);

            if (vol)
                ret = virGetStorageVol(conn,
                                       driver->pools.objs[i]->def->name,
                                       vol->name,
                                       vol->key);
        }
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }

    if (!ret)
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              "%s", _("no storage vol with matching path"));

cleanup:
    VIR_FREE(cleanpath);
    storageDriverUnlock(driver);
    return ret;
}

static int storageVolumeDelete(virStorageVolPtr obj, unsigned int flags);

static virStorageVolPtr
storageVolumeCreateXML(virStoragePoolPtr obj,
                       const char *xmldesc,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    voldef = virStorageVolDefParseString(pool->def, xmldesc);
    if (voldef == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, voldef->name)) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              "%s", _("storage vol already exists"));
        goto cleanup;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!backend->createVol) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support volume "
                                      "creation"));
        goto cleanup;
    }

    if (backend->createVol(obj->conn, pool, voldef) < 0) {
        goto cleanup;
    }

    pool->volumes.objs[pool->volumes.count++] = voldef;
    volobj = virGetStorageVol(obj->conn, pool->def->name, voldef->name,
                              voldef->key);

    if (volobj && backend->buildVol) {
        int buildret;
        virStorageVolDefPtr buildvoldef = NULL;

        if (VIR_ALLOC(buildvoldef) < 0) {
            virReportOOMError();
            voldef = NULL;
            goto cleanup;
        }

        /* Make a shallow copy of the 'defined' volume definition, since the
         * original allocation value will change as the user polls 'info',
         * but we only need the initial requested values
         */
        memcpy(buildvoldef, voldef, sizeof(*voldef));

        /* Drop the pool lock during volume allocation */
        pool->asyncjobs++;
        voldef->building = 1;
        virStoragePoolObjUnlock(pool);

        buildret = backend->buildVol(obj->conn, pool, buildvoldef);

        storageDriverLock(driver);
        virStoragePoolObjLock(pool);
        storageDriverUnlock(driver);

        voldef->building = 0;
        pool->asyncjobs--;

        voldef = NULL;
        VIR_FREE(buildvoldef);

        if (buildret < 0) {
            virStoragePoolObjUnlock(pool);
            storageVolumeDelete(volobj, 0);
            pool = NULL;
            goto cleanup;
        }

    }

    ret = volobj;
    volobj = NULL;
    voldef = NULL;

cleanup:
    if (volobj)
        virUnrefStorageVol(volobj);
    virStorageVolDefFree(voldef);
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStorageVolPtr
storageVolumeCreateXMLFrom(virStoragePoolPtr obj,
                           const char *xmldesc,
                           virStorageVolPtr vobj,
                           unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool, origpool = NULL;
    virStorageBackendPtr backend;
    virStorageVolDefPtr origvol = NULL, newvol = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;
    int buildret;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    if (pool && STRNEQ(obj->name, vobj->pool)) {
        virStoragePoolObjUnlock(pool);
        origpool = virStoragePoolObjFindByName(&driver->pools, vobj->pool);
        virStoragePoolObjLock(pool);
    }
    storageDriverUnlock(driver);
    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (STRNEQ(obj->name, vobj->pool) && !origpool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              _("no storage pool with matching name '%s'"),
                              vobj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if (origpool && !virStoragePoolObjIsActive(origpool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    origvol = virStorageVolDefFindByName(origpool ? origpool : pool, vobj->name);
    if (!origvol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              _("no storage vol with matching name '%s'"),
                              vobj->name);
        goto cleanup;
    }

    newvol = virStorageVolDefParseString(pool->def, xmldesc);
    if (newvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, newvol->name)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("storage volume name '%s' already in use."),
                              newvol->name);
        goto cleanup;
    }

    /* Is there ever a valid case for this? */
    if (newvol->capacity < origvol->capacity)
        newvol->capacity = origvol->capacity;

    /* Make sure allocation is at least as large as the destination cap,
     * to make absolutely sure we copy all possible contents */
    if (newvol->allocation < origvol->capacity)
        newvol->allocation = origvol->capacity;

    if (!backend->buildVolFrom) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support volume creation from an existing volume"));
        goto cleanup;
    }

    if (origvol->building) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("volume '%s' is still being allocated."),
                              origvol->name);
        goto cleanup;
    }

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, origvol) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* 'Define' the new volume so we get async progress reporting */
    if (backend->createVol(obj->conn, pool, newvol) < 0) {
        goto cleanup;
    }

    pool->volumes.objs[pool->volumes.count++] = newvol;
    volobj = virGetStorageVol(obj->conn, pool->def->name, newvol->name,
                              newvol->key);

    /* Drop the pool lock during volume allocation */
    pool->asyncjobs++;
    origvol->building = 1;
    newvol->building = 1;
    virStoragePoolObjUnlock(pool);

    if (origpool) {
        origpool->asyncjobs++;
        virStoragePoolObjUnlock(origpool);
    }

    buildret = backend->buildVolFrom(obj->conn, pool, newvol, origvol, flags);

    storageDriverLock(driver);
    virStoragePoolObjLock(pool);
    if (origpool)
        virStoragePoolObjLock(origpool);
    storageDriverUnlock(driver);

    origvol->building = 0;
    newvol->building = 0;
    newvol = NULL;
    pool->asyncjobs--;

    if (origpool) {
        origpool->asyncjobs--;
        virStoragePoolObjUnlock(origpool);
        origpool = NULL;
    }

    if (buildret < 0) {
        virStoragePoolObjUnlock(pool);
        storageVolumeDelete(volobj, 0);
        pool = NULL;
        goto cleanup;
    }

    ret = volobj;
    volobj = NULL;

cleanup:
    if (volobj)
        virUnrefStorageVol(volobj);
    virStorageVolDefFree(newvol);
    if (pool)
        virStoragePoolObjUnlock(pool);
    if (origpool)
        virStoragePoolObjUnlock(origpool);
    return ret;
}


/* If the volume we're wiping is already a sparse file, we simply
 * truncate and extend it to its original size, filling it with
 * zeroes.  This behavior is guaranteed by POSIX:
 *
 * http://www.opengroup.org/onlinepubs/9699919799/functions/ftruncate.html
 *
 * If fildes refers to a regular file, the ftruncate() function shall
 * cause the size of the file to be truncated to length. If the size
 * of the file previously exceeded length, the extra data shall no
 * longer be available to reads on the file. If the file previously
 * was smaller than this size, ftruncate() shall increase the size of
 * the file. If the file size is increased, the extended area shall
 * appear as if it were zero-filled.
 */
static int
storageVolumeZeroSparseFile(virStorageVolDefPtr vol,
                            off_t size,
                            int fd)
{
    int ret = -1;

    ret = ftruncate(fd, 0);
    if (ret == -1) {
        virReportSystemError(errno,
                             _("Failed to truncate volume with "
                               "path '%s' to 0 bytes"),
                             vol->target.path);
        goto out;
    }

    ret = ftruncate(fd, size);
    if (ret == -1) {
        virReportSystemError(errno,
                             _("Failed to truncate volume with "
                               "path '%s' to %ju bytes"),
                             vol->target.path, (intmax_t)size);
    }

out:
    return ret;
}


static int
storageWipeExtent(virStorageVolDefPtr vol,
                  int fd,
                  off_t extent_start,
                  off_t extent_length,
                  char *writebuf,
                  size_t writebuf_length,
                  size_t *bytes_wiped)
{
    int ret = -1, written = 0;
    off_t remaining = 0;
    size_t write_size = 0;

    VIR_DEBUG("extent logical start: %ju len: %ju",
              (intmax_t)extent_start, (intmax_t)extent_length);

    if ((ret = lseek(fd, extent_start, SEEK_SET)) < 0) {
        virReportSystemError(errno,
                             _("Failed to seek to position %ju in volume "
                               "with path '%s'"),
                             (intmax_t)extent_start, vol->target.path);
        goto out;
    }

    remaining = extent_length;
    while (remaining > 0) {

        write_size = (writebuf_length < remaining) ? writebuf_length : remaining;
        written = safewrite(fd, writebuf, write_size);
        if (written < 0) {
            virReportSystemError(errno,
                                 _("Failed to write %zu bytes to "
                                   "storage volume with path '%s'"),
                                 write_size, vol->target.path);

            goto out;
        }

        *bytes_wiped += written;
        remaining -= written;
    }

    VIR_DEBUG("Wrote %zu bytes to volume with path '%s'",
              *bytes_wiped, vol->target.path);

    ret = 0;

out:
    return ret;
}


static int
storageVolumeWipeInternal(virStorageVolDefPtr def)
{
    int ret = -1, fd = -1;
    struct stat st;
    char *writebuf = NULL;
    size_t bytes_wiped = 0;

    VIR_DEBUG("Wiping volume with path '%s'", def->target.path);

    fd = open(def->target.path, O_RDWR);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("Failed to open storage volume with path '%s'"),
                             def->target.path);
        goto out;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno,
                             _("Failed to stat storage volume with path '%s'"),
                             def->target.path);
        goto out;
    }

    if (S_ISREG(st.st_mode) && st.st_blocks < (st.st_size / DEV_BSIZE)) {
        ret = storageVolumeZeroSparseFile(def, st.st_size, fd);
    } else {

        if (VIR_ALLOC_N(writebuf, st.st_blksize) != 0) {
            virReportOOMError();
            goto out;
        }

        ret = storageWipeExtent(def,
                                fd,
                                0,
                                def->allocation,
                                writebuf,
                                st.st_blksize,
                                &bytes_wiped);
    }

out:
    VIR_FREE(writebuf);

    if (fd != -1) {
        close(fd);
    }

    return ret;
}


static int
storageVolumeWipe(virStorageVolPtr obj,
                  unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto out;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto out;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (vol == NULL) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                             _("no storage vol with matching name '%s'"),
                              obj->name);
        goto out;
    }

    if (vol->building) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("volume '%s' is still being allocated."),
                              vol->name);
        goto out;
    }

    if (storageVolumeWipeInternal(vol) == -1) {
        goto out;
    }

    ret = 0;

out:
    if (pool) {
        virStoragePoolObjUnlock(pool);
    }

    return ret;

}

static int
storageVolumeDelete(virStorageVolPtr obj,
                    unsigned int flags) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol = NULL;
    unsigned int i;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                             _("no storage vol with matching name '%s'"),
                              obj->name);
        goto cleanup;
    }

    if (vol->building) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("volume '%s' is still being allocated."),
                              vol->name);
        goto cleanup;
    }

    if (!backend->deleteVol) {
        virStorageReportError(VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support vol deletion"));

        goto cleanup;
    }

    if (backend->deleteVol(obj->conn, pool, vol, flags) < 0)
        goto cleanup;

    for (i = 0 ; i < pool->volumes.count ; i++) {
        if (pool->volumes.objs[i] == vol) {
            virStorageVolDefFree(vol);
            vol = NULL;

            if (i < (pool->volumes.count - 1))
                memmove(pool->volumes.objs + i, pool->volumes.objs + i + 1,
                        sizeof(*(pool->volumes.objs)) * (pool->volumes.count - (i + 1)));

            if (VIR_REALLOC_N(pool->volumes.objs, pool->volumes.count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            pool->volumes.count--;

            break;
        }
    }
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storageVolumeGetInfo(virStorageVolPtr obj,
                     virStorageVolInfoPtr info) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              _("no storage vol with matching name '%s'"),
                              obj->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        goto cleanup;

    memset(info, 0, sizeof(*info));
    info->type = vol->type;
    info->capacity = vol->capacity;
    info->allocation = vol->allocation;
    ret = 0;

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static char *
storageVolumeGetXMLDesc(virStorageVolPtr obj,
                        unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                             _("no storage vol with matching name '%s'"),
                              obj->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        goto cleanup;

    ret = virStorageVolDefFormat(pool->def, vol);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);

    return ret;
}

static char *
storageVolumeGetPath(virStorageVolPtr obj) {
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);
    if (!pool) {
        virStorageReportError(VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(VIR_ERR_NO_STORAGE_VOL,
                              _("no storage vol with matching name '%s'"),
                              obj->name);
        goto cleanup;
    }

    ret = strdup(vol->target.path);
    if (ret == NULL)
        virReportOOMError();

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStorageDriver storageDriver = {
    .name = "storage",
    .open = storageOpen,
    .close = storageClose,
    .numOfPools = storageNumPools,
    .listPools = storageListPools,
    .numOfDefinedPools = storageNumDefinedPools,
    .listDefinedPools = storageListDefinedPools,
    .findPoolSources = storageFindPoolSources,
    .poolLookupByName = storagePoolLookupByName,
    .poolLookupByUUID = storagePoolLookupByUUID,
    .poolLookupByVolume = storagePoolLookupByVolume,
    .poolCreateXML = storagePoolCreate,
    .poolDefineXML = storagePoolDefine,
    .poolBuild = storagePoolBuild,
    .poolUndefine = storagePoolUndefine,
    .poolCreate = storagePoolStart,
    .poolDestroy = storagePoolDestroy,
    .poolDelete = storagePoolDelete,
    .poolRefresh = storagePoolRefresh,
    .poolGetInfo = storagePoolGetInfo,
    .poolGetXMLDesc = storagePoolDumpXML,
    .poolGetAutostart = storagePoolGetAutostart,
    .poolSetAutostart = storagePoolSetAutostart,
    .poolNumOfVolumes = storagePoolNumVolumes,
    .poolListVolumes = storagePoolListVolumes,

    .volLookupByName = storageVolumeLookupByName,
    .volLookupByKey = storageVolumeLookupByKey,
    .volLookupByPath = storageVolumeLookupByPath,
    .volCreateXML = storageVolumeCreateXML,
    .volCreateXMLFrom = storageVolumeCreateXMLFrom,
    .volDelete = storageVolumeDelete,
    .volWipe = storageVolumeWipe,
    .volGetInfo = storageVolumeGetInfo,
    .volGetXMLDesc = storageVolumeGetXMLDesc,
    .volGetPath = storageVolumeGetPath,

    .poolIsActive = storagePoolIsActive,
    .poolIsPersistent = storagePoolIsPersistent,
};


static virStateDriver stateDriver = {
    .name = "Storage",
    .initialize = storageDriverStartup,
    .cleanup = storageDriverShutdown,
    .reload = storageDriverReload,
    .active = storageDriverActive,
};

int storageRegister(void) {
    virRegisterStorageDriver(&storageDriver);
    virRegisterStateDriver(&stateDriver);
    return 0;
}
