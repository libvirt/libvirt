/*
 * storage_driver.c: core driver for storage APIs
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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

#include "virerror.h"
#include "datatypes.h"
#include "driver.h"
#include "storage_driver.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "storage_backend.h"
#include "virlog.h"
#include "virfile.h"
#include "fdstream.h"
#include "configmake.h"
#include "virstring.h"
#include "viraccessapicheck.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_driver");

static virStorageDriverStatePtr driverState;

static int storageStateCleanup(void);

static void storageDriverLock(virStorageDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}
static void storageDriverUnlock(virStorageDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

static void
storageDriverAutostart(virStorageDriverStatePtr driver)
{
    size_t i;
    virConnectPtr conn = NULL;

    /* XXX Remove hardcoding of QEMU URI */
    if (driverState->privileged)
        conn = virConnectOpen("qemu:///system");
    else
        conn = virConnectOpen("qemu:///session");
    /* Ignoring NULL conn - let backends decide */

    for (i = 0; i < driver->pools.count; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];
        virStorageBackendPtr backend;
        bool started = false;

        virStoragePoolObjLock(pool);
        if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
            VIR_ERROR(_("Missing backend %d"), pool->def->type);
            virStoragePoolObjUnlock(pool);
            continue;
        }

        if (backend->checkPool &&
            backend->checkPool(conn, pool, &started) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to initialize storage pool '%s': %s"),
                      pool->def->name, err ? err->message :
                      _("no error message found"));
            virStoragePoolObjUnlock(pool);
            continue;
        }

        if (!started &&
            pool->autostart &&
            !virStoragePoolObjIsActive(pool)) {
            if (backend->startPool &&
                backend->startPool(conn, pool) < 0) {
                virErrorPtr err = virGetLastError();
                VIR_ERROR(_("Failed to autostart storage pool '%s': %s"),
                          pool->def->name, err ? err->message :
                          _("no error message found"));
                virStoragePoolObjUnlock(pool);
                continue;
            }
            started = true;
        }

        if (started) {
            if (backend->refreshPool(conn, pool) < 0) {
                virErrorPtr err = virGetLastError();
                if (backend->stopPool)
                    backend->stopPool(conn, pool);
                VIR_ERROR(_("Failed to autostart storage pool '%s': %s"),
                          pool->def->name, err ? err->message :
                          _("no error message found"));
                virStoragePoolObjUnlock(pool);
                continue;
            }
            pool->active = 1;
        }
        virStoragePoolObjUnlock(pool);
    }

    virObjectUnref(conn);
}

/**
 * virStorageStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
storageStateInitialize(bool privileged,
                       virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                       void *opaque ATTRIBUTE_UNUSED)
{
    char *base = NULL;

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_FREE(driverState);
        return -1;
    }
    storageDriverLock(driverState);

    if (privileged) {
        if (VIR_STRDUP(base, SYSCONFDIR "/libvirt") < 0)
            goto error;
    } else {
        base = virGetUserConfigDirectory();
        if (!base)
            goto error;
    }
    driverState->privileged = privileged;

    /* Configuration paths are either $USER_CONFIG_HOME/libvirt/storage/... (session) or
     * /etc/libvirt/storage/... (system).
     */
    if (virAsprintf(&driverState->configDir,
                    "%s/storage", base) == -1)
        goto error;

    if (virAsprintf(&driverState->autostartDir,
                    "%s/storage/autostart", base) == -1)
        goto error;

    VIR_FREE(base);

    if (virStoragePoolLoadAllConfigs(&driverState->pools,
                                     driverState->configDir,
                                     driverState->autostartDir) < 0)
        goto error;

    storageDriverUnlock(driverState);
    return 0;

 error:
    VIR_FREE(base);
    storageDriverUnlock(driverState);
    storageStateCleanup();
    return -1;
}

/**
 * storageStateAutoStart:
 *
 * Function to auto start the storage driver
 */
static void
storageStateAutoStart(void)
{
    if (!driverState)
        return;

    storageDriverLock(driverState);
    storageDriverAutostart(driverState);
    storageDriverUnlock(driverState);
}

/**
 * storageStateReload:
 *
 * Function to restart the storage driver, it will recheck the configuration
 * files and update its state
 */
static int
storageStateReload(void)
{
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
 * storageStateCleanup
 *
 * Shutdown the storage driver, it will stop all active storage pools
 */
static int
storageStateCleanup(void)
{
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
                        const unsigned char *uuid)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), uuid);
        goto cleanup;
    }

    if (virStoragePoolLookupByUUIDEnsureACL(conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByName(virConnectPtr conn,
                        const char *name)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, name);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"), name);
        goto cleanup;
    }

    if (virStoragePoolLookupByNameEnsureACL(conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByVolume(virStorageVolPtr vol)
{
    virStorageDriverStatePtr driver = vol->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, vol->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"), vol->pool);
        goto cleanup;
    }

    if (virStoragePoolLookupByVolumeEnsureACL(vol->conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(vol->conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virDrvOpenStatus
storageOpen(virConnectPtr conn,
            virConnectAuthPtr auth ATTRIBUTE_UNUSED,
            unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (!driverState)
        return VIR_DRV_OPEN_DECLINED;

    conn->storagePrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}

static int
storageClose(virConnectPtr conn)
{
    conn->storagePrivateData = NULL;
    return 0;
}

static int
storageConnectNumOfStoragePools(virConnectPtr conn)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    size_t i;
    int nactive = 0;

    if (virConnectNumOfStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count; i++) {
        virStoragePoolObjPtr obj = driver->pools.objs[i];
        virStoragePoolObjLock(obj);
        if (virConnectNumOfStoragePoolsCheckACL(conn, obj->def) &&
            virStoragePoolObjIsActive(obj))
            nactive++;
        virStoragePoolObjUnlock(obj);
    }
    storageDriverUnlock(driver);

    return nactive;
}

static int
storageConnectListStoragePools(virConnectPtr conn,
                               char **const names,
                               int nnames)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    int got = 0;
    size_t i;

    if (virConnectListStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count && got < nnames; i++) {
        virStoragePoolObjPtr obj = driver->pools.objs[i];
        virStoragePoolObjLock(obj);
        if (virConnectListStoragePoolsCheckACL(conn, obj->def) &&
            virStoragePoolObjIsActive(obj)) {
            if (VIR_STRDUP(names[got], obj->def->name) < 0) {
                virStoragePoolObjUnlock(obj);
                goto cleanup;
            }
            got++;
        }
        virStoragePoolObjUnlock(obj);
    }
    storageDriverUnlock(driver);
    return got;

 cleanup:
    storageDriverUnlock(driver);
    for (i = 0; i < got; i++)
        VIR_FREE(names[i]);
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

static int
storageConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    size_t i;
    int nactive = 0;

    if (virConnectNumOfDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count; i++) {
        virStoragePoolObjPtr obj = driver->pools.objs[i];
        virStoragePoolObjLock(obj);
        if (virConnectNumOfDefinedStoragePoolsCheckACL(conn, obj->def) &&
            !virStoragePoolObjIsActive(obj))
            nactive++;
        virStoragePoolObjUnlock(obj);
    }
    storageDriverUnlock(driver);

    return nactive;
}

static int
storageConnectListDefinedStoragePools(virConnectPtr conn,
                                      char **const names,
                                      int nnames)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    int got = 0;
    size_t i;

    if (virConnectListDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count && got < nnames; i++) {
        virStoragePoolObjPtr obj = driver->pools.objs[i];
        virStoragePoolObjLock(obj);
        if (virConnectListDefinedStoragePoolsCheckACL(conn, obj->def) &&
            !virStoragePoolObjIsActive(obj)) {
            if (VIR_STRDUP(names[got], obj->def->name) < 0) {
                virStoragePoolObjUnlock(obj);
                goto cleanup;
            }
            got++;
        }
        virStoragePoolObjUnlock(obj);
    }
    storageDriverUnlock(driver);
    return got;

 cleanup:
    storageDriverUnlock(driver);
    for (i = 0; i < got; i++) {
        VIR_FREE(names[i]);
    }
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

/* This method is required to be re-entrant / thread safe, so
   uses no driver lock */
static char *
storageConnectFindStoragePoolSources(virConnectPtr conn,
                                     const char *type,
                                     const char *srcSpec,
                                     unsigned int flags)
{
    int backend_type;
    virStorageBackendPtr backend;
    char *ret = NULL;

    if (virConnectFindStoragePoolSourcesEnsureACL(conn) < 0)
        return NULL;

    backend_type = virStoragePoolTypeFromString(type);
    if (backend_type < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown storage pool type %s"), type);
        goto cleanup;
    }

    backend = virStorageBackendForType(backend_type);
    if (backend == NULL)
        goto cleanup;

    if (!backend->findPoolSources) {
        virReportError(VIR_ERR_NO_SUPPORT,
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
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    if (virStoragePoolIsActiveEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

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
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    if (virStoragePoolIsPersistentEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->configFile ? 1 : 0;

 cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}


static virStoragePoolPtr
storagePoolCreateXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virStorageBackendPtr backend;

    virCheckFlags(0, NULL);

    storageDriverLock(driver);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 1) < 0)
        goto cleanup;

    if (virStoragePoolSourceFindDuplicate(&driver->pools, def) < 0)
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
    VIR_INFO("Creating storage pool '%s'", pool->def->name);
    pool->active = 1;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}

static virStoragePoolPtr
storagePoolDefineXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    virCheckFlags(0, NULL);

    storageDriverLock(driver);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 0) < 0)
        goto cleanup;

    if (virStoragePoolSourceFindDuplicate(&driver->pools, def) < 0)
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

    VIR_INFO("Defining storage pool '%s'", pool->def->name);
    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock(driver);
    return ret;
}

static int
storagePoolUndefine(virStoragePoolPtr obj)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolUndefineEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is still active"),
                       pool->def->name);
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       pool->def->name);
        goto cleanup;
    }

    if (virStoragePoolObjDeleteDef(pool) < 0)
        goto cleanup;

    if (unlink(pool->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to delete autostart link '%s': %s"),
                  pool->autostartLink, virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    VIR_FREE(pool->configFile);
    VIR_FREE(pool->autostartLink);

    VIR_INFO("Undefining storage pool '%s'", pool->def->name);
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
storagePoolCreate(virStoragePoolPtr obj,
                  unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    virCheckFlags(0, -1);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolCreateEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"),
                       pool->def->name);
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

    VIR_INFO("Starting up storage pool '%s'", pool->def->name);
    pool->active = 1;
    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolBuild(virStoragePoolPtr obj,
                 unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolBuildEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"),
                       pool->def->name);
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
storagePoolDestroy(virStoragePoolPtr obj)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolDestroyEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       pool->def->name);
        goto cleanup;
    }

    if (backend->stopPool &&
        backend->stopPool(obj->conn, pool) < 0)
        goto cleanup;

    virStoragePoolObjClearVols(pool);

    pool->active = 0;
    VIR_INFO("Shutting down storage pool '%s'", pool->def->name);

    if (pool->configFile == NULL) {
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
    } else if (pool->newDef) {
        virStoragePoolDefFree(pool->def);
        pool->def = pool->newDef;
        pool->newDef = NULL;
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
                  unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolDeleteEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is still active"),
                       pool->def->name);
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                              pool->def->name);
        goto cleanup;
    }

    if (!backend->deletePool) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("pool does not support pool deletion"));
        goto cleanup;
    }
    if (backend->deletePool(obj->conn, pool, flags) < 0)
        goto cleanup;
    VIR_INFO("Deleting storage pool '%s'", pool->def->name);
    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolRefresh(virStoragePoolPtr obj,
                   unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    virCheckFlags(0, -1);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolRefreshEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if (pool->asyncjobs > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
                   virStoragePoolInfoPtr info)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolGetInfoEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

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
storagePoolGetXMLDesc(virStoragePoolPtr obj,
                      unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStoragePoolDefPtr def;
    char *ret = NULL;

    virCheckFlags(VIR_STORAGE_XML_INACTIVE, NULL);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolGetXMLDescEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((flags & VIR_STORAGE_XML_INACTIVE) && pool->newDef)
        def = pool->newDef;
    else
        def = pool->def;

    ret = virStoragePoolDefFormat(def);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolGetAutostart(virStoragePoolPtr obj,
                        int *autostart)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolGetAutostartEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

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
                        int autostart)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolSetAutostartEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!pool->configFile) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("pool has no config file"));
        goto cleanup;
    }

    autostart = (autostart != 0);

    if (pool->autostart != autostart) {
        if (autostart) {
            if (virFileMakePath(driver->autostartDir) < 0) {
                virReportSystemError(errno,
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
storagePoolNumOfVolumes(virStoragePoolPtr obj)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    int ret = -1;
    size_t i;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolNumOfVolumesEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }
    ret = 0;
    for (i = 0; i < pool->volumes.count; i++) {
        if (virStoragePoolNumOfVolumesCheckACL(obj->conn, pool->def,
                                               pool->volumes.objs[i]))
            ret++;
    }

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolListVolumes(virStoragePoolPtr obj,
                       char **const names,
                       int maxnames)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    size_t i;
    int n = 0;

    memset(names, 0, maxnames * sizeof(*names));

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (virStoragePoolListVolumesEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    for (i = 0; i < pool->volumes.count && n < maxnames; i++) {
        if (!virStoragePoolListVolumesCheckACL(obj->conn, pool->def,
                                               pool->volumes.objs[i]))
            continue;
        if (VIR_STRDUP(names[n++], pool->volumes.objs[i]->name) < 0)
            goto cleanup;
    }

    virStoragePoolObjUnlock(pool);
    return n;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    for (n = 0; n < maxnames; n++)
        VIR_FREE(names[n]);

    memset(names, 0, maxnames * sizeof(*names));
    return -1;
}

static int
storagePoolListAllVolumes(virStoragePoolPtr pool,
                          virStorageVolPtr **vols,
                          unsigned int flags)
{
    virStorageDriverStatePtr driver = pool->conn->storagePrivateData;
    virStoragePoolObjPtr obj;
    size_t i;
    virStorageVolPtr *tmp_vols = NULL;
    virStorageVolPtr vol = NULL;
    int nvols = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    storageDriverLock(driver);
    obj = virStoragePoolObjFindByUUID(&driver->pools, pool->uuid);
    storageDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"),
                       pool->uuid);
        goto cleanup;
    }

    if (virStoragePoolListAllVolumesEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), obj->def->name);
        goto cleanup;
    }

     /* Just returns the volumes count */
    if (!vols) {
        ret = obj->volumes.count;
        goto cleanup;
    }

    if (VIR_ALLOC_N(tmp_vols, obj->volumes.count + 1) < 0)
        goto cleanup;

    for (i = 0; i < obj->volumes.count; i++) {
        if (!virStoragePoolListAllVolumesCheckACL(pool->conn, obj->def,
                                                  obj->volumes.objs[i]))
            continue;
        if (!(vol = virGetStorageVol(pool->conn, obj->def->name,
                                     obj->volumes.objs[i]->name,
                                     obj->volumes.objs[i]->key,
                                     NULL, NULL)))
            goto cleanup;
        tmp_vols[nvols++] = vol;
    }

    *vols = tmp_vols;
    tmp_vols = NULL;
    ret = nvols;

 cleanup:
    if (tmp_vols) {
        for (i = 0; i < nvols; i++) {
            if (tmp_vols[i])
                virStorageVolFree(tmp_vols[i]);
        }
        VIR_FREE(tmp_vols);
    }

    if (obj)
        virStoragePoolObjUnlock(obj);

    return ret;
}

static virStorageVolPtr
storageVolLookupByName(virStoragePoolPtr obj,
                       const char *name)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    virStorageVolPtr ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, name);

    if (!vol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       name);
        goto cleanup;
    }

    if (virStorageVolLookupByNameEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    ret = virGetStorageVol(obj->conn, pool->def->name, vol->name, vol->key,
                           NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static virStorageVolPtr
storageVolLookupByKey(virConnectPtr conn,
                      const char *key)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count && !ret; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByKey(driver->pools.objs[i], key);

            if (vol) {
                if (virStorageVolLookupByKeyEnsureACL(conn, driver->pools.objs[i]->def, vol) < 0) {
                    virStoragePoolObjUnlock(driver->pools.objs[i]);
                    goto cleanup;
                }

                ret = virGetStorageVol(conn,
                                       driver->pools.objs[i]->def->name,
                                       vol->name,
                                       vol->key,
                                       NULL, NULL);
            }
        }
        virStoragePoolObjUnlock(driver->pools.objs[i]);
    }

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching key %s"), key);

 cleanup:
    storageDriverUnlock(driver);
    return ret;
}

static virStorageVolPtr
storageVolLookupByPath(virConnectPtr conn,
                       const char *path)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    size_t i;
    virStorageVolPtr ret = NULL;
    char *cleanpath;

    cleanpath = virFileSanitizePath(path);
    if (!cleanpath)
        return NULL;

    storageDriverLock(driver);
    for (i = 0; i < driver->pools.count && !ret; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];
        virStorageVolDefPtr vol;
        char *stable_path = NULL;

        virStoragePoolObjLock(pool);

        if (!virStoragePoolObjIsActive(pool)) {
           virStoragePoolObjUnlock(pool);
           continue;
        }

        switch ((enum virStoragePoolType) pool->def->type) {
            case VIR_STORAGE_POOL_DIR:
            case VIR_STORAGE_POOL_FS:
            case VIR_STORAGE_POOL_NETFS:
            case VIR_STORAGE_POOL_LOGICAL:
            case VIR_STORAGE_POOL_DISK:
            case VIR_STORAGE_POOL_ISCSI:
            case VIR_STORAGE_POOL_SCSI:
            case VIR_STORAGE_POOL_MPATH:
                stable_path = virStorageBackendStablePath(pool,
                                                          cleanpath,
                                                          false);
                if (stable_path == NULL) {
                    /* Don't break the whole lookup process if it fails on
                     * getting the stable path for some of the pools.
                     */
                    VIR_WARN("Failed to get stable path for pool '%s'",
                             pool->def->name);
                    virStoragePoolObjUnlock(pool);
                    continue;
                }
                break;

            case VIR_STORAGE_POOL_GLUSTER:
            case VIR_STORAGE_POOL_RBD:
            case VIR_STORAGE_POOL_SHEEPDOG:
            case VIR_STORAGE_POOL_LAST:
                if (VIR_STRDUP(stable_path, path) < 0) {
                     virStoragePoolObjUnlock(pool);
                    goto cleanup;
                }
                break;
        }

        vol = virStorageVolDefFindByPath(pool, stable_path);
        VIR_FREE(stable_path);

        if (vol) {
            if (virStorageVolLookupByPathEnsureACL(conn, pool->def, vol) < 0) {
                virStoragePoolObjUnlock(pool);
                goto cleanup;
            }

            ret = virGetStorageVol(conn, pool->def->name,
                                   vol->name, vol->key,
                                   NULL, NULL);
        }

        virStoragePoolObjUnlock(pool);
    }

    if (!ret) {
        if (STREQ(path, cleanpath)) {
            virReportError(VIR_ERR_NO_STORAGE_VOL,
                           _("no storage vol with matching path '%s'"), path);
        } else {
            virReportError(VIR_ERR_NO_STORAGE_VOL,
                           _("no storage vol with matching path '%s' (%s)"),
                           path, cleanpath);
        }
    }

 cleanup:
    VIR_FREE(cleanpath);
    storageDriverUnlock(driver);
    return ret;
}


static int
storageVolDelete(virStorageVolPtr obj,
                 unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol = NULL;
    size_t i;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolDeleteEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (!backend->deleteVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support vol deletion"));

        goto cleanup;
    }

    if (backend->deleteVol(obj->conn, pool, vol, flags) < 0)
        goto cleanup;

    /* Update pool metadata */
    pool->def->allocation -= vol->allocation;
    pool->def->available += vol->allocation;

    for (i = 0; i < pool->volumes.count; i++) {
        if (pool->volumes.objs[i] == vol) {
            VIR_INFO("Deleting volume '%s' from storage pool '%s'",
                     vol->name, pool->def->name);
            virStorageVolDefFree(vol);

            VIR_DELETE_ELEMENT(pool->volumes.objs, i, pool->volumes.count);
            break;
        }
    }
    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}


static virStorageVolPtr
storageVolCreateXML(virStoragePoolPtr obj,
                    const char *xmldesc,
                    unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;
    virStorageVolDefPtr buildvoldef = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    voldef = virStorageVolDefParseString(pool->def, xmldesc);
    if (voldef == NULL)
        goto cleanup;

    if (virStorageVolCreateXMLEnsureACL(obj->conn, pool->def, voldef) < 0)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, voldef->name)) {
        virReportError(VIR_ERR_STORAGE_VOL_EXIST,
                       _("'%s'"), voldef->name);
        goto cleanup;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0)
        goto cleanup;

    if (!backend->createVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support volume "
                               "creation"));
        goto cleanup;
    }

    /* Wipe any key the user may have suggested, as volume creation
     * will generate the canonical key.  */
    VIR_FREE(voldef->key);
    if (backend->createVol(obj->conn, pool, voldef) < 0) {
        goto cleanup;
    }

    pool->volumes.objs[pool->volumes.count++] = voldef;
    volobj = virGetStorageVol(obj->conn, pool->def->name, voldef->name,
                              voldef->key, NULL, NULL);
    if (!volobj) {
        pool->volumes.count--;
        goto cleanup;
    }

    if (VIR_ALLOC(buildvoldef) < 0) {
        voldef = NULL;
        goto cleanup;
    }

    /* Make a shallow copy of the 'defined' volume definition, since the
     * original allocation value will change as the user polls 'info',
     * but we only need the initial requested values
     */
    memcpy(buildvoldef, voldef, sizeof(*voldef));

    if (backend->buildVol) {
        int buildret;

        /* Drop the pool lock during volume allocation */
        pool->asyncjobs++;
        voldef->building = 1;
        virStoragePoolObjUnlock(pool);

        buildret = backend->buildVol(obj->conn, pool, buildvoldef, flags);

        storageDriverLock(driver);
        virStoragePoolObjLock(pool);
        storageDriverUnlock(driver);

        voldef->building = 0;
        pool->asyncjobs--;

        voldef = NULL;

        if (buildret < 0) {
            virStoragePoolObjUnlock(pool);
            storageVolDelete(volobj, 0);
            pool = NULL;
            goto cleanup;
        }

    }

    /* Update pool metadata */
    pool->def->allocation += buildvoldef->allocation;
    pool->def->available -= buildvoldef->allocation;

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             volobj->name, pool->def->name);
    ret = volobj;
    volobj = NULL;
    voldef = NULL;

 cleanup:
    virObjectUnref(volobj);
    virStorageVolDefFree(voldef);
    VIR_FREE(buildvoldef);
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStorageVolPtr
storageVolCreateXMLFrom(virStoragePoolPtr obj,
                        const char *xmldesc,
                        virStorageVolPtr vobj,
                        unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool, origpool = NULL;
    virStorageBackendPtr backend;
    virStorageVolDefPtr origvol = NULL, newvol = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;
    unsigned long long allocation;
    int buildret;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    if (pool && STRNEQ(obj->name, vobj->pool)) {
        virStoragePoolObjUnlock(pool);
        origpool = virStoragePoolObjFindByName(&driver->pools, vobj->pool);
        virStoragePoolObjLock(pool);
    }
    storageDriverUnlock(driver);
    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid %s"), obj->uuid);
        goto cleanup;
    }

    if (STRNEQ(obj->name, vobj->pool) && !origpool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       vobj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if (origpool && !virStoragePoolObjIsActive(origpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"),
                       origpool->def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    origvol = virStorageVolDefFindByName(origpool ? origpool : pool, vobj->name);
    if (!origvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vobj->name);
        goto cleanup;
    }

    newvol = virStorageVolDefParseString(pool->def, xmldesc);
    if (newvol == NULL)
        goto cleanup;

    if (virStorageVolCreateXMLFromEnsureACL(obj->conn, pool->def, newvol) < 0)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, newvol->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support volume creation from an existing volume"));
        goto cleanup;
    }

    if (origvol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       origvol->name);
        goto cleanup;
    }

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, origvol) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0)
        goto cleanup;

    /* 'Define' the new volume so we get async progress reporting.
     * Wipe any key the user may have suggested, as volume creation
     * will generate the canonical key.  */
    VIR_FREE(newvol->key);
    if (backend->createVol(obj->conn, pool, newvol) < 0) {
        goto cleanup;
    }

    pool->volumes.objs[pool->volumes.count++] = newvol;
    volobj = virGetStorageVol(obj->conn, pool->def->name, newvol->name,
                              newvol->key, NULL, NULL);
    if (!volobj) {
        pool->volumes.count--;
        goto cleanup;
    }

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
    allocation = newvol->allocation;
    newvol = NULL;
    pool->asyncjobs--;

    if (origpool) {
        origpool->asyncjobs--;
        virStoragePoolObjUnlock(origpool);
        origpool = NULL;
    }

    if (buildret < 0) {
        virStoragePoolObjUnlock(pool);
        storageVolDelete(volobj, 0);
        pool = NULL;
        goto cleanup;
    }

    /* Updating pool metadata */
    pool->def->allocation += allocation;
    pool->def->available -= allocation;

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             volobj->name, pool->def->name);
    ret = volobj;
    volobj = NULL;

 cleanup:
    virObjectUnref(volobj);
    virStorageVolDefFree(newvol);
    if (pool)
        virStoragePoolObjUnlock(pool);
    if (origpool)
        virStoragePoolObjUnlock(origpool);
    return ret;
}


static int
storageVolDownload(virStorageVolPtr obj,
                   virStreamPtr stream,
                   unsigned long long offset,
                   unsigned long long length,
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
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (vol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolDownloadEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (virFDStreamOpenFile(stream,
                            vol->target.path,
                            offset, length,
                            O_RDONLY) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);

    return ret;
}


static int
storageVolUpload(virStorageVolPtr obj,
                 virStreamPtr stream,
                 unsigned long long offset,
                 unsigned long long length,
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
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (vol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolUploadEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    switch ((enum virStoragePoolType) pool->def->type) {
    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
    case VIR_STORAGE_POOL_LOGICAL:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_ISCSI:
    case VIR_STORAGE_POOL_SCSI:
    case VIR_STORAGE_POOL_MPATH:
        /* Not using O_CREAT because the file is required to already exist at
         * this point */
        if (virFDStreamOpenFile(stream, vol->target.path,
                                offset, length, O_WRONLY) < 0)
            goto cleanup;

        break;

    case VIR_STORAGE_POOL_SHEEPDOG:
    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_GLUSTER:
    case VIR_STORAGE_POOL_LAST:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("volume upload is not supported with pools of type %s"),
                       virStoragePoolTypeToString(pool->def->type));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);

    return ret;
}

static int
storageVolResize(virStorageVolPtr obj,
                 unsigned long long capacity,
                 unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStorageBackendPtr backend;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    unsigned long long abs_capacity;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE |
                  VIR_STORAGE_VOL_RESIZE_DELTA |
                  VIR_STORAGE_VOL_RESIZE_SHRINK, -1);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (vol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolResizeEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_RESIZE_DELTA) {
        abs_capacity = vol->capacity + capacity;
        flags &= ~VIR_STORAGE_VOL_RESIZE_DELTA;
    } else {
        abs_capacity = capacity;
    }

    if (abs_capacity < vol->allocation) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("can't shrink capacity below "
                         "existing allocation"));
        goto cleanup;
    }

    if (abs_capacity < vol->capacity &&
        !(flags & VIR_STORAGE_VOL_RESIZE_SHRINK)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Can't shrink capacity below current "
                         "capacity with shrink flag explicitly specified"));
        goto cleanup;
    }

    if (abs_capacity > vol->capacity + pool->def->available) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Not enough space left on storage pool"));
        goto cleanup;
    }

    if (!backend->resizeVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool does not support changing of "
                         "volume capacity"));
        goto cleanup;
    }

    if (backend->resizeVol(obj->conn, pool, vol, abs_capacity, flags) < 0)
        goto cleanup;

    vol->capacity = abs_capacity;
    if (flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE)
        vol->allocation = abs_capacity;

    /* Update pool metadata */
    pool->def->allocation += (abs_capacity - vol->capacity);
    pool->def->available -= (abs_capacity - vol->capacity);

    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);

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
storageVolZeroSparseFile(virStorageVolDefPtr vol,
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
        return ret;
    }

    ret = ftruncate(fd, size);
    if (ret == -1) {
        virReportSystemError(errno,
                             _("Failed to truncate volume with "
                               "path '%s' to %ju bytes"),
                             vol->target.path, (uintmax_t)size);
    }

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
              (uintmax_t)extent_start, (uintmax_t)extent_length);

    if ((ret = lseek(fd, extent_start, SEEK_SET)) < 0) {
        virReportSystemError(errno,
                             _("Failed to seek to position %ju in volume "
                               "with path '%s'"),
                             (uintmax_t)extent_start, vol->target.path);
        goto cleanup;
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

            goto cleanup;
        }

        *bytes_wiped += written;
        remaining -= written;
    }

    if (fdatasync(fd) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot sync data to volume with path '%s'"),
                             vol->target.path);
        goto cleanup;
    }

    VIR_DEBUG("Wrote %zu bytes to volume with path '%s'",
              *bytes_wiped, vol->target.path);

    ret = 0;

 cleanup:
    return ret;
}


static int
storageVolWipeInternal(virStorageVolDefPtr def,
                       unsigned int algorithm)
{
    int ret = -1, fd = -1;
    struct stat st;
    char *writebuf = NULL;
    size_t bytes_wiped = 0;
    virCommandPtr cmd = NULL;

    VIR_DEBUG("Wiping volume with path '%s' and algorithm %u",
              def->target.path, algorithm);

    fd = open(def->target.path, O_RDWR);
    if (fd == -1) {
        virReportSystemError(errno,
                             _("Failed to open storage volume with path '%s'"),
                             def->target.path);
        goto cleanup;
    }

    if (fstat(fd, &st) == -1) {
        virReportSystemError(errno,
                             _("Failed to stat storage volume with path '%s'"),
                             def->target.path);
        goto cleanup;
    }

    if (algorithm != VIR_STORAGE_VOL_WIPE_ALG_ZERO) {
        const char *alg_char ATTRIBUTE_UNUSED = NULL;
        switch (algorithm) {
        case VIR_STORAGE_VOL_WIPE_ALG_NNSA:
            alg_char = "nnsa";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_DOD:
            alg_char = "dod";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_BSI:
            alg_char = "bsi";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_GUTMANN:
            alg_char = "gutmann";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER:
            alg_char = "schneier";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7:
            alg_char = "pfitzner7";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33:
            alg_char = "pfitzner33";
            break;
        case VIR_STORAGE_VOL_WIPE_ALG_RANDOM:
            alg_char = "random";
            break;
        default:
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unsupported algorithm %d"),
                           algorithm);
        }
        cmd = virCommandNew(SCRUB);
        virCommandAddArgList(cmd, "-f", "-p", alg_char,
                             def->target.path, NULL);

        if (virCommandRun(cmd, NULL) < 0)
            goto cleanup;

        ret = 0;
        goto cleanup;
    } else {
        if (S_ISREG(st.st_mode) && st.st_blocks < (st.st_size / DEV_BSIZE)) {
            ret = storageVolZeroSparseFile(def, st.st_size, fd);
        } else {

            if (VIR_ALLOC_N(writebuf, st.st_blksize) < 0)
                goto cleanup;

            ret = storageWipeExtent(def,
                                    fd,
                                    0,
                                    def->allocation,
                                    writebuf,
                                    st.st_blksize,
                                    &bytes_wiped);
        }
    }

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(writebuf);
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static int
storageVolWipePattern(virStorageVolPtr obj,
                      unsigned int algorithm,
                      unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (algorithm >= VIR_STORAGE_VOL_WIPE_ALG_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("wiping algorithm %d not supported"),
                       algorithm);
        return -1;
    }

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (vol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolWipePatternEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (storageVolWipeInternal(vol, algorithm) == -1) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (pool) {
        virStoragePoolObjUnlock(pool);
    }

    return ret;

}

static int
storageVolWipe(virStorageVolPtr obj,
               unsigned int flags)
{
    return storageVolWipePattern(obj, VIR_STORAGE_VOL_WIPE_ALG_ZERO, flags);
}


static int
storageVolGetInfo(virStorageVolPtr obj,
                  virStorageVolInfoPtr info)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    int ret = -1;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolGetInfoEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

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
storageVolGetXMLDesc(virStorageVolPtr obj,
                     unsigned int flags)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolGetXMLDescEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

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
storageVolGetPath(virStorageVolPtr obj)
{
    virStorageDriverStatePtr driver = obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    storageDriverLock(driver);
    pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    storageDriverUnlock(driver);
    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       obj->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto cleanup;
    }

    if (virStorageVolGetPathEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    ignore_value(VIR_STRDUP(ret, vol->target.path));

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storageConnectListAllStoragePools(virConnectPtr conn,
                                  virStoragePoolPtr **pools,
                                  unsigned int flags)
{
    virStorageDriverStatePtr driver = conn->storagePrivateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL, -1);

    if (virConnectListAllStoragePoolsEnsureACL(conn) < 0)
        goto cleanup;

    storageDriverLock(driver);
    ret = virStoragePoolObjListExport(conn, driver->pools, pools,
                                      virConnectListAllStoragePoolsCheckACL, flags);
    storageDriverUnlock(driver);

 cleanup:
    return ret;
}


static virStorageDriver storageDriver = {
    .name = "storage",
    .storageOpen = storageOpen, /* 0.4.0 */
    .storageClose = storageClose, /* 0.4.0 */
    .connectNumOfStoragePools = storageConnectNumOfStoragePools, /* 0.4.0 */
    .connectListStoragePools = storageConnectListStoragePools, /* 0.4.0 */
    .connectNumOfDefinedStoragePools = storageConnectNumOfDefinedStoragePools, /* 0.4.0 */
    .connectListDefinedStoragePools = storageConnectListDefinedStoragePools, /* 0.4.0 */
    .connectListAllStoragePools = storageConnectListAllStoragePools, /* 0.10.2 */
    .connectFindStoragePoolSources = storageConnectFindStoragePoolSources, /* 0.4.0 */
    .storagePoolLookupByName = storagePoolLookupByName, /* 0.4.0 */
    .storagePoolLookupByUUID = storagePoolLookupByUUID, /* 0.4.0 */
    .storagePoolLookupByVolume = storagePoolLookupByVolume, /* 0.4.0 */
    .storagePoolCreateXML = storagePoolCreateXML, /* 0.4.0 */
    .storagePoolDefineXML = storagePoolDefineXML, /* 0.4.0 */
    .storagePoolBuild = storagePoolBuild, /* 0.4.0 */
    .storagePoolUndefine = storagePoolUndefine, /* 0.4.0 */
    .storagePoolCreate = storagePoolCreate, /* 0.4.0 */
    .storagePoolDestroy = storagePoolDestroy, /* 0.4.0 */
    .storagePoolDelete = storagePoolDelete, /* 0.4.0 */
    .storagePoolRefresh = storagePoolRefresh, /* 0.4.0 */
    .storagePoolGetInfo = storagePoolGetInfo, /* 0.4.0 */
    .storagePoolGetXMLDesc = storagePoolGetXMLDesc, /* 0.4.0 */
    .storagePoolGetAutostart = storagePoolGetAutostart, /* 0.4.0 */
    .storagePoolSetAutostart = storagePoolSetAutostart, /* 0.4.0 */
    .storagePoolNumOfVolumes = storagePoolNumOfVolumes, /* 0.4.0 */
    .storagePoolListVolumes = storagePoolListVolumes, /* 0.4.0 */
    .storagePoolListAllVolumes = storagePoolListAllVolumes, /* 0.10.2 */

    .storageVolLookupByName = storageVolLookupByName, /* 0.4.0 */
    .storageVolLookupByKey = storageVolLookupByKey, /* 0.4.0 */
    .storageVolLookupByPath = storageVolLookupByPath, /* 0.4.0 */
    .storageVolCreateXML = storageVolCreateXML, /* 0.4.0 */
    .storageVolCreateXMLFrom = storageVolCreateXMLFrom, /* 0.6.4 */
    .storageVolDownload = storageVolDownload, /* 0.9.0 */
    .storageVolUpload = storageVolUpload, /* 0.9.0 */
    .storageVolDelete = storageVolDelete, /* 0.4.0 */
    .storageVolWipe = storageVolWipe, /* 0.8.0 */
    .storageVolWipePattern = storageVolWipePattern, /* 0.9.10 */
    .storageVolGetInfo = storageVolGetInfo, /* 0.4.0 */
    .storageVolGetXMLDesc = storageVolGetXMLDesc, /* 0.4.0 */
    .storageVolGetPath = storageVolGetPath, /* 0.4.0 */
    .storageVolResize = storageVolResize, /* 0.9.10 */

    .storagePoolIsActive = storagePoolIsActive, /* 0.7.3 */
    .storagePoolIsPersistent = storagePoolIsPersistent, /* 0.7.3 */
};


static virStateDriver stateDriver = {
    .name = "Storage",
    .stateInitialize = storageStateInitialize,
    .stateAutoStart = storageStateAutoStart,
    .stateCleanup = storageStateCleanup,
    .stateReload = storageStateReload,
};

int storageRegister(void)
{
    if (virRegisterStorageDriver(&storageDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    return 0;
}


/* ----------- file handlers cooperating with storage driver --------------- */
void
virStorageFileFree(virStorageFilePtr file)
{
    if (!file)
        return;

    if (file->backend &&
        file->backend->backendDeinit)
        file->backend->backendDeinit(file);

    VIR_FREE(file->path);
    virDomainDiskHostDefFree(file->nhosts, file->hosts);
    VIR_FREE(file);
}


static virStorageFilePtr
virStorageFileInitInternal(int type,
                           const char *path,
                           int protocol,
                           size_t nhosts,
                           virDomainDiskHostDefPtr hosts)
{
    virStorageFilePtr file = NULL;

    if (VIR_ALLOC(file) < 0)
        return NULL;

    file->type = type;
    file->protocol = protocol;
    file->nhosts = nhosts;

    if (VIR_STRDUP(file->path, path) < 0)
        goto error;

    if (!(file->hosts = virDomainDiskHostDefCopy(nhosts, hosts)))
        goto error;

    if (!(file->backend = virStorageFileBackendForType(file->type,
                                                       file->protocol)))
        goto error;

    if (file->backend->backendInit &&
        file->backend->backendInit(file) < 0)
        goto error;

    return file;

 error:
    VIR_FREE(file->path);
    virDomainDiskHostDefFree(file->nhosts, file->hosts);
    VIR_FREE(file);
    return NULL;
}


virStorageFilePtr
virStorageFileInitFromDiskDef(virDomainDiskDefPtr disk)
{
    return virStorageFileInitInternal(virDomainDiskGetActualType(disk),
                                      disk->src.path,
                                      disk->src.protocol,
                                      disk->src.nhosts,
                                      disk->src.hosts);
}


virStorageFilePtr
virStorageFileInitFromSnapshotDef(virDomainSnapshotDiskDefPtr disk)
{
    return virStorageFileInitInternal(virDomainSnapshotDiskGetActualType(disk),
                                      disk->file,
                                      disk->protocol,
                                      disk->nhosts,
                                      disk->hosts);
}



/**
 * virStorageFileCreate: Creates an empty storage file via storage driver
 *
 * @file: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileCreate(virStorageFilePtr file)
{
    if (!file->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    return file->backend->storageFileCreate(file);
}


/**
 * virStorageFileUnlink: Unlink storage file via storage driver
 *
 * @file: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileUnlink(virStorageFilePtr file)
{
    if (!file->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    return file->backend->storageFileUnlink(file);
}


/**
 * virStorageFileStat: returns stat struct of a file via storage driver
 *
 * @file: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageFileStat(virStorageFilePtr file,
                   struct stat *st)
{
    if (!(file->backend->storageFileStat)) {
        errno = ENOSYS;
        return -2;
    }

    return file->backend->storageFileStat(file, st);
}
