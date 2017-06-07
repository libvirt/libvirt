/*
 * storage_driver.c: core driver for storage APIs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
#include "storage_event.h"
#include "viralloc.h"
#include "storage_backend.h"
#include "virlog.h"
#include "virfile.h"
#include "virfdstream.h"
#include "configmake.h"
#include "virstring.h"
#include "viraccessapicheck.h"
#include "dirname.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_driver");

static virStorageDriverStatePtr driver;

static int storageStateCleanup(void);

typedef struct _virStorageVolStreamInfo virStorageVolStreamInfo;
typedef virStorageVolStreamInfo *virStorageVolStreamInfoPtr;
struct _virStorageVolStreamInfo {
    char *pool_name;
    char *vol_path;
};

static void storageDriverLock(void)
{
    virMutexLock(&driver->lock);
}
static void storageDriverUnlock(void)
{
    virMutexUnlock(&driver->lock);
}


/**
 * virStoragePoolUpdateInactive:
 * @poolptr: pointer to a variable holding the pool object pointer
 *
 * This function is supposed to be called after a pool becomes inactive. The
 * function switches to the new config object for persistent pools. Inactive
 * pools are removed.
 */
static void
virStoragePoolUpdateInactive(virStoragePoolObjPtr *poolptr)
{
    virStoragePoolObjPtr pool = *poolptr;

    if (pool->configFile == NULL) {
        virStoragePoolObjRemove(&driver->pools, pool);
        *poolptr = NULL;
    } else if (pool->newDef) {
        virStoragePoolDefFree(pool->def);
        pool->def = pool->newDef;
        pool->newDef = NULL;
    }
}


static void
storagePoolUpdateState(virStoragePoolObjPtr pool)
{
    bool active = false;
    virStorageBackendPtr backend;
    char *stateFile;

    if (!(stateFile = virFileBuildPath(driver->stateDir,
                                       pool->def->name, ".xml")))
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing backend %d"), pool->def->type);
        goto cleanup;
    }

    /* Backends which do not support 'checkPool' are considered
     * inactive by default. */
    if (backend->checkPool &&
        backend->checkPool(pool, &active) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to initialize storage pool '%s': %s"),
                       pool->def->name, virGetLastErrorMessage());
        active = false;
    }

    /* We can pass NULL as connection, most backends do not use
     * it anyway, but if they do and fail, we want to log error and
     * continue with other pools.
     */
    if (active) {
        virStoragePoolObjClearVols(pool);
        if (backend->refreshPool(NULL, pool) < 0) {
            if (backend->stopPool)
                backend->stopPool(NULL, pool);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to restart storage pool '%s': %s"),
                           pool->def->name, virGetLastErrorMessage());
            active = false;
        }
    }

    pool->active = active;

    if (!pool->active)
        virStoragePoolUpdateInactive(&pool);

 cleanup:
    if (!active && stateFile)
        ignore_value(unlink(stateFile));
    VIR_FREE(stateFile);

    return;
}

static void
storagePoolUpdateAllState(void)
{
    size_t i;

    for (i = 0; i < driver->pools.count; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];

        virStoragePoolObjLock(pool);
        storagePoolUpdateState(pool);
        virStoragePoolObjUnlock(pool);
    }
}

static void
storageDriverAutostart(void)
{
    size_t i;
    virConnectPtr conn = NULL;

    /* XXX Remove hardcoding of QEMU URI */
    if (driver->privileged)
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
            virStoragePoolObjUnlock(pool);
            continue;
        }

        if (pool->autostart &&
            !virStoragePoolObjIsActive(pool)) {
            if (backend->startPool &&
                backend->startPool(conn, pool) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to autostart storage pool '%s': %s"),
                               pool->def->name, virGetLastErrorMessage());
                virStoragePoolObjUnlock(pool);
                continue;
            }
            started = true;
        }

        if (started) {
            char *stateFile;

            virStoragePoolObjClearVols(pool);
            stateFile = virFileBuildPath(driver->stateDir,
                                         pool->def->name, ".xml");
            if (!stateFile ||
                virStoragePoolSaveState(stateFile, pool->def) < 0 ||
                backend->refreshPool(conn, pool) < 0) {
                if (stateFile)
                    unlink(stateFile);
                if (backend->stopPool)
                    backend->stopPool(conn, pool);
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to autostart storage pool '%s': %s"),
                               pool->def->name, virGetLastErrorMessage());
            } else {
                pool->active = true;
            }
            VIR_FREE(stateFile);
        }
        virStoragePoolObjUnlock(pool);
    }

    virObjectUnref(conn);
}

/**
 * virStorageStartup:
 *
 * Initialization function for the Storage Driver
 */
static int
storageStateInitialize(bool privileged,
                       virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                       void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    char *configdir = NULL;
    char *rundir = NULL;

    if (VIR_ALLOC(driver) < 0)
        return ret;

    if (virMutexInit(&driver->lock) < 0) {
        VIR_FREE(driver);
        return ret;
    }
    storageDriverLock();

    if (privileged) {
        if (VIR_STRDUP(driver->configDir,
                       SYSCONFDIR "/libvirt/storage") < 0 ||
            VIR_STRDUP(driver->autostartDir,
                       SYSCONFDIR "/libvirt/storage/autostart") < 0 ||
            VIR_STRDUP(driver->stateDir,
                       LOCALSTATEDIR "/run/libvirt/storage") < 0)
            goto error;
    } else {
        configdir = virGetUserConfigDirectory();
        rundir = virGetUserRuntimeDirectory();
        if (!(configdir && rundir))
            goto error;

        if ((virAsprintf(&driver->configDir,
                        "%s/storage", configdir) < 0) ||
            (virAsprintf(&driver->autostartDir,
                        "%s/storage/autostart", configdir) < 0) ||
            (virAsprintf(&driver->stateDir,
                         "%s/storage/run", rundir) < 0))
            goto error;
    }
    driver->privileged = privileged;

    if (virFileMakePath(driver->stateDir) < 0) {
        virReportError(errno,
                       _("cannot create directory %s"),
                       driver->stateDir);
        goto error;
    }

    if (virStoragePoolObjLoadAllState(&driver->pools,
                                      driver->stateDir) < 0)
        goto error;

    if (virStoragePoolObjLoadAllConfigs(&driver->pools,
                                        driver->configDir,
                                        driver->autostartDir) < 0)
        goto error;

    storagePoolUpdateAllState();

    driver->storageEventState = virObjectEventStateNew();

    storageDriverUnlock();

    ret = 0;
 cleanup:
    VIR_FREE(configdir);
    VIR_FREE(rundir);
    return ret;

 error:
    storageDriverUnlock();
    storageStateCleanup();
    goto cleanup;
}

/**
 * storageStateAutoStart:
 *
 * Function to auto start the storage driver
 */
static void
storageStateAutoStart(void)
{
    if (!driver)
        return;

    storageDriverLock();
    storageDriverAutostart();
    storageDriverUnlock();
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
    if (!driver)
        return -1;

    storageDriverLock();
    virStoragePoolObjLoadAllState(&driver->pools,
                                  driver->stateDir);
    virStoragePoolObjLoadAllConfigs(&driver->pools,
                                    driver->configDir,
                                    driver->autostartDir);
    storageDriverAutostart();
    storageDriverUnlock();

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
    if (!driver)
        return -1;

    storageDriverLock();

    virObjectUnref(driver->storageEventState);

    /* free inactive pools */
    virStoragePoolObjListFree(&driver->pools);

    VIR_FREE(driver->configDir);
    VIR_FREE(driver->autostartDir);
    VIR_FREE(driver->stateDir);
    storageDriverUnlock();
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);

    return 0;
}


static virStoragePoolObjPtr
storagePoolObjFindByUUID(const unsigned char *uuid,
                         const char *name)
{
    virStoragePoolObjPtr pool;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(pool = virStoragePoolObjFindByUUID(&driver->pools, uuid))) {
        virUUIDFormat(uuid, uuidstr);
        if (name)
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           _("no storage pool with matching uuid '%s' (%s)"),
                           uuidstr, name);
        else
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           _("no storage pool with matching uuid '%s'"),
                           uuidstr);
    }

    return pool;
}


static virStoragePoolObjPtr
virStoragePoolObjFromStoragePool(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr ret;

    storageDriverLock();
    ret = storagePoolObjFindByUUID(pool->uuid, pool->name);
    storageDriverUnlock();

    return ret;
}


static virStoragePoolObjPtr
storagePoolObjFindByName(const char *name)
{
    virStoragePoolObjPtr pool;

    storageDriverLock();
    if (!(pool = virStoragePoolObjFindByName(&driver->pools, name)))
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"), name);
    storageDriverUnlock();

    return pool;
}


static virStoragePoolPtr
storagePoolLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid)
{
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    storageDriverLock();
    pool = storagePoolObjFindByUUID(uuid, NULL);
    storageDriverUnlock();
    if (!pool)
        return NULL;

    if (virStoragePoolLookupByUUIDEnsureACL(conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByName(virConnectPtr conn,
                        const char *name)
{
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    if (!(pool = storagePoolObjFindByName(name)))
        return NULL;

    if (virStoragePoolLookupByNameEnsureACL(conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByVolume(virStorageVolPtr vol)
{
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    if (!(pool = storagePoolObjFindByName(vol->pool)))
        return NULL;

    if (virStoragePoolLookupByVolumeEnsureACL(vol->conn, pool->def) < 0)
        goto cleanup;

    ret = virGetStoragePool(vol->conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storageConnectNumOfStoragePools(virConnectPtr conn)
{
    int nactive = 0;

    if (virConnectNumOfStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock();
    nactive = virStoragePoolObjNumOfStoragePools(&driver->pools, conn, true,
                                                 virConnectNumOfStoragePoolsCheckACL);
    storageDriverUnlock();

    return nactive;
}


static int
storageConnectListStoragePools(virConnectPtr conn,
                               char **const names,
                               int maxnames)
{
    int got = 0;

    if (virConnectListStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock();
    got = virStoragePoolObjGetNames(&driver->pools, conn, true,
                                    virConnectListStoragePoolsCheckACL,
                                    names, maxnames);
    storageDriverUnlock();
    return got;
}

static int
storageConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    int nactive = 0;

    if (virConnectNumOfDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock();
    nactive = virStoragePoolObjNumOfStoragePools(&driver->pools, conn, false,
                                                 virConnectNumOfDefinedStoragePoolsCheckACL);
    storageDriverUnlock();

    return nactive;
}


static int
storageConnectListDefinedStoragePools(virConnectPtr conn,
                                      char **const names,
                                      int maxnames)
{
    int got = 0;

    if (virConnectListDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    storageDriverLock();
    got = virStoragePoolObjGetNames(&driver->pools, conn, false,
                                    virConnectListDefinedStoragePoolsCheckACL,
                                    names, maxnames);
    storageDriverUnlock();
    return got;
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
    virStoragePoolObjPtr obj;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;

    if (virStoragePoolIsActiveEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

    ret = virStoragePoolObjIsActive(obj);

 cleanup:
    virStoragePoolObjUnlock(obj);
    return ret;
}

static int storagePoolIsPersistent(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;

    if (virStoragePoolIsPersistentEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

    ret = obj->configFile ? 1 : 0;

 cleanup:
    virStoragePoolObjUnlock(obj);
    return ret;
}


static virStoragePoolPtr
storagePoolCreateXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    char *stateFile = NULL;
    unsigned int build_flags = 0;

    virCheckFlags(VIR_STORAGE_POOL_CREATE_WITH_BUILD |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE, NULL);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, NULL);

    storageDriverLock();
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolCreateXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 1) < 0)
        goto cleanup;

    if (virStoragePoolObjSourceFindDuplicate(conn, &driver->pools, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&driver->pools, def)))
        goto cleanup;
    def = NULL;

    if (backend->buildPool) {
        if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;
        else if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;

        if (build_flags ||
            (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD)) {
            if (backend->buildPool(conn, pool, build_flags) < 0) {
                virStoragePoolObjRemove(&driver->pools, pool);
                pool = NULL;
                goto cleanup;
            }
        }
    }

    if (backend->startPool &&
        backend->startPool(conn, pool) < 0) {
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
        goto cleanup;
    }

    stateFile = virFileBuildPath(driver->stateDir,
                                 pool->def->name, ".xml");

    virStoragePoolObjClearVols(pool);
    if (!stateFile || virStoragePoolSaveState(stateFile, pool->def) < 0 ||
        backend->refreshPool(conn, pool) < 0) {
        if (stateFile)
            unlink(stateFile);
        if (backend->stopPool)
            backend->stopPool(conn, pool);
        virStoragePoolObjRemove(&driver->pools, pool);
        pool = NULL;
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(pool->def->name,
                                            pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);

    VIR_INFO("Creating storage pool '%s'", pool->def->name);
    pool->active = true;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    VIR_FREE(stateFile);
    virStoragePoolDefFree(def);
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    return ret;
}

static virStoragePoolPtr
storagePoolDefineXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, NULL);

    storageDriverLock();
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (virStoragePoolDefineXMLEnsureACL(conn, def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsDuplicate(&driver->pools, def, 0) < 0)
        goto cleanup;

    if (virStoragePoolObjSourceFindDuplicate(conn, &driver->pools, def) < 0)
        goto cleanup;

    if (virStorageBackendForType(def->type) == NULL)
        goto cleanup;

    if (!(pool = virStoragePoolObjAssignDef(&driver->pools, def)))
        goto cleanup;

    if (virStoragePoolObjSaveDef(driver, pool, def) < 0) {
        virStoragePoolObjRemove(&driver->pools, pool);
        def = NULL;
        pool = NULL;
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(def->name, def->uuid,
                                            VIR_STORAGE_POOL_EVENT_DEFINED,
                                            0);

    def = NULL;

    VIR_INFO("Defining storage pool '%s'", pool->def->name);
    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    return ret;
}

static int
storagePoolUndefine(virStoragePoolPtr obj)
{
    virStoragePoolObjPtr pool;
    virObjectEventPtr event = NULL;
    int ret = -1;

    storageDriverLock();
    if (!(pool = storagePoolObjFindByUUID(obj->uuid, obj->name)))
        goto cleanup;

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

    if (unlink(pool->autostartLink) < 0 &&
        errno != ENOENT &&
        errno != ENOTDIR) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to delete autostart link '%s': %s"),
                  pool->autostartLink, virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    VIR_FREE(pool->configFile);
    VIR_FREE(pool->autostartLink);

    event = virStoragePoolEventLifecycleNew(pool->def->name,
                                            pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_UNDEFINED,
                                            0);

    VIR_INFO("Undefining storage pool '%s'", pool->def->name);
    virStoragePoolObjRemove(&driver->pools, pool);
    pool = NULL;
    ret = 0;

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    return ret;
}

static int
storagePoolCreate(virStoragePoolPtr obj,
                  unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    int ret = -1;
    char *stateFile = NULL;
    unsigned int build_flags = 0;

    virCheckFlags(VIR_STORAGE_POOL_CREATE_WITH_BUILD |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE, -1);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, -1);

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

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

    if (backend->buildPool) {
        if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;
        else if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;

        if (build_flags ||
            (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD)) {
            if (backend->buildPool(obj->conn, pool, build_flags) < 0)
                goto cleanup;
        }
    }

    VIR_INFO("Starting up storage pool '%s'", pool->def->name);
    if (backend->startPool &&
        backend->startPool(obj->conn, pool) < 0)
        goto cleanup;

    stateFile = virFileBuildPath(driver->stateDir,
                                 pool->def->name, ".xml");

    virStoragePoolObjClearVols(pool);
    if (!stateFile || virStoragePoolSaveState(stateFile, pool->def) < 0 ||
        backend->refreshPool(obj->conn, pool) < 0) {
        if (stateFile)
            unlink(stateFile);
        if (backend->stopPool)
            backend->stopPool(obj->conn, pool);
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(pool->def->name,
                                            pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);

    pool->active = true;
    ret = 0;

 cleanup:
    VIR_FREE(stateFile);
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolBuild(virStoragePoolPtr obj,
                 unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

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
    virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolDestroy(virStoragePoolPtr obj)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    char *stateFile = NULL;
    int ret = -1;

    storageDriverLock();
    if (!(pool = storagePoolObjFindByUUID(obj->uuid, obj->name)))
        goto cleanup;

    if (virStoragePoolDestroyEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    VIR_INFO("Destroying storage pool '%s'", pool->def->name);

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

    if (!(stateFile = virFileBuildPath(driver->stateDir,
                                       pool->def->name,
                                       ".xml")))
        goto cleanup;

    unlink(stateFile);
    VIR_FREE(stateFile);

    if (backend->stopPool &&
        backend->stopPool(obj->conn, pool) < 0)
        goto cleanup;

    virStoragePoolObjClearVols(pool);

    event = virStoragePoolEventLifecycleNew(pool->def->name,
                                            pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STOPPED,
                                            0);

    pool->active = false;

    virStoragePoolUpdateInactive(&pool);

    ret = 0;

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    return ret;
}

static int
storagePoolDelete(virStoragePoolPtr obj,
                  unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    char *stateFile = NULL;
    int ret = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

    if (virStoragePoolDeleteEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    VIR_INFO("Deleting storage pool '%s'", pool->def->name);

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

    if (!(stateFile = virFileBuildPath(driver->stateDir,
                                       pool->def->name,
                                       ".xml")))
        goto cleanup;

    unlink(stateFile);
    VIR_FREE(stateFile);

    if (!backend->deletePool) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("pool does not support pool deletion"));
        goto cleanup;
    }
    if (backend->deletePool(obj->conn, pool, flags) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolRefresh(virStoragePoolPtr obj,
                   unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    int ret = -1;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, -1);

    storageDriverLock();
    if (!(pool = storagePoolObjFindByUUID(obj->uuid, obj->name)))
        goto cleanup;

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

        event = virStoragePoolEventLifecycleNew(pool->def->name,
                                                pool->def->uuid,
                                                VIR_STORAGE_POOL_EVENT_STOPPED,
                                                0);
        pool->active = false;

        virStoragePoolUpdateInactive(&pool);

        goto cleanup;
    }

    event = virStoragePoolEventRefreshNew(pool->def->name,
                                          pool->def->uuid);
    ret = 0;

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    return ret;
}


static int
storagePoolGetInfo(virStoragePoolPtr obj,
                   virStoragePoolInfoPtr info)
{
    virStoragePoolObjPtr pool;
    int ret = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

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
    virStoragePoolObjUnlock(pool);
    return ret;
}

static char *
storagePoolGetXMLDesc(virStoragePoolPtr obj,
                      unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStoragePoolDefPtr def;
    char *ret = NULL;

    virCheckFlags(VIR_STORAGE_XML_INACTIVE, NULL);

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return NULL;

    if (virStoragePoolGetXMLDescEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if ((flags & VIR_STORAGE_XML_INACTIVE) && pool->newDef)
        def = pool->newDef;
    else
        def = pool->def;

    ret = virStoragePoolDefFormat(def);

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolGetAutostart(virStoragePoolPtr obj,
                        int *autostart)
{
    virStoragePoolObjPtr pool;
    int ret = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

    if (virStoragePoolGetAutostartEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!pool->configFile) {
        *autostart = 0;
    } else {
        *autostart = pool->autostart;
    }
    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storagePoolSetAutostart(virStoragePoolPtr obj,
                        int autostart)
{
    virStoragePoolObjPtr pool;
    int ret = -1;

    storageDriverLock();
    if (!(pool = storagePoolObjFindByUUID(obj->uuid, obj->name)))
        goto cleanup;

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
    storageDriverUnlock();
    return ret;
}


static int
storagePoolNumOfVolumes(virStoragePoolPtr obj)
{
    virStoragePoolObjPtr pool;
    int ret = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

    if (virStoragePoolNumOfVolumesEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    ret = virStoragePoolObjNumOfVolumes(&pool->volumes, obj->conn, pool->def,
                                        virStoragePoolNumOfVolumesCheckACL);

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storagePoolListVolumes(virStoragePoolPtr obj,
                       char **const names,
                       int maxnames)
{
    virStoragePoolObjPtr pool;
    int n = -1;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return -1;

    if (virStoragePoolListVolumesEnsureACL(obj->conn, pool->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    n = virStoragePoolObjVolumeGetNames(&pool->volumes, obj->conn, pool->def,
                                        virStoragePoolListVolumesCheckACL,
                                        names, maxnames);
 cleanup:
    virStoragePoolObjUnlock(pool);
    return n;
}


static int
storagePoolListAllVolumes(virStoragePoolPtr pool,
                          virStorageVolPtr **vols,
                          unsigned int flags)
{
    virStoragePoolObjPtr obj;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;

    if (virStoragePoolListAllVolumesEnsureACL(pool->conn, obj->def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), obj->def->name);
        goto cleanup;
    }

    ret = virStoragePoolObjVolumeListExport(pool->conn, &obj->volumes,
                                            obj->def, vols,
                                            virStoragePoolListAllVolumesCheckACL);


 cleanup:
    virStoragePoolObjUnlock(obj);

    return ret;
}

static virStorageVolPtr
storageVolLookupByName(virStoragePoolPtr obj,
                       const char *name)
{
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    virStorageVolPtr ret = NULL;

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return NULL;

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
    virStoragePoolObjUnlock(pool);
    return ret;
}


static virStorageVolPtr
storageVolLookupByKey(virConnectPtr conn,
                      const char *key)
{
    size_t i;
    virStorageVolPtr ret = NULL;

    storageDriverLock();
    for (i = 0; i < driver->pools.count && !ret; i++) {
        virStoragePoolObjLock(driver->pools.objs[i]);
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByKey(driver->pools.objs[i], key);

            if (vol) {
                virStoragePoolDefPtr def = driver->pools.objs[i]->def;
                if (virStorageVolLookupByKeyEnsureACL(conn, def, vol) < 0) {
                    virStoragePoolObjUnlock(driver->pools.objs[i]);
                    goto cleanup;
                }

                ret = virGetStorageVol(conn,
                                       def->name,
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
    storageDriverUnlock();
    return ret;
}

static virStorageVolPtr
storageVolLookupByPath(virConnectPtr conn,
                       const char *path)
{
    size_t i;
    virStorageVolPtr ret = NULL;
    char *cleanpath;

    cleanpath = virFileSanitizePath(path);
    if (!cleanpath)
        return NULL;

    storageDriverLock();
    for (i = 0; i < driver->pools.count && !ret; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];
        virStorageVolDefPtr vol;
        char *stable_path = NULL;

        virStoragePoolObjLock(pool);

        if (!virStoragePoolObjIsActive(pool)) {
           virStoragePoolObjUnlock(pool);
           continue;
        }

        switch ((virStoragePoolType) pool->def->type) {
            case VIR_STORAGE_POOL_DIR:
            case VIR_STORAGE_POOL_FS:
            case VIR_STORAGE_POOL_NETFS:
            case VIR_STORAGE_POOL_LOGICAL:
            case VIR_STORAGE_POOL_DISK:
            case VIR_STORAGE_POOL_ISCSI:
            case VIR_STORAGE_POOL_SCSI:
            case VIR_STORAGE_POOL_MPATH:
            case VIR_STORAGE_POOL_VSTORAGE:
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
            case VIR_STORAGE_POOL_ZFS:
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
    storageDriverUnlock();
    return ret;
}

virStoragePoolPtr
storagePoolLookupByTargetPath(virConnectPtr conn,
                              const char *path)
{
    size_t i;
    virStoragePoolPtr ret = NULL;
    char *cleanpath;

    cleanpath = virFileSanitizePath(path);
    if (!cleanpath)
        return NULL;

    storageDriverLock();
    for (i = 0; i < driver->pools.count && !ret; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];

        virStoragePoolObjLock(pool);

        if (!virStoragePoolObjIsActive(pool)) {
            virStoragePoolObjUnlock(pool);
            continue;
        }

        if (STREQ(path, pool->def->target.path)) {
            ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                                    NULL, NULL);
        }

        virStoragePoolObjUnlock(pool);
    }
    storageDriverUnlock();

    if (!ret) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage pool with matching target path '%s'"),
                       path);
    }

    VIR_FREE(cleanpath);
    return ret;
}


static void
storageVolRemoveFromPool(virStoragePoolObjPtr pool,
                         virStorageVolDefPtr vol)
{
    size_t i;

    for (i = 0; i < pool->volumes.count; i++) {
        if (pool->volumes.objs[i] == vol) {
            VIR_INFO("Deleting volume '%s' from storage pool '%s'",
                     vol->name, pool->def->name);
            virStorageVolDefFree(vol);

            VIR_DELETE_ELEMENT(pool->volumes.objs, i, pool->volumes.count);
            break;
        }
    }
}


static int
storageVolDeleteInternal(virStorageVolPtr obj,
                         virStorageBackendPtr backend,
                         virStoragePoolObjPtr pool,
                         virStorageVolDefPtr vol,
                         unsigned int flags,
                         bool updateMeta)
{
    int ret = -1;

    if (!backend->deleteVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support vol deletion"));

        goto cleanup;
    }

    if (backend->deleteVol(obj->conn, pool, vol, flags) < 0)
        goto cleanup;

    /* Update pool metadata - don't update meta data from error paths
     * in this module since the allocation/available weren't adjusted yet.
     * Ignore the disk backend since it updates the pool values.
     */
    if (updateMeta) {
        if (pool->def->type != VIR_STORAGE_POOL_DISK) {
            pool->def->allocation -= vol->target.allocation;
            pool->def->available += vol->target.allocation;
        }
    }

    storageVolRemoveFromPool(pool, vol);
    ret = 0;

 cleanup:
    return ret;
}


static virStorageVolDefPtr
virStorageVolDefFromVol(virStorageVolPtr obj,
                        virStoragePoolObjPtr *pool,
                        virStorageBackendPtr *backend)
{
    virStorageVolDefPtr vol = NULL;

    if (!(*pool = storagePoolObjFindByName(obj->pool)))
        return NULL;

    if (!virStoragePoolObjIsActive(*pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"),
                       (*pool)->def->name);
        goto error;
    }

    if (!(vol = virStorageVolDefFindByName(*pool, obj->name))) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       obj->name);
        goto error;
    }

    if (backend) {
        if (!(*backend = virStorageBackendForType((*pool)->def->type)))
            goto error;
    }

    return vol;

 error:
    virStoragePoolObjUnlock(*pool);
    *pool = NULL;

    return NULL;
}


static int
storageVolDelete(virStorageVolPtr obj,
                 unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol = NULL;
    int ret = -1;

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;

    if (virStorageVolDeleteEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       vol->name);
        goto cleanup;
    }

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (storageVolDeleteInternal(obj, backend, pool, vol, flags, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}


static virStorageVolPtr
storageVolCreateXML(virStoragePoolPtr obj,
                    const char *xmldesc,
                    unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    if (!(pool = virStoragePoolObjFromStoragePool(obj)))
        return NULL;

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        goto cleanup;

    voldef = virStorageVolDefParseString(pool->def, xmldesc,
                                         VIR_VOL_XML_PARSE_OPT_CAPACITY);
    if (voldef == NULL)
        goto cleanup;

    if (!voldef->target.capacity && !backend->buildVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("volume capacity required for this "
                               "storage pool"));
        goto cleanup;
    }

    if (virStorageVolCreateXMLEnsureACL(obj->conn, pool->def, voldef) < 0)
        goto cleanup;

    if (virStorageVolDefFindByName(pool, voldef->name)) {
        virReportError(VIR_ERR_STORAGE_VOL_EXIST,
                       _("'%s'"), voldef->name);
        goto cleanup;
    }

    if (!backend->createVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support volume "
                               "creation"));
        goto cleanup;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0)
        goto cleanup;

    /* Wipe any key the user may have suggested, as volume creation
     * will generate the canonical key.  */
    VIR_FREE(voldef->key);
    if (backend->createVol(obj->conn, pool, voldef) < 0)
        goto cleanup;

    pool->volumes.objs[pool->volumes.count++] = voldef;
    volobj = virGetStorageVol(obj->conn, pool->def->name, voldef->name,
                              voldef->key, NULL, NULL);
    if (!volobj) {
        pool->volumes.count--;
        goto cleanup;
    }


    if (backend->buildVol) {
        int buildret;
        virStorageVolDefPtr buildvoldef = NULL;

        if (VIR_ALLOC(buildvoldef) < 0) {
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
        voldef->building = true;
        virStoragePoolObjUnlock(pool);

        buildret = backend->buildVol(obj->conn, pool, buildvoldef, flags);

        VIR_FREE(buildvoldef);

        storageDriverLock();
        virStoragePoolObjLock(pool);
        storageDriverUnlock();

        voldef->building = false;
        pool->asyncjobs--;

        if (buildret < 0) {
            /* buildVol handles deleting volume on failure */
            storageVolRemoveFromPool(pool, voldef);
            voldef = NULL;
            goto cleanup;
        }

    }

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, voldef) < 0) {
        storageVolDeleteInternal(volobj, backend, pool, voldef,
                                 0, false);
        voldef = NULL;
        goto cleanup;
    }

    /* Update pool metadata ignoring the disk backend since
     * it updates the pool values.
     */
    if (pool->def->type != VIR_STORAGE_POOL_DISK) {
        pool->def->allocation += voldef->target.allocation;
        pool->def->available -= voldef->target.allocation;
    }

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             volobj->name, pool->def->name);
    ret = volobj;
    volobj = NULL;
    voldef = NULL;

 cleanup:
    virObjectUnref(volobj);
    virStorageVolDefFree(voldef);
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
    virStoragePoolObjPtr pool, origpool = NULL;
    virStorageBackendPtr backend;
    virStorageVolDefPtr origvol = NULL, newvol = NULL, shadowvol = NULL;
    virStorageVolPtr ret = NULL, volobj = NULL;
    int buildret;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  NULL);

    storageDriverLock();
    pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    if (pool && STRNEQ(obj->name, vobj->pool)) {
        virStoragePoolObjUnlock(pool);
        origpool = virStoragePoolObjFindByName(&driver->pools, vobj->pool);
        virStoragePoolObjLock(pool);
    }
    storageDriverUnlock();
    if (!pool) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(obj->uuid, uuidstr);
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid '%s' (%s)"),
                       uuidstr, obj->name);
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

    origvol = virStorageVolDefFindByName(origpool ?
                                         origpool : pool, vobj->name);
    if (!origvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vobj->name);
        goto cleanup;
    }

    newvol = virStorageVolDefParseString(pool->def, xmldesc,
                                         VIR_VOL_XML_PARSE_NO_CAPACITY);
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

    /* Use the original volume's capacity in case the new capacity
     * is less than that, or it was omitted */
    if (newvol->target.capacity < origvol->target.capacity)
        newvol->target.capacity = origvol->target.capacity;

    /* If the allocation was not provided in the XML, then use capacity
     * as it's specifically documented "If omitted when creating a volume,
     * the  volume will be fully allocated at time of creation.". This
     * is especially important for logical volume creation. */
    if (!newvol->target.has_allocation)
        newvol->target.allocation = newvol->target.capacity;

    if (!backend->buildVolFrom) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support"
                               " volume creation from an existing volume"));
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
    if (backend->createVol(obj->conn, pool, newvol) < 0)
        goto cleanup;

    /* Make a shallow copy of the 'defined' volume definition, since the
     * original allocation value will change as the user polls 'info',
     * but we only need the initial requested values
     */
    if (VIR_ALLOC(shadowvol) < 0)
        goto cleanup;

    memcpy(shadowvol, newvol, sizeof(*newvol));

    pool->volumes.objs[pool->volumes.count++] = newvol;
    volobj = virGetStorageVol(obj->conn, pool->def->name, newvol->name,
                              newvol->key, NULL, NULL);
    if (!volobj) {
        pool->volumes.count--;
        goto cleanup;
    }

    /* Drop the pool lock during volume allocation */
    pool->asyncjobs++;
    newvol->building = true;
    origvol->in_use++;
    virStoragePoolObjUnlock(pool);

    if (origpool) {
        origpool->asyncjobs++;
        virStoragePoolObjUnlock(origpool);
    }

    buildret = backend->buildVolFrom(obj->conn, pool, shadowvol, origvol, flags);

    storageDriverLock();
    virStoragePoolObjLock(pool);
    if (origpool)
        virStoragePoolObjLock(origpool);
    storageDriverUnlock();

    origvol->in_use--;
    newvol->building = false;
    pool->asyncjobs--;

    if (origpool) {
        origpool->asyncjobs--;
        virStoragePoolObjUnlock(origpool);
        origpool = NULL;
    }

    if (buildret < 0 ||
        (backend->refreshVol &&
         backend->refreshVol(obj->conn, pool, newvol) < 0)) {
        storageVolDeleteInternal(volobj, backend, pool, newvol, 0, false);
        newvol = NULL;
        goto cleanup;
    }

    /* Updating pool metadata ignoring the disk backend since
     * it updates the pool values
     */
    if (pool->def->type != VIR_STORAGE_POOL_DISK) {
        pool->def->allocation += newvol->target.allocation;
        pool->def->available -= newvol->target.allocation;
    }

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             volobj->name, pool->def->name);
    ret = volobj;
    volobj = NULL;
    newvol = NULL;

 cleanup:
    virObjectUnref(volobj);
    virStorageVolDefFree(newvol);
    VIR_FREE(shadowvol);
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
    virStorageBackendPtr backend;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM, -1);

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;

    if (virStorageVolDownloadEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (!backend->downloadVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool doesn't support volume download"));
        goto cleanup;
    }

    ret = backend->downloadVol(obj->conn, pool, vol, stream,
                               offset, length, flags);

 cleanup:
    virStoragePoolObjUnlock(pool);

    return ret;
}


/**
 * Frees opaque data.
 *
 * @opaque Data to be freed.
 */
static void
virStorageVolPoolRefreshDataFree(void *opaque)
{
    virStorageVolStreamInfoPtr cbdata = opaque;

    VIR_FREE(cbdata->pool_name);
    VIR_FREE(cbdata);
}

static int
virStorageBackendPloopRestoreDesc(char *path)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char *refresh_tool = NULL;
    char *desc = NULL;

    if (virAsprintf(&desc, "%s/DiskDescriptor.xml", path) < 0)
        return ret;

    if (virFileRemove(desc, 0, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("refresh ploop failed:"
                         " unable to delete DiskDescriptor.xml"));
        goto cleanup;
    }

    refresh_tool = virFindFileInPath("ploop");
    if (!refresh_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop, please install ploop tools"));
        goto cleanup;
    }

    cmd = virCommandNewArgList(refresh_tool, "restore-descriptor",
                               path, NULL);
    virCommandAddArgFormat(cmd, "%s/root.hds", path);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(refresh_tool);
    virCommandFree(cmd);
    VIR_FREE(desc);
    return ret;
}



/**
 * Thread to handle the pool refresh
 *
 * @st Pointer to stream being closed.
 * @opaque Domain's device information structure.
 */
static void
virStorageVolPoolRefreshThread(void *opaque)
{

    virStorageVolStreamInfoPtr cbdata = opaque;
    virStoragePoolObjPtr pool = NULL;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;

    storageDriverLock();
    if (cbdata->vol_path) {
        if (virStorageBackendPloopRestoreDesc(cbdata->vol_path) < 0)
            goto cleanup;
    }
    if (!(pool = virStoragePoolObjFindByName(&driver->pools,
                                             cbdata->pool_name)))
        goto cleanup;

    if (!(backend = virStorageBackendForType(pool->def->type)))
        goto cleanup;

    virStoragePoolObjClearVols(pool);
    if (backend->refreshPool(NULL, pool) < 0)
        VIR_DEBUG("Failed to refresh storage pool");

    event = virStoragePoolEventRefreshNew(pool->def->name,
                                          pool->def->uuid);

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->storageEventState, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    storageDriverUnlock();
    virStorageVolPoolRefreshDataFree(cbdata);
}

/**
 * Callback being called if a FDstream is closed. Will spin off a thread
 * to perform a pool refresh.
 *
 * @st Pointer to stream being closed.
 * @opaque Buffer to hold the pool name to be refreshed
 */
static void
virStorageVolFDStreamCloseCb(virStreamPtr st ATTRIBUTE_UNUSED,
                             void *opaque)
{
    virThread thread;

    if (virThreadCreate(&thread, false, virStorageVolPoolRefreshThread,
                        opaque) < 0) {
        /* Not much else can be done */
        VIR_ERROR(_("Failed to create thread to handle pool refresh"));
        goto error;
    }
    return; /* Thread will free opaque data */

 error:
    virStorageVolPoolRefreshDataFree(opaque);
}

static int
storageVolUpload(virStorageVolPtr obj,
                 virStreamPtr stream,
                 unsigned long long offset,
                 unsigned long long length,
                 unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    virStorageVolStreamInfoPtr cbdata = NULL;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM, -1);

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;

    if (virStorageVolUploadEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       vol->name);
        goto cleanup;
    }

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (!backend->uploadVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool doesn't support volume upload"));
        goto cleanup;
    }

    /* Use the callback routine in order to
     * refresh the pool after the volume upload stream closes. This way
     * we make sure the volume and pool data are refreshed without user
     * interaction and we can just lookup the backend in the callback
     * routine in order to call the refresh API.
     */
    if (VIR_ALLOC(cbdata) < 0 ||
        VIR_STRDUP(cbdata->pool_name, pool->def->name) < 0)
        goto cleanup;
    if (vol->type == VIR_STORAGE_VOL_PLOOP &&
        VIR_STRDUP(cbdata->vol_path, vol->target.path) < 0)
        goto cleanup;

    if ((ret = backend->uploadVol(obj->conn, pool, vol, stream,
                                  offset, length, flags)) < 0)
        goto cleanup;

    /* Add cleanup callback - call after uploadVol since the stream
     * is then fully set up
     */
    virFDStreamSetInternalCloseCb(stream,
                                  virStorageVolFDStreamCloseCb,
                                  cbdata, NULL);
    cbdata = NULL;

 cleanup:
    virStoragePoolObjUnlock(pool);
    if (cbdata)
        virStorageVolPoolRefreshDataFree(cbdata);

    return ret;
}

static int
storageVolResize(virStorageVolPtr obj,
                 unsigned long long capacity,
                 unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;
    unsigned long long abs_capacity, delta = 0;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE |
                  VIR_STORAGE_VOL_RESIZE_DELTA |
                  VIR_STORAGE_VOL_RESIZE_SHRINK, -1);

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;

    if (virStorageVolResizeEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       vol->name);
        goto cleanup;
    }

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_RESIZE_DELTA) {
        if (flags & VIR_STORAGE_VOL_RESIZE_SHRINK)
            abs_capacity = vol->target.capacity - MIN(capacity, vol->target.capacity);
        else
            abs_capacity = vol->target.capacity + capacity;
        flags &= ~VIR_STORAGE_VOL_RESIZE_DELTA;
    } else {
        abs_capacity = capacity;
    }

    if (abs_capacity < vol->target.allocation) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("can't shrink capacity below "
                         "existing allocation"));
        goto cleanup;
    }

    if (abs_capacity < vol->target.capacity &&
        !(flags & VIR_STORAGE_VOL_RESIZE_SHRINK)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Can't shrink capacity below current "
                         "capacity unless shrink flag explicitly specified"));
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE)
        delta = abs_capacity - vol->target.allocation;

    if (delta > pool->def->available) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Not enough space left in storage pool"));
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

    vol->target.capacity = abs_capacity;
    /* Only update the allocation and pool values if we actually did the
     * allocation; otherwise, this is akin to a create operation with a
     * capacity value different and potentially much larger than available
     */
    if (flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE) {
        vol->target.allocation = abs_capacity;
        pool->def->allocation += delta;
        pool->def->available -= delta;
    }

    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);

    return ret;
}


static int
storageVolWipePattern(virStorageVolPtr obj,
                      unsigned int algorithm,
                      unsigned int flags)
{
    virStorageBackendPtr backend;
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

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;


    if (virStorageVolWipePatternEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (vol->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       vol->name);
        goto cleanup;
    }

    if (vol->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       vol->name);
        goto cleanup;
    }

    if (!backend->wipeVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool doesn't support volume wiping"));
        goto cleanup;
    }

    if (backend->wipeVol(obj->conn, pool, vol, algorithm, flags) < 0)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);

    return ret;
}

static int
storageVolWipe(virStorageVolPtr obj,
               unsigned int flags)
{
    return storageVolWipePattern(obj, VIR_STORAGE_VOL_WIPE_ALG_ZERO, flags);
}


static int
storageVolGetInfoFlags(virStorageVolPtr obj,
                       virStorageVolInfoPtr info,
                       unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_GET_PHYSICAL, -1);

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return -1;

    if (virStorageVolGetInfoFlagsEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        goto cleanup;

    memset(info, 0, sizeof(*info));
    info->type = vol->type;
    info->capacity = vol->target.capacity;
    if (flags & VIR_STORAGE_VOL_GET_PHYSICAL)
        info->allocation = vol->target.physical;
    else
        info->allocation = vol->target.allocation;
    ret = 0;

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}


static int
storageVolGetInfo(virStorageVolPtr obj,
                  virStorageVolInfoPtr info)
{
    return storageVolGetInfoFlags(obj, info, 0);
}


static char *
storageVolGetXMLDesc(virStorageVolPtr obj,
                     unsigned int flags)
{
    virStoragePoolObjPtr pool;
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (!(vol = virStorageVolDefFromVol(obj, &pool, &backend)))
        return NULL;

    if (virStorageVolGetXMLDescEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        goto cleanup;

    ret = virStorageVolDefFormat(pool->def, vol);

 cleanup:
    virStoragePoolObjUnlock(pool);

    return ret;
}

static char *
storageVolGetPath(virStorageVolPtr obj)
{
    virStoragePoolObjPtr pool;
    virStorageVolDefPtr vol;
    char *ret = NULL;

    if (!(vol = virStorageVolDefFromVol(obj, &pool, NULL)))
        return NULL;

    if (virStorageVolGetPathEnsureACL(obj->conn, pool->def, vol) < 0)
        goto cleanup;

    ignore_value(VIR_STRDUP(ret, vol->target.path));

 cleanup:
    virStoragePoolObjUnlock(pool);
    return ret;
}

static int
storageConnectListAllStoragePools(virConnectPtr conn,
                                  virStoragePoolPtr **pools,
                                  unsigned int flags)
{
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL, -1);

    if (virConnectListAllStoragePoolsEnsureACL(conn) < 0)
        goto cleanup;

    storageDriverLock();
    ret = virStoragePoolObjListExport(conn, &driver->pools, pools,
                                      virConnectListAllStoragePoolsCheckACL,
                                      flags);
    storageDriverUnlock();

 cleanup:
    return ret;
}

static int
storageConnectStoragePoolEventRegisterAny(virConnectPtr conn,
                                          virStoragePoolPtr pool,
                                          int eventID,
                                          virConnectStoragePoolEventGenericCallback callback,
                                          void *opaque,
                                          virFreeCallback freecb)
{
    int callbackID = -1;

    if (virConnectStoragePoolEventRegisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virStoragePoolEventStateRegisterID(conn, driver->storageEventState,
                                           pool, eventID, callback,
                                           opaque, freecb, &callbackID) < 0)
        callbackID = -1;
 cleanup:
    return callbackID;
}

static int
storageConnectStoragePoolEventDeregisterAny(virConnectPtr conn,
                                            int callbackID)
{
    int ret = -1;

    if (virConnectStoragePoolEventDeregisterAnyEnsureACL(conn) < 0)
        goto cleanup;

    if (virObjectEventStateDeregisterID(conn,
                                        driver->storageEventState,
                                        callbackID) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}



static virStorageDriver storageDriver = {
    .name = "storage",
    .connectNumOfStoragePools = storageConnectNumOfStoragePools, /* 0.4.0 */
    .connectListStoragePools = storageConnectListStoragePools, /* 0.4.0 */
    .connectNumOfDefinedStoragePools = storageConnectNumOfDefinedStoragePools, /* 0.4.0 */
    .connectListDefinedStoragePools = storageConnectListDefinedStoragePools, /* 0.4.0 */
    .connectListAllStoragePools = storageConnectListAllStoragePools, /* 0.10.2 */
    .connectStoragePoolEventRegisterAny = storageConnectStoragePoolEventRegisterAny, /* 2.0.0 */
    .connectStoragePoolEventDeregisterAny = storageConnectStoragePoolEventDeregisterAny, /* 2.0.0 */
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
    .storageVolGetInfoFlags = storageVolGetInfoFlags, /* 3.0.0 */
    .storageVolGetXMLDesc = storageVolGetXMLDesc, /* 0.4.0 */
    .storageVolGetPath = storageVolGetPath, /* 0.4.0 */
    .storageVolResize = storageVolResize, /* 0.9.10 */

    .storagePoolIsActive = storagePoolIsActive, /* 0.7.3 */
    .storagePoolIsPersistent = storagePoolIsPersistent, /* 0.7.3 */
};


static virStateDriver stateDriver = {
    .name = "storage",
    .stateInitialize = storageStateInitialize,
    .stateAutoStart = storageStateAutoStart,
    .stateCleanup = storageStateCleanup,
    .stateReload = storageStateReload,
};

static int
storageRegisterFull(bool allbackends)
{
    if (virStorageBackendDriversRegister(allbackends) < 0)
        return -1;
    if (virSetSharedStorageDriver(&storageDriver) < 0)
        return -1;
    if (virRegisterStateDriver(&stateDriver) < 0)
        return -1;
    return 0;
}


int
storageRegister(void)
{
    return storageRegisterFull(false);
}


int
storageRegisterAll(void)
{
    return storageRegisterFull(true);
}


/* ----------- file handlers cooperating with storage driver --------------- */
static bool
virStorageFileIsInitialized(const virStorageSource *src)
{
    return src && src->drv;
}


static bool
virStorageFileSupportsBackingChainTraversal(virStorageSourcePtr src)
{
    int actualType;
    virStorageFileBackendPtr backend;

    if (!src)
        return false;
    actualType = virStorageSourceGetActualType(src);

    if (src->drv) {
        backend = src->drv->backend;
    } else {
        if (!(backend = virStorageFileBackendForTypeInternal(actualType,
                                                             src->protocol,
                                                             false)))
            return false;
    }

    return backend->storageFileGetUniqueIdentifier &&
           backend->storageFileReadHeader &&
           backend->storageFileAccess;
}


/**
 * virStorageFileSupportsSecurityDriver:
 *
 * @src: a storage file structure
 *
 * Check if a storage file supports operations needed by the security
 * driver to perform labelling
 */
bool
virStorageFileSupportsSecurityDriver(const virStorageSource *src)
{
    int actualType;
    virStorageFileBackendPtr backend;

    if (!src)
        return false;
    actualType = virStorageSourceGetActualType(src);

    if (src->drv) {
        backend = src->drv->backend;
    } else {
        if (!(backend = virStorageFileBackendForTypeInternal(actualType,
                                                             src->protocol,
                                                             false)))
            return false;
    }

    return !!backend->storageFileChown;
}


void
virStorageFileDeinit(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src))
        return;

    if (src->drv->backend &&
        src->drv->backend->backendDeinit)
        src->drv->backend->backendDeinit(src);

    VIR_FREE(src->drv);
}


/**
 * virStorageFileInitAs:
 *
 * @src: storage source definition
 * @uid: uid used to access the file, or -1 for current uid
 * @gid: gid used to access the file, or -1 for current gid
 *
 * Initialize a storage source to be used with storage driver. Use the provided
 * uid and gid if possible for the operations.
 *
 * Returns 0 if the storage file was successfully initialized, -1 if the
 * initialization failed. Libvirt error is reported.
 */
int
virStorageFileInitAs(virStorageSourcePtr src,
                     uid_t uid, gid_t gid)
{
    int actualType = virStorageSourceGetActualType(src);
    if (VIR_ALLOC(src->drv) < 0)
        return -1;

    if (uid == (uid_t) -1)
        src->drv->uid = geteuid();
    else
        src->drv->uid = uid;

    if (gid == (gid_t) -1)
        src->drv->gid = getegid();
    else
        src->drv->gid = gid;

    if (!(src->drv->backend = virStorageFileBackendForType(actualType,
                                                           src->protocol)))
        goto error;

    if (src->drv->backend->backendInit &&
        src->drv->backend->backendInit(src) < 0)
        goto error;

    return 0;

 error:
    VIR_FREE(src->drv);
    return -1;
}


/**
 * virStorageFileInit:
 *
 * See virStorageFileInitAs. The file is initialized to be accessed by the
 * current user.
 */
int
virStorageFileInit(virStorageSourcePtr src)
{
    return virStorageFileInitAs(src, -1, -1);
}


/**
 * virStorageFileCreate: Creates an empty storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileCreate(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileCreate) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileCreate(src);

    VIR_DEBUG("created storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileUnlink: Unlink storage file via storage driver
 *
 * @src: file structure pointing to the file
 *
 * Unlinks the file described by the @file structure.
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
 */
int
virStorageFileUnlink(virStorageSourcePtr src)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileUnlink) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileUnlink(src);

    VIR_DEBUG("unlinked storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileStat: returns stat struct of a file via storage driver
 *
 * @src: file structure pointing to the file
 * @stat: stat structure to return data
 *
 * Returns 0 on success, -2 if the function isn't supported by the backend,
 * -1 on other failure. Errno is set in case of failure.
*/
int
virStorageFileStat(virStorageSourcePtr src,
                   struct stat *st)
{
    int ret;

    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileStat) {
        errno = ENOSYS;
        return -2;
    }

    ret = src->drv->backend->storageFileStat(src, st);

    VIR_DEBUG("stat of storage file %p: ret=%d, errno=%d",
              src, ret, errno);

    return ret;
}


/**
 * virStorageFileReadHeader: read the beginning bytes of a file into a buffer
 *
 * @src: file structure pointing to the file
 * @max_len: maximum number of bytes read from the storage file
 * @buf: buffer to read the data into. buffer shall be freed by caller)
 *
 * Returns the count of bytes read on success and -1 on failure, -2 if the
 * function isn't supported by the backend.
 * Libvirt error is reported on failure.
 */
ssize_t
virStorageFileReadHeader(virStorageSourcePtr src,
                         ssize_t max_len,
                         char **buf)
{
    ssize_t ret;

    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return -1;
    }

    if (!src->drv->backend->storageFileReadHeader) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("storage file header reading is not supported for "
                         "storage type %s (protocol: %s)"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return -2;
    }

    ret = src->drv->backend->storageFileReadHeader(src, max_len, buf);

    VIR_DEBUG("read of storage header %p: ret=%zd", src, ret);

    return ret;
}


/*
 * virStorageFileGetUniqueIdentifier: Get a unique string describing the volume
 *
 * @src: file structure pointing to the file
 *
 * Returns a string uniquely describing a single volume (canonical path).
 * The string shall not be freed and is valid until the storage file is
 * deinitialized. Returns NULL on error and sets a libvirt error code */
const char *
virStorageFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    if (!virStorageFileIsInitialized(src)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage file backend not initialized"));
        return NULL;
    }

    if (!src->drv->backend->storageFileGetUniqueIdentifier) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unique storage file identifier not implemented for "
                          "storage type %s (protocol: %s)'"),
                       virStorageTypeToString(src->type),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    return src->drv->backend->storageFileGetUniqueIdentifier(src);
}


/**
 * virStorageFileAccess: Check accessibility of a storage file
 *
 * @src: storage file to check access permissions
 * @mode: accessibility check options (see man 2 access)
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileAccess(virStorageSourcePtr src,
                     int mode)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileAccess) {
        errno = ENOSYS;
        return -2;
    }

    return src->drv->backend->storageFileAccess(src, mode);
}


/**
 * virStorageFileChown: Change owner of a storage file
 *
 * @src: storage file to change owner of
 * @uid: new owner id
 * @gid: new group id
 *
 * Returns 0 on success, -1 on error and sets errno. No libvirt
 * error is reported. Returns -2 if the operation isn't supported
 * by libvirt storage backend.
 */
int
virStorageFileChown(const virStorageSource *src,
                    uid_t uid,
                    gid_t gid)
{
    if (!virStorageFileIsInitialized(src) ||
        !src->drv->backend->storageFileChown) {
        errno = ENOSYS;
        return -2;
    }

    VIR_DEBUG("chown of storage file %p to %u:%u",
              src, (unsigned int)uid, (unsigned int)gid);

    return src->drv->backend->storageFileChown(src, uid, gid);
}


/* Recursive workhorse for virStorageFileGetMetadata.  */
static int
virStorageFileGetMetadataRecurse(virStorageSourcePtr src,
                                 virStorageSourcePtr parent,
                                 uid_t uid, gid_t gid,
                                 bool allow_probe,
                                 bool report_broken,
                                 virHashTablePtr cycle)
{
    int ret = -1;
    const char *uniqueName;
    char *buf = NULL;
    ssize_t headerLen;
    virStorageSourcePtr backingStore = NULL;
    int backingFormat;

    VIR_DEBUG("path=%s format=%d uid=%u gid=%u probe=%d",
              src->path, src->format,
              (unsigned int)uid, (unsigned int)gid, allow_probe);

    /* exit if we can't load information about the current image */
    if (!virStorageFileSupportsBackingChainTraversal(src))
        return 0;

    if (virStorageFileInitAs(src, uid, gid) < 0)
        return -1;

    if (virStorageFileAccess(src, F_OK) < 0) {
        if (src == parent) {
            virReportSystemError(errno,
                                 _("Cannot access storage file '%s' "
                                   "(as uid:%u, gid:%u)"),
                                 src->path, (unsigned int)uid,
                                 (unsigned int)gid);
        } else {
            virReportSystemError(errno,
                                 _("Cannot access backing file '%s' "
                                   "of storage file '%s' (as uid:%u, gid:%u)"),
                                 src->path, parent->path,
                                 (unsigned int)uid, (unsigned int)gid);
        }

        goto cleanup;
    }

    if (!(uniqueName = virStorageFileGetUniqueIdentifier(src)))
        goto cleanup;

    if (virHashLookup(cycle, uniqueName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("backing store for %s (%s) is self-referential"),
                       src->path, uniqueName);
        goto cleanup;
    }

    if (virHashAddEntry(cycle, uniqueName, (void *)1) < 0)
        goto cleanup;

    if ((headerLen = virStorageFileReadHeader(src, VIR_STORAGE_MAX_HEADER,
                                              &buf)) < 0)
        goto cleanup;

    if (virStorageFileGetMetadataInternal(src, buf, headerLen,
                                          &backingFormat) < 0)
        goto cleanup;

    /* check whether we need to go deeper */
    if (!src->backingStoreRaw) {
        ret = 0;
        goto cleanup;
    }

    if (!(backingStore = virStorageSourceNewFromBacking(src)))
        goto cleanup;

    if (backingFormat == VIR_STORAGE_FILE_AUTO && !allow_probe)
        backingStore->format = VIR_STORAGE_FILE_RAW;
    else if (backingFormat == VIR_STORAGE_FILE_AUTO_SAFE)
        backingStore->format = VIR_STORAGE_FILE_AUTO;
    else
        backingStore->format = backingFormat;

    if ((ret = virStorageFileGetMetadataRecurse(backingStore, parent,
                                                uid, gid,
                                                allow_probe, report_broken,
                                                cycle)) < 0) {
        if (report_broken)
            goto cleanup;

        /* if we fail somewhere midway, just accept and return a
         * broken chain */
        ret = 0;
        goto cleanup;
    }

    src->backingStore = backingStore;
    backingStore = NULL;
    ret = 0;

 cleanup:
    VIR_FREE(buf);
    virStorageFileDeinit(src);
    virStorageSourceFree(backingStore);
    return ret;
}


/**
 * virStorageFileGetMetadata:
 *
 * Extract metadata about the storage volume with the specified
 * image format. If image format is VIR_STORAGE_FILE_AUTO, it
 * will probe to automatically identify the format.  Recurses through
 * the entire chain.
 *
 * Open files using UID and GID (or pass -1 for the current user/group).
 * Treat any backing files without explicit type as raw, unless ALLOW_PROBE.
 *
 * Callers are advised never to use VIR_STORAGE_FILE_AUTO as a
 * format, since a malicious guest can turn a raw file into any
 * other non-raw format at will.
 *
 * If @report_broken is true, the whole function fails with a possibly sane
 * error instead of just returning a broken chain.
 *
 * Caller MUST free result after use via virStorageSourceFree.
 */
int
virStorageFileGetMetadata(virStorageSourcePtr src,
                          uid_t uid, gid_t gid,
                          bool allow_probe,
                          bool report_broken)
{
    VIR_DEBUG("path=%s format=%d uid=%u gid=%u probe=%d, report_broken=%d",
              src->path, src->format, (unsigned int)uid, (unsigned int)gid,
              allow_probe, report_broken);

    virHashTablePtr cycle = NULL;
    int ret = -1;

    if (!(cycle = virHashCreate(5, NULL)))
        return -1;

    if (src->format <= VIR_STORAGE_FILE_NONE)
        src->format = allow_probe ?
            VIR_STORAGE_FILE_AUTO : VIR_STORAGE_FILE_RAW;

    ret = virStorageFileGetMetadataRecurse(src, src, uid, gid,
                                           allow_probe, report_broken, cycle);

    virHashFree(cycle);
    return ret;
}


static int
virStorageAddISCSIPoolSourceHost(virDomainDiskDefPtr def,
                                 virStoragePoolDefPtr pooldef)
{
    int ret = -1;
    char **tokens = NULL;

    /* Only support one host */
    if (pooldef->source.nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    /* iscsi pool only supports one host */
    def->src->nhosts = 1;

    if (VIR_ALLOC_N(def->src->hosts, def->src->nhosts) < 0)
        goto cleanup;

    if (VIR_STRDUP(def->src->hosts[0].name, pooldef->source.hosts[0].name) < 0)
        goto cleanup;

    if (virAsprintf(&def->src->hosts[0].port, "%d",
                    pooldef->source.hosts[0].port ?
                    pooldef->source.hosts[0].port :
                    3260) < 0)
        goto cleanup;

    /* iscsi volume has name like "unit:0:0:1" */
    if (!(tokens = virStringSplit(def->src->srcpool->volume, ":", 0)))
        goto cleanup;

    if (virStringListLength((const char * const *)tokens) != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected iscsi volume name '%s'"),
                       def->src->srcpool->volume);
        goto cleanup;
    }

    /* iscsi pool has only one source device path */
    if (virAsprintf(&def->src->path, "%s/%s",
                    pooldef->source.devices[0].path,
                    tokens[3]) < 0)
        goto cleanup;

    /* Storage pool have not supported these 2 attributes yet,
     * use the defaults.
     */
    def->src->hosts[0].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    def->src->hosts[0].socket = NULL;

    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

    ret = 0;

 cleanup:
    virStringListFree(tokens);
    return ret;
}


static int
virStorageTranslateDiskSourcePoolAuth(virDomainDiskDefPtr def,
                                      virStoragePoolSourcePtr source)
{
    int ret = -1;

    /* Only necessary when authentication set */
    if (!source->auth) {
        ret = 0;
        goto cleanup;
    }
    def->src->auth = virStorageAuthDefCopy(source->auth);
    if (!def->src->auth)
        goto cleanup;
    /* A <disk> doesn't use <auth type='%s', so clear that out for the disk */
    def->src->auth->authType = VIR_STORAGE_AUTH_TYPE_NONE;
    ret = 0;

 cleanup:
    return ret;
}


int
virStorageTranslateDiskSourcePool(virConnectPtr conn,
                                  virDomainDiskDefPtr def)
{
    virStoragePoolDefPtr pooldef = NULL;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    char *poolxml = NULL;
    virStorageVolInfo info;
    int ret = -1;

    if (def->src->type != VIR_STORAGE_TYPE_VOLUME)
        return 0;

    if (!def->src->srcpool)
        return 0;

    if (!(pool = virStoragePoolLookupByName(conn, def->src->srcpool->pool)))
        return -1;

    if (virStoragePoolIsActive(pool) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("storage pool '%s' containing volume '%s' "
                         "is not active"),
                       def->src->srcpool->pool, def->src->srcpool->volume);
        goto cleanup;
    }

    if (!(vol = virStorageVolLookupByName(pool, def->src->srcpool->volume)))
        goto cleanup;

    if (virStorageVolGetInfo(vol, &info) < 0)
        goto cleanup;

    if (!(poolxml = virStoragePoolGetXMLDesc(pool, 0)))
        goto cleanup;

    if (!(pooldef = virStoragePoolDefParseString(poolxml)))
        goto cleanup;

    def->src->srcpool->pooltype = pooldef->type;
    def->src->srcpool->voltype = info.type;

    if (def->src->srcpool->mode && pooldef->type != VIR_STORAGE_POOL_ISCSI) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("disk source mode is only valid when "
                         "storage pool is of iscsi type"));
        goto cleanup;
    }

    VIR_FREE(def->src->path);
    virStorageNetHostDefFree(def->src->nhosts, def->src->hosts);
    def->src->nhosts = 0;
    def->src->hosts = NULL;
    virStorageAuthDefFree(def->src->auth);
    def->src->auth = NULL;

    switch ((virStoragePoolType) pooldef->type) {
    case VIR_STORAGE_POOL_DIR:
    case VIR_STORAGE_POOL_FS:
    case VIR_STORAGE_POOL_NETFS:
    case VIR_STORAGE_POOL_LOGICAL:
    case VIR_STORAGE_POOL_DISK:
    case VIR_STORAGE_POOL_SCSI:
    case VIR_STORAGE_POOL_ZFS:
    case VIR_STORAGE_POOL_VSTORAGE:
        if (!(def->src->path = virStorageVolGetPath(vol)))
            goto cleanup;

        if (def->startupPolicy && info.type != VIR_STORAGE_VOL_FILE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'startupPolicy' is only valid for "
                             "'file' type volume"));
            goto cleanup;
        }


        switch (info.type) {
        case VIR_STORAGE_VOL_FILE:
            def->src->srcpool->actualtype = VIR_STORAGE_TYPE_FILE;
            break;

        case VIR_STORAGE_VOL_DIR:
            def->src->srcpool->actualtype = VIR_STORAGE_TYPE_DIR;
            break;

        case VIR_STORAGE_VOL_BLOCK:
            def->src->srcpool->actualtype = VIR_STORAGE_TYPE_BLOCK;
            break;

        case VIR_STORAGE_VOL_PLOOP:
            def->src->srcpool->actualtype = VIR_STORAGE_TYPE_FILE;
            break;

        case VIR_STORAGE_VOL_NETWORK:
        case VIR_STORAGE_VOL_NETDIR:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected storage volume type '%s' "
                             "for storage pool type '%s'"),
                           virStorageVolTypeToString(info.type),
                           virStoragePoolTypeToString(pooldef->type));
            goto cleanup;
        }

        break;

    case VIR_STORAGE_POOL_ISCSI:
        if (def->startupPolicy) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'startupPolicy' is only valid for "
                             "'file' type volume"));
            goto cleanup;
        }

       switch (def->src->srcpool->mode) {
       case VIR_STORAGE_SOURCE_POOL_MODE_DEFAULT:
       case VIR_STORAGE_SOURCE_POOL_MODE_LAST:
           def->src->srcpool->mode = VIR_STORAGE_SOURCE_POOL_MODE_HOST;
           ATTRIBUTE_FALLTHROUGH;
       case VIR_STORAGE_SOURCE_POOL_MODE_HOST:
           def->src->srcpool->actualtype = VIR_STORAGE_TYPE_BLOCK;
           if (!(def->src->path = virStorageVolGetPath(vol)))
               goto cleanup;
           break;

       case VIR_STORAGE_SOURCE_POOL_MODE_DIRECT:
           def->src->srcpool->actualtype = VIR_STORAGE_TYPE_NETWORK;
           def->src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

           if (virStorageTranslateDiskSourcePoolAuth(def,
                                                     &pooldef->source) < 0)
               goto cleanup;

           /* Source pool may not fill in the secrettype field,
            * so we need to do so here
            */
           if (def->src->auth && !def->src->auth->secrettype) {
               const char *secrettype =
                   virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_ISCSI);
               if (VIR_STRDUP(def->src->auth->secrettype, secrettype) < 0)
                   goto cleanup;
           }

           if (virStorageAddISCSIPoolSourceHost(def, pooldef) < 0)
               goto cleanup;
           break;
       }
       break;

    case VIR_STORAGE_POOL_MPATH:
    case VIR_STORAGE_POOL_RBD:
    case VIR_STORAGE_POOL_SHEEPDOG:
    case VIR_STORAGE_POOL_GLUSTER:
    case VIR_STORAGE_POOL_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("using '%s' pools for backing 'volume' disks "
                         "isn't yet supported"),
                       virStoragePoolTypeToString(pooldef->type));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(pool);
    virObjectUnref(vol);
    VIR_FREE(poolxml);
    virStoragePoolDefFree(pooldef);
    return ret;
}


/*
 * virStoragePoolObjFindPoolByUUID
 * @uuid: The uuid to lookup
 *
 * Using the passed @uuid, search the driver pools for a matching uuid.
 * If found, then lock the pool
 *
 * Returns NULL if pool is not found or a locked pool object pointer
 */
virStoragePoolObjPtr
virStoragePoolObjFindPoolByUUID(const unsigned char *uuid)
{
    virStoragePoolObjPtr pool;

    storageDriverLock();
    pool = virStoragePoolObjFindByUUID(&driver->pools, uuid);
    storageDriverUnlock();
    return pool;
}


/*
 * virStoragePoolObjBuildTempFilePath
 * @pool: pool object pointer
 * @vol: volume definition
 *
 * Generate a name for a temporary file using the driver stateDir
 * as a path, the pool name, and the volume name to be used as input
 * for a mkostemp
 *
 * Returns a string pointer on success, NULL on failure
 */
char *
virStoragePoolObjBuildTempFilePath(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol)

{
    char *tmp = NULL;

    ignore_value(virAsprintf(&tmp, "%s/%s.%s.secret.XXXXXX",
                             driver->stateDir, pool->def->name, vol->name));
    return tmp;
}
