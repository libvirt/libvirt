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
 */

#include <config.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

#if HAVE_PWD_H
# include <pwd.h>
#endif

#include "virerror.h"
#include "datatypes.h"
#include "driver.h"
#include "storage_driver.h"
#include "storage_capabilities.h"
#include "storage_conf.h"
#include "storage_event.h"
#include "viralloc.h"
#include "storage_backend.h"
#include "virlog.h"
#include "virfile.h"
#include "virfdstream.h"
#include "virpidfile.h"
#include "configmake.h"
#include "virsecret.h"
#include "virstring.h"
#include "viraccessapicheck.h"
//#include "dirname.h"
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


static void
storagePoolRefreshFailCleanup(virStorageBackendPtr backend,
                              virStoragePoolObjPtr obj,
                              const char *stateFile)
{
    virErrorPtr orig_err = virSaveLastError();

    virStoragePoolObjClearVols(obj);

    if (stateFile)
        unlink(stateFile);
    if (backend->stopPool)
        backend->stopPool(obj);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
}


static int
storagePoolRefreshImpl(virStorageBackendPtr backend,
                       virStoragePoolObjPtr obj,
                       const char *stateFile)
{
    virStoragePoolObjClearVols(obj);
    if (backend->refreshPool(obj) < 0) {
        storagePoolRefreshFailCleanup(backend, obj, stateFile);
        return -1;
    }

    return 0;
}


/**
 * virStoragePoolUpdateInactive:
 * @obj: pool object
 *
 * This function is supposed to be called after a pool becomes inactive. The
 * function switches to the new config object for persistent pools. Inactive
 * pools are removed.
 */
static void
virStoragePoolUpdateInactive(virStoragePoolObjPtr obj)
{
    if (!virStoragePoolObjGetConfigFile(obj)) {
        virStoragePoolObjRemove(driver->pools, obj);
    } else if (virStoragePoolObjGetNewDef(obj)) {
        virStoragePoolObjDefUseNewDef(obj);
    }
}


static void
storagePoolUpdateStateCallback(virStoragePoolObjPtr obj,
                               const void *opaque ATTRIBUTE_UNUSED)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(obj);
    bool active = false;
    virStorageBackendPtr backend;
    VIR_AUTOFREE(char *) stateFile = NULL;

    if ((backend = virStorageBackendForType(def->type)) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing backend %d"), def->type);
        return;
    }

    if (!(stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml")))
        return;

    /* Backends which do not support 'checkPool' are considered
     * inactive by default. */
    if (backend->checkPool &&
        backend->checkPool(obj, &active) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to initialize storage pool '%s': %s"),
                       def->name, virGetLastErrorMessage());
        unlink(stateFile);
        active = false;
    }

    /* We can pass NULL as connection, most backends do not use
     * it anyway, but if they do and fail, we want to log error and
     * continue with other pools.
     */
    if (active &&
        storagePoolRefreshImpl(backend, obj, stateFile) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to restart storage pool '%s': %s"),
                       def->name, virGetLastErrorMessage());
        active = false;
    }

    virStoragePoolObjSetActive(obj, active);

    if (!virStoragePoolObjIsActive(obj))
        virStoragePoolUpdateInactive(obj);

    return;
}


static void
storagePoolUpdateAllState(void)
{
    virStoragePoolObjListForEach(driver->pools,
                                 storagePoolUpdateStateCallback,
                                 NULL);
}


static void
storageDriverAutostartCallback(virStoragePoolObjPtr obj,
                               const void *opaque ATTRIBUTE_UNUSED)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(obj);
    virStorageBackendPtr backend;
    bool started = false;

    if (!(backend = virStorageBackendForType(def->type)))
        return;

    if (virStoragePoolObjIsAutostart(obj) &&
        !virStoragePoolObjIsActive(obj)) {
        if (backend->startPool &&
            backend->startPool(obj) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to autostart storage pool '%s': %s"),
                           def->name, virGetLastErrorMessage());
            return;
        }
        started = true;
    }

    if (started) {
        VIR_AUTOFREE(char *) stateFile = NULL;

        stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml");
        if (!stateFile ||
            virStoragePoolSaveState(stateFile, def) < 0 ||
            storagePoolRefreshImpl(backend, obj, stateFile) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to autostart storage pool '%s': %s"),
                           def->name, virGetLastErrorMessage());
        } else {
            virStoragePoolObjSetActive(obj, true);
        }
    }
}


static void
storageDriverAutostart(void)
{
    virStoragePoolObjListForEach(driver->pools,
                                 storageDriverAutostartCallback,
                                 NULL);
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
    VIR_AUTOFREE(char *) configdir = NULL;
    VIR_AUTOFREE(char *) rundir = NULL;

    if (VIR_ALLOC(driver) < 0)
        return VIR_DRV_STATE_INIT_ERROR;

    driver->lockFD = -1;
    if (virMutexInit(&driver->lock) < 0) {
        VIR_FREE(driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }
    storageDriverLock();

    if (!(driver->pools = virStoragePoolObjListNew()))
        goto error;

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

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver",
                           true, getpid())) < 0)
        goto error;

    if (virStoragePoolObjLoadAllState(driver->pools,
                                      driver->stateDir) < 0)
        goto error;

    if (virStoragePoolObjLoadAllConfigs(driver->pools,
                                        driver->configDir,
                                        driver->autostartDir) < 0)
        goto error;

    storagePoolUpdateAllState();

    storageDriverAutostart();

    driver->storageEventState = virObjectEventStateNew();

    /* Only one load of storage driver plus backends exists. Unlike
     * domains where new binaries could change the capabilities. A
     * new/changed backend requires a reinitialization. */
    if (!(driver->caps = virStorageBackendGetCapabilities()))
        goto error;

    storageDriverUnlock();

    return VIR_DRV_STATE_INIT_COMPLETE;

 error:
    storageDriverUnlock();
    storageStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;
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
    virStoragePoolObjLoadAllState(driver->pools,
                                  driver->stateDir);
    virStoragePoolObjLoadAllConfigs(driver->pools,
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

    virObjectUnref(driver->caps);
    virObjectUnref(driver->storageEventState);

    /* free inactive pools */
    virObjectUnref(driver->pools);

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver",
                          driver->lockFD);

    VIR_FREE(driver->configDir);
    VIR_FREE(driver->autostartDir);
    VIR_FREE(driver->stateDir);
    storageDriverUnlock();
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);

    return 0;
}

static virDrvOpenStatus
storageConnectOpen(virConnectPtr conn,
                   virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                   virConfPtr conf ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("storage state driver is not active"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (driver->privileged) {
        if (STRNEQ(conn->uri->path, "/system")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected storage URI path '%s', try storage:///system"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else {
        if (STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected storage URI path '%s', try storage:///session"),
                           conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (virConnectOpenEnsureACL(conn) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int storageConnectClose(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}


static int storageConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Trivially secure, since always inside the daemon */
    return 1;
}


static int storageConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Not encrypted, but remote driver takes care of that */
    return 0;
}


static int storageConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}


static virStoragePoolObjPtr
storagePoolObjFindByUUID(const unsigned char *uuid,
                         const char *name)
{
    virStoragePoolObjPtr obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!(obj = virStoragePoolObjFindByUUID(driver->pools, uuid))) {
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

    return obj;
}


static virStoragePoolObjPtr
virStoragePoolObjFromStoragePool(virStoragePoolPtr pool)
{
    return storagePoolObjFindByUUID(pool->uuid, pool->name);
}


static virStoragePoolObjPtr
storagePoolObjFindByName(const char *name)
{
    virStoragePoolObjPtr obj;

    if (!(obj = virStoragePoolObjFindByName(driver->pools, name)))
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"), name);
    return obj;
}


static virStoragePoolPtr
storagePoolLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;

    obj = storagePoolObjFindByUUID(uuid, NULL);
    if (!obj)
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolLookupByUUIDEnsureACL(conn, def) < 0)
        goto cleanup;

    pool = virGetStoragePool(conn, def->name, def->uuid, NULL, NULL);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return pool;
}

static virStoragePoolPtr
storagePoolLookupByName(virConnectPtr conn,
                        const char *name)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;

    if (!(obj = storagePoolObjFindByName(name)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolLookupByNameEnsureACL(conn, def) < 0)
        goto cleanup;

    pool = virGetStoragePool(conn, def->name, def->uuid, NULL, NULL);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return pool;
}

static virStoragePoolPtr
storagePoolLookupByVolume(virStorageVolPtr vol)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;

    if (!(obj = storagePoolObjFindByName(vol->pool)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolLookupByVolumeEnsureACL(vol->conn, def) < 0)
        goto cleanup;

    pool = virGetStoragePool(vol->conn, def->name, def->uuid, NULL, NULL);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return pool;
}

static int
storageConnectNumOfStoragePools(virConnectPtr conn)
{
    if (virConnectNumOfStoragePoolsEnsureACL(conn) < 0)
        return -1;

    return virStoragePoolObjNumOfStoragePools(driver->pools, conn, true,
                                              virConnectNumOfStoragePoolsCheckACL);
}


static int
storageConnectListStoragePools(virConnectPtr conn,
                               char **const names,
                               int maxnames)
{
    if (virConnectListStoragePoolsEnsureACL(conn) < 0)
        return -1;

    return virStoragePoolObjGetNames(driver->pools, conn, true,
                                     virConnectListStoragePoolsCheckACL,
                                     names, maxnames);
}


static char *
storageConnectGetCapabilities(virConnectPtr conn)
{

    if (virConnectGetCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    return virCapabilitiesFormatXML(driver->caps);
}


static int
storageConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    if (virConnectNumOfDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    return virStoragePoolObjNumOfStoragePools(driver->pools, conn, false,
                                               virConnectNumOfDefinedStoragePoolsCheckACL);
}


static int
storageConnectListDefinedStoragePools(virConnectPtr conn,
                                      char **const names,
                                      int maxnames)
{
    if (virConnectListDefinedStoragePoolsEnsureACL(conn) < 0)
        return -1;

    return virStoragePoolObjGetNames(driver->pools, conn, false,
                                     virConnectListDefinedStoragePoolsCheckACL,
                                     names, maxnames);
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

    ret = backend->findPoolSources(srcSpec, flags);

 cleanup:
    return ret;
}


static char *
storageConnectGetStoragePoolCapabilities(virConnectPtr conn,
                                         unsigned int flags)
{
    virStoragePoolCapsPtr caps = NULL;
    char *ret;

    virCheckFlags(0, NULL);

    if (virConnectGetStoragePoolCapabilitiesEnsureACL(conn) < 0)
        return NULL;

    if (!(caps = virStoragePoolCapsNew(driver->caps)))
        return NULL;

    ret = virStoragePoolCapsFormat(caps);

    virObjectUnref(caps);
    return ret;
}


static int
storagePoolIsActive(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolIsActiveEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    ret = virStoragePoolObjIsActive(obj);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolIsPersistent(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolIsPersistentEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    ret = virStoragePoolObjGetConfigFile(obj) ? 1 : 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static virStoragePoolPtr
storagePoolCreateXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStoragePoolObjPtr obj = NULL;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    unsigned int build_flags = 0;
    VIR_AUTOPTR(virStoragePoolDef) newDef = NULL;
    VIR_AUTOFREE(char *) stateFile = NULL;

    virCheckFlags(VIR_STORAGE_POOL_CREATE_WITH_BUILD |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE, NULL);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, NULL);

    if (!(newDef = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virStoragePoolCreateXMLEnsureACL(conn, newDef) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(newDef->type)) == NULL)
        goto cleanup;

    if (!(obj = virStoragePoolObjListAdd(driver->pools, newDef, true)))
        goto cleanup;
    newDef = NULL;
    def = virStoragePoolObjGetDef(obj);

    if (backend->buildPool) {
        if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;
        else if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;

        if (build_flags ||
            (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD)) {
            if (backend->buildPool(obj, build_flags) < 0)
                goto error;
        }
    }

    if (backend->startPool &&
        backend->startPool(obj) < 0)
        goto error;

    stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml");

    if (!stateFile ||
        virStoragePoolSaveState(stateFile, def) < 0 ||
        storagePoolRefreshImpl(backend, obj, stateFile) < 0) {
        goto error;
    }

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);

    VIR_INFO("Creating storage pool '%s'", def->name);
    virStoragePoolObjSetActive(obj, true);

    pool = virGetStoragePool(conn, def->name, def->uuid, NULL, NULL);

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return pool;

 error:
    virStoragePoolObjRemove(driver->pools, obj);
    goto cleanup;
}

static virStoragePoolPtr
storagePoolDefineXML(virConnectPtr conn,
                     const char *xml,
                     unsigned int flags)
{
    virStoragePoolObjPtr obj = NULL;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;
    virObjectEventPtr event = NULL;
    VIR_AUTOPTR(virStoragePoolDef) newDef = NULL;

    virCheckFlags(0, NULL);

    if (!(newDef = virStoragePoolDefParseString(xml)))
        goto cleanup;

    if (virXMLCheckIllegalChars("name", newDef->name, "\n") < 0)
        goto cleanup;

    if (virStoragePoolDefineXMLEnsureACL(conn, newDef) < 0)
        goto cleanup;

    if (virStorageBackendForType(newDef->type) == NULL)
        goto cleanup;

    if (!(obj = virStoragePoolObjListAdd(driver->pools, newDef, false)))
        goto cleanup;
    newDef = virStoragePoolObjGetNewDef(obj);
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolObjSaveDef(driver, obj, newDef ? newDef : def) < 0) {
        virStoragePoolObjRemove(driver->pools, obj);
        newDef = NULL;
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(def->name, def->uuid,
                                            VIR_STORAGE_POOL_EVENT_DEFINED,
                                            0);

    VIR_INFO("Defining storage pool '%s'", def->name);
    pool = virGetStoragePool(conn, def->name, def->uuid, NULL, NULL);
    newDef = NULL;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return pool;
}

static int
storagePoolUndefine(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    const char *autostartLink;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(obj = storagePoolObjFindByUUID(pool->uuid, pool->name)))
        goto cleanup;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolUndefineEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if (virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is still active"),
                       def->name);
        goto cleanup;
    }

    if (virStoragePoolObjGetAsyncjobs(obj) > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       def->name);
        goto cleanup;
    }

    autostartLink = virStoragePoolObjGetAutostartLink(obj);
    if (virStoragePoolObjDeleteDef(obj) < 0)
        goto cleanup;

    if (autostartLink && unlink(autostartLink) < 0 &&
        errno != ENOENT && errno != ENOTDIR) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to delete autostart link '%s': %s"),
                  autostartLink, virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_UNDEFINED,
                                            0);

    VIR_INFO("Undefining storage pool '%s'", def->name);
    virStoragePoolObjRemove(driver->pools, obj);
    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storagePoolCreate(virStoragePoolPtr pool,
                  unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    int ret = -1;
    unsigned int build_flags = 0;
    VIR_AUTOFREE(char *) stateFile = NULL;

    virCheckFlags(VIR_STORAGE_POOL_CREATE_WITH_BUILD |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE, -1);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, -1);

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolCreateEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"),
                       def->name);
        goto cleanup;
    }

    if (backend->buildPool) {
        if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;
        else if (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE)
            build_flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;

        if (build_flags ||
            (flags & VIR_STORAGE_POOL_CREATE_WITH_BUILD)) {
            if (backend->buildPool(obj, build_flags) < 0)
                goto cleanup;
        }
    }

    VIR_INFO("Starting up storage pool '%s'", def->name);
    if (backend->startPool &&
        backend->startPool(obj) < 0)
        goto cleanup;

    stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml");

    if (!stateFile ||
        virStoragePoolSaveState(stateFile, def) < 0 ||
        storagePoolRefreshImpl(backend, obj, stateFile) < 0) {
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);

    virStoragePoolObjSetActive(obj, true);
    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storagePoolBuild(virStoragePoolPtr pool,
                 unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolBuildEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    if (virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"),
                       def->name);
        goto cleanup;
    }

    if (backend->buildPool &&
        backend->buildPool(obj, flags) < 0)
        goto cleanup;

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_CREATED,
                                            0);

    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolDestroy(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    int ret = -1;
    VIR_AUTOFREE(char *) stateFile = NULL;

    if (!(obj = storagePoolObjFindByUUID(pool->uuid, pool->name)))
        goto cleanup;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolDestroyEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    VIR_INFO("Destroying storage pool '%s'", def->name);

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    if (virStoragePoolObjGetAsyncjobs(obj) > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       def->name);
        goto cleanup;
    }

    if (!(stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml")))
        goto cleanup;

    unlink(stateFile);

    if (backend->stopPool &&
        backend->stopPool(obj) < 0)
        goto cleanup;

    virStoragePoolObjClearVols(obj);

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STOPPED,
                                            0);

    virStoragePoolObjSetActive(obj, false);

    virStoragePoolUpdateInactive(obj);

    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storagePoolDelete(virStoragePoolPtr pool,
                  unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;
    int ret = -1;
    VIR_AUTOFREE(char *) stateFile = NULL;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolDeleteEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    VIR_INFO("Deleting storage pool '%s'", def->name);

    if (virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is still active"),
                       def->name);
        goto cleanup;
    }

    if (virStoragePoolObjGetAsyncjobs(obj) > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       def->name);
        goto cleanup;
    }

    if (!(stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml")))
        goto cleanup;

    unlink(stateFile);

    if (!backend->deletePool) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("pool does not support pool deletion"));
        goto cleanup;
    }
    if (backend->deletePool(obj, flags) < 0)
        goto cleanup;

    event = virStoragePoolEventLifecycleNew(def->name,
                                            def->uuid,
                                            VIR_STORAGE_POOL_EVENT_DELETED,
                                            0);

    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolRefresh(virStoragePoolPtr pool,
                   unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    VIR_AUTOFREE(char *) stateFile = NULL;
    int ret = -1;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, -1);

    if (!(obj = storagePoolObjFindByUUID(pool->uuid, pool->name)))
        goto cleanup;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolRefreshEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    if (virStoragePoolObjGetAsyncjobs(obj) > 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pool '%s' has asynchronous jobs running."),
                       def->name);
        goto cleanup;
    }

    stateFile = virFileBuildPath(driver->stateDir, def->name, ".xml");
    if (storagePoolRefreshImpl(backend, obj, stateFile) < 0) {
        event = virStoragePoolEventLifecycleNew(def->name,
                                                def->uuid,
                                                VIR_STORAGE_POOL_EVENT_STOPPED,
                                                0);
        virStoragePoolObjSetActive(obj, false);

        virStoragePoolUpdateInactive(obj);

        goto cleanup;
    }

    event = virStoragePoolEventRefreshNew(def->name,
                                          def->uuid);
    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolGetInfo(virStoragePoolPtr pool,
                   virStoragePoolInfoPtr info)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolGetInfoEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if (virStorageBackendForType(def->type) == NULL)
        goto cleanup;

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (virStoragePoolObjIsActive(obj))
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = def->capacity;
    info->allocation = def->allocation;
    info->available = def->available;
    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static char *
storagePoolGetXMLDesc(virStoragePoolPtr pool,
                      unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolDefPtr newDef;
    virStoragePoolDefPtr curDef;
    char *ret = NULL;

    virCheckFlags(VIR_STORAGE_XML_INACTIVE, NULL);

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);
    newDef = virStoragePoolObjGetNewDef(obj);

    if (virStoragePoolGetXMLDescEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if ((flags & VIR_STORAGE_XML_INACTIVE) && newDef)
        curDef = newDef;
    else
        curDef = def;

    ret = virStoragePoolDefFormat(curDef);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storagePoolGetAutostart(virStoragePoolPtr pool,
                        int *autostart)
{
    virStoragePoolObjPtr obj;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;

    if (virStoragePoolGetAutostartEnsureACL(pool->conn,
                                            virStoragePoolObjGetDef(obj)) < 0)
        goto cleanup;

    *autostart = virStoragePoolObjIsAutostart(obj) ? 1 : 0;

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storagePoolSetAutostart(virStoragePoolPtr pool,
                        int autostart)
{
    virStoragePoolObjPtr obj;
    const char *configFile;
    const char *autostartLink;
    bool new_autostart;
    bool cur_autostart;
    int ret = -1;

    if (!(obj = storagePoolObjFindByUUID(pool->uuid, pool->name)))
        goto cleanup;

    if (virStoragePoolSetAutostartEnsureACL(pool->conn,
                                            virStoragePoolObjGetDef(obj)) < 0)
        goto cleanup;

    if (!(configFile = virStoragePoolObjGetConfigFile(obj))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("pool has no config file"));
        goto cleanup;
    }

    autostartLink = virStoragePoolObjGetAutostartLink(obj);

    new_autostart = (autostart != 0);
    cur_autostart = virStoragePoolObjIsAutostart(obj);
    if (cur_autostart != new_autostart) {
        if (new_autostart) {
            if (virFileMakePath(driver->autostartDir) < 0) {
                virReportSystemError(errno,
                                     _("cannot create autostart directory %s"),
                                     driver->autostartDir);
                goto cleanup;
            }

            if (symlink(configFile, autostartLink) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create symlink '%s' to '%s'"),
                                     autostartLink, configFile);
                goto cleanup;
            }
        } else {
            if (autostartLink && unlink(autostartLink) < 0 &&
                errno != ENOENT && errno != ENOTDIR) {
                virReportSystemError(errno,
                                     _("Failed to delete symlink '%s'"),
                                     autostartLink);
                goto cleanup;
            }
        }
        virStoragePoolObjSetAutostart(obj, new_autostart);
    }

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolNumOfVolumes(virStoragePoolPtr pool)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int ret = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolNumOfVolumesEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    ret = virStoragePoolObjNumOfVolumes(obj, pool->conn,
                                        virStoragePoolNumOfVolumesCheckACL);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storagePoolListVolumes(virStoragePoolPtr pool,
                       char **const names,
                       int maxnames)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int n = -1;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolListVolumesEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    n = virStoragePoolObjVolumeGetNames(obj, pool->conn,
                                        virStoragePoolListVolumesCheckACL,
                                        names, maxnames);
 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return n;
}


static int
storagePoolListAllVolumes(virStoragePoolPtr pool,
                          virStorageVolPtr **vols,
                          unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStoragePoolListAllVolumesEnsureACL(pool->conn, def) < 0)
        goto cleanup;

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    ret = virStoragePoolObjVolumeListExport(pool->conn, obj, vols,
                                            virStoragePoolListAllVolumesCheckACL);


 cleanup:
    virStoragePoolObjEndAPI(&obj);

    return ret;
}

static virStorageVolPtr
storageVolLookupByName(virStoragePoolPtr pool,
                       const char *name)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageVolDefPtr voldef;
    virStorageVolPtr vol = NULL;

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    voldef = virStorageVolDefFindByName(obj, name);

    if (!voldef) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       name);
        goto cleanup;
    }

    if (virStorageVolLookupByNameEnsureACL(pool->conn, def, voldef) < 0)
        goto cleanup;

    vol = virGetStorageVol(pool->conn, def->name, voldef->name,
                           voldef->key, NULL, NULL);

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return vol;
}


struct storageVolLookupData {
    const char *key;
    char *cleanpath;
    const char *path;
    virStorageVolDefPtr voldef;
};

static bool
storageVolLookupByKeyCallback(virStoragePoolObjPtr obj,
                              const void *opaque)
{
    struct storageVolLookupData *data = (struct storageVolLookupData *)opaque;

    if (virStoragePoolObjIsActive(obj))
        data->voldef = virStorageVolDefFindByKey(obj, data->key);

    return !!data->voldef;
}


static virStorageVolPtr
storageVolLookupByKey(virConnectPtr conn,
                      const char *key)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    struct storageVolLookupData data = {
        .key = key, .voldef = NULL };
    virStorageVolPtr vol = NULL;

    if ((obj = virStoragePoolObjListSearch(driver->pools,
                                           storageVolLookupByKeyCallback,
                                           &data)) && data.voldef) {
        def = virStoragePoolObjGetDef(obj);
        if (virStorageVolLookupByKeyEnsureACL(conn, def, data.voldef) == 0) {
            vol = virGetStorageVol(conn, def->name,
                                   data.voldef->name, data.voldef->key,
                                   NULL, NULL);
        }
        virStoragePoolObjEndAPI(&obj);
    }

    if (!vol)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching key %s"), key);

    return vol;
}


static bool
storageVolLookupByPathCallback(virStoragePoolObjPtr obj,
                               const void *opaque)
{
    struct storageVolLookupData *data = (struct storageVolLookupData *)opaque;
    virStoragePoolDefPtr def;
    VIR_AUTOFREE(char *) stable_path = NULL;

    if (!virStoragePoolObjIsActive(obj))
        return false;

    def = virStoragePoolObjGetDef(obj);

    switch ((virStoragePoolType)def->type) {
        case VIR_STORAGE_POOL_DIR:
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_NETFS:
        case VIR_STORAGE_POOL_LOGICAL:
        case VIR_STORAGE_POOL_DISK:
        case VIR_STORAGE_POOL_ISCSI:
        case VIR_STORAGE_POOL_ISCSI_DIRECT:
        case VIR_STORAGE_POOL_SCSI:
        case VIR_STORAGE_POOL_MPATH:
        case VIR_STORAGE_POOL_VSTORAGE:
            stable_path = virStorageBackendStablePath(obj, data->cleanpath,
                                                      false);
            break;

        case VIR_STORAGE_POOL_GLUSTER:
        case VIR_STORAGE_POOL_RBD:
        case VIR_STORAGE_POOL_SHEEPDOG:
        case VIR_STORAGE_POOL_ZFS:
        case VIR_STORAGE_POOL_LAST:
            ignore_value(VIR_STRDUP(stable_path, data->path));
            break;
    }

    /* Don't break the whole lookup process if it fails on
     * getting the stable path for some of the pools. */
    if (!stable_path) {
        VIR_WARN("Failed to get stable path for pool '%s'", def->name);
        return false;
    }

    data->voldef = virStorageVolDefFindByPath(obj, stable_path);

    return !!data->voldef;
}


static virStorageVolPtr
storageVolLookupByPath(virConnectPtr conn,
                       const char *path)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    struct storageVolLookupData data = {
        .path = path, .voldef = NULL };
    virStorageVolPtr vol = NULL;

    if (!(data.cleanpath = virFileSanitizePath(path)))
        return NULL;

    if ((obj = virStoragePoolObjListSearch(driver->pools,
                                           storageVolLookupByPathCallback,
                                           &data)) && data.voldef) {
        def = virStoragePoolObjGetDef(obj);

        if (virStorageVolLookupByPathEnsureACL(conn, def, data.voldef) == 0) {
            vol = virGetStorageVol(conn, def->name,
                                   data.voldef->name, data.voldef->key,
                                   NULL, NULL);
        }
        virStoragePoolObjEndAPI(&obj);
    }

    if (!vol) {
        if (STREQ(path, data.cleanpath)) {
            virReportError(VIR_ERR_NO_STORAGE_VOL,
                           _("no storage vol with matching path '%s'"), path);
        } else {
            virReportError(VIR_ERR_NO_STORAGE_VOL,
                           _("no storage vol with matching path '%s' (%s)"),
                           path, data.cleanpath);
        }
    }

    VIR_FREE(data.cleanpath);
    return vol;
}


static bool
storagePoolLookupByTargetPathCallback(virStoragePoolObjPtr obj,
                                      const void *opaque)
{
    const char *path = opaque;
    virStoragePoolDefPtr def;

    if (!virStoragePoolObjIsActive(obj))
        return false;

    def = virStoragePoolObjGetDef(obj);
    return STREQ(path, def->target.path);
}


virStoragePoolPtr
storagePoolLookupByTargetPath(virConnectPtr conn,
                              const char *path)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolPtr pool = NULL;
    VIR_AUTOFREE(char *) cleanpath = NULL;

    cleanpath = virFileSanitizePath(path);
    if (!cleanpath)
        return NULL;

    if ((obj = virStoragePoolObjListSearch(driver->pools,
                                           storagePoolLookupByTargetPathCallback,
                                           cleanpath))) {
        def = virStoragePoolObjGetDef(obj);
        if (virStoragePoolLookupByTargetPathEnsureACL(conn, def) < 0)
            return NULL;

        pool = virGetStoragePool(conn, def->name, def->uuid, NULL, NULL);
        virStoragePoolObjEndAPI(&obj);
    }

    if (!pool) {
        if (STREQ(path, cleanpath)) {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           _("no storage pool with matching target path '%s'"),
                           path);
        } else {
            virReportError(VIR_ERR_NO_STORAGE_POOL,
                           _("no storage pool with matching target path '%s' (%s)"),
                           path, cleanpath);
        }
    }

    return pool;
}


static int
storageVolDeleteInternal(virStorageBackendPtr backend,
                         virStoragePoolObjPtr obj,
                         virStorageVolDefPtr voldef,
                         unsigned int flags,
                         bool updateMeta)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(obj);
    int ret = -1;

    if (!backend->deleteVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support vol deletion"));

        goto cleanup;
    }

    if (backend->deleteVol(obj, voldef, flags) < 0)
        goto cleanup;

    /* The disk backend updated the pool data including removing the
     * voldef from the pool (for both the deleteVol and the createVol
     * failure path. */
    if (def->type == VIR_STORAGE_POOL_DISK) {
        ret = 0;
        goto cleanup;
    }

    /* Update pool metadata - don't update meta data from error paths
     * in this module since the allocation/available weren't adjusted yet.
     * Ignore the disk backend since it updates the pool values.
     */
    if (updateMeta) {
        def->allocation -= voldef->target.allocation;
        def->available += voldef->target.allocation;
    }

    virStoragePoolObjRemoveVol(obj, voldef);
    ret = 0;

 cleanup:
    return ret;
}


static virStorageVolDefPtr
virStorageVolDefFromVol(virStorageVolPtr vol,
                        virStoragePoolObjPtr *obj,
                        virStorageBackendPtr *backend)
{
    virStorageVolDefPtr voldef = NULL;
    virStoragePoolDefPtr def;

    if (!(*obj = storagePoolObjFindByName(vol->pool)))
        return NULL;
    def = virStoragePoolObjGetDef(*obj);

    if (!virStoragePoolObjIsActive(*obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"),
                       def->name);
        goto error;
    }

    if (!(voldef = virStorageVolDefFindByName(*obj, vol->name))) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vol->name);
        goto error;
    }

    if (backend) {
        if (!(*backend = virStorageBackendForType(def->type)))
            goto error;
    }

    return voldef;

 error:
    virStoragePoolObjEndAPI(obj);

    return NULL;
}


static int
storageVolDelete(virStorageVolPtr vol,
                 unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef = NULL;
    int ret = -1;

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;

    if (virStorageVolDeleteEnsureACL(vol->conn, virStoragePoolObjGetDef(obj),
                                     voldef) < 0)
        goto cleanup;

    if (voldef->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       voldef->name);
        goto cleanup;
    }

    if (voldef->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldef->name);
        goto cleanup;
    }

    if (storageVolDeleteInternal(backend, obj, voldef, flags, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static virStorageVolPtr
storageVolCreateXML(virStoragePoolPtr pool,
                    const char *xmldesc,
                    unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virStorageVolPtr vol = NULL, newvol = NULL;
    VIR_AUTOPTR(virStorageVolDef) voldef = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, NULL);

    if (!(obj = virStoragePoolObjFromStoragePool(pool)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    voldef = virStorageVolDefParseString(def, xmldesc,
                                         VIR_VOL_XML_PARSE_OPT_CAPACITY);
    if (voldef == NULL)
        goto cleanup;

    if (!voldef->target.capacity && !backend->buildVol) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("volume capacity required for this "
                               "storage pool"));
        goto cleanup;
    }

    if (virStorageVolCreateXMLEnsureACL(pool->conn, def, voldef) < 0)
        goto cleanup;

    if (virStorageVolDefFindByName(obj, voldef->name)) {
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

    /* Wipe any key the user may have suggested, as volume creation
     * will generate the canonical key.  */
    VIR_FREE(voldef->key);
    if (backend->createVol(obj, voldef) < 0)
        goto cleanup;

    if (!(newvol = virGetStorageVol(pool->conn, def->name, voldef->name,
                                    voldef->key, NULL, NULL)))
        goto cleanup;

    /* NB: Upon success voldef "owned" by storage pool for deletion purposes */
    if (virStoragePoolObjAddVol(obj, voldef) < 0)
        goto cleanup;

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
        virStoragePoolObjIncrAsyncjobs(obj);
        voldef->building = true;
        virObjectUnlock(obj);

        buildret = backend->buildVol(obj, buildvoldef, flags);

        VIR_FREE(buildvoldef);

        virObjectLock(obj);

        voldef->building = false;
        virStoragePoolObjDecrAsyncjobs(obj);

        if (buildret < 0) {
            /* buildVol handles deleting volume on failure */
            virStoragePoolObjRemoveVol(obj, voldef);
            voldef = NULL;
            goto cleanup;
        }

    }

    if (backend->refreshVol &&
        backend->refreshVol(obj, voldef) < 0) {
        storageVolDeleteInternal(backend, obj, voldef,
                                 0, false);
        voldef = NULL;
        goto cleanup;
    }

    /* Update pool metadata ignoring the disk backend since
     * it updates the pool values.
     */
    if (def->type != VIR_STORAGE_POOL_DISK) {
        def->allocation += voldef->target.allocation;
        def->available -= voldef->target.allocation;
    }

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             newvol->name, def->name);
    VIR_STEAL_PTR(vol, newvol);
    voldef = NULL;

 cleanup:
    virObjectUnref(newvol);
    virStoragePoolObjEndAPI(&obj);
    return vol;
}

static virStorageVolPtr
storageVolCreateXMLFrom(virStoragePoolPtr pool,
                        const char *xmldesc,
                        virStorageVolPtr volsrc,
                        unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr objsrc = NULL;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldefsrc = NULL;
    virStorageVolDefPtr shadowvol = NULL;
    virStorageVolPtr newvol = NULL;
    virStorageVolPtr vol = NULL;
    int buildret;
    VIR_AUTOPTR(virStorageVolDef) voldef = NULL;

    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  NULL);

    obj = virStoragePoolObjFindByUUID(driver->pools, pool->uuid);
    if (obj && STRNEQ(pool->name, volsrc->pool)) {
        virObjectUnlock(obj);
        objsrc = virStoragePoolObjFindByName(driver->pools, volsrc->pool);
        virObjectLock(obj);
    }
    if (!obj) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virUUIDFormat(pool->uuid, uuidstr);
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching uuid '%s' (%s)"),
                       uuidstr, pool->name);
        goto cleanup;
    }
    def = virStoragePoolObjGetDef(obj);

    if (STRNEQ(pool->name, volsrc->pool) && !objsrc) {
        virReportError(VIR_ERR_NO_STORAGE_POOL,
                       _("no storage pool with matching name '%s'"),
                       volsrc->pool);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(obj)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), def->name);
        goto cleanup;
    }

    if (objsrc && !virStoragePoolObjIsActive(objsrc)) {
        virStoragePoolDefPtr objsrcdef = virStoragePoolObjGetDef(objsrc);
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"),
                       objsrcdef->name);
        goto cleanup;
    }

    if ((backend = virStorageBackendForType(def->type)) == NULL)
        goto cleanup;

    voldefsrc = virStorageVolDefFindByName(objsrc ?
                                           objsrc : obj, volsrc->name);
    if (!voldefsrc) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       volsrc->name);
        goto cleanup;
    }

    voldef = virStorageVolDefParseString(def, xmldesc,
                                         VIR_VOL_XML_PARSE_NO_CAPACITY);
    if (voldef == NULL)
        goto cleanup;

    if (virStorageVolCreateXMLFromEnsureACL(pool->conn, def, voldef) < 0)
        goto cleanup;

    if (virStorageVolDefFindByName(obj, voldef->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("storage volume name '%s' already in use."),
                       voldef->name);
        goto cleanup;
    }

    /* Use the original volume's capacity in case the new capacity
     * is less than that, or it was omitted */
    if (voldef->target.capacity < voldefsrc->target.capacity)
        voldef->target.capacity = voldefsrc->target.capacity;

    /* If the allocation was not provided in the XML, then use capacity
     * as it's specifically documented "If omitted when creating a volume,
     * the  volume will be fully allocated at time of creation.". This
     * is especially important for logical volume creation. */
    if (!voldef->target.has_allocation)
        voldef->target.allocation = voldef->target.capacity;

    if (!backend->buildVolFrom) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       "%s", _("storage pool does not support"
                               " volume creation from an existing volume"));
        goto cleanup;
    }

    if (voldefsrc->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldefsrc->name);
        goto cleanup;
    }

    if (backend->refreshVol &&
        backend->refreshVol(obj, voldefsrc) < 0)
        goto cleanup;

    /* 'Define' the new volume so we get async progress reporting.
     * Wipe any key the user may have suggested, as volume creation
     * will generate the canonical key.  */
    VIR_FREE(voldef->key);
    if (backend->createVol(obj, voldef) < 0)
        goto cleanup;

    /* Make a shallow copy of the 'defined' volume definition, since the
     * original allocation value will change as the user polls 'info',
     * but we only need the initial requested values
     */
    if (VIR_ALLOC(shadowvol) < 0)
        goto cleanup;

    memcpy(shadowvol, voldef, sizeof(*voldef));

    if (!(newvol = virGetStorageVol(pool->conn, def->name, voldef->name,
                                    voldef->key, NULL, NULL)))
        goto cleanup;

    /* NB: Upon success voldef "owned" by storage pool for deletion purposes */
    if (virStoragePoolObjAddVol(obj, voldef) < 0)
        goto cleanup;

    /* Drop the pool lock during volume allocation */
    virStoragePoolObjIncrAsyncjobs(obj);
    voldef->building = true;
    voldefsrc->in_use++;
    virObjectUnlock(obj);

    if (objsrc) {
        virStoragePoolObjIncrAsyncjobs(objsrc);
        virObjectUnlock(objsrc);
    }

    buildret = backend->buildVolFrom(obj, shadowvol, voldefsrc, flags);

    virObjectLock(obj);
    if (objsrc)
        virObjectLock(objsrc);

    voldefsrc->in_use--;
    voldef->building = false;
    virStoragePoolObjDecrAsyncjobs(obj);

    if (objsrc) {
        virStoragePoolObjDecrAsyncjobs(objsrc);
        virStoragePoolObjEndAPI(&objsrc);
    }

    if (buildret < 0 ||
        (backend->refreshVol &&
         backend->refreshVol(obj, voldef) < 0)) {
        storageVolDeleteInternal(backend, obj, voldef, 0, false);
        voldef = NULL;
        goto cleanup;
    }

    /* Updating pool metadata ignoring the disk backend since
     * it updates the pool values
     */
    if (def->type != VIR_STORAGE_POOL_DISK) {
        def->allocation += voldef->target.allocation;
        def->available -= voldef->target.allocation;
    }

    VIR_INFO("Creating volume '%s' in storage pool '%s'",
             newvol->name, def->name);
    VIR_STEAL_PTR(vol, newvol);
    voldef = NULL;

 cleanup:
    virObjectUnref(newvol);
    VIR_FREE(shadowvol);
    virStoragePoolObjEndAPI(&obj);
    virStoragePoolObjEndAPI(&objsrc);
    return vol;
}


static int
storageVolDownload(virStorageVolPtr vol,
                   virStreamPtr stream,
                   unsigned long long offset,
                   unsigned long long length,
                   unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr obj = NULL;
    virStorageVolDefPtr voldef = NULL;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM, -1);

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;

    if (virStorageVolDownloadEnsureACL(vol->conn, virStoragePoolObjGetDef(obj),
                                       voldef) < 0)
        goto cleanup;

    if (voldef->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldef->name);
        goto cleanup;
    }

    if (!backend->downloadVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool doesn't support volume download"));
        goto cleanup;
    }

    virStoragePoolObjIncrAsyncjobs(obj);
    voldef->in_use++;
    virObjectUnlock(obj);

    ret = backend->downloadVol(obj, voldef, stream, offset, length, flags);

    virObjectLock(obj);
    voldef->in_use--;
    virStoragePoolObjDecrAsyncjobs(obj);

 cleanup:
    virStoragePoolObjEndAPI(&obj);

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
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) refresh_tool = NULL;
    VIR_AUTOFREE(char *) desc = NULL;

    if (virAsprintf(&desc, "%s/DiskDescriptor.xml", path) < 0)
        return -1;

    if (virFileRemove(desc, 0, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("refresh ploop failed:"
                         " unable to delete DiskDescriptor.xml"));
        return -1;
    }

    refresh_tool = virFindFileInPath("ploop");
    if (!refresh_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to find ploop, please install ploop tools"));
        return -1;
    }

    cmd = virCommandNewArgList(refresh_tool, "restore-descriptor",
                               path, NULL);
    virCommandAddArgFormat(cmd, "%s/root.hds", path);
    return virCommandRun(cmd, NULL);
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
    virStoragePoolObjPtr obj = NULL;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virObjectEventPtr event = NULL;

    if (cbdata->vol_path) {
        if (virStorageBackendPloopRestoreDesc(cbdata->vol_path) < 0)
            goto cleanup;
    }
    if (!(obj = virStoragePoolObjFindByName(driver->pools,
                                            cbdata->pool_name)))
        goto cleanup;
    def = virStoragePoolObjGetDef(obj);

    /* If some thread is building a new volume in the pool, then we cannot
     * clear out all vols and refresh the pool. So we'll just pass. */
    if (virStoragePoolObjGetAsyncjobs(obj) > 0) {
        VIR_DEBUG("Asyncjob in process, cannot refresh storage pool");
        goto cleanup;
    }

    if (!(backend = virStorageBackendForType(def->type)))
        goto cleanup;

    if (storagePoolRefreshImpl(backend, obj, NULL) < 0)
        VIR_DEBUG("Failed to refresh storage pool");

    event = virStoragePoolEventRefreshNew(def->name, def->uuid);

 cleanup:
    virObjectEventStateQueue(driver->storageEventState, event);
    virStoragePoolObjEndAPI(&obj);
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
storageVolUpload(virStorageVolPtr vol,
                 virStreamPtr stream,
                 unsigned long long offset,
                 unsigned long long length,
                 unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr obj = NULL;
    virStoragePoolDefPtr def;
    virStorageVolDefPtr voldef = NULL;
    virStorageVolStreamInfoPtr cbdata = NULL;
    int rc;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM, -1);

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStorageVolUploadEnsureACL(vol->conn, def, voldef) < 0)
        goto cleanup;

    if (voldef->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       voldef->name);
        goto cleanup;
    }

    if (voldef->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldef->name);
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
        VIR_STRDUP(cbdata->pool_name, def->name) < 0)
        goto cleanup;
    if (voldef->type == VIR_STORAGE_VOL_PLOOP &&
        VIR_STRDUP(cbdata->vol_path, voldef->target.path) < 0)
        goto cleanup;

    virStoragePoolObjIncrAsyncjobs(obj);
    voldef->in_use++;
    virObjectUnlock(obj);

    rc = backend->uploadVol(obj, voldef, stream, offset, length, flags);

    virObjectLock(obj);
    voldef->in_use--;
    virStoragePoolObjDecrAsyncjobs(obj);

    if (rc < 0)
        goto cleanup;

    /* Add cleanup callback - call after uploadVol since the stream
     * is then fully set up
     */
    virFDStreamSetInternalCloseCb(stream,
                                  virStorageVolFDStreamCloseCb,
                                  cbdata, NULL);
    cbdata = NULL;
    ret = 0;
 cleanup:
    virStoragePoolObjEndAPI(&obj);
    if (cbdata)
        virStorageVolPoolRefreshDataFree(cbdata);

    return ret;
}

static int
storageVolResize(virStorageVolPtr vol,
                 unsigned long long capacity,
                 unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr obj = NULL;
    virStoragePoolDefPtr def;
    virStorageVolDefPtr voldef = NULL;
    unsigned long long abs_capacity, delta = 0;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE |
                  VIR_STORAGE_VOL_RESIZE_DELTA |
                  VIR_STORAGE_VOL_RESIZE_SHRINK, -1);

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;
    def = virStoragePoolObjGetDef(obj);

    if (virStorageVolResizeEnsureACL(vol->conn, def, voldef) < 0)
        goto cleanup;

    if (voldef->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       voldef->name);
        goto cleanup;
    }

    if (voldef->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldef->name);
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_RESIZE_DELTA) {
        if (flags & VIR_STORAGE_VOL_RESIZE_SHRINK)
            abs_capacity = voldef->target.capacity - MIN(capacity, voldef->target.capacity);
        else
            abs_capacity = voldef->target.capacity + capacity;
        flags &= ~VIR_STORAGE_VOL_RESIZE_DELTA;
    } else {
        abs_capacity = capacity;
    }

    if (abs_capacity < voldef->target.allocation) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("can't shrink capacity below "
                         "existing allocation"));
        goto cleanup;
    }

    if (abs_capacity < voldef->target.capacity &&
        !(flags & VIR_STORAGE_VOL_RESIZE_SHRINK)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Can't shrink capacity below current "
                         "capacity unless shrink flag explicitly specified"));
        goto cleanup;
    }

    if (flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE)
        delta = abs_capacity - voldef->target.allocation;

    if (delta > def->available) {
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

    if (backend->resizeVol(obj, voldef, abs_capacity, flags) < 0)
        goto cleanup;

    voldef->target.capacity = abs_capacity;
    /* Only update the allocation and pool values if we actually did the
     * allocation; otherwise, this is akin to a create operation with a
     * capacity value different and potentially much larger than available
     */
    if (flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE) {
        voldef->target.allocation = abs_capacity;
        def->allocation += delta;
        def->available -= delta;
    }

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);

    return ret;
}


static int
storageVolWipePattern(virStorageVolPtr vol,
                      unsigned int algorithm,
                      unsigned int flags)
{
    virStorageBackendPtr backend;
    virStoragePoolObjPtr obj = NULL;
    virStorageVolDefPtr voldef = NULL;
    int rc;
    int ret = -1;

    virCheckFlags(0, -1);

    if (algorithm >= VIR_STORAGE_VOL_WIPE_ALG_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("wiping algorithm %d not supported"),
                       algorithm);
        return -1;
    }

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;

    if (virStorageVolWipePatternEnsureACL(vol->conn,
                                          virStoragePoolObjGetDef(obj),
                                          voldef) < 0)
        goto cleanup;

    if (voldef->in_use) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still in use."),
                       voldef->name);
        goto cleanup;
    }

    if (voldef->building) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume '%s' is still being allocated."),
                       voldef->name);
        goto cleanup;
    }

    if (!backend->wipeVol) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("storage pool doesn't support volume wiping"));
        goto cleanup;
    }

    virStoragePoolObjIncrAsyncjobs(obj);
    voldef->in_use++;
    virObjectUnlock(obj);

    rc = backend->wipeVol(obj, voldef, algorithm, flags);

    virObjectLock(obj);
    voldef->in_use--;
    virStoragePoolObjDecrAsyncjobs(obj);

    if (rc < 0)
        goto cleanup;

    /* For local volumes, Instead of using the refreshVol, since
     * much changes on the target volume, let's update using the
     * same function as refreshPool would use when it discovers a
     * volume. The only failure to capture is -1, we can ignore
     * -2. */
    if ((backend->type == VIR_STORAGE_POOL_DIR ||
         backend->type == VIR_STORAGE_POOL_FS ||
         backend->type == VIR_STORAGE_POOL_NETFS ||
         backend->type == VIR_STORAGE_POOL_VSTORAGE) &&
        virStorageBackendRefreshVolTargetUpdate(voldef) == -1)
        goto cleanup;

    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);

    return ret;
}

static int
storageVolWipe(virStorageVolPtr vol,
               unsigned int flags)
{
    return storageVolWipePattern(vol, VIR_STORAGE_VOL_WIPE_ALG_ZERO, flags);
}


static int
storageVolGetInfoFlags(virStorageVolPtr vol,
                       virStorageVolInfoPtr info,
                       unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef;
    int ret = -1;

    virCheckFlags(VIR_STORAGE_VOL_GET_PHYSICAL, -1);

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return -1;

    if (virStorageVolGetInfoFlagsEnsureACL(vol->conn,
                                           virStoragePoolObjGetDef(obj),
                                           voldef) < 0)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj, voldef) < 0)
        goto cleanup;

    memset(info, 0, sizeof(*info));
    info->type = voldef->type;
    info->capacity = voldef->target.capacity;
    if (flags & VIR_STORAGE_VOL_GET_PHYSICAL)
        info->allocation = voldef->target.physical;
    else
        info->allocation = voldef->target.allocation;
    ret = 0;

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}


static int
storageVolGetInfo(virStorageVolPtr vol,
                  virStorageVolInfoPtr info)
{
    return storageVolGetInfoFlags(vol, info, 0);
}


static char *
storageVolGetXMLDesc(virStorageVolPtr vol,
                     unsigned int flags)
{
    virStoragePoolObjPtr obj;
    virStoragePoolDefPtr def;
    virStorageBackendPtr backend;
    virStorageVolDefPtr voldef;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, &backend)))
        return NULL;
    def = virStoragePoolObjGetDef(obj);

    if (virStorageVolGetXMLDescEnsureACL(vol->conn, def, voldef) < 0)
        goto cleanup;

    if (backend->refreshVol &&
        backend->refreshVol(obj, voldef) < 0)
        goto cleanup;

    ret = virStorageVolDefFormat(def, voldef);

 cleanup:
    virStoragePoolObjEndAPI(&obj);

    return ret;
}

static char *
storageVolGetPath(virStorageVolPtr vol)
{
    virStoragePoolObjPtr obj;
    virStorageVolDefPtr voldef;
    char *ret = NULL;

    if (!(voldef = virStorageVolDefFromVol(vol, &obj, NULL)))
        return NULL;

    if (virStorageVolGetPathEnsureACL(vol->conn, virStoragePoolObjGetDef(obj),
                                      voldef) < 0)
        goto cleanup;

    ignore_value(VIR_STRDUP(ret, voldef->target.path));

 cleanup:
    virStoragePoolObjEndAPI(&obj);
    return ret;
}

static int
storageConnectListAllStoragePools(virConnectPtr conn,
                                  virStoragePoolPtr **pools,
                                  unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL, -1);

    if (virConnectListAllStoragePoolsEnsureACL(conn) < 0)
        return -1;

    return virStoragePoolObjListExport(conn, driver->pools, pools,
                                       virConnectListAllStoragePoolsCheckACL,
                                       flags);
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
                                        callbackID, true) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
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
    return virStoragePoolObjFindByUUID(driver->pools, uuid);
}


/*
 * virStoragePoolObjBuildTempFilePath
 * @obj: pool object pointer
 * @vol: volume definition
 *
 * Generate a name for a temporary file using the driver stateDir
 * as a path, the pool name, and the volume name to be used as input
 * for a mkostemp
 *
 * Returns a string pointer on success, NULL on failure
 */
char *
virStoragePoolObjBuildTempFilePath(virStoragePoolObjPtr obj,
                                   virStorageVolDefPtr voldef)

{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(obj);
    char *tmp = NULL;

    ignore_value(virAsprintf(&tmp, "%s/%s.%s.secret.XXXXXX",
                             driver->stateDir, def->name, voldef->name));
    return tmp;
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
    .connectGetStoragePoolCapabilities = storageConnectGetStoragePoolCapabilities, /* 5.2.0 */
    .storagePoolLookupByName = storagePoolLookupByName, /* 0.4.0 */
    .storagePoolLookupByUUID = storagePoolLookupByUUID, /* 0.4.0 */
    .storagePoolLookupByVolume = storagePoolLookupByVolume, /* 0.4.0 */
    .storagePoolLookupByTargetPath = storagePoolLookupByTargetPath, /* 4.1.0 */
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


static virHypervisorDriver storageHypervisorDriver = {
    .name = "storage",
    .connectOpen = storageConnectOpen, /* 4.1.0 */
    .connectClose = storageConnectClose, /* 4.1.0 */
    .connectIsEncrypted = storageConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = storageConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = storageConnectIsAlive, /* 4.1.0 */
    .connectGetCapabilities = storageConnectGetCapabilities, /* 5.2.0 */
};

static virConnectDriver storageConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "storage", NULL },
    .hypervisorDriver = &storageHypervisorDriver,
    .storageDriver = &storageDriver,
};


static virStateDriver stateDriver = {
    .name = "storage",
    .stateInitialize = storageStateInitialize,
    .stateCleanup = storageStateCleanup,
    .stateReload = storageStateReload,
};


static int
storageRegisterFull(bool allbackends)
{
    if (virRegisterConnectDriver(&storageConnectDriver, false) < 0)
        return -1;
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
