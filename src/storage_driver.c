/*
 * storage_driver.c: core driver for storage APIs
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
#if HAVE_PWD_H
#include <pwd.h>
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

#define storageLog(msg...) fprintf(stderr, msg)

static virStorageDriverStatePtr driverState;

static int storageDriverShutdown(void);


static void
storageDriverAutostart(virStorageDriverStatePtr driver) {
    unsigned int i;

    for (i = 0 ; i < driver->pools.count ; i++) {
        virStoragePoolObjPtr pool = driver->pools.objs[i];

        if (pool->autostart &&
            !virStoragePoolObjIsActive(pool)) {
            virStorageBackendPtr backend;
            if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
                storageLog("Missing backend %d",
                           pool->def->type);
                continue;
            }

            if (backend->startPool &&
                backend->startPool(NULL, pool) < 0) {
                virErrorPtr err = virGetLastError();
                storageLog("Failed to autostart storage pool '%s': %s",
                           pool->def->name, err ? err->message : NULL);
                continue;
            }

            if (backend->refreshPool(NULL, pool) < 0) {
                virErrorPtr err = virGetLastError();
                if (backend->stopPool)
                    backend->stopPool(NULL, pool);
                storageLog("Failed to autostart storage pool '%s': %s",
                           pool->def->name, err ? err->message : NULL);
                continue;
            }
            pool->active = 1;
        }
    }
}

/**
 * virStorageStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
storageDriverStartup(void) {
    uid_t uid = geteuid();
    struct passwd *pw;
    char *base = NULL;
    char driverConf[PATH_MAX];

    if (VIR_ALLOC(driverState) < 0)
        return -1;

    if (!uid) {
        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        if (!(pw = getpwuid(uid))) {
            storageLog("Failed to find user record for uid '%d': %s",
                       uid, strerror(errno));
            goto out_of_memory;
        }

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1) {
            storageLog("out of memory in asprintf");
            goto out_of_memory;
        }
    }

    /* Configuration paths are either ~/.libvirt/storage/... (session) or
     * /etc/libvirt/storage/... (system).
     */
    if (snprintf (driverConf, sizeof(driverConf),
                  "%s/storage.conf", base) == -1)
        goto out_of_memory;
    driverConf[sizeof(driverConf)-1] = '\0';

    if (asprintf (&driverState->configDir,
                  "%s/storage", base) == -1)
        goto out_of_memory;

    if (asprintf (&driverState->autostartDir,
                  "%s/storage/autostart", base) == -1)
        goto out_of_memory;

    free(base);
    base = NULL;

    /*
    if (virStorageLoadDriverConfig(driver, driverConf) < 0) {
        virStorageDriverShutdown();
        return -1;
    }
    */

    if (virStoragePoolLoadAllConfigs(NULL,
                                     &driverState->pools,
                                     driverState->configDir,
                                     driverState->autostartDir) < 0) {
        storageDriverShutdown();
        return -1;
    }
    storageDriverAutostart(driverState);

    return 0;

 out_of_memory:
    storageLog("virStorageStartup: out of memory");
    free(base);
    free(driverState);
    driverState = NULL;
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

    virStoragePoolLoadAllConfigs(NULL,
                                 &driverState->pools,
                                 driverState->configDir,
                                 driverState->autostartDir);
    storageDriverAutostart(driverState);

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

    if (!driverState)
        return 0;

    /* If we've any active networks or guests, then we
     * mark this driver as active
     */
    for (i = 0 ; i < driverState->pools.count ; i++)
        if (virStoragePoolObjIsActive(driverState->pools.objs[i]))
            return 1;

    /* Otherwise we're happy to deal with a shutdown */
    return 0;
}

/**
 * virStorageShutdown:
 *
 * Shutdown the storage driver, it will stop all active storage pools
 */
static int
storageDriverShutdown(void) {
    unsigned int i;

    if (!driverState)
        return -1;

    /* shutdown active pools */
    for (i = 0 ; i < driverState->pools.count ; i++) {
        virStoragePoolObjPtr pool = driverState->pools.objs[i];

        if (virStoragePoolObjIsActive(pool)) {
            virStorageBackendPtr backend;
            if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
                storageLog("Missing backend");
                continue;
            }

            if (backend->stopPool &&
                backend->stopPool(NULL, pool) < 0) {
                virErrorPtr err = virGetLastError();
                storageLog("Failed to stop storage pool '%s': %s",
                           pool->def->name, err ? err->message : NULL);
            }
            virStoragePoolObjClearVols(pool);
        }
    }

    /* free inactive pools */
    virStoragePoolObjListFree(&driverState->pools);

    VIR_FREE(driverState->configDir);
    VIR_FREE(driverState->autostartDir);
    VIR_FREE(driverState);

    return 0;
}



static virStoragePoolPtr
storagePoolLookupByUUID(virConnectPtr conn,
                        const unsigned char *uuid) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, uuid);
    virStoragePoolPtr ret;

    if (!pool) {
        virStorageReportError(conn, VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        return NULL;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);
    return ret;
}

static virStoragePoolPtr
storagePoolLookupByName(virConnectPtr conn,
                        const char *name) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByName(&driver->pools, name);
    virStoragePoolPtr ret;

    if (!pool) {
        virStorageReportError(conn, VIR_ERR_NO_STORAGE_POOL,
                              "%s", _("no pool with matching name"));
        return NULL;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);
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
    virStorageDriverStatePtr driver
        = (virStorageDriverStatePtr)conn->storagePrivateData;
    unsigned int i, nactive = 0;

    for (i = 0 ; i < driver->pools.count ; i++)
        if (virStoragePoolObjIsActive(driver->pools.objs[i]))
            nactive++;

    return nactive;
}

static int
storageListPools(virConnectPtr conn,
                 char **const names,
                 int nnames) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)conn->storagePrivateData;
    int got = 0, i;

    for (i = 0 ; i < driver->pools.count && got < nnames ; i++) {
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            if (!(names[got] = strdup(driver->pools.objs[i]->def->name))) {
                virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                      "%s", _("names"));
                goto cleanup;
            }
            got++;
        }
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++) {
        free(names[i]);
        names[i] = NULL;
    }
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

static int
storageNumDefinedPools(virConnectPtr conn) {
    virStorageDriverStatePtr driver
        = (virStorageDriverStatePtr)conn->storagePrivateData;
    unsigned int i, nactive = 0;

    for (i = 0 ; i < driver->pools.count ; i++)
        if (!virStoragePoolObjIsActive(driver->pools.objs[i]))
            nactive++;

    return nactive;
}

static int
storageListDefinedPools(virConnectPtr conn,
                        char **const names,
                        int nnames) {
    virStorageDriverStatePtr driver
        = (virStorageDriverStatePtr)conn->storagePrivateData;
    int got = 0, i;

    for (i = 0 ; i < driver->pools.count && got < nnames ; i++) {
        if (!virStoragePoolObjIsActive(driver->pools.objs[i])) {
            if (!(names[got] = strdup(driver->pools.objs[i]->def->name))) {
                virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                      "%s", _("names"));
                goto cleanup;
            }
            got++;
        }
    }
    return got;

 cleanup:
    for (i = 0 ; i < got ; i++) {
        free(names[i]);
        names[i] = NULL;
    }
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}

static char *
storageFindPoolSources(virConnectPtr conn,
                       const char *type,
                       const char *srcSpec,
                       unsigned int flags)
{
    int backend_type;
    virStorageBackendPtr backend;

    backend_type = virStoragePoolTypeFromString(type);
    if (backend_type < 0)
        return NULL;

    backend = virStorageBackendForType(backend_type);
    if (backend == NULL)
        return NULL;

    if (backend->findPoolSources)
        return backend->findPoolSources(conn, srcSpec, flags);

    return NULL;
}


static virStoragePoolPtr
storagePoolCreate(virConnectPtr conn,
                  const char *xml,
                  unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr )conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret;
    virStorageBackendPtr backend;

    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        return NULL;

    if (virStoragePoolObjFindByUUID(&driver->pools, def->uuid) ||
        virStoragePoolObjFindByName(&driver->pools, def->name)) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool already exists"));
        virStoragePoolDefFree(def);
        return NULL;
    }

    if ((backend = virStorageBackendForType(def->type)) == NULL) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, &driver->pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (backend->startPool &&
        backend->startPool(conn, pool) < 0)
        return NULL;
    if (backend->refreshPool(conn, pool) < 0) {
        if (backend->stopPool)
            backend->stopPool(conn, pool);
        return NULL;
    }
    pool->active = 1;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

    return ret;
}

static virStoragePoolPtr
storagePoolDefine(virConnectPtr conn,
                  const char *xml,
                  unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver
        = (virStorageDriverStatePtr )conn->storagePrivateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret;
    virStorageBackendPtr backend;

    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        return NULL;

    if ((backend = virStorageBackendForType(def->type)) == NULL) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, &driver->pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (virStoragePoolObjSaveDef(conn, driver, pool, def) < 0) {
        virStoragePoolObjRemove(&driver->pools, pool);
        return NULL;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);
    return ret;
}

static int
storagePoolUndefine(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("pool is still active"));
        return -1;
    }

    if (virStoragePoolObjDeleteDef(obj->conn, pool) < 0)
        return -1;

    if (unlink(pool->autostartLink) < 0 && errno != ENOENT && errno != ENOTDIR)
        storageLog("Failed to delete autostart link '%s': %s",
                   pool->autostartLink, strerror(errno));

    VIR_FREE(pool->configFile);
    VIR_FREE(pool->autostartLink);

    virStoragePoolObjRemove(&driver->pools, pool);

    return 0;
}

static int
storagePoolStart(virStoragePoolPtr obj,
                 unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("pool already active"));
        return -1;
    }
    if (backend->startPool &&
        backend->startPool(obj->conn, pool) < 0)
        return -1;
    if (backend->refreshPool(obj->conn, pool) < 0) {
        if (backend->stopPool)
            backend->stopPool(obj->conn, pool);
        return -1;
    }

    pool->active = 1;

    return 0;
}

static int
storagePoolBuild(virStoragePoolPtr obj,
                 unsigned int flags) {
    virStorageDriverStatePtr driver
        = (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is already active"));
        return -1;
    }

    if (backend->buildPool &&
        backend->buildPool(obj->conn, pool, flags) < 0)
        return -1;

    return 0;
}


static int
storagePoolDestroy(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    if (backend->stopPool &&
        backend->stopPool(obj->conn, pool) < 0)
        return -1;

    virStoragePoolObjClearVols(pool);

    pool->active = 0;

    if (pool->configFile == NULL)
        virStoragePoolObjRemove(&driver->pools, pool);

    return 0;
}


static int
storagePoolDelete(virStoragePoolPtr obj,
                  unsigned int flags) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    if (virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is still active"));
        return -1;
    }

    if (!backend->deletePool) {
        virStorageReportError(obj->conn, VIR_ERR_NO_SUPPORT,
                              "%s", _("pool does not support volume delete"));
        return -1;
    }
    if (backend->deletePool(obj->conn, pool, flags) < 0)
        return -1;

    return 0;
}


static int
storagePoolRefresh(virStoragePoolPtr obj,
                   unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;
    int ret = 0;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    virStoragePoolObjClearVols(pool);
    if ((ret = backend->refreshPool(obj->conn, pool)) < 0) {
        if (backend->stopPool)
            backend->stopPool(obj->conn, pool);

        pool->active = 0;

        if (pool->configFile == NULL)
            virStoragePoolObjRemove(&driver->pools, pool);
    }

    return ret;
}


static int
storagePoolGetInfo(virStoragePoolPtr obj,
                   virStoragePoolInfoPtr info) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL) {
        return -1;
    }

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (pool->active)
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = pool->def->capacity;
    info->allocation = pool->def->allocation;
    info->available = pool->def->available;

    return 0;
}

static char *
storagePoolDumpXML(virStoragePoolPtr obj,
                   unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return NULL;
    }

    return virStoragePoolDefFormat(obj->conn, pool->def);
}

static int
storagePoolGetAutostart(virStoragePoolPtr obj,
                        int *autostart) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        return -1;
    }

    if (!pool->configFile) {
        *autostart = 0;
    } else {
        *autostart = pool->autostart;
    }

    return 0;
}

static int
storagePoolSetAutostart(virStoragePoolPtr obj,
                        int autostart) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no pool with matching uuid"));
        return -1;
    }

    if (!pool->configFile) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_ARG,
                              "%s", _("pool has no config file"));
        return -1;
    }

    autostart = (autostart != 0);

    if (pool->autostart == autostart)
        return 0;

    if (autostart) {
        int err;

        if ((err = virFileMakePath(driver->autostartDir))) {
            virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot create autostart directory %s: %s"),
                                  driver->autostartDir, strerror(err));
            return -1;
        }

        if (symlink(pool->configFile, pool->autostartLink) < 0) {
            virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to create symlink '%s' to '%s': %s"),
                                  pool->autostartLink, pool->configFile,
                                  strerror(errno));
            return -1;
        }
    } else {
        if (unlink(pool->autostartLink) < 0 &&
            errno != ENOENT && errno != ENOTDIR) {
            virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to delete symlink '%s': %s"),
                                  pool->autostartLink, strerror(errno));
            return -1;
        }
    }

    pool->autostart = autostart;

    return 0;
}


static int
storagePoolNumVolumes(virStoragePoolPtr obj) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    return pool->volumes.count;
}

static int
storagePoolListVolumes(virStoragePoolPtr obj,
                       char **const names,
                       int maxnames) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    int i, n = 0;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    memset(names, 0, maxnames * sizeof(*names));
    for (i = 0 ; i < pool->volumes.count && n < maxnames ; i++) {
        if ((names[n++] = strdup(pool->volumes.objs[i]->name)) == NULL) {
            virStorageReportError(obj->conn, VIR_ERR_NO_MEMORY,
                                  "%s", _("name"));
            goto cleanup;
        }
    }

    return n;

 cleanup:
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[i]);

    memset(names, 0, maxnames * sizeof(*names));
    return -1;
}


static virStorageVolPtr
storageVolumeLookupByName(virStoragePoolPtr obj,
                          const char *name) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageVolDefPtr vol;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return NULL;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return NULL;
    }

    vol = virStorageVolDefFindByName(pool, name);

    if (!vol) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage vol with matching name"));
        return NULL;
    }

    return virGetStorageVol(obj->conn, pool->def->name, vol->name, vol->key);
}


static virStorageVolPtr
storageVolumeLookupByKey(virConnectPtr conn,
                         const char *key) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)conn->storagePrivateData;
    unsigned int i;

    for (i = 0 ; i < driver->pools.count ; i++) {
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByKey(driver->pools.objs[i], key);

            if (vol)
                return virGetStorageVol(conn,
                                        driver->pools.objs[i]->def->name,
                                        vol->name,
                                        vol->key);
        }
    }

    virStorageReportError(conn, VIR_ERR_INVALID_STORAGE_VOL,
                          "%s", _("no storage vol with matching key"));
    return NULL;
}

static virStorageVolPtr
storageVolumeLookupByPath(virConnectPtr conn,
                          const char *path) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)conn->storagePrivateData;
    unsigned int i;

    for (i = 0 ; i < driver->pools.count ; i++) {
        if (virStoragePoolObjIsActive(driver->pools.objs[i])) {
            virStorageVolDefPtr vol;
            const char *stable_path;

            stable_path = virStorageBackendStablePath(conn,
                                                      driver->pools.objs[i],
                                                      path);
            /*
             * virStorageBackendStablePath already does
             * virStorageReportError if it fails; we just need to keep
             * propagating the return code
             */
            if (stable_path == NULL)
                return NULL;

            vol = virStorageVolDefFindByPath(driver->pools.objs[i],
                                             stable_path);
            VIR_FREE(stable_path);

            if (vol)
                return virGetStorageVol(conn,
                                        driver->pools.objs[i]->def->name,
                                        vol->name,
                                        vol->key);
        }
    }

    virStorageReportError(conn, VIR_ERR_INVALID_STORAGE_VOL,
                          "%s", _("no storage vol with matching path"));
    return NULL;
}

static virStorageVolPtr
storageVolumeCreateXML(virStoragePoolPtr obj,
                       const char *xmldesc,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByUUID(&driver->pools, obj->uuid);
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return NULL;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return NULL;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        return NULL;

    vol = virStorageVolDefParse(obj->conn, pool->def, xmldesc, NULL);
    if (vol == NULL)
        return NULL;

    if (virStorageVolDefFindByName(pool, vol->name)) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("storage vol already exists"));
        virStorageVolDefFree(vol);
        return NULL;
    }

    if (VIR_REALLOC_N(pool->volumes.objs,
                      pool->volumes.count+1) < 0) {
        virStorageReportError(obj->conn, VIR_ERR_NO_MEMORY, NULL);
        virStorageVolDefFree(vol);
        return NULL;
    }

    if (!backend->createVol) {
        virStorageReportError(obj->conn, VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support volume creation"));
        virStorageVolDefFree(vol);
        return NULL;
    }

    if (backend->createVol(obj->conn, pool, vol) < 0) {
        virStorageVolDefFree(vol);
        return NULL;
    }

    pool->volumes.objs[pool->volumes.count++] = vol;

    return virGetStorageVol(obj->conn, pool->def->name, vol->name, vol->key);
}

static int
storageVolumeDelete(virStorageVolPtr obj,
                    unsigned int flags) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;
    unsigned int i;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        return -1;

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage vol with matching name"));
        return -1;
    }

    if (!backend->deleteVol) {
        virStorageReportError(obj->conn, VIR_ERR_NO_SUPPORT,
                              "%s", _("storage pool does not support vol deletion"));
        virStorageVolDefFree(vol);
        return -1;
    }

    if (backend->deleteVol(obj->conn, pool, vol, flags) < 0) {
        return -1;
    }

    for (i = 0 ; i < pool->volumes.count ; i++) {
        if (pool->volumes.objs[i] == vol) {
            virStorageVolDefFree(vol);

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

    return 0;
}

static int
storageVolumeGetInfo(virStorageVolPtr obj,
                     virStorageVolInfoPtr info) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return -1;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return -1;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage vol with matching name"));
        return -1;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        return -1;

    if (backend->refreshVol &&
        backend->refreshVol(obj->conn, pool, vol) < 0)
        return -1;

    memset(info, 0, sizeof(*info));
    info->type = vol->type;
    info->capacity = vol->capacity;
    info->allocation = vol->allocation;

    return 0;
}

static char *
storageVolumeGetXMLDesc(virStorageVolPtr obj,
                        unsigned int flags ATTRIBUTE_UNUSED) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    virStorageBackendPtr backend;
    virStorageVolDefPtr vol;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return NULL;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return NULL;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage vol with matching name"));
        return NULL;
    }

    if ((backend = virStorageBackendForType(pool->def->type)) == NULL)
        return NULL;

    return virStorageVolDefFormat(obj->conn, pool->def, vol);
}

static char *
storageVolumeGetPath(virStorageVolPtr obj) {
    virStorageDriverStatePtr driver =
        (virStorageDriverStatePtr)obj->conn->storagePrivateData;
    virStoragePoolObjPtr pool = virStoragePoolObjFindByName(&driver->pools, obj->pool);
    virStorageVolDefPtr vol;
    char *ret;

    if (!pool) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage pool with matching uuid"));
        return NULL;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virStorageReportError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("storage pool is not active"));
        return NULL;
    }

    vol = virStorageVolDefFindByName(pool, obj->name);

    if (!vol) {
        virStorageReportError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                              "%s", _("no storage vol with matching name"));
        return NULL;
    }

    ret = strdup(vol->target.path);
    if (ret == NULL) {
        virStorageReportError(obj->conn, VIR_ERR_NO_MEMORY, "%s", _("path"));
        return NULL;
    }
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
    .volDelete = storageVolumeDelete,
    .volGetInfo = storageVolumeGetInfo,
    .volGetXMLDesc = storageVolumeGetXMLDesc,
    .volGetPath = storageVolumeGetPath,
};


static virStateDriver stateDriver = {
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
