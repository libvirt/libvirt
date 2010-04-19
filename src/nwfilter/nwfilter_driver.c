/*
 * nwfilter_driver.c: core driver for network filter APIs
 *                    (based on storage_driver.c)
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
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
 *         Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "internal.h"

#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "domain_conf.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"


#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

#define nwfilterLog(msg...) fprintf(stderr, msg)


static virNWFilterDriverStatePtr driverState;

static int nwfilterDriverShutdown(void);

static void nwfilterDriverLock(virNWFilterDriverStatePtr driver)
{
    virMutexLock(&driver->lock);
}
static void nwfilterDriverUnlock(virNWFilterDriverStatePtr driver)
{
    virMutexUnlock(&driver->lock);
}


/**
 * virNWFilterStartup:
 *
 * Initialization function for the QEmu daemon
 */
static int
nwfilterDriverStartup(int privileged) {
    char *base = NULL;

    if (virNWFilterLearnInit() < 0)
        return -1;

    virNWFilterTechDriversInit();

    if (virNWFilterConfLayerInit(virNWFilterDomainFWUpdateCB) < 0)
        goto conf_init_err;

    if (VIR_ALLOC(driverState) < 0)
        goto alloc_err_exit;

    if (virMutexInit(&driverState->lock) < 0)
        goto alloc_err_exit;

    nwfilterDriverLock(driverState);

    if (privileged) {
        if ((base = strdup (SYSCONF_DIR "/libvirt")) == NULL)
            goto out_of_memory;
    } else {
        uid_t uid = geteuid();
        char *userdir = virGetUserDirectory(uid);

        if (!userdir)
            goto error;

        if (virAsprintf(&base, "%s/.libvirt", userdir) == -1) {
            nwfilterLog("out of memory in virAsprintf");
            VIR_FREE(userdir);
            goto out_of_memory;
        }
        VIR_FREE(userdir);
    }

    if (virAsprintf(&driverState->configDir,
                    "%s/nwfilter", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if (virNWFilterPoolLoadAllConfigs(NULL,
                                      &driverState->pools,
                                      driverState->configDir) < 0)
        goto error;

    nwfilterDriverUnlock(driverState);

    return 0;

out_of_memory:
    nwfilterLog("virNWFilterStartup: out of memory");

error:
    VIR_FREE(base);
    nwfilterDriverUnlock(driverState);
    nwfilterDriverShutdown();

alloc_err_exit:
    virNWFilterConfLayerShutdown();

conf_init_err:
    virNWFilterTechDriversShutdown();
    virNWFilterLearnShutdown();

    return -1;
}

/**
 * virNWFilterReload:
 *
 * Function to restart the nwfilter driver, it will recheck the configuration
 * files and update its state
 */
static int
nwfilterDriverReload(void) {
    if (!driverState) {
        return -1;
    }

    nwfilterDriverLock(driverState);
    virNWFilterPoolLoadAllConfigs(NULL,
                                  &driverState->pools,
                                  driverState->configDir);
    nwfilterDriverUnlock(driverState);

    return 0;
}

/**
 * virNWFilterActive:
 *
 * Checks if the nwfilter driver is active, i.e. has an active pool
 *
 * Returns 1 if active, 0 otherwise
 */
static int
nwfilterDriverActive(void) {
    int ret;

    if (!driverState)
        return 0;

    nwfilterDriverLock(driverState);
    ret = driverState->pools.count ? 1 : 0;
    nwfilterDriverUnlock(driverState);

    return ret;
}

/**
 * virNWFilterShutdown:
 *
 * Shutdown the nwfilter driver, it will stop all active nwfilter pools
 */
static int
nwfilterDriverShutdown(void) {
    if (!driverState)
        return -1;

    virNWFilterLearnShutdown();

    nwfilterDriverLock(driverState);

    /* free inactive pools */
    virNWFilterPoolObjListFree(&driverState->pools);

    VIR_FREE(driverState->configDir);
    nwfilterDriverUnlock(driverState);
    virMutexDestroy(&driverState->lock);
    VIR_FREE(driverState);

    return 0;
}


static virNWFilterPtr
nwfilterLookupByUUID(virConnectPtr conn,
                     const unsigned char *uuid) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterPoolObjPtr pool;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    pool = virNWFilterPoolObjFindByUUID(&driver->pools, uuid);
    nwfilterDriverUnlock(driver);

    if (!pool) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               "%s", _("no pool with matching uuid"));
        goto cleanup;
    }

    ret = virGetNWFilter(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virNWFilterPoolObjUnlock(pool);
    return ret;
}


static virNWFilterPtr
nwfilterLookupByName(virConnectPtr conn,
                     const char *name) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterPoolObjPtr pool;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    pool = virNWFilterPoolObjFindByName(&driver->pools, name);
    nwfilterDriverUnlock(driver);

    if (!pool) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("no pool with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNWFilter(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virNWFilterPoolObjUnlock(pool);
    return ret;
}


static virDrvOpenStatus
nwfilterOpen(virConnectPtr conn,
            virConnectAuthPtr auth ATTRIBUTE_UNUSED,
            int flags ATTRIBUTE_UNUSED) {
    if (!driverState)
        return VIR_DRV_OPEN_DECLINED;

    conn->nwfilterPrivateData = driverState;
    return VIR_DRV_OPEN_SUCCESS;
}


static int
nwfilterClose(virConnectPtr conn) {
    conn->nwfilterPrivateData = NULL;
    return 0;
}


static int
nwfilterNumNWFilters(virConnectPtr conn) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    return driver->pools.count;
}


static int
nwfilterListNWFilters(virConnectPtr conn,
                      char **const names,
                      int nnames) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    int got = 0, i;

    nwfilterDriverLock(driver);
    for (i = 0 ; i < driver->pools.count && got < nnames ; i++) {
        virNWFilterPoolObjLock(driver->pools.objs[i]);
        if (!(names[got] = strdup(driver->pools.objs[i]->def->name))) {
             virNWFilterPoolObjUnlock(driver->pools.objs[i]);
             virReportOOMError();
             goto cleanup;
        }
        got++;
        virNWFilterPoolObjUnlock(driver->pools.objs[i]);
    }
    nwfilterDriverUnlock(driver);
    return got;

 cleanup:
    nwfilterDriverUnlock(driver);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    memset(names, 0, nnames * sizeof(*names));
    return -1;
}


static virNWFilterPtr
nwfilterDefine(virConnectPtr conn,
               const char *xml,
               unsigned int flags ATTRIBUTE_UNUSED) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterDefPtr def;
    virNWFilterPoolObjPtr pool = NULL;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    if (!(def = virNWFilterDefParseString(conn, xml)))
        goto cleanup;

    if (!(pool = virNWFilterPoolObjAssignDef(conn, &driver->pools, def)))
        goto cleanup;

    if (virNWFilterPoolObjSaveDef(driver, pool, def) < 0) {
        virNWFilterPoolObjRemove(&driver->pools, pool);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    ret = virGetNWFilter(conn, pool->def->name, pool->def->uuid);

cleanup:
    virNWFilterDefFree(def);
    if (pool)
        virNWFilterPoolObjUnlock(pool);
    nwfilterDriverUnlock(driver);
    return ret;
}


static int
nwfilterUndefine(virNWFilterPtr obj) {
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterPoolObjPtr pool;
    int ret = -1;

    nwfilterDriverLock(driver);
    pool = virNWFilterPoolObjFindByUUID(&driver->pools, obj->uuid);
    if (!pool) {
        virNWFilterReportError(VIR_ERR_INVALID_NWFILTER,
                               "%s", _("no nwfilter pool with matching uuid"));
        goto cleanup;
    }

    if (virNWFilterTestUnassignDef(obj->conn, pool)) {
        virNWFilterReportError(VIR_ERR_INVALID_NWFILTER,
                               "%s",
                               _("nwfilter is in use"));
        goto cleanup;
    }

    if (virNWFilterPoolObjDeleteDef(pool) < 0)
        goto cleanup;

    VIR_FREE(pool->configFile);

    virNWFilterPoolObjRemove(&driver->pools, pool);
    pool = NULL;
    ret = 0;

cleanup:
    if (pool)
        virNWFilterPoolObjUnlock(pool);
    nwfilterDriverUnlock(driver);
    return ret;
}


static char *
nwfilterDumpXML(virNWFilterPtr obj,
                unsigned int flags) {
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterPoolObjPtr pool;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    nwfilterDriverLock(driver);
    pool = virNWFilterPoolObjFindByUUID(&driver->pools, obj->uuid);
    nwfilterDriverUnlock(driver);

    if (!pool) {
        virNWFilterReportError(VIR_ERR_INVALID_NWFILTER,
                               "%s", _("no nwfilter pool with matching uuid"));
        goto cleanup;
    }

    ret = virNWFilterDefFormat(pool->def);

cleanup:
    if (pool)
        virNWFilterPoolObjUnlock(pool);
    return ret;
}


static virNWFilterDriver nwfilterDriver = {
    .name = "nwfilter",
    .open = nwfilterOpen,
    .close = nwfilterClose,
    .numOfNWFilters = nwfilterNumNWFilters,
    .listNWFilters = nwfilterListNWFilters,
    .nwfilterLookupByName = nwfilterLookupByName,
    .nwfilterLookupByUUID = nwfilterLookupByUUID,
    .defineXML = nwfilterDefine,
    .undefine = nwfilterUndefine,
    .getXMLDesc = nwfilterDumpXML,
};


static virStateDriver stateDriver = {
    .name = "NWFilter",
    .initialize = nwfilterDriverStartup,
    .cleanup = nwfilterDriverShutdown,
    .reload = nwfilterDriverReload,
    .active = nwfilterDriverActive,
};

int nwfilterRegister(void) {
    virRegisterNWFilterDriver(&nwfilterDriver);
    virRegisterStateDriver(&stateDriver);
    return 0;
}
