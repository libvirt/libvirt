/*
 * nwfilter_driver.c: core driver for network filter APIs
 *                    (based on storage_driver.c)
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
#include "domain_nwfilter.h"
#include "nwfilter_conf.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"
#include "configmake.h"

#include "nwfilter_learnipaddr.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

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

    virNWFilterTechDriversInit(privileged);

    if (virNWFilterConfLayerInit(virNWFilterDomainFWUpdateCB) < 0)
        goto conf_init_err;

    if (VIR_ALLOC(driverState) < 0)
        goto alloc_err_exit;

    if (virMutexInit(&driverState->lock) < 0)
        goto alloc_err_exit;

    nwfilterDriverLock(driverState);

    if (privileged) {
        if ((base = strdup (SYSCONFDIR "/libvirt")) == NULL)
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

    if (virAsprintf(&driverState->configDir,
                    "%s/nwfilter", base) == -1)
        goto out_of_memory;

    VIR_FREE(base);

    if (virNWFilterLoadAllConfigs(NULL,
                                  &driverState->nwfilters,
                                  driverState->configDir) < 0)
        goto error;

    nwfilterDriverUnlock(driverState);

    return 0;

out_of_memory:
    virReportOOMError();

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
    virConnectPtr conn;

    if (!driverState) {
        return -1;
    }

    conn = virConnectOpen("qemu:///system");

    if (conn) {
        /* shut down all threads -- they will be restarted if necessary */
        virNWFilterLearnThreadsTerminate(true);

        nwfilterDriverLock(driverState);
        virNWFilterCallbackDriversLock();

        virNWFilterLoadAllConfigs(conn,
                                  &driverState->nwfilters,
                                  driverState->configDir);

        virNWFilterCallbackDriversUnlock();
        nwfilterDriverUnlock(driverState);

        virNWFilterInstFiltersOnAllVMs(conn);

        virConnectClose(conn);
    }

    return 0;
}

/**
 * virNWFilterActive:
 *
 * Checks if the nwfilter driver is active, i.e. has an active nwfilter
 *
 * Returns 1 if active, 0 otherwise
 */
static int
nwfilterDriverActive(void) {
    int ret;

    if (!driverState)
        return 0;

    nwfilterDriverLock(driverState);
    ret = driverState->nwfilters.count ? 1 : 0;
    nwfilterDriverUnlock(driverState);

    return ret;
}

/**
 * virNWFilterShutdown:
 *
 * Shutdown the nwfilter driver, it will stop all active nwfilters
 */
static int
nwfilterDriverShutdown(void) {
    if (!driverState)
        return -1;

    virNWFilterConfLayerShutdown();
    virNWFilterTechDriversShutdown();
    virNWFilterLearnShutdown();

    nwfilterDriverLock(driverState);

    /* free inactive nwfilters */
    virNWFilterObjListFree(&driverState->nwfilters);

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
    virNWFilterObjPtr nwfilter;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, uuid);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static virNWFilterPtr
nwfilterLookupByName(virConnectPtr conn,
                     const char *name) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByName(&driver->nwfilters, name);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               _("no nwfilter with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static virDrvOpenStatus
nwfilterOpen(virConnectPtr conn,
             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
             unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
    return driver->nwfilters.count;
}


static int
nwfilterListNWFilters(virConnectPtr conn,
                      char **const names,
                      int nnames) {
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    int got = 0, i;

    nwfilterDriverLock(driver);
    for (i = 0 ; i < driver->nwfilters.count && got < nnames ; i++) {
        virNWFilterObjLock(driver->nwfilters.objs[i]);
        if (!(names[got] = strdup(driver->nwfilters.objs[i]->def->name))) {
             virNWFilterObjUnlock(driver->nwfilters.objs[i]);
             virReportOOMError();
             goto cleanup;
        }
        got++;
        virNWFilterObjUnlock(driver->nwfilters.objs[i]);
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
               const char *xml)
{
    virNWFilterDriverStatePtr driver = conn->nwfilterPrivateData;
    virNWFilterDefPtr def;
    virNWFilterObjPtr nwfilter = NULL;
    virNWFilterPtr ret = NULL;

    nwfilterDriverLock(driver);
    virNWFilterCallbackDriversLock();

    if (!(def = virNWFilterDefParseString(conn, xml)))
        goto cleanup;

    if (!(nwfilter = virNWFilterObjAssignDef(conn, &driver->nwfilters, def)))
        goto cleanup;

    if (virNWFilterObjSaveDef(driver, nwfilter, def) < 0) {
        virNWFilterObjRemove(&driver->nwfilters, nwfilter);
        def = NULL;
        goto cleanup;
    }
    def = NULL;

    ret = virGetNWFilter(conn, nwfilter->def->name, nwfilter->def->uuid);

cleanup:
    virNWFilterDefFree(def);
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);

    virNWFilterCallbackDriversUnlock();
    nwfilterDriverUnlock(driver);
    return ret;
}


static int
nwfilterUndefine(virNWFilterPtr obj) {
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    int ret = -1;

    nwfilterDriverLock(driver);
    virNWFilterCallbackDriversLock();

    virNWFilterLockFilterUpdates();

    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, obj->uuid);
    if (!nwfilter) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    if (virNWFilterTestUnassignDef(obj->conn, nwfilter) < 0) {
        virNWFilterReportError(VIR_ERR_OPERATION_INVALID,
                               "%s",
                               _("nwfilter is in use"));
        goto cleanup;
    }

    if (virNWFilterObjDeleteDef(nwfilter) < 0)
        goto cleanup;

    VIR_FREE(nwfilter->configFile);

    virNWFilterObjRemove(&driver->nwfilters, nwfilter);
    nwfilter = NULL;
    ret = 0;

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);

    virNWFilterUnlockFilterUpdates();

    virNWFilterCallbackDriversUnlock();
    nwfilterDriverUnlock(driver);
    return ret;
}


static char *
nwfilterGetXMLDesc(virNWFilterPtr obj,
                   unsigned int flags)
{
    virNWFilterDriverStatePtr driver = obj->conn->nwfilterPrivateData;
    virNWFilterObjPtr nwfilter;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    nwfilterDriverLock(driver);
    nwfilter = virNWFilterObjFindByUUID(&driver->nwfilters, obj->uuid);
    nwfilterDriverUnlock(driver);

    if (!nwfilter) {
        virNWFilterReportError(VIR_ERR_NO_NWFILTER,
                               "%s", _("no nwfilter with matching uuid"));
        goto cleanup;
    }

    ret = virNWFilterDefFormat(nwfilter->def);

cleanup:
    if (nwfilter)
        virNWFilterObjUnlock(nwfilter);
    return ret;
}


static int
nwfilterInstantiateFilter(virConnectPtr conn,
                          const unsigned char *vmuuid,
                          virDomainNetDefPtr net)
{
    return virNWFilterInstantiateFilter(conn, vmuuid, net);
}


static void
nwfilterTeardownFilter(virDomainNetDefPtr net) {
    if ((net->ifname) && (net->filter))
        virNWFilterTeardownFilter(net);
}


static virNWFilterDriver nwfilterDriver = {
    .name = "nwfilter",
    .open = nwfilterOpen, /* 0.8.0 */
    .close = nwfilterClose, /* 0.8.0 */
    .numOfNWFilters = nwfilterNumNWFilters, /* 0.8.0 */
    .listNWFilters = nwfilterListNWFilters, /* 0.8.0 */
    .nwfilterLookupByName = nwfilterLookupByName, /* 0.8.0 */
    .nwfilterLookupByUUID = nwfilterLookupByUUID, /* 0.8.0 */
    .defineXML = nwfilterDefine, /* 0.8.0 */
    .undefine = nwfilterUndefine, /* 0.8.0 */
    .getXMLDesc = nwfilterGetXMLDesc, /* 0.8.0 */
};


static virStateDriver stateDriver = {
    .name = "NWFilter",
    .initialize = nwfilterDriverStartup,
    .cleanup = nwfilterDriverShutdown,
    .reload = nwfilterDriverReload,
    .active = nwfilterDriverActive,
};


static virDomainConfNWFilterDriver domainNWFilterDriver = {
    .instantiateFilter = nwfilterInstantiateFilter,
    .teardownFilter = nwfilterTeardownFilter,
};


int nwfilterRegister(void) {
    virRegisterNWFilterDriver(&nwfilterDriver);
    virRegisterStateDriver(&stateDriver);
    virDomainConfNWFilterRegister(&domainNWFilterDriver);
    return 0;
}
