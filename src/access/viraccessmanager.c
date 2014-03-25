/*
 * viraccessmanager.c: access control manager
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
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

#include "viraccessmanager.h"
#include "viraccessdrivernop.h"
#include "viraccessdriverstack.h"
#if WITH_POLKIT1
# include "viraccessdriverpolkit.h"
#endif
#include "viralloc.h"
#include "virerror.h"
#include "virobject.h"
#include "virthread.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_ACCESS

VIR_LOG_INIT("access.accessmanager");

#define virAccessError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virAccessManager {
    virObjectLockable parent;

    virAccessDriverPtr drv;
    void *privateData;
};

static virClassPtr virAccessManagerClass;
static virAccessManagerPtr virAccessManagerDefault;

static void virAccessManagerDispose(void *obj);

static int virAccessManagerOnceInit(void)
{
    if (!(virAccessManagerClass = virClassNew(virClassForObjectLockable(),
                                              "virAccessManagerClass",
                                              sizeof(virAccessManager),
                                              virAccessManagerDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virAccessManager);


virAccessManagerPtr virAccessManagerGetDefault(void)
{
    return virObjectRef(virAccessManagerDefault);
}


void virAccessManagerSetDefault(virAccessManagerPtr mgr)
{
    virObjectUnref(virAccessManagerDefault);

    virAccessManagerDefault = virObjectRef(mgr);
}


static virAccessManagerPtr virAccessManagerNewDriver(virAccessDriverPtr drv)
{
    virAccessManagerPtr mgr;
    char *privateData;

    if (virAccessManagerInitialize() < 0)
        return NULL;

    if (VIR_ALLOC_N(privateData, drv->privateDataLen) < 0)
        return NULL;

    if (!(mgr = virObjectLockableNew(virAccessManagerClass))) {
        VIR_FREE(privateData);
        return NULL;
    }

    mgr->drv = drv;
    mgr->privateData = privateData;

    if (mgr->drv->setup &&
        mgr->drv->setup(mgr) < 0) {
        virObjectUnref(mgr);
        return NULL;
    }

    VIR_DEBUG("Initialized with %s", mgr->drv->name);
    return mgr;
}


static virAccessDriverPtr accessDrivers[] = {
    &accessDriverNop,
#if WITH_POLKIT1
    &accessDriverPolkit,
#endif
};


static virAccessDriverPtr virAccessManagerFindDriver(const char *name)
{
    size_t i;
    for (i = 0; i < ARRAY_CARDINALITY(accessDrivers); i++) {
        if (STREQ(name, accessDrivers[i]->name))
            return accessDrivers[i];
    }

    return NULL;
}


virAccessManagerPtr virAccessManagerNew(const char *name)
{
    virAccessDriverPtr drv;

    if (virAccessManagerInitialize() < 0)
        return NULL;

    if (!(drv = virAccessManagerFindDriver(name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find security driver '%s'"),
                       name);
        return NULL;
    }

    return virAccessManagerNewDriver(drv);
}


virAccessManagerPtr virAccessManagerNewStack(const char **names)
{
    virAccessManagerPtr manager = virAccessManagerNewDriver(&accessDriverStack);
    size_t i;

    if (!manager)
        return NULL;

    for (i = 0; names[i] != NULL; i++) {
        virAccessManagerPtr child = virAccessManagerNew(names[i]);

        if (!child)
            goto error;

        if (virAccessDriverStackAppend(manager, child) < 0) {
            virObjectUnref(child);
            goto error;
        }
    }

    return manager;

 error:
    virObjectUnref(manager);
    return NULL;
}


void *virAccessManagerGetPrivateData(virAccessManagerPtr mgr)
{
    return mgr->privateData;
}


static void virAccessManagerDispose(void *object)
{
    virAccessManagerPtr mgr = object;

    if (mgr->drv->cleanup)
        mgr->drv->cleanup(mgr);
    VIR_FREE(mgr->privateData);
}


/* Standard security practice is to not tell the caller *why*
 * they were denied access. So this method takes the real
 * libvirt errors & replaces it with a generic error. Fortunately
 * the daemon logs will still contain the original error message
 * should the admin need to debug things
 */
static int
virAccessManagerSanitizeError(int ret)
{
    if (ret < 0) {
        virResetLastError();
        virAccessError(VIR_ERR_ACCESS_DENIED, NULL);
    }

    return ret;
}

int virAccessManagerCheckConnect(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virAccessPermConnect perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s perm=%d",
              manager, manager->drv->name, driverName, perm);

    if (manager->drv->checkConnect)
        ret = manager->drv->checkConnect(manager, driverName, perm);

    return virAccessManagerSanitizeError(ret);
}


int virAccessManagerCheckDomain(virAccessManagerPtr manager,
                                const char *driverName,
                                virDomainDefPtr domain,
                                virAccessPermDomain perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s domain=%p perm=%d",
              manager, manager->drv->name, driverName, domain, perm);

    if (manager->drv->checkDomain)
        ret = manager->drv->checkDomain(manager, driverName, domain, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckInterface(virAccessManagerPtr manager,
                                   const char *driverName,
                                   virInterfaceDefPtr iface,
                                   virAccessPermInterface perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s iface=%p perm=%d",
              manager, manager->drv->name, driverName, iface, perm);

    if (manager->drv->checkInterface)
        ret = manager->drv->checkInterface(manager, driverName, iface, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckNetwork(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virNetworkDefPtr network,
                                 virAccessPermNetwork perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s network=%p perm=%d",
              manager, manager->drv->name, driverName, network, perm);

    if (manager->drv->checkNetwork)
        ret = manager->drv->checkNetwork(manager, driverName, network, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckNodeDevice(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virNodeDeviceDefPtr nodedev,
                                    virAccessPermNodeDevice perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s nodedev=%p perm=%d",
              manager, manager->drv->name, driverName, nodedev, perm);

    if (manager->drv->checkNodeDevice)
        ret = manager->drv->checkNodeDevice(manager, driverName, nodedev, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckNWFilter(virAccessManagerPtr manager,
                                  const char *driverName,
                                  virNWFilterDefPtr nwfilter,
                                  virAccessPermNWFilter perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s nwfilter=%p perm=%d",
              manager, manager->drv->name, driverName, nwfilter, perm);

    if (manager->drv->checkNWFilter)
        ret = manager->drv->checkNWFilter(manager, driverName, nwfilter, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckSecret(virAccessManagerPtr manager,
                                const char *driverName,
                                virSecretDefPtr secret,
                                virAccessPermSecret perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s secret=%p perm=%d",
              manager, manager->drv->name, driverName, secret, perm);

    if (manager->drv->checkSecret)
        ret = manager->drv->checkSecret(manager, driverName, secret, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckStoragePool(virAccessManagerPtr manager,
                                     const char *driverName,
                                     virStoragePoolDefPtr pool,
                                     virAccessPermStoragePool perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s pool=%p perm=%d",
              manager, manager->drv->name, driverName, pool, perm);

    if (manager->drv->checkStoragePool)
        ret = manager->drv->checkStoragePool(manager, driverName, pool, perm);

    return virAccessManagerSanitizeError(ret);
}

int virAccessManagerCheckStorageVol(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virStoragePoolDefPtr pool,
                                    virStorageVolDefPtr vol,
                                    virAccessPermStorageVol perm)
{
    int ret = 0;
    VIR_DEBUG("manager=%p(name=%s) driver=%s pool=%p vol=%p perm=%d",
              manager, manager->drv->name, driverName, pool, vol, perm);

    if (manager->drv->checkStorageVol)
        ret = manager->drv->checkStorageVol(manager, driverName, pool, vol, perm);

    return virAccessManagerSanitizeError(ret);
}
