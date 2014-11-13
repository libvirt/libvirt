/*
 * viraccessdriverstack.c: stacked access control driver
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

#include "viraccessdriverstack.h"
#include "viralloc.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_ACCESS

typedef struct _virAccessDriverStackPrivate virAccessDriverStackPrivate;
typedef virAccessDriverStackPrivate *virAccessDriverStackPrivatePtr;

struct _virAccessDriverStackPrivate {
    virAccessManagerPtr *managers;
    size_t managersLen;
};


int virAccessDriverStackAppend(virAccessManagerPtr manager,
                               virAccessManagerPtr child)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);

    if (VIR_EXPAND_N(priv->managers, priv->managersLen, 1) < 0)
        return -1;

    priv->managers[priv->managersLen-1] = child;

    return 0;
}


static void virAccessDriverStackCleanup(virAccessManagerPtr manager)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    size_t i;

    for (i = 0; i < priv->managersLen; i++)
        virObjectUnref(priv->managers[i]);
    VIR_FREE(priv->managers);
}


static int
virAccessDriverStackCheckConnect(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virAccessPermConnect perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckConnect(priv->managers[i], driverName, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckDomain(virAccessManagerPtr manager,
                                const char *driverName,
                                virDomainDefPtr domain,
                                virAccessPermDomain perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckDomain(priv->managers[i], driverName, domain, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckInterface(virAccessManagerPtr manager,
                                   const char *driverName,
                                   virInterfaceDefPtr iface,
                                   virAccessPermInterface perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckInterface(priv->managers[i], driverName, iface, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckNetwork(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virNetworkDefPtr network,
                                 virAccessPermNetwork perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckNetwork(priv->managers[i], driverName, network, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckNodeDevice(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virNodeDeviceDefPtr nodedev,
                                    virAccessPermNodeDevice perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckNodeDevice(priv->managers[i], driverName, nodedev, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckNWFilter(virAccessManagerPtr manager,
                                  const char *driverName,
                                  virNWFilterDefPtr nwfilter,
                                  virAccessPermNWFilter perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckNWFilter(priv->managers[i], driverName, nwfilter, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckSecret(virAccessManagerPtr manager,
                                const char *driverName,
                                virSecretDefPtr secret,
                                virAccessPermSecret perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckSecret(priv->managers[i], driverName, secret, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckStoragePool(virAccessManagerPtr manager,
                                     const char *driverName,
                                     virStoragePoolDefPtr pool,
                                     virAccessPermStoragePool perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckStoragePool(priv->managers[i], driverName, pool, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckStorageVol(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virStoragePoolDefPtr pool,
                                    virStorageVolDefPtr vol,
                                    virAccessPermStorageVol perm)
{
    virAccessDriverStackPrivatePtr priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckStorageVol(priv->managers[i], driverName, pool, vol, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

virAccessDriver accessDriverStack = {
    .privateDataLen = sizeof(virAccessDriverStackPrivate),
    .name = "stack",
    .cleanup = virAccessDriverStackCleanup,
    .checkConnect = virAccessDriverStackCheckConnect,
    .checkDomain = virAccessDriverStackCheckDomain,
    .checkInterface = virAccessDriverStackCheckInterface,
    .checkNetwork = virAccessDriverStackCheckNetwork,
    .checkNodeDevice = virAccessDriverStackCheckNodeDevice,
    .checkNWFilter = virAccessDriverStackCheckNWFilter,
    .checkSecret = virAccessDriverStackCheckSecret,
    .checkStoragePool = virAccessDriverStackCheckStoragePool,
    .checkStorageVol = virAccessDriverStackCheckStorageVol,
};
