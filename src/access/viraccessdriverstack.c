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

#define VIR_FROM_THIS VIR_FROM_ACCESS

typedef struct _virAccessDriverStackPrivate virAccessDriverStackPrivate;
struct _virAccessDriverStackPrivate {
    virAccessManager **managers;
    size_t managersLen;
};


int virAccessDriverStackAppend(virAccessManager *manager,
                               virAccessManager *child)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);

    VIR_EXPAND_N(priv->managers, priv->managersLen, 1);

    priv->managers[priv->managersLen-1] = child;

    return 0;
}


static void virAccessDriverStackCleanup(virAccessManager *manager)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
    size_t i;

    for (i = 0; i < priv->managersLen; i++)
        virObjectUnref(priv->managers[i]);
    VIR_FREE(priv->managers);
}


static int
virAccessDriverStackCheckConnect(virAccessManager *manager,
                                 const char *driverName,
                                 virAccessPermConnect perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckDomain(virAccessManager *manager,
                                const char *driverName,
                                virDomainDef *domain,
                                virAccessPermDomain perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckInterface(virAccessManager *manager,
                                   const char *driverName,
                                   virInterfaceDef *iface,
                                   virAccessPermInterface perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckNetwork(virAccessManager *manager,
                                 const char *driverName,
                                 virNetworkDef *network,
                                 virAccessPermNetwork perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckNetworkPort(virAccessManager *manager,
                                     const char *driverName,
                                     virNetworkDef *network,
                                     virNetworkPortDef *port,
                                     virAccessPermNetworkPort perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckNetworkPort(priv->managers[i], driverName, network, port, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckNodeDevice(virAccessManager *manager,
                                    const char *driverName,
                                    virNodeDeviceDef *nodedev,
                                    virAccessPermNodeDevice perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckNWFilter(virAccessManager *manager,
                                  const char *driverName,
                                  virNWFilterDef *nwfilter,
                                  virAccessPermNWFilter perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckNWFilterBinding(virAccessManager *manager,
                                         const char *driverName,
                                         virNWFilterBindingDef *binding,
                                         virAccessPermNWFilterBinding perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
    int ret = 1;
    size_t i;

    for (i = 0; i < priv->managersLen; i++) {
        int rv;
        /* We do not short-circuit on first denial - always check all drivers */
        rv = virAccessManagerCheckNWFilterBinding(priv->managers[i], driverName, binding, perm);
        if (rv == 0 && ret != -1)
            ret = 0;
        else if (rv < 0)
            ret = -1;
    }

    return ret;
}

static int
virAccessDriverStackCheckSecret(virAccessManager *manager,
                                const char *driverName,
                                virSecretDef *secret,
                                virAccessPermSecret perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckStoragePool(virAccessManager *manager,
                                     const char *driverName,
                                     virStoragePoolDef *pool,
                                     virAccessPermStoragePool perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
virAccessDriverStackCheckStorageVol(virAccessManager *manager,
                                    const char *driverName,
                                    virStoragePoolDef *pool,
                                    virStorageVolDef *vol,
                                    virAccessPermStorageVol perm)
{
    virAccessDriverStackPrivate *priv = virAccessManagerGetPrivateData(manager);
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
    .checkNetworkPort = virAccessDriverStackCheckNetworkPort,
    .checkNodeDevice = virAccessDriverStackCheckNodeDevice,
    .checkNWFilter = virAccessDriverStackCheckNWFilter,
    .checkNWFilterBinding = virAccessDriverStackCheckNWFilterBinding,
    .checkSecret = virAccessDriverStackCheckSecret,
    .checkStoragePool = virAccessDriverStackCheckStoragePool,
    .checkStorageVol = virAccessDriverStackCheckStorageVol,
};
