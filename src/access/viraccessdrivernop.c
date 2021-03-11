/*
 * viraccessdrivernop.c: no-op access control driver
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

#include "access/viraccessdrivernop.h"

static int
virAccessDriverNopCheckConnect(virAccessManager *manager G_GNUC_UNUSED,
                               const char *driverName G_GNUC_UNUSED,
                               virAccessPermConnect perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckDomain(virAccessManager *manager G_GNUC_UNUSED,
                              const char *driverName G_GNUC_UNUSED,
                              virDomainDef *domain G_GNUC_UNUSED,
                              virAccessPermDomain perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckInterface(virAccessManager *manager G_GNUC_UNUSED,
                                 const char *driverName G_GNUC_UNUSED,
                                 virInterfaceDef *iface G_GNUC_UNUSED,
                                 virAccessPermInterface perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetwork(virAccessManager *manager G_GNUC_UNUSED,
                               const char *driverName G_GNUC_UNUSED,
                               virNetworkDef *network G_GNUC_UNUSED,
                               virAccessPermNetwork perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetworkPort(virAccessManager *manager G_GNUC_UNUSED,
                                   const char *driverName G_GNUC_UNUSED,
                                   virNetworkDef *network G_GNUC_UNUSED,
                                   virNetworkPortDef *port G_GNUC_UNUSED,
                                   virAccessPermNetworkPort perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNodeDevice(virAccessManager *manager G_GNUC_UNUSED,
                                  const char *driverName G_GNUC_UNUSED,
                                  virNodeDeviceDef *nodedev G_GNUC_UNUSED,
                                  virAccessPermNodeDevice perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilter(virAccessManager *manager G_GNUC_UNUSED,
                                const char *driverName G_GNUC_UNUSED,
                                virNWFilterDef *nwfilter G_GNUC_UNUSED,
                                virAccessPermNWFilter perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilterBinding(virAccessManager *manager G_GNUC_UNUSED,
                                       const char *driverName G_GNUC_UNUSED,
                                       virNWFilterBindingDef *binding G_GNUC_UNUSED,
                                       virAccessPermNWFilterBinding perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckSecret(virAccessManager *manager G_GNUC_UNUSED,
                              const char *driverName G_GNUC_UNUSED,
                              virSecretDef *secret G_GNUC_UNUSED,
                              virAccessPermSecret perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStoragePool(virAccessManager *manager G_GNUC_UNUSED,
                                   const char *driverName G_GNUC_UNUSED,
                                   virStoragePoolDef *pool G_GNUC_UNUSED,
                                   virAccessPermStoragePool perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStorageVol(virAccessManager *manager G_GNUC_UNUSED,
                                  const char *driverName G_GNUC_UNUSED,
                                  virStoragePoolDef *pool G_GNUC_UNUSED,
                                  virStorageVolDef *vol G_GNUC_UNUSED,
                                  virAccessPermStorageVol perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}


virAccessDriver accessDriverNop = {
    .name = "none",
    .checkConnect = virAccessDriverNopCheckConnect,
    .checkDomain = virAccessDriverNopCheckDomain,
    .checkInterface = virAccessDriverNopCheckInterface,
    .checkNetwork = virAccessDriverNopCheckNetwork,
    .checkNetworkPort = virAccessDriverNopCheckNetworkPort,
    .checkNodeDevice = virAccessDriverNopCheckNodeDevice,
    .checkNWFilter = virAccessDriverNopCheckNWFilter,
    .checkNWFilterBinding = virAccessDriverNopCheckNWFilterBinding,
    .checkSecret = virAccessDriverNopCheckSecret,
    .checkStoragePool = virAccessDriverNopCheckStoragePool,
    .checkStorageVol = virAccessDriverNopCheckStorageVol,
};
