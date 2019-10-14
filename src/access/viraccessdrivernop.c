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
virAccessDriverNopCheckConnect(virAccessManagerPtr manager G_GNUC_UNUSED,
                               const char *driverName G_GNUC_UNUSED,
                               virAccessPermConnect perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckDomain(virAccessManagerPtr manager G_GNUC_UNUSED,
                              const char *driverName G_GNUC_UNUSED,
                              virDomainDefPtr domain G_GNUC_UNUSED,
                              virAccessPermDomain perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckInterface(virAccessManagerPtr manager G_GNUC_UNUSED,
                                 const char *driverName G_GNUC_UNUSED,
                                 virInterfaceDefPtr iface G_GNUC_UNUSED,
                                 virAccessPermInterface perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetwork(virAccessManagerPtr manager G_GNUC_UNUSED,
                               const char *driverName G_GNUC_UNUSED,
                               virNetworkDefPtr network G_GNUC_UNUSED,
                               virAccessPermNetwork perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetworkPort(virAccessManagerPtr manager G_GNUC_UNUSED,
                                   const char *driverName G_GNUC_UNUSED,
                                   virNetworkDefPtr network G_GNUC_UNUSED,
                                   virNetworkPortDefPtr port G_GNUC_UNUSED,
                                   virAccessPermNetworkPort perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNodeDevice(virAccessManagerPtr manager G_GNUC_UNUSED,
                                  const char *driverName G_GNUC_UNUSED,
                                  virNodeDeviceDefPtr nodedev G_GNUC_UNUSED,
                                  virAccessPermNodeDevice perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilter(virAccessManagerPtr manager G_GNUC_UNUSED,
                                const char *driverName G_GNUC_UNUSED,
                                virNWFilterDefPtr nwfilter G_GNUC_UNUSED,
                                virAccessPermNWFilter perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilterBinding(virAccessManagerPtr manager G_GNUC_UNUSED,
                                       const char *driverName G_GNUC_UNUSED,
                                       virNWFilterBindingDefPtr binding G_GNUC_UNUSED,
                                       virAccessPermNWFilterBinding perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckSecret(virAccessManagerPtr manager G_GNUC_UNUSED,
                              const char *driverName G_GNUC_UNUSED,
                              virSecretDefPtr secret G_GNUC_UNUSED,
                              virAccessPermSecret perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStoragePool(virAccessManagerPtr manager G_GNUC_UNUSED,
                                   const char *driverName G_GNUC_UNUSED,
                                   virStoragePoolDefPtr pool G_GNUC_UNUSED,
                                   virAccessPermStoragePool perm G_GNUC_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStorageVol(virAccessManagerPtr manager G_GNUC_UNUSED,
                                  const char *driverName G_GNUC_UNUSED,
                                  virStoragePoolDefPtr pool G_GNUC_UNUSED,
                                  virStorageVolDefPtr vol G_GNUC_UNUSED,
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
