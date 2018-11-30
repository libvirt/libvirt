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
virAccessDriverNopCheckConnect(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                               const char *driverName ATTRIBUTE_UNUSED,
                               virAccessPermConnect perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckDomain(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                              const char *driverName ATTRIBUTE_UNUSED,
                              virDomainDefPtr domain ATTRIBUTE_UNUSED,
                              virAccessPermDomain perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckInterface(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                 const char *driverName ATTRIBUTE_UNUSED,
                                 virInterfaceDefPtr iface ATTRIBUTE_UNUSED,
                                 virAccessPermInterface perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetwork(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                               const char *driverName ATTRIBUTE_UNUSED,
                               virNetworkDefPtr network ATTRIBUTE_UNUSED,
                               virAccessPermNetwork perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNetworkPort(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                   const char *driverName ATTRIBUTE_UNUSED,
                                   virNetworkDefPtr network ATTRIBUTE_UNUSED,
                                   virNetworkPortDefPtr port ATTRIBUTE_UNUSED,
                                   virAccessPermNetworkPort perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNodeDevice(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                  const char *driverName ATTRIBUTE_UNUSED,
                                  virNodeDeviceDefPtr nodedev ATTRIBUTE_UNUSED,
                                  virAccessPermNodeDevice perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilter(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                const char *driverName ATTRIBUTE_UNUSED,
                                virNWFilterDefPtr nwfilter ATTRIBUTE_UNUSED,
                                virAccessPermNWFilter perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckNWFilterBinding(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                       const char *driverName ATTRIBUTE_UNUSED,
                                       virNWFilterBindingDefPtr binding ATTRIBUTE_UNUSED,
                                       virAccessPermNWFilterBinding perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckSecret(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                              const char *driverName ATTRIBUTE_UNUSED,
                              virSecretDefPtr secret ATTRIBUTE_UNUSED,
                              virAccessPermSecret perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStoragePool(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                   const char *driverName ATTRIBUTE_UNUSED,
                                   virStoragePoolDefPtr pool ATTRIBUTE_UNUSED,
                                   virAccessPermStoragePool perm ATTRIBUTE_UNUSED)
{
    return 1; /* Allow */
}

static int
virAccessDriverNopCheckStorageVol(virAccessManagerPtr manager ATTRIBUTE_UNUSED,
                                  const char *driverName ATTRIBUTE_UNUSED,
                                  virStoragePoolDefPtr pool ATTRIBUTE_UNUSED,
                                  virStorageVolDefPtr vol ATTRIBUTE_UNUSED,
                                  virAccessPermStorageVol perm ATTRIBUTE_UNUSED)
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
