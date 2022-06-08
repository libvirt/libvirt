/*
 * viraccessdriver.h: access control driver
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

#pragma once

#include "access/viraccessmanager.h"

typedef int (*virAccessDriverCheckConnectDrv)(virAccessManager *manager,
                                              const char *driverName,
                                              virAccessPermConnect av);
typedef int (*virAccessDriverCheckDomainDrv)(virAccessManager *manager,
                                             const char *driverName,
                                             virDomainDef *domain,
                                             virAccessPermDomain av);
typedef int (*virAccessDriverCheckInterfaceDrv)(virAccessManager *manager,
                                                const char *driverName,
                                                virInterfaceDef *iface,
                                                virAccessPermInterface av);
typedef int (*virAccessDriverCheckNetworkDrv)(virAccessManager *manager,
                                              const char *driverName,
                                              virNetworkDef *network,
                                              virAccessPermNetwork av);
typedef int (*virAccessDriverCheckNetworkPortDrv)(virAccessManager *manager,
                                                  const char *driverName,
                                                  virNetworkDef *network,
                                                  virNetworkPortDef *port,
                                                  virAccessPermNetworkPort av);
typedef int (*virAccessDriverCheckNodeDeviceDrv)(virAccessManager *manager,
                                                 const char *driverName,
                                                 virNodeDeviceDef *nodedev,
                                                 virAccessPermNodeDevice av);
typedef int (*virAccessDriverCheckNWFilterDrv)(virAccessManager *manager,
                                               const char *driverName,
                                               virNWFilterDef *nwfilter,
                                               virAccessPermNWFilter av);
typedef int (*virAccessDriverCheckNWFilterBindingDrv)(virAccessManager *manager,
                                                      const char *driverName,
                                                      virNWFilterBindingDef *binding,
                                                      virAccessPermNWFilterBinding av);
typedef int (*virAccessDriverCheckSecretDrv)(virAccessManager *manager,
                                             const char *driverName,
                                             virSecretDef *secret,
                                             virAccessPermSecret av);
typedef int (*virAccessDriverCheckStoragePoolDrv)(virAccessManager *manager,
                                                  const char *driverName,
                                                  virStoragePoolDef *pool,
                                                  virAccessPermStoragePool av);
typedef int (*virAccessDriverCheckStorageVolDrv)(virAccessManager *manager,
                                                 const char *driverName,
                                                 virStoragePoolDef *pool,
                                                 virStorageVolDef *vol,
                                                 virAccessPermStorageVol av);

typedef int (*virAccessDriverSetupDrv)(virAccessManager *manager);
typedef void (*virAccessDriverCleanupDrv)(virAccessManager *manager);

typedef struct _virAccessDriver virAccessDriver;
struct _virAccessDriver {
    size_t privateDataLen;
    const char *name;

    virAccessDriverSetupDrv setup;
    virAccessDriverCleanupDrv cleanup;

    virAccessDriverCheckConnectDrv checkConnect;
    virAccessDriverCheckDomainDrv checkDomain;
    virAccessDriverCheckInterfaceDrv checkInterface;
    virAccessDriverCheckNetworkDrv checkNetwork;
    virAccessDriverCheckNetworkPortDrv checkNetworkPort;
    virAccessDriverCheckNodeDeviceDrv checkNodeDevice;
    virAccessDriverCheckNWFilterDrv checkNWFilter;
    virAccessDriverCheckNWFilterBindingDrv checkNWFilterBinding;
    virAccessDriverCheckSecretDrv checkSecret;
    virAccessDriverCheckStoragePoolDrv checkStoragePool;
    virAccessDriverCheckStorageVolDrv checkStorageVol;
};
