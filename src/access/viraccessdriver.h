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

#ifndef __VIR_ACCESS_DRIVER_H__
# define __VIR_ACCESS_DRIVER_H__

# include "conf/domain_conf.h"
# include "access/viraccessmanager.h"

typedef int (*virAccessDriverCheckConnectDrv)(virAccessManagerPtr manager,
                                              const char *driverName,
                                              virAccessPermConnect av);
typedef int (*virAccessDriverCheckDomainDrv)(virAccessManagerPtr manager,
                                             const char *driverName,
                                             virDomainDefPtr domain,
                                             virAccessPermDomain av);
typedef int (*virAccessDriverCheckInterfaceDrv)(virAccessManagerPtr manager,
                                                const char *driverName,
                                                virInterfaceDefPtr iface,
                                                virAccessPermInterface av);
typedef int (*virAccessDriverCheckNetworkDrv)(virAccessManagerPtr manager,
                                              const char *driverName,
                                              virNetworkDefPtr network,
                                              virAccessPermNetwork av);
typedef int (*virAccessDriverCheckNodeDeviceDrv)(virAccessManagerPtr manager,
                                                 const char *driverName,
                                                 virNodeDeviceDefPtr nodedev,
                                                 virAccessPermNodeDevice av);
typedef int (*virAccessDriverCheckNWFilterDrv)(virAccessManagerPtr manager,
                                               const char *driverName,
                                               virNWFilterDefPtr nwfilter,
                                               virAccessPermNWFilter av);
typedef int (*virAccessDriverCheckSecretDrv)(virAccessManagerPtr manager,
                                             const char *driverName,
                                             virSecretDefPtr secret,
                                             virAccessPermSecret av);
typedef int (*virAccessDriverCheckStoragePoolDrv)(virAccessManagerPtr manager,
                                                  const char *driverName,
                                                  virStoragePoolDefPtr pool,
                                                  virAccessPermStoragePool av);
typedef int (*virAccessDriverCheckStorageVolDrv)(virAccessManagerPtr manager,
                                                 const char *driverName,
                                                 virStoragePoolDefPtr pool,
                                                 virStorageVolDefPtr vol,
                                                 virAccessPermStorageVol av);

typedef int (*virAccessDriverSetupDrv)(virAccessManagerPtr manager);
typedef void (*virAccessDriverCleanupDrv)(virAccessManagerPtr manager);

typedef struct _virAccessDriver virAccessDriver;
typedef virAccessDriver *virAccessDriverPtr;

struct _virAccessDriver {
    size_t privateDataLen;
    const char *name;

    virAccessDriverSetupDrv setup;
    virAccessDriverCleanupDrv cleanup;

    virAccessDriverCheckConnectDrv checkConnect;
    virAccessDriverCheckDomainDrv checkDomain;
    virAccessDriverCheckInterfaceDrv checkInterface;
    virAccessDriverCheckNetworkDrv checkNetwork;
    virAccessDriverCheckNodeDeviceDrv checkNodeDevice;
    virAccessDriverCheckNWFilterDrv checkNWFilter;
    virAccessDriverCheckSecretDrv checkSecret;
    virAccessDriverCheckStoragePoolDrv checkStoragePool;
    virAccessDriverCheckStorageVolDrv checkStorageVol;
};


#endif /* __VIR_ACCESS_DRIVER_H__ */
