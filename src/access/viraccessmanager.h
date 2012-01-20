/*
 * viraccessmanager.h: access control manager
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

#ifndef __VIR_ACCESS_MANAGER_H__
# define __VIR_ACCESS_MANAGER_H__

# include "viridentity.h"
# include "conf/domain_conf.h"
# include "conf/network_conf.h"
# include "conf/nwfilter_conf.h"
# include "conf/node_device_conf.h"
# include "conf/storage_conf.h"
# include "conf/secret_conf.h"
# include "conf/interface_conf.h"
# include "access/viraccessperm.h"

typedef struct _virAccessManager virAccessManager;
typedef virAccessManager *virAccessManagerPtr;

virAccessManagerPtr virAccessManagerGetDefault(void);
void virAccessManagerSetDefault(virAccessManagerPtr manager);

virAccessManagerPtr virAccessManagerNew(const char *name);
virAccessManagerPtr virAccessManagerNewStack(const char **names);


void *virAccessManagerGetPrivateData(virAccessManagerPtr manager);


/*
 * The virAccessManagerCheckXXX functions will
 * Return -1 on error
 * Return 0 on auth deny
 * Return 1 on auth allow
 */
int virAccessManagerCheckConnect(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virAccessPermConnect perm);
int virAccessManagerCheckDomain(virAccessManagerPtr manager,
                                const char *driverName,
                                virDomainDefPtr domain,
                                virAccessPermDomain perm);
int virAccessManagerCheckInterface(virAccessManagerPtr manager,
                                   const char *driverName,
                                   virInterfaceDefPtr iface,
                                   virAccessPermInterface perm);
int virAccessManagerCheckNetwork(virAccessManagerPtr manager,
                                 const char *driverName,
                                 virNetworkDefPtr network,
                                 virAccessPermNetwork perm);
int virAccessManagerCheckNodeDevice(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virNodeDeviceDefPtr nodedev,
                                    virAccessPermNodeDevice perm);
int virAccessManagerCheckNWFilter(virAccessManagerPtr manager,
                                  const char *driverName,
                                  virNWFilterDefPtr nwfilter,
                                  virAccessPermNWFilter perm);
int virAccessManagerCheckSecret(virAccessManagerPtr manager,
                                const char *driverName,
                                virSecretDefPtr secret,
                                virAccessPermSecret perm);
int virAccessManagerCheckStoragePool(virAccessManagerPtr manager,
                                     const char *driverName,
                                     virStoragePoolDefPtr pool,
                                     virAccessPermStoragePool perm);
int virAccessManagerCheckStorageVol(virAccessManagerPtr manager,
                                    const char *driverName,
                                    virStoragePoolDefPtr pool,
                                    virStorageVolDefPtr vol,
                                    virAccessPermStorageVol perm);


#endif /* __VIR_ACCESS_MANAGER_H__ */
