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

#pragma once

#include "viridentity.h"
#include "conf/network_conf.h"
#include "conf/nwfilter_conf.h"
#include "conf/node_device_conf.h"
#include "conf/storage_conf.h"
#include "conf/secret_conf.h"
#include "conf/interface_conf.h"
#include "conf/virnwfilterbindingdef.h"
#include "conf/virnetworkportdef.h"
#include "access/viraccessperm.h"

typedef struct _virAccessManager virAccessManager;

virAccessManager *virAccessManagerGetDefault(void);
void virAccessManagerSetDefault(virAccessManager *manager);

virAccessManager *virAccessManagerNew(const char *name);
virAccessManager *virAccessManagerNewStack(const char **names);


void *virAccessManagerGetPrivateData(virAccessManager *manager);


/*
 * The virAccessManagerCheckXXX functions will
 * Return -1 on error
 * Return 0 on auth deny
 * Return 1 on auth allow
 */
int virAccessManagerCheckConnect(virAccessManager *manager,
                                 const char *driverName,
                                 virAccessPermConnect perm);
int virAccessManagerCheckDomain(virAccessManager *manager,
                                const char *driverName,
                                virDomainDef *domain,
                                virAccessPermDomain perm);
int virAccessManagerCheckInterface(virAccessManager *manager,
                                   const char *driverName,
                                   virInterfaceDef *iface,
                                   virAccessPermInterface perm);
int virAccessManagerCheckNetwork(virAccessManager *manager,
                                 const char *driverName,
                                 virNetworkDef *network,
                                 virAccessPermNetwork perm);
int virAccessManagerCheckNetworkPort(virAccessManager *manager,
                                     const char *driverName,
                                     virNetworkDef *network,
                                     virNetworkPortDef *port,
                                     virAccessPermNetworkPort perm);
int virAccessManagerCheckNodeDevice(virAccessManager *manager,
                                    const char *driverName,
                                    virNodeDeviceDef *nodedev,
                                    virAccessPermNodeDevice perm);
int virAccessManagerCheckNWFilter(virAccessManager *manager,
                                  const char *driverName,
                                  virNWFilterDef *nwfilter,
                                  virAccessPermNWFilter perm);
int virAccessManagerCheckNWFilterBinding(virAccessManager *manager,
                                         const char *driverName,
                                         virNWFilterBindingDef *binding,
                                         virAccessPermNWFilterBinding perm);
int virAccessManagerCheckSecret(virAccessManager *manager,
                                const char *driverName,
                                virSecretDef *secret,
                                virAccessPermSecret perm);
int virAccessManagerCheckStoragePool(virAccessManager *manager,
                                     const char *driverName,
                                     virStoragePoolDef *pool,
                                     virAccessPermStoragePool perm);
int virAccessManagerCheckStorageVol(virAccessManager *manager,
                                    const char *driverName,
                                    virStoragePoolDef *pool,
                                    virStorageVolDef *vol,
                                    virAccessPermStorageVol perm);
