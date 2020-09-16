/*
 * driver-secret.h: entry points for secret drivers
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef __VIR_DRIVER_H_INCLUDES___
# error "Don't include this file directly, only use driver.h"
#endif

typedef virSecretPtr
(*virDrvSecretLookupByUUID)(virConnectPtr conn,
                            const unsigned char *uuid);

typedef virSecretPtr
(*virDrvSecretLookupByUsage)(virConnectPtr conn,
                             int usageType,
                             const char *usageID);

typedef virSecretPtr
(*virDrvSecretDefineXML)(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags);

typedef char *
(*virDrvSecretGetXMLDesc)(virSecretPtr secret,
                          unsigned int flags);

typedef int
(*virDrvSecretSetValue)(virSecretPtr secret,
                        const unsigned char *value,
                        size_t value_size,
                        unsigned int flags);

typedef unsigned char *
(*virDrvSecretGetValue)(virSecretPtr secret,
                        size_t *value_size,
                        unsigned int flags);

typedef int
(*virDrvSecretUndefine)(virSecretPtr secret);

typedef int
(*virDrvConnectNumOfSecrets)(virConnectPtr conn);

typedef int
(*virDrvConnectListSecrets)(virConnectPtr conn,
                            char **uuids,
                            int maxuuids);

typedef int
(*virDrvConnectListAllSecrets)(virConnectPtr conn,
                               virSecretPtr **secrets,
                               unsigned int flags);

typedef int
(*virDrvConnectSecretEventRegisterAny)(virConnectPtr conn,
                                       virSecretPtr secret,
                                       int eventID,
                                       virConnectSecretEventGenericCallback cb,
                                       void *opaque,
                                       virFreeCallback freecb);

typedef int
(*virDrvConnectSecretEventDeregisterAny)(virConnectPtr conn,
                                         int callbackID);

typedef struct _virSecretDriver virSecretDriver;

/**
 * _virSecretDriver:
 *
 * Structure associated to a driver for storing secrets, defining the various
 * entry points for it.
 */
struct _virSecretDriver {
    const char *name; /* the name of the driver */
    virDrvConnectNumOfSecrets connectNumOfSecrets;
    virDrvConnectListSecrets connectListSecrets;
    virDrvConnectListAllSecrets connectListAllSecrets;
    virDrvSecretLookupByUUID secretLookupByUUID;
    virDrvSecretLookupByUsage secretLookupByUsage;
    virDrvSecretDefineXML secretDefineXML;
    virDrvSecretGetXMLDesc secretGetXMLDesc;
    virDrvSecretSetValue secretSetValue;
    virDrvSecretGetValue secretGetValue;
    virDrvSecretUndefine secretUndefine;
    virDrvConnectSecretEventRegisterAny connectSecretEventRegisterAny;
    virDrvConnectSecretEventDeregisterAny connectSecretEventDeregisterAny;
};
