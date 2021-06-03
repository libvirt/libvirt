/*
 * driver-nodedev.h: entry points for nodedev drivers
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

typedef int
(*virDrvNodeNumOfDevices)(virConnectPtr conn,
                          const char *cap,
                          unsigned int flags);

typedef int
(*virDrvNodeListDevices)(virConnectPtr conn,
                         const char *cap,
                         char **const names,
                         int maxnames,
                         unsigned int flags);

typedef int
(*virDrvConnectListAllNodeDevices)(virConnectPtr conn,
                                   virNodeDevicePtr **devices,
                                   unsigned int flags);

typedef virNodeDevicePtr
(*virDrvNodeDeviceLookupByName)(virConnectPtr conn,
                                const char *name);

typedef virNodeDevicePtr
(*virDrvNodeDeviceLookupSCSIHostByWWN)(virConnectPtr conn,
                                       const char *wwnn,
                                       const char *wwpn,
                                       unsigned int flags);

typedef char *
(*virDrvNodeDeviceGetXMLDesc)(virNodeDevicePtr dev,
                              unsigned int flags);

typedef char *
(*virDrvNodeDeviceGetParent)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceNumOfCaps)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceListCaps)(virNodeDevicePtr dev,
                            char **const names,
                            int maxnames);

typedef virNodeDevicePtr
(*virDrvNodeDeviceCreateXML)(virConnectPtr conn,
                             const char *xmlDesc,
                             unsigned int flags);

typedef int
(*virDrvNodeDeviceDestroy)(virNodeDevicePtr dev);

typedef virNodeDevicePtr
(*virDrvNodeDeviceDefineXML)(virConnectPtr conn,
                             const char *xmlDesc,
                             unsigned int flags);

typedef int
(*virDrvNodeDeviceUndefine)(virNodeDevicePtr dev,
                            unsigned int flags);

typedef int
(*virDrvNodeDeviceCreate)(virNodeDevicePtr dev,
                          unsigned int flags);

typedef int
(*virDrvNodeDeviceSetAutostart)(virNodeDevicePtr dev,
                                int autostart);

typedef int
(*virDrvNodeDeviceGetAutostart)(virNodeDevicePtr dev,
                                int *autostart);

typedef int
(*virDrvNodeDeviceIsPersistent)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceIsActive)(virNodeDevicePtr dev);

typedef int
(*virDrvConnectNodeDeviceEventRegisterAny)(virConnectPtr conn,
                                           virNodeDevicePtr dev,
                                           int eventID,
                                           virConnectNodeDeviceEventGenericCallback cb,
                                           void *opaque,
                                           virFreeCallback freecb);

typedef int
(*virDrvConnectNodeDeviceEventDeregisterAny)(virConnectPtr conn,
                                             int callbackID);



typedef struct _virNodeDeviceDriver virNodeDeviceDriver;

/**
 * _virNodeDeviceDriver:
 *
 * Structure associated with monitoring the devices
 * on a virtualized node.
 *
 */
struct _virNodeDeviceDriver {
    const char *name; /* the name of the driver */
    virDrvNodeNumOfDevices nodeNumOfDevices;
    virDrvNodeListDevices nodeListDevices;
    virDrvConnectListAllNodeDevices connectListAllNodeDevices;
    virDrvConnectNodeDeviceEventRegisterAny connectNodeDeviceEventRegisterAny;
    virDrvConnectNodeDeviceEventDeregisterAny connectNodeDeviceEventDeregisterAny;
    virDrvNodeDeviceLookupByName nodeDeviceLookupByName;
    virDrvNodeDeviceLookupSCSIHostByWWN nodeDeviceLookupSCSIHostByWWN;
    virDrvNodeDeviceGetXMLDesc nodeDeviceGetXMLDesc;
    virDrvNodeDeviceGetParent nodeDeviceGetParent;
    virDrvNodeDeviceNumOfCaps nodeDeviceNumOfCaps;
    virDrvNodeDeviceListCaps nodeDeviceListCaps;
    virDrvNodeDeviceCreateXML nodeDeviceCreateXML;
    virDrvNodeDeviceDestroy nodeDeviceDestroy;
    virDrvNodeDeviceDefineXML nodeDeviceDefineXML;
    virDrvNodeDeviceUndefine nodeDeviceUndefine;
    virDrvNodeDeviceCreate nodeDeviceCreate;
    virDrvNodeDeviceSetAutostart nodeDeviceSetAutostart;
    virDrvNodeDeviceGetAutostart nodeDeviceGetAutostart;
    virDrvNodeDeviceIsPersistent nodeDeviceIsPersistent;
    virDrvNodeDeviceIsActive nodeDeviceIsActive;
};
