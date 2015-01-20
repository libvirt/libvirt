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

#ifndef __VIR_DRIVER_NODEDEV_H__
# define __VIR_DRIVER_NODEDEV_H__

# ifndef __VIR_DRIVER_H_INCLUDES___
#  error "Don't include this file directly, only use driver.h"
# endif

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



typedef struct _virNodeDeviceDriver virNodeDeviceDriver;
typedef virNodeDeviceDriver *virNodeDeviceDriverPtr;

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
    virDrvNodeDeviceLookupByName nodeDeviceLookupByName;
    virDrvNodeDeviceLookupSCSIHostByWWN nodeDeviceLookupSCSIHostByWWN;
    virDrvNodeDeviceGetXMLDesc nodeDeviceGetXMLDesc;
    virDrvNodeDeviceGetParent nodeDeviceGetParent;
    virDrvNodeDeviceNumOfCaps nodeDeviceNumOfCaps;
    virDrvNodeDeviceListCaps nodeDeviceListCaps;
    virDrvNodeDeviceCreateXML nodeDeviceCreateXML;
    virDrvNodeDeviceDestroy nodeDeviceDestroy;
};


#endif /* __VIR_DRIVER_NODEDEV_H__ */
