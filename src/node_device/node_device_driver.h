/*
 * node_device_driver.h: node device enumeration
 *
 * Copyright (C) 2008 Virtual Iron Software, Inc.
 * Copyright (C) 2008 David F. Lively
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
 *
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#ifndef __VIR_NODE_DEVICE_H__
# define __VIR_NODE_DEVICE_H__

# include "internal.h"
# include "driver.h"
# include "virnodedeviceobj.h"

# define LINUX_NEW_DEVICE_WAIT_TIME 60

# ifdef WITH_HAL
int halNodeRegister(void);
# endif
# ifdef WITH_UDEV
int udevNodeRegister(void);
# endif

void nodeDeviceLock(void);
void nodeDeviceUnlock(void);

extern virNodeDeviceDriverStatePtr driver;

int nodedevRegister(void);

int nodeNumOfDevices(virConnectPtr conn, const char *cap, unsigned int flags);
int nodeListDevices(virConnectPtr conn, const char *cap, char **const names,
                    int maxnames, unsigned int flags);
int nodeConnectListAllNodeDevices(virConnectPtr conn,
                                  virNodeDevicePtr **devices,
                                  unsigned int flags);
virNodeDevicePtr nodeDeviceLookupByName(virConnectPtr conn, const char *name);
virNodeDevicePtr nodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                                               const char *wwnn,
                                               const char *wwpn,
                                               unsigned int flags);
char *nodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags);
char *nodeDeviceGetParent(virNodeDevicePtr dev);
int nodeDeviceNumOfCaps(virNodeDevicePtr dev);
int nodeDeviceListCaps(virNodeDevicePtr dev, char **const names, int maxnames);
virNodeDevicePtr nodeDeviceCreateXML(virConnectPtr conn,
                                     const char *xmlDesc, unsigned int flags);
int nodeDeviceDestroy(virNodeDevicePtr dev);

int
nodeConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                      virNodeDevicePtr dev,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb);
int
nodeConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                        int callbackID);
#endif /* __VIR_NODE_DEVICE_H__ */
