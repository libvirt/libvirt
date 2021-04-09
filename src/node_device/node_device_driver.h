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
 */

#pragma once

#include "internal.h"
#include "driver.h"
#include "virnodedeviceobj.h"
#include "vircommand.h"

#define LINUX_NEW_DEVICE_WAIT_TIME 60

#ifdef WITH_UDEV
int
udevNodeRegister(void);
#endif

void
nodeDeviceLock(void);

void
nodeDeviceUnlock(void);

extern virNodeDeviceDriverStatePtr driver;

int
nodedevRegister(void);

virDrvOpenStatus nodeConnectOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth,
                                 virConfPtr conf,
                                 unsigned int flags);
int nodeConnectClose(virConnectPtr conn);
int nodeConnectIsSecure(virConnectPtr conn);
int nodeConnectIsEncrypted(virConnectPtr conn);
int nodeConnectIsAlive(virConnectPtr conn);

int
nodeNumOfDevices(virConnectPtr conn,
                 const char *cap,
                 unsigned int flags);

int nodeListDevices(virConnectPtr conn,
                    const char *cap,
                    char **const names,
                    int maxnames,
                    unsigned int flags);

int
nodeConnectListAllNodeDevices(virConnectPtr conn,
                              virNodeDevicePtr **devices,
                              unsigned int flags);

virNodeDevicePtr
nodeDeviceLookupByName(virConnectPtr conn,
                       const char *name);

virNodeDevicePtr
nodeDeviceLookupSCSIHostByWWN(virConnectPtr conn,
                              const char *wwnn,
                              const char *wwpn,
                              unsigned int flags);

char *
nodeDeviceGetXMLDesc(virNodeDevicePtr dev,
                     unsigned int flags);

char *
nodeDeviceGetParent(virNodeDevicePtr dev);

int
nodeDeviceNumOfCaps(virNodeDevicePtr dev);

int
nodeDeviceListCaps(virNodeDevicePtr dev,
                   char **const names,
                   int maxnames);

virNodeDevicePtr
nodeDeviceCreateXML(virConnectPtr conn,
                    const char *xmlDesc,
                    unsigned int flags);

int
nodeDeviceDestroy(virNodeDevicePtr dev);

virNodeDevice*
nodeDeviceDefineXML(virConnect *conn,
                    const char *xmlDesc,
                    unsigned int flags);

int
nodeDeviceUndefine(virNodeDevice *dev,
                   unsigned int flags);

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

virCommandPtr
nodeDeviceGetMdevctlStartCommand(virNodeDeviceDefPtr def,
                                 char **uuid_out,
                                 char **errmsg);

virCommand*
nodeDeviceGetMdevctlDefineCommand(virNodeDeviceDef *def,
                                  char **uuid_out,
                                  char **errmsg);

virCommandPtr
nodeDeviceGetMdevctlStopCommand(const char *uuid,
                                char **errmsg);

virCommand *
nodeDeviceGetMdevctlUndefineCommand(const char *uuid,
                                    char **errmsg);

virCommandPtr
nodeDeviceGetMdevctlListCommand(bool defined,
                                char **output,
                                char **errmsg);

int
nodeDeviceParseMdevctlJSON(const char *jsonstring,
                           virNodeDeviceDef ***devs);

int
nodeDeviceUpdateMediatedDevices(void);

void
nodeDeviceGenerateName(virNodeDeviceDef *def,
                       const char *subsystem,
                       const char *sysname,
                       const char *s);

bool nodeDeviceDefCopyFromMdevctl(virNodeDeviceDef *dst,
                                  virNodeDeviceDef *src);

virCommand*
nodeDeviceGetMdevctlCreateCommand(const char *uuid,
                                  char **errmsg);

int
nodeDeviceCreate(virNodeDevice *dev,
                 unsigned int flags);
