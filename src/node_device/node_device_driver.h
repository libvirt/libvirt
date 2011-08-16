/*
 * node_device.h: node device enumeration
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#ifndef __VIR_NODE_DEVICE_H__
# define __VIR_NODE_DEVICE_H__

# include "internal.h"
# include "driver.h"
# include "node_device_conf.h"

# define LINUX_SYSFS_SCSI_HOST_PREFIX "/sys/class/scsi_host/"
# define LINUX_SYSFS_SCSI_HOST_POSTFIX "device"
# define LINUX_SYSFS_FC_HOST_PREFIX "/sys/class/fc_host/"

# define VPORT_CREATE 0
# define VPORT_DELETE 1
# define LINUX_SYSFS_VPORT_CREATE_POSTFIX "/vport_create"
# define LINUX_SYSFS_VPORT_DELETE_POSTFIX "/vport_delete"

# define LINUX_NEW_DEVICE_WAIT_TIME 60

# ifdef HAVE_HAL
int halNodeRegister(void);
# endif
# ifdef HAVE_UDEV
int udevNodeRegister(void);
# endif

void nodeDeviceLock(virDeviceMonitorStatePtr driver);
void nodeDeviceUnlock(virDeviceMonitorStatePtr driver);

int nodedevRegister(void);

# ifdef __linux__

#  define check_fc_host(d) check_fc_host_linux(d)
int check_fc_host_linux(union _virNodeDevCapData *d);

#  define check_vport_capable(d) check_vport_capable_linux(d)
int check_vport_capable_linux(union _virNodeDevCapData *d);

#  define read_wwn(host, file, wwn) read_wwn_linux(host, file, wwn)
int read_wwn_linux(int host, const char *file, char **wwn);

# else  /* __linux__ */

#  define check_fc_host(d)                      (-1)
#  define check_vport_capable(d)                (-1)
#  define read_wwn(host, file, wwn)

# endif /* __linux__ */

int nodeNumOfDevices(virConnectPtr conn, const char *cap, unsigned int flags);
int nodeListDevices(virConnectPtr conn, const char *cap, char **const names,
                    int maxnames, unsigned int flags);
virNodeDevicePtr nodeDeviceLookupByName(virConnectPtr conn, const char *name);
char *nodeDeviceGetXMLDesc(virNodeDevicePtr dev, unsigned int flags);
char *nodeDeviceGetParent(virNodeDevicePtr dev);
int nodeDeviceNumOfCaps(virNodeDevicePtr dev);
int nodeDeviceListCaps(virNodeDevicePtr dev, char **const names, int maxnames);
virNodeDevicePtr nodeDeviceCreateXML(virConnectPtr conn,
                                     const char *xmlDesc, unsigned int flags);
int nodeDeviceDestroy(virNodeDevicePtr dev);

#endif /* __VIR_NODE_DEVICE_H__ */
