/*
 * node_device_linux_sysfs.h: Linux specific code to gather device data
 * that is available from sysfs (but not from UDEV or HAL).
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
 */

#ifndef __VIR_NODE_DEVICE_LINUX_SYSFS_H__
# define __VIR_NODE_DEVICE_LINUX_SYSFS_H__

# include "node_device_conf.h"

int nodeDeviceSysfsGetSCSIHostCaps(virNodeDevCapSCSIHostPtr scsi_host);
int nodeDeviceSysfsGetPCIRelatedDevCaps(const char *sysfsPath,
                                        virNodeDevCapPCIDevPtr pci_dev);

#endif /* __VIR_NODE_DEVICE_LINUX_SYSFS_H__ */
