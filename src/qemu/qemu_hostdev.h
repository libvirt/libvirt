/*
 * qemu_hostdev.h: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_HOSTDEV_H__
# define __QEMU_HOSTDEV_H__

# include "qemu_conf.h"
# include "domain_conf.h"

int qemuUpdateActivePciHostdevs(virQEMUDriverPtr driver,
                                virDomainDefPtr def);
int qemuUpdateActiveUsbHostdevs(virQEMUDriverPtr driver,
                                virDomainDefPtr def);
int qemuUpdateActiveScsiHostdevs(virQEMUDriverPtr driver,
                                 virDomainDefPtr def);
int qemuPrepareHostdevPCIDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 const unsigned char *uuid,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs);
int qemuFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
                             bool mandatory,
                             virUSBDevicePtr *usb);
int qemuPrepareHostdevUSBDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virUSBDeviceListPtr list);
int qemuPrepareHostdevSCSIDevices(virQEMUDriverPtr driver,
                                  const char *name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs);
int qemuPrepareHostDevices(virQEMUDriverPtr driver,
                           virDomainDefPtr def,
                           bool coldBoot);
void qemuDomainReAttachHostScsiDevices(virQEMUDriverPtr driver,
                                       const char *name,
                                       virDomainHostdevDefPtr *hostdevs,
                                       int nhostdevs);
void qemuReattachPciDevice(virPCIDevicePtr dev, virQEMUDriverPtr driver);
void qemuDomainReAttachHostdevDevices(virQEMUDriverPtr driver,
                                      const char *name,
                                      virDomainHostdevDefPtr *hostdevs,
                                      int nhostdevs);
void qemuDomainReAttachHostDevices(virQEMUDriverPtr driver,
                                   virDomainDefPtr def);
int qemuDomainHostdevIsVirtualFunction(virDomainHostdevDefPtr hostdev);
int qemuDomainHostdevNetConfigReplace(virDomainHostdevDefPtr hostdev,
                                      const unsigned char *uuid,
                                      char *stateDir);
int qemuDomainHostdevNetConfigRestore(virDomainHostdevDefPtr hostdev,
                                      char *stateDir);

#endif /* __QEMU_HOSTDEV_H__ */
