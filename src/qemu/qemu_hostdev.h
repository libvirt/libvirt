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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMU_HOSTDEV_H__
# define __QEMU_HOSTDEV_H__

# include "qemu_conf.h"
# include "domain_conf.h"

int qemuUpdateActivePciHostdevs(struct qemud_driver *driver,
                                virDomainDefPtr def);
int qemuPrepareHostdevPCIDevices(struct qemud_driver *driver,
                                 const char *name,
                                 const unsigned char *uuid,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs);
int qemuPrepareHostdevUSBDevices(struct qemud_driver *driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs);
int qemuPrepareHostDevices(struct qemud_driver *driver,
                           virDomainDefPtr def);
void qemuReattachPciDevice(pciDevice *dev, struct qemud_driver *driver);
void qemuDomainReAttachHostdevDevices(struct qemud_driver *driver,
                                      const char *name,
                                      virDomainHostdevDefPtr *hostdevs,
                                      int nhostdevs);
void qemuDomainReAttachHostDevices(struct qemud_driver *driver,
                                   virDomainDefPtr def);
int qemuDomainHostdevIsVirtualFunction(virDomainHostdevDefPtr hostdev);
int qemuDomainHostdevNetConfigReplace(virDomainHostdevDefPtr hostdev,
                                      const unsigned char *uuid,
                                      char *stateDir);
int qemuDomainHostdevNetConfigRestore(virDomainHostdevDefPtr hostdev,
                                      char *stateDir);

#endif /* __QEMU_HOSTDEV_H__ */
