/*
 * qemu_hotplug.h: QEMU device hotplug management
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

#ifndef __QEMU_HOTPLUG_H__
# define __QEMU_HOTPLUG_H__

# include <stdbool.h>

# include "qemu_conf.h"
# include "domain_conf.h"

int qemuDomainChangeEjectableMedia(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainDiskDefPtr disk,
                                   unsigned long long qemuCmdFlags,
                                   bool force);
int qemuDomainAttachPciDiskDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk,
                                  unsigned long long qemuCmdFlags);
int qemuDomainAttachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainControllerDefPtr controller,
                                        unsigned long long qemuCmdFlags);
int qemuDomainAttachSCSIDisk(struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk,
                             unsigned long long qemuCmdFlags);
int qemuDomainAttachUsbMassstorageDevice(struct qemud_driver *driver,
                                         virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk,
                                         unsigned long long qemuCmdFlags);
int qemuDomainAttachNetDevice(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainNetDefPtr net,
                              unsigned long long qemuCmdFlags);
int qemuDomainAttachHostPciDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev,
                                  unsigned long long qemuCmdFlags);
int qemuDomainAttachHostUsbDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev,
                                  unsigned long long qemuCmdFlags);
int qemuDomainAttachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev,
                               unsigned long long qemuCmdFlags);
int qemuDomainChangeGraphics(struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             virDomainGraphicsDefPtr dev);
int qemuDomainChangeGraphicsPasswords(struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      int type,
                                      virDomainGraphicsAuthDefPtr auth,
                                      const char *defaultPasswd);
int qemuDomainDetachPciDiskDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags);
int qemuDomainDetachSCSIDiskDevice(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainDeviceDefPtr dev,
                                   unsigned long long qemuCmdFlags);
int qemuDomainDetachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainDeviceDefPtr dev,
                                        unsigned long long qemuCmdFlags);
int qemuDomainDetachNetDevice(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev,
                              unsigned long long qemuCmdFlags);
int qemuDomainDetachHostPciDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags);
int qemuDomainDetachHostUsbDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev,
                                  unsigned long long qemuCmdFlags);
int qemuDomainDetachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev,
                               unsigned long long qemuCmdFlags);


#endif /* __QEMU_HOTPLUG_H__ */
