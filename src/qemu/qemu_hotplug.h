/*
 * qemu_hotplug.h: QEMU device hotplug management
 *
 * Copyright (C) 2006-2007, 2009-2011 Red Hat, Inc.
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

# include "qemu_conf.h"
# include "qemu_domain.h"
# include "domain_conf.h"

int qemuDomainChangeEjectableMedia(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainDiskDefPtr disk,
                                   bool force);
int qemuDomainCheckEjectableMedia(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  enum qemuDomainAsyncJob asyncJob);
int qemuDomainAttachPciDiskDevice(virConnectPtr conn,
                                  struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk);
int qemuDomainAttachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainControllerDefPtr controller);
int qemuDomainAttachSCSIDisk(virConnectPtr conn,
                             struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             virDomainDiskDefPtr disk);
int qemuDomainAttachUsbMassstorageDevice(virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         virDomainObjPtr vm,
                                         virDomainDiskDefPtr disk);
int qemuDomainAttachNetDevice(virConnectPtr conn,
                              struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainNetDefPtr net);
int qemuDomainAttachHostPciDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev);
int qemuDomainAttachHostUsbDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainHostdevDefPtr hostdev);
int qemuDomainAttachRedirdevDevice(struct qemud_driver *driver,
                                   virDomainObjPtr vm,
                                   virDomainRedirdevDefPtr hostdev);
int qemuDomainAttachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainHostdevDefPtr hostdev);
int qemuDomainChangeGraphics(struct qemud_driver *driver,
                             virDomainObjPtr vm,
                             virDomainGraphicsDefPtr dev);
int qemuDomainChangeGraphicsPasswords(struct qemud_driver *driver,
                                      virDomainObjPtr vm,
                                      int type,
                                      virDomainGraphicsAuthDefPtr auth,
                                      const char *defaultPasswd);
int qemuDomainChangeNet(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        virDomainPtr dom,
                        virDomainNetDefPtr dev);
int qemuDomainChangeNetLinkState(struct qemud_driver *driver,
                                 virDomainObjPtr vm,
                                 virDomainNetDefPtr dev,
                                 int linkstate);
int qemuDomainDetachPciDiskDevice(struct qemud_driver *driver,
                                  virDomainObjPtr vm,
                                  virDomainDeviceDefPtr dev);
int qemuDomainDetachDiskDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev);
int qemuDomainDetachPciControllerDevice(struct qemud_driver *driver,
                                        virDomainObjPtr vm,
                                        virDomainDeviceDefPtr dev);
int qemuDomainDetachNetDevice(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev);
int qemuDomainDetachHostDevice(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virDomainDeviceDefPtr dev);
int qemuDomainAttachLease(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          virDomainLeaseDefPtr lease);
int qemuDomainDetachLease(struct qemud_driver *driver,
                          virDomainObjPtr vm,
                          virDomainLeaseDefPtr lease);


#endif /* __QEMU_HOTPLUG_H__ */
