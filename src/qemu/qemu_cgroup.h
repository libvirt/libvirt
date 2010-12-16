/*
 * qemu_cgroup.h: QEMU cgroup management
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

#ifndef __QEMU_CGROUP_H__
# define __QEMU_CGROUP_H__

# include "hostusb.h"
# include "domain_conf.h"
# include "qemu_conf.h"

int qemuCgroupControllerActive(struct qemud_driver *driver,
                               int controller);
int qemuSetupDiskPathAllow(virDomainDiskDefPtr disk,
                           const char *path,
                           size_t depth,
                           void *opaque);
int qemuSetupDiskCgroup(struct qemud_driver *driver,
                        virCgroupPtr cgroup,
                        virDomainDiskDefPtr disk);
int qemuTeardownDiskPathDeny(virDomainDiskDefPtr disk,
                             const char *path,
                             size_t depth,
                             void *opaque);
int qemuTeardownDiskCgroup(struct qemud_driver *driver,
                           virCgroupPtr cgroup,
                           virDomainDiskDefPtr disk);
int qemuSetupChardevCgroup(virDomainDefPtr def,
                           virDomainChrDefPtr dev,
                           void *opaque);
int qemuSetupHostUsbDeviceCgroup(usbDevice *dev,
                                 const char *path,
                                 void *opaque);
int qemuSetupCgroup(struct qemud_driver *driver,
                    virDomainObjPtr vm);
int qemuRemoveCgroup(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int quiet);
int qemuAddToCgroup(struct qemud_driver *driver,
                    virDomainDefPtr def);

#endif /* __QEMU_CGROUP_H__ */
