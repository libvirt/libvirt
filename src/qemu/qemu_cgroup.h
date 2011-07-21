/*
 * qemu_cgroup.h: QEMU cgroup management
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

#ifndef __QEMU_CGROUP_H__
# define __QEMU_CGROUP_H__

# include "hostusb.h"
# include "domain_conf.h"
# include "qemu_conf.h"

struct _qemuCgroupData {
    virDomainObjPtr vm;
    virCgroupPtr cgroup;
};
typedef struct _qemuCgroupData qemuCgroupData;

bool qemuCgroupControllerActive(struct qemud_driver *driver,
                                int controller);
int qemuSetupDiskCgroup(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        virCgroupPtr cgroup,
                        virDomainDiskDefPtr disk);
int qemuTeardownDiskCgroup(struct qemud_driver *driver,
                           virDomainObjPtr vm,
                           virCgroupPtr cgroup,
                           virDomainDiskDefPtr disk);
int qemuSetupHostUsbDeviceCgroup(usbDevice *dev,
                                 const char *path,
                                 void *opaque);
int qemuSetupCgroup(struct qemud_driver *driver,
                    virDomainObjPtr vm);
int qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                          unsigned long long period,
                          long long quota);
int qemuSetupCgroupForVcpu(struct qemud_driver *driver, virDomainObjPtr vm);
int qemuRemoveCgroup(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int quiet);
int qemuAddToCgroup(struct qemud_driver *driver,
                    virDomainDefPtr def);

#endif /* __QEMU_CGROUP_H__ */
