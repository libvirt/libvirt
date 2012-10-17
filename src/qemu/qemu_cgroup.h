/*
 * qemu_cgroup.h: QEMU cgroup management
 *
 * Copyright (C) 2006-2007, 2009-2012 Red Hat, Inc.
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
                    virDomainObjPtr vm,
                    virBitmapPtr nodemask);
int qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                          unsigned long long period,
                          long long quota);
int qemuSetupCgroupVcpuPin(virCgroupPtr cgroup,
                           virDomainVcpuPinDefPtr *vcpupin,
                           int nvcpupin,
                           int vcpuid);
int qemuSetupCgroupEmulatorPin(virCgroupPtr cgroup, virBitmapPtr cpumask);
int qemuSetupCgroupForVcpu(struct qemud_driver *driver, virDomainObjPtr vm);
int qemuSetupCgroupForEmulator(struct qemud_driver *driver,
                               virDomainObjPtr vm);
int qemuRemoveCgroup(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int quiet);
int qemuAddToCgroup(struct qemud_driver *driver,
                    virDomainDefPtr def);

#endif /* __QEMU_CGROUP_H__ */
