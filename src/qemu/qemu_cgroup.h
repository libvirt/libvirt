/*
 * qemu_cgroup.h: QEMU cgroup management
 *
 * Copyright (C) 2006-2007, 2009-2014 Red Hat, Inc.
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

# include "virusb.h"
# include "vircgroup.h"
# include "domain_conf.h"
# include "qemu_conf.h"

int qemuSetImageCgroup(virDomainObjPtr vm,
                       virStorageSourcePtr src,
                       bool deny);
int qemuSetupDiskCgroup(virDomainObjPtr vm,
                        virDomainDiskDefPtr disk);
int qemuTeardownDiskCgroup(virDomainObjPtr vm,
                           virDomainDiskDefPtr disk);
int qemuSetupHostdevCgroup(virDomainObjPtr vm,
                           virDomainHostdevDefPtr dev)
   ATTRIBUTE_RETURN_CHECK;
int qemuTeardownHostdevCgroup(virDomainObjPtr vm,
                              virDomainHostdevDefPtr dev)
   ATTRIBUTE_RETURN_CHECK;
int qemuConnectCgroup(virQEMUDriverPtr driver,
                      virDomainObjPtr vm);
int qemuSetupCgroup(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    size_t nnicindexes,
                    int *nicindexes);
int qemuSetupCpusetMems(virDomainObjPtr vm);
int qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                          unsigned long long period,
                          long long quota);
int qemuSetupCgroupCpusetCpus(virCgroupPtr cgroup, virBitmapPtr cpumask);
int qemuSetupCgroupForVcpu(virDomainObjPtr vm);
int qemuSetupCgroupForIOThreads(virDomainObjPtr vm);
int qemuSetupCgroupForEmulator(virDomainObjPtr vm);
int qemuRemoveCgroup(virQEMUDriverPtr driver, virDomainObjPtr vm);
int qemuAddToCgroup(virDomainObjPtr vm);

#endif /* __QEMU_CGROUP_H__ */
