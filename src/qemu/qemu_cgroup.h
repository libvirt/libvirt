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
 */

#pragma once

#include "virusb.h"
#include "vircgroup.h"
#include "domain_conf.h"
#include "qemu_conf.h"

int qemuSetupImageCgroup(virDomainObjPtr vm,
                         virStorageSourcePtr src);
int qemuTeardownImageCgroup(virDomainObjPtr vm,
                            virStorageSourcePtr src);
int qemuSetupImageChainCgroup(virDomainObjPtr vm,
                              virStorageSourcePtr src);
int qemuTeardownImageChainCgroup(virDomainObjPtr vm,
                                 virStorageSourcePtr src);
int qemuSetupInputCgroup(virDomainObjPtr vm,
                         virDomainInputDefPtr dev);
int qemuTeardownInputCgroup(virDomainObjPtr vm,
                            virDomainInputDefPtr dev);
int qemuSetupHostdevCgroup(virDomainObjPtr vm,
                           virDomainHostdevDefPtr dev)
   ATTRIBUTE_RETURN_CHECK;
int qemuTeardownHostdevCgroup(virDomainObjPtr vm,
                              virDomainHostdevDefPtr dev)
   ATTRIBUTE_RETURN_CHECK;
int qemuSetupMemoryDevicesCgroup(virDomainObjPtr vm,
                                 virDomainMemoryDefPtr mem);
int qemuTeardownMemoryDevicesCgroup(virDomainObjPtr vm,
                                    virDomainMemoryDefPtr mem);
int qemuSetupRNGCgroup(virDomainObjPtr vm,
                       virDomainRNGDefPtr rng);
int qemuTeardownRNGCgroup(virDomainObjPtr vm,
                          virDomainRNGDefPtr rng);
int qemuSetupChardevCgroup(virDomainObjPtr vm,
                           virDomainChrDefPtr dev);
int qemuTeardownChardevCgroup(virDomainObjPtr vm,
                              virDomainChrDefPtr dev);
int qemuConnectCgroup(virDomainObjPtr vm);
int qemuSetupCgroup(virDomainObjPtr vm,
                    size_t nnicindexes,
                    int *nicindexes);
int qemuSetupCgroupVcpuBW(virCgroupPtr cgroup,
                          unsigned long long period,
                          long long quota);
int qemuSetupCgroupCpusetCpus(virCgroupPtr cgroup, virBitmapPtr cpumask);
int qemuSetupGlobalCpuCgroup(virDomainObjPtr vm);
int qemuSetupCgroupForExtDevices(virDomainObjPtr vm,
                                 virQEMUDriverPtr driver);
int qemuRemoveCgroup(virDomainObjPtr vm);

typedef struct _qemuCgroupEmulatorAllNodesData qemuCgroupEmulatorAllNodesData;
typedef qemuCgroupEmulatorAllNodesData *qemuCgroupEmulatorAllNodesDataPtr;
struct _qemuCgroupEmulatorAllNodesData {
    virCgroupPtr emulatorCgroup;
    char *emulatorMemMask;
};

int qemuCgroupEmulatorAllNodesAllow(virCgroupPtr cgroup,
                                    qemuCgroupEmulatorAllNodesDataPtr *data);
void qemuCgroupEmulatorAllNodesRestore(qemuCgroupEmulatorAllNodesDataPtr data);

extern const char *const defaultDeviceACL[];
