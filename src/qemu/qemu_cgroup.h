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

int qemuSetupImageCgroup(virDomainObj *vm,
                         virStorageSource *src);
int qemuTeardownImageCgroup(virDomainObj *vm,
                            virStorageSource *src);
int qemuSetupImageChainCgroup(virDomainObj *vm,
                              virStorageSource *src);
int qemuTeardownImageChainCgroup(virDomainObj *vm,
                                 virStorageSource *src);
int qemuSetupInputCgroup(virDomainObj *vm,
                         virDomainInputDef *dev);
int qemuTeardownInputCgroup(virDomainObj *vm,
                            virDomainInputDef *dev);
int qemuSetupHostdevCgroup(virDomainObj *vm,
                           virDomainHostdevDef *dev)
   G_GNUC_WARN_UNUSED_RESULT;
int qemuTeardownHostdevCgroup(virDomainObj *vm,
                              virDomainHostdevDef *dev)
   G_GNUC_WARN_UNUSED_RESULT;
int qemuSetupMemoryDevicesCgroup(virDomainObj *vm,
                                 virDomainMemoryDef *mem);
int qemuTeardownMemoryDevicesCgroup(virDomainObj *vm,
                                    virDomainMemoryDef *mem);
int qemuSetupRNGCgroup(virDomainObj *vm,
                       virDomainRNGDef *rng);
int qemuTeardownRNGCgroup(virDomainObj *vm,
                          virDomainRNGDef *rng);
int qemuSetupChardevCgroup(virDomainObj *vm,
                           virDomainChrDef *dev);
int qemuTeardownChardevCgroup(virDomainObj *vm,
                              virDomainChrDef *dev);
int qemuConnectCgroup(virDomainObj *vm);
int qemuSetupCgroup(virDomainObj *vm,
                    size_t nnicindexes,
                    int *nicindexes);
int qemuSetupCgroupVcpuBW(virCgroup *cgroup,
                          unsigned long long period,
                          long long quota);
int qemuSetupCgroupCpusetCpus(virCgroup *cgroup, virBitmap *cpumask);
int qemuSetupGlobalCpuCgroup(virDomainObj *vm);
int qemuSetupCgroupForExtDevices(virDomainObj *vm,
                                 virQEMUDriver *driver);
int qemuRemoveCgroup(virDomainObj *vm);

typedef struct _qemuCgroupEmulatorAllNodesData qemuCgroupEmulatorAllNodesData;
struct _qemuCgroupEmulatorAllNodesData {
    virCgroup *emulatorCgroup;
    char *emulatorMemMask;
};

int qemuCgroupEmulatorAllNodesAllow(virCgroup *cgroup,
                                    qemuCgroupEmulatorAllNodesData **data);
void qemuCgroupEmulatorAllNodesRestore(qemuCgroupEmulatorAllNodesData *data);

extern const char *const defaultDeviceACL[];
