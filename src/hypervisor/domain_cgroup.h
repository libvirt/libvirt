/*
 * domain_cgroup.h: cgroup functions shared between hypervisor drivers
 *
 * Copyright IBM Corp. 2020
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

#include "vircgroup.h"
#include "domain_conf.h"

typedef struct _virCgroupEmulatorAllNodesData virCgroupEmulatorAllNodesData;
struct _virCgroupEmulatorAllNodesData {
    virCgroup *emulatorCgroup;
    char *emulatorMemMask;
};

int virDomainCgroupSetupBlkio(virCgroup *cgroup, virDomainBlkiotune blkio);
int virDomainCgroupSetupMemtune(virCgroup *cgroup, virDomainMemtune mem);
int virDomainCgroupSetupDomainBlkioParameters(virCgroup *cgroup,
                                              virDomainDef *def,
                                              virTypedParameterPtr params,
                                              int nparams);
int virDomainCgroupSetMemoryLimitParameters(virCgroup *cgroup,
                                            virDomainObj *vm,
                                            virDomainDef *liveDef,
                                            virDomainDef *persistentDef,
                                            virTypedParameterPtr params,
                                            int nparams);
int
virDomainCgroupSetupBlkioCgroup(virDomainObj *vm,
                                virCgroup *cgroup);
int
virDomainCgroupSetupMemoryCgroup(virDomainObj *vm,
                                 virCgroup *cgroup);
int
virDomainCgroupSetupCpusetCgroup(virCgroup *cgroup);
int
virDomainCgroupSetupCpuCgroup(virDomainObj *vm,
                              virCgroup *cgroup);
int
virDomainCgroupInitCgroup(const char *prefix,
                          virDomainObj *vm,
                          size_t nnicindexes,
                          int *nicindexes,
                          virCgroup **cgroup,
                          int cgroupControllers,
                          unsigned int maxThreadsPerProc,
                          bool privileged,
                          char *machineName);
void
virDomainCgroupRestoreCgroupState(virDomainObj *vm,
                                  virCgroup *cgroup);
int
virDomainCgroupConnectCgroup(const char *prefix,
                             virDomainObj *vm,
                             virCgroup **cgroup,
                             int cgroupControllers,
                             bool privileged,
                             char *machineName);
int
virDomainCgroupSetupCgroup(const char *prefix,
                           virDomainObj *vm,
                           size_t nnicindexes,
                           int *nicindexes,
                           virCgroup **cgroup,
                           int cgroupControllers,
                           unsigned int maxThreadsPerProc,
                           bool privileged,
                           char *machineName);
void
virDomainCgroupEmulatorAllNodesDataFree(virCgroupEmulatorAllNodesData *data);
int
virDomainCgroupEmulatorAllNodesAllow(virCgroup *cgroup,
                                     virCgroupEmulatorAllNodesData **retData);
void
virDomainCgroupEmulatorAllNodesRestore(virCgroupEmulatorAllNodesData *data);
int
virDomainCgroupSetupVcpuBW(virCgroup *cgroup,
                           unsigned long long period,
                           long long quota);
int
virDomainCgroupSetupCpusetCpus(virCgroup *cgroup,
                               virBitmap *cpumask);
int
virDomainCgroupSetupGlobalCpuCgroup(virDomainObj *vm,
                                    virCgroup *cgroup);
int
virDomainCgroupRemoveCgroup(virDomainObj *vm,
                            virCgroup *cgroup,
                            char *machineName);
int
virDomainCgroupRestoreCgroupThread(virCgroup *cgroup,
                                   virCgroupThreadName thread,
                                   int id);
