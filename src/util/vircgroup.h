/*
 * vircgroup.h: methods for managing control cgroups
 *
 * Copyright (C) 2011-2015 Red Hat, Inc.
 * Copyright IBM Corp. 2008
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

#include "virbitmap.h"
#include "virenum.h"

struct _virCgroup;
typedef struct _virCgroup virCgroup;

enum {
    VIR_CGROUP_CONTROLLER_CPU,
    VIR_CGROUP_CONTROLLER_CPUACCT,
    VIR_CGROUP_CONTROLLER_CPUSET,
    VIR_CGROUP_CONTROLLER_MEMORY,
    VIR_CGROUP_CONTROLLER_DEVICES,
    VIR_CGROUP_CONTROLLER_FREEZER,
    VIR_CGROUP_CONTROLLER_BLKIO,
    VIR_CGROUP_CONTROLLER_NET_CLS,
    VIR_CGROUP_CONTROLLER_PERF_EVENT,
    VIR_CGROUP_CONTROLLER_SYSTEMD,

    VIR_CGROUP_CONTROLLER_LAST
};

VIR_ENUM_DECL(virCgroupController);
/* Items of this enum are used later in virCgroupNew to create
 * bit array stored in int. Like this:
 *   1 << VIR_CGROUP_CONTROLLER_CPU
 * Make sure we will not overflow */
G_STATIC_ASSERT(VIR_CGROUP_CONTROLLER_LAST < 8 * sizeof(int));

typedef enum {
    VIR_CGROUP_THREAD_VCPU = 0,
    VIR_CGROUP_THREAD_EMULATOR,
    VIR_CGROUP_THREAD_IOTHREAD,

    VIR_CGROUP_THREAD_LAST
} virCgroupThreadName;

bool virCgroupAvailable(void);

int virCgroupNew(const char *path,
                 int controllers,
                 virCgroup **group);

int virCgroupNewSelf(virCgroup **group)
    ATTRIBUTE_NONNULL(1);

int virCgroupNewThread(virCgroup *domain,
                       virCgroupThreadName nameval,
                       int id,
                       bool create,
                       virCgroup **group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(5);

int virCgroupDelThread(virCgroup *cgroup,
                       virCgroupThreadName nameval,
                       int idx);

int virCgroupNewDetect(pid_t pid,
                       int controllers,
                       virCgroup **group);

int
virCgroupNewDetectMachine(const char *name,
                          const char *drivername,
                          pid_t pid,
                          int controllers,
                          char *machinename,
                          virCgroup **group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virCgroupNewMachine(const char *name,
                        const char *drivername,
                        const unsigned char *uuid,
                        const char *rootdir,
                        pid_t pidleader,
                        bool isContainer,
                        size_t nnicindexes,
                        int *nicindexes,
                        const char *partition,
                        int controllers,
                        unsigned int maxthreads,
                        virCgroup **group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3);

int virCgroupTerminateMachine(const char *name)
    ATTRIBUTE_NONNULL(1);

bool virCgroupNewIgnoreError(void);

void virCgroupFree(virCgroup *group);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCgroup, virCgroupFree);

bool virCgroupHasController(virCgroup *cgroup, int controller);
int virCgroupPathOfController(virCgroup *group,
                              unsigned int controller,
                              const char *key,
                              char **path);

int virCgroupAddProcess(virCgroup *group, pid_t pid);
int virCgroupAddMachineProcess(virCgroup *group, pid_t pid);
int virCgroupAddThread(virCgroup *group, pid_t pid);

int virCgroupSetBlkioWeight(virCgroup *group, unsigned int weight);
int virCgroupGetBlkioWeight(virCgroup *group, unsigned int *weight);

int virCgroupGetBlkioIoServiced(virCgroup *group,
                                long long *bytes_read,
                                long long *bytes_write,
                                long long *requests_read,
                                long long *requests_write);
int virCgroupGetBlkioIoDeviceServiced(virCgroup *group,
                                      const char *path,
                                      long long *bytes_read,
                                      long long *bytes_write,
                                      long long *requests_read,
                                      long long *requests_write);

int virCgroupSetupBlkioDeviceWeight(virCgroup *cgroup,
                                    const char *path,
                                    unsigned int *weight);

int virCgroupSetupBlkioDeviceReadIops(virCgroup *cgroup,
                                      const char *path,
                                      unsigned int *riops);

int virCgroupSetupBlkioDeviceWriteIops(virCgroup *cgroup,
                                       const char *path,
                                       unsigned int *wiops);

int virCgroupSetupBlkioDeviceReadBps(virCgroup *cgroup,
                                     const char *path,
                                     unsigned long long *rbps);

int virCgroupSetupBlkioDeviceWriteBps(virCgroup *cgroup,
                                      const char *path,
                                      unsigned long long *wbps);

int virCgroupSetMemory(virCgroup *group, unsigned long long kb);
int virCgroupGetMemoryStat(virCgroup *group,
                           unsigned long long *cache,
                           unsigned long long *activeAnon,
                           unsigned long long *inactiveAnon,
                           unsigned long long *activeFile,
                           unsigned long long *inactiveFile,
                           unsigned long long *unevictable);
int virCgroupGetMemoryUsage(virCgroup *group, unsigned long *kb);

int virCgroupSetMemoryHardLimit(virCgroup *group, unsigned long long kb);
int virCgroupGetMemoryHardLimit(virCgroup *group, unsigned long long *kb);
int virCgroupSetMemorySoftLimit(virCgroup *group, unsigned long long kb);
int virCgroupGetMemorySoftLimit(virCgroup *group, unsigned long long *kb);
int virCgroupSetMemSwapHardLimit(virCgroup *group, unsigned long long kb);
int virCgroupGetMemSwapHardLimit(virCgroup *group, unsigned long long *kb);
int virCgroupGetMemSwapUsage(virCgroup *group, unsigned long long *kb);

enum {
    VIR_CGROUP_DEVICE_READ  = 1,
    VIR_CGROUP_DEVICE_WRITE = 2,
    VIR_CGROUP_DEVICE_MKNOD = 4,
    VIR_CGROUP_DEVICE_RW    = VIR_CGROUP_DEVICE_READ | VIR_CGROUP_DEVICE_WRITE,
    VIR_CGROUP_DEVICE_RWM   = VIR_CGROUP_DEVICE_RW | VIR_CGROUP_DEVICE_MKNOD,
};

const char *virCgroupGetDevicePermsString(int perms);

int virCgroupDenyAllDevices(virCgroup *group);

int virCgroupAllowAllDevices(virCgroup *group, int perms);

int virCgroupAllowDevice(virCgroup *group,
                         char type,
                         int major,
                         int minor,
                         int perms);
int virCgroupAllowDevicePath(virCgroup *group,
                             const char *path,
                             int perms,
                             bool ignoreEacces);

int virCgroupDenyDevice(virCgroup *group,
                        char type,
                        int major,
                        int minor,
                        int perms);
int virCgroupDenyDevicePath(virCgroup *group,
                            const char *path,
                            int perms,
                            bool ignoreEacces);

int
virCgroupGetPercpuStats(virCgroup *group,
                        virTypedParameterPtr params,
                        unsigned int nparams,
                        int start_cpu,
                        unsigned int ncpus,
                        virBitmap *guestvcpus);

int
virCgroupGetDomainTotalCpuStats(virCgroup *group,
                                virTypedParameterPtr params,
                                int nparams);

int virCgroupSetCpuShares(virCgroup *group, unsigned long long shares);
int virCgroupGetCpuShares(virCgroup *group, unsigned long long *shares);

#define VIR_CGROUP_CPU_SHARES_MIN 2LL
#define VIR_CGROUP_CPU_SHARES_MAX 262144LL
#define VIR_CGROUP_CPU_PERIOD_MIN 1000LL
#define VIR_CGROUP_CPU_PERIOD_MAX 1000000LL
#define VIR_CGROUP_CPU_QUOTA_MIN 1000LL
/* Based on kernel code ((1ULL << MAX_BW_BITS) - 1) where MAX_BW_BITS is
 * (64 - BW_SHIFT) and BW_SHIFT is 20 */
#define VIR_CGROUP_CPU_QUOTA_MAX 17592186044415LL
#define VIR_CGROUPV2_WEIGHT_MIN 1LL
#define VIR_CGROUPV2_WEIGHT_MAX 10000LL

int virCgroupSetCpuCfsPeriod(virCgroup *group, unsigned long long cfs_period);
int virCgroupGetCpuCfsPeriod(virCgroup *group, unsigned long long *cfs_period);
int virCgroupGetCpuPeriodQuota(virCgroup *cgroup, unsigned long long *period,
                               long long *quota);
int virCgroupSetupCpuPeriodQuota(virCgroup *cgroup, unsigned long long period,
                                 long long quota);

int virCgroupSetCpuCfsQuota(virCgroup *group, long long cfs_quota);
int virCgroupGetCpuCfsQuota(virCgroup *group, long long *cfs_quota);

int virCgroupGetCpuacctUsage(virCgroup *group, unsigned long long *usage);
int virCgroupGetCpuacctPercpuUsage(virCgroup *group, char **usage);
int virCgroupGetCpuacctStat(virCgroup *group, unsigned long long *user,
                            unsigned long long *sys);

int virCgroupSetFreezerState(virCgroup *group, const char *state);
int virCgroupGetFreezerState(virCgroup *group, char **state);

int virCgroupSetCpusetMems(virCgroup *group, const char *mems);
int virCgroupGetCpusetMems(virCgroup *group, char **mems);

int virCgroupSetCpusetMemoryMigrate(virCgroup *group, bool migrate);
int virCgroupGetCpusetMemoryMigrate(virCgroup *group, bool *migrate);

int virCgroupSetCpusetCpus(virCgroup *group, const char *cpus);
int virCgroupGetCpusetCpus(virCgroup *group, char **cpus);
int virCgroupSetupCpusetCpus(virCgroup *cgroup, virBitmap *cpumask);

int virCgroupRemove(virCgroup *group);

int virCgroupKillRecursive(virCgroup *group, int signum);
int virCgroupKillPainfully(virCgroup *group);

int virCgroupBindMount(virCgroup *group,
                       const char *oldroot,
                       const char *mountopts);

bool virCgroupSupportsCpuBW(virCgroup *cgroup);

int virCgroupSetOwner(virCgroup *cgroup,
                      uid_t uid,
                      gid_t gid,
                      int controllers);

int virCgroupHasEmptyTasks(virCgroup *cgroup, int controller);

bool virCgroupControllerAvailable(int controller);

int virCgroupGetInode(virCgroup *cgroup);
