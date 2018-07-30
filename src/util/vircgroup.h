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
 *
 * Authors:
 *  Dan Smith <danms@us.ibm.com>
 */

#ifndef __VIR_CGROUP_H__
# define __VIR_CGROUP_H__

# include "virutil.h"
# include "virbitmap.h"

struct virCgroup;
typedef struct virCgroup *virCgroupPtr;

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
verify(VIR_CGROUP_CONTROLLER_LAST < 8 * sizeof(int));

typedef enum {
    VIR_CGROUP_THREAD_VCPU = 0,
    VIR_CGROUP_THREAD_EMULATOR,
    VIR_CGROUP_THREAD_IOTHREAD,

    VIR_CGROUP_THREAD_LAST
} virCgroupThreadName;

bool virCgroupAvailable(void);

int virCgroupNewPartition(const char *path,
                          bool create,
                          int controllers,
                          virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

int virCgroupNewSelf(virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1);

int virCgroupNewDomainPartition(virCgroupPtr partition,
                                const char *driver,
                                const char *name,
                                bool create,
                                virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int virCgroupNewThread(virCgroupPtr domain,
                       virCgroupThreadName nameval,
                       int id,
                       bool create,
                       virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(5);

int virCgroupDelThread(virCgroupPtr cgroup,
                       virCgroupThreadName nameval,
                       int idx);

int virCgroupNewDetect(pid_t pid,
                       int controllers,
                       virCgroupPtr *group);

int
virCgroupNewDetectMachine(const char *name,
                          const char *drivername,
                          pid_t pid,
                          int controllers,
                          char *machinename,
                          virCgroupPtr *group)
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
                        virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_NONNULL(3);

int virCgroupTerminateMachine(const char *name)
    ATTRIBUTE_NONNULL(1);

bool virCgroupNewIgnoreError(void);

void virCgroupFree(virCgroupPtr *group);

bool virCgroupHasController(virCgroupPtr cgroup, int controller);
int virCgroupPathOfController(virCgroupPtr group,
                              int controller,
                              const char *key,
                              char **path);

int virCgroupAddTask(virCgroupPtr group, pid_t pid);
int virCgroupAddMachineTask(virCgroupPtr group, pid_t pid);

int virCgroupAddTaskController(virCgroupPtr group,
                               pid_t pid,
                               int controller);

int virCgroupSetBlkioWeight(virCgroupPtr group, unsigned int weight);
int virCgroupGetBlkioWeight(virCgroupPtr group, unsigned int *weight);

int virCgroupGetBlkioIoServiced(virCgroupPtr group,
                                long long *bytes_read,
                                long long *bytes_write,
                                long long *requests_read,
                                long long *requests_write);
int virCgroupGetBlkioIoDeviceServiced(virCgroupPtr group,
                                      const char *path,
                                      long long *bytes_read,
                                      long long *bytes_write,
                                      long long *requests_read,
                                      long long *requests_write);

int virCgroupSetBlkioDeviceWeight(virCgroupPtr group,
                                  const char *path,
                                  unsigned int weight);

int virCgroupSetBlkioDeviceReadIops(virCgroupPtr group,
                                    const char *path,
                                    unsigned int riops);

int virCgroupSetBlkioDeviceWriteIops(virCgroupPtr group,
                                     const char *path,
                                     unsigned int wiops);

int virCgroupSetBlkioDeviceReadBps(virCgroupPtr group,
                                   const char *path,
                                   unsigned long long rbps);

int virCgroupSetBlkioDeviceWriteBps(virCgroupPtr group,
                                    const char *path,
                                    unsigned long long wbps);

int virCgroupGetBlkioDeviceWeight(virCgroupPtr group,
                                  const char *path,
                                  unsigned int *weight);

int virCgroupGetBlkioDeviceReadIops(virCgroupPtr group,
                                    const char *path,
                                    unsigned int *riops);

int virCgroupGetBlkioDeviceWriteIops(virCgroupPtr group,
                                     const char *path,
                                     unsigned int *wiops);

int virCgroupGetBlkioDeviceReadBps(virCgroupPtr group,
                                   const char *path,
                                   unsigned long long *rbps);

int virCgroupGetBlkioDeviceWriteBps(virCgroupPtr group,
                                    const char *path,
                                    unsigned long long *wbps);

int virCgroupSetMemory(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemoryUsage(virCgroupPtr group, unsigned long *kb);

int virCgroupSetMemoryHardLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemoryHardLimit(virCgroupPtr group, unsigned long long *kb);
int virCgroupSetMemorySoftLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemorySoftLimit(virCgroupPtr group, unsigned long long *kb);
int virCgroupSetMemSwapHardLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemSwapHardLimit(virCgroupPtr group, unsigned long long *kb);
int virCgroupGetMemSwapUsage(virCgroupPtr group, unsigned long long *kb);

enum {
    VIR_CGROUP_DEVICE_READ  = 1,
    VIR_CGROUP_DEVICE_WRITE = 2,
    VIR_CGROUP_DEVICE_MKNOD = 4,
    VIR_CGROUP_DEVICE_RW    = VIR_CGROUP_DEVICE_READ | VIR_CGROUP_DEVICE_WRITE,
    VIR_CGROUP_DEVICE_RWM   = VIR_CGROUP_DEVICE_RW | VIR_CGROUP_DEVICE_MKNOD,
};

const char *virCgroupGetDevicePermsString(int perms);

int virCgroupDenyAllDevices(virCgroupPtr group);

int virCgroupAllowAllDevices(virCgroupPtr group, int perms);

int virCgroupAllowDevice(virCgroupPtr group,
                         char type,
                         int major,
                         int minor,
                         int perms);
int virCgroupAllowDevicePath(virCgroupPtr group,
                             const char *path,
                             int perms,
                             bool ignoreEacces);

int virCgroupDenyDevice(virCgroupPtr group,
                        char type,
                        int major,
                        int minor,
                        int perms);
int virCgroupDenyDevicePath(virCgroupPtr group,
                            const char *path,
                            int perms,
                            bool ignoreEacces);

int
virCgroupGetPercpuStats(virCgroupPtr group,
                        virTypedParameterPtr params,
                        unsigned int nparams,
                        int start_cpu,
                        unsigned int ncpus,
                        virBitmapPtr guestvcpus);

int
virCgroupGetDomainTotalCpuStats(virCgroupPtr group,
                                virTypedParameterPtr params,
                                int nparams);

int virCgroupSetCpuShares(virCgroupPtr group, unsigned long long shares);
int virCgroupGetCpuShares(virCgroupPtr group, unsigned long long *shares);

int virCgroupSetCpuCfsPeriod(virCgroupPtr group, unsigned long long cfs_period);
int virCgroupGetCpuCfsPeriod(virCgroupPtr group, unsigned long long *cfs_period);

int virCgroupSetCpuCfsQuota(virCgroupPtr group, long long cfs_quota);
int virCgroupGetCpuCfsQuota(virCgroupPtr group, long long *cfs_quota);

int virCgroupGetCpuacctUsage(virCgroupPtr group, unsigned long long *usage);
int virCgroupGetCpuacctPercpuUsage(virCgroupPtr group, char **usage);
int virCgroupGetCpuacctStat(virCgroupPtr group, unsigned long long *user,
                            unsigned long long *sys);

int virCgroupSetFreezerState(virCgroupPtr group, const char *state);
int virCgroupGetFreezerState(virCgroupPtr group, char **state);

int virCgroupSetCpusetMems(virCgroupPtr group, const char *mems);
int virCgroupGetCpusetMems(virCgroupPtr group, char **mems);

int virCgroupSetCpusetMemoryMigrate(virCgroupPtr group, bool migrate);
int virCgroupGetCpusetMemoryMigrate(virCgroupPtr group, bool *migrate);

int virCgroupSetCpusetCpus(virCgroupPtr group, const char *cpus);
int virCgroupGetCpusetCpus(virCgroupPtr group, char **cpus);

int virCgroupRemoveRecursively(char *grppath);
int virCgroupRemove(virCgroupPtr group);

int virCgroupKill(virCgroupPtr group, int signum);
int virCgroupKillRecursive(virCgroupPtr group, int signum);
int virCgroupKillPainfully(virCgroupPtr group);

int virCgroupBindMount(virCgroupPtr group,
                       const char *oldroot,
                       const char *mountopts);

bool virCgroupSupportsCpuBW(virCgroupPtr cgroup);

int virCgroupSetOwner(virCgroupPtr cgroup,
                      uid_t uid,
                      gid_t gid,
                      int controllers);

int virCgroupHasEmptyTasks(virCgroupPtr cgroup, int controller);

bool virCgroupControllerAvailable(int controller);
#endif /* __VIR_CGROUP_H__ */
