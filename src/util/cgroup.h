/*
 * cgroup.h: Interface to tools for managing cgroups
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * See COPYING.LIB for the License of this software
 *
 * Authors:
 *  Dan Smith <danms@us.ibm.com>
 */

#ifndef CGROUP_H
# define CGROUP_H

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

    VIR_CGROUP_CONTROLLER_LAST
};

VIR_ENUM_DECL(virCgroupController);

int virCgroupForDriver(const char *name,
                       virCgroupPtr *group,
                       int privileged,
                       int create);

int virCgroupForDomain(virCgroupPtr driver,
                       const char *name,
                       virCgroupPtr *group,
                       int create);

int virCgroupForVcpu(virCgroupPtr driver,
                     int vcpuid,
                     virCgroupPtr *group,
                     int create);

int virCgroupPathOfController(virCgroupPtr group,
                              int controller,
                              const char *key,
                              char **path);

int virCgroupAddTask(virCgroupPtr group, pid_t pid);

int virCgroupSetBlkioWeight(virCgroupPtr group, unsigned int weight);
int virCgroupGetBlkioWeight(virCgroupPtr group, unsigned int *weight);

int virCgroupSetBlkioDeviceWeight(virCgroupPtr group,
                                  const char *path,
                                  unsigned int weight);

int virCgroupSetMemory(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemoryUsage(virCgroupPtr group, unsigned long *kb);

int virCgroupSetMemoryHardLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemoryHardLimit(virCgroupPtr group, unsigned long long *kb);
int virCgroupSetMemorySoftLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemorySoftLimit(virCgroupPtr group, unsigned long long *kb);
int virCgroupSetMemSwapHardLimit(virCgroupPtr group, unsigned long long kb);
int virCgroupGetMemSwapHardLimit(virCgroupPtr group, unsigned long long *kb);

enum {
    VIR_CGROUP_DEVICE_READ  = 1,
    VIR_CGROUP_DEVICE_WRITE = 2,
    VIR_CGROUP_DEVICE_MKNOD = 4,
    VIR_CGROUP_DEVICE_RW    = VIR_CGROUP_DEVICE_READ | VIR_CGROUP_DEVICE_WRITE,
    VIR_CGROUP_DEVICE_RWM   = VIR_CGROUP_DEVICE_RW | VIR_CGROUP_DEVICE_MKNOD,
};

int virCgroupDenyAllDevices(virCgroupPtr group);

int virCgroupAllowDevice(virCgroupPtr group,
                         char type,
                         int major,
                         int minor,
                         int perms);
int virCgroupAllowDeviceMajor(virCgroupPtr group,
                              char type,
                              int major,
                              int perms);
int virCgroupAllowDevicePath(virCgroupPtr group,
                             const char *path,
                             int perms);

int virCgroupDenyDevice(virCgroupPtr group,
                        char type,
                        int major,
                        int minor,
                        int perms);
int virCgroupDenyDeviceMajor(virCgroupPtr group,
                             char type,
                             int major,
                             int perms);
int virCgroupDenyDevicePath(virCgroupPtr group,
                            const char *path,
                            int perms);

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

int virCgroupRemove(virCgroupPtr group);

void virCgroupFree(virCgroupPtr *group);
bool virCgroupMounted(virCgroupPtr cgroup, int controller);

int virCgroupKill(virCgroupPtr group, int signum);
int virCgroupKillRecursive(virCgroupPtr group, int signum);
int virCgroupKillPainfully(virCgroupPtr group);

#endif /* CGROUP_H */
