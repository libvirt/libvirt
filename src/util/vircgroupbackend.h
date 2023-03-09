/*
 * vircgroupbackend.h: methods for cgroups backend
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "internal.h"

#include "vircgroup.h"

#define CGROUP_MAX_VAL 512

typedef enum {
    VIR_CGROUP_NONE = 0, /* create subdir under each cgroup if possible. */
    VIR_CGROUP_MEM_HIERACHY = 1 << 0, /* call virCgroupSetMemoryUseHierarchy
                                       * before creating subcgroups and
                                       * attaching tasks
                                       */
    VIR_CGROUP_THREAD = 1 << 1, /* cgroup v2 handles threads differently */
    VIR_CGROUP_SYSTEMD = 1 << 2, /* with systemd and cgroups v2 we cannot
                                  * manually enable controllers that systemd
                                  * doesn't know how to delegate */
} virCgroupBackendFlags;

typedef enum {
    /* Adds a whole process with all threads to specific cgroup except
     * to systemd named controller. */
    VIR_CGROUP_TASK_PROCESS = 1 << 0,

    /* Same as VIR_CGROUP_TASK_PROCESS but it also adds the task to systemd
     * named controller. */
    VIR_CGROUP_TASK_SYSTEMD = 1 << 1,

    /* Moves only specific thread into cgroup except to systemd
     * named controller. */
    VIR_CGROUP_TASK_THREAD = 1 << 2,
} virCgroupBackendTaskFlags;

typedef enum {
    VIR_CGROUP_BACKEND_TYPE_V2 = 0,
    VIR_CGROUP_BACKEND_TYPE_V1,
    VIR_CGROUP_BACKEND_TYPE_LAST,
} virCgroupBackendType;

VIR_ENUM_DECL(virCgroupBackend);

typedef bool
(*virCgroupAvailableCB)(void);

typedef bool
(*virCgroupValidateMachineGroupCB)(virCgroup *group,
                                   const char *name,
                                   const char *drivername,
                                   const char *machinename);

typedef int
(*virCgroupCopyMountsCB)(virCgroup *group,
                         virCgroup *parent);

typedef int
(*virCgroupCopyPlacementCB)(virCgroup *group,
                            const char *path,
                            virCgroup *parent);

typedef int
(*virCgroupDetectMountsCB)(virCgroup *group,
                           const char *mntType,
                           const char *mntOpts,
                           const char *mntDir);

typedef int
(*virCgroupDetectPlacementCB)(virCgroup *group,
                              const char *path,
                              const char *controllers,
                              const char *selfpath);

typedef int
(*virCgroupSetPlacementCB)(virCgroup *group,
                           const char *path);

typedef int
(*virCgroupValidatePlacementCB)(virCgroup *group,
                                pid_t pid);

typedef char *
(*virCgroupStealPlacementCB)(virCgroup *group);

typedef int
(*virCgroupDetectControllersCB)(virCgroup *group,
                                int controllers,
                                virCgroup *parent,
                                int detected);

typedef bool
(*virCgroupHasControllerCB)(virCgroup *cgroup,
                            int controller);

typedef int
(*virCgroupGetAnyControllerCB)(virCgroup *group);

typedef int
(*virCgroupPathOfControllerCB)(virCgroup *group,
                               int controller,
                               const char *key,
                               char **path);

typedef bool
(*virCgroupExistsCB)(virCgroup *group);

typedef int
(*virCgroupMakeGroupCB)(virCgroup *parent,
                        virCgroup *group,
                        bool create,
                        pid_t pid,
                        unsigned int flags);

typedef int
(*virCgroupRemoveCB)(virCgroup *group);

typedef int
(*virCgroupAddTaskCB)(virCgroup *group,
                      pid_t pid,
                      unsigned int flags);

typedef int
(*virCgroupHasEmptyTasksCB)(virCgroup *cgroup,
                            int controller);

typedef int
(*virCgroupKillRecursiveCB)(virCgroup *group,
                            int signum,
                            GHashTable *pids);

typedef int
(*virCgroupBindMountCB)(virCgroup *group,
                        const char *oldroot,
                        const char *mountopts);

typedef int
(*virCgroupSetOwnerCB)(virCgroup *cgroup,
                       uid_t uid,
                       gid_t gid,
                       int controllers);

typedef int
(*virCgroupSetBlkioWeightCB)(virCgroup *group,
                             unsigned int weight);

typedef int
(*virCgroupGetBlkioWeightCB)(virCgroup *group,
                             unsigned int *weight);

typedef int
(*virCgroupGetBlkioIoServicedCB)(virCgroup *group,
                                 long long *bytes_read,
                                 long long *bytes_write,
                                 long long *requests_read,
                                 long long *requests_write);

typedef int
(*virCgroupGetBlkioIoDeviceServicedCB)(virCgroup *group,
                                       const char *path,
                                       long long *bytes_read,
                                       long long *bytes_write,
                                       long long *requests_read,
                                       long long *requests_write);

typedef int
(*virCgroupSetBlkioDeviceWeightCB)(virCgroup *group,
                                   const char *path,
                                   unsigned int weight);

typedef int
(*virCgroupGetBlkioDeviceWeightCB)(virCgroup *group,
                                   const char *path,
                                   unsigned int *weight);

typedef int
(*virCgroupSetBlkioDeviceReadIopsCB)(virCgroup *group,
                                     const char *path,
                                     unsigned int riops);

typedef int
(*virCgroupGetBlkioDeviceReadIopsCB)(virCgroup *group,
                                     const char *path,
                                     unsigned int *riops);

typedef int
(*virCgroupSetBlkioDeviceWriteIopsCB)(virCgroup *group,
                                      const char *path,
                                      unsigned int wiops);

typedef int
(*virCgroupGetBlkioDeviceWriteIopsCB)(virCgroup *group,
                                      const char *path,
                                      unsigned int *wiops);

typedef int
(*virCgroupSetBlkioDeviceReadBpsCB)(virCgroup *group,
                                    const char *path,
                                    unsigned long long rbps);

typedef int
(*virCgroupGetBlkioDeviceReadBpsCB)(virCgroup *group,
                                    const char *path,
                                    unsigned long long *rbps);

typedef int
(*virCgroupSetBlkioDeviceWriteBpsCB)(virCgroup *group,
                                     const char *path,
                                     unsigned long long wbps);

typedef int
(*virCgroupGetBlkioDeviceWriteBpsCB)(virCgroup *group,
                                     const char *path,
                                     unsigned long long *wbps);

typedef int
(*virCgroupSetMemoryCB)(virCgroup *group,
                        unsigned long long kb);

typedef int
(*virCgroupGetMemoryStatCB)(virCgroup *group,
                            unsigned long long *cache,
                            unsigned long long *activeAnon,
                            unsigned long long *inactiveAnon,
                            unsigned long long *activeFile,
                            unsigned long long *inactiveFile,
                            unsigned long long *unevictable);

typedef int
(*virCgroupGetMemoryUsageCB)(virCgroup *group,
                             unsigned long *kb);

typedef int
(*virCgroupSetMemoryHardLimitCB)(virCgroup *group,
                                 unsigned long long kb);

typedef int
(*virCgroupGetMemoryHardLimitCB)(virCgroup *group,
                                 unsigned long long *kb);

typedef int
(*virCgroupSetMemorySoftLimitCB)(virCgroup *group,
                                 unsigned long long kb);

typedef int
(*virCgroupGetMemorySoftLimitCB)(virCgroup *group,
                                 unsigned long long *kb);

typedef int
(*virCgroupSetMemSwapHardLimitCB)(virCgroup *group,
                                  unsigned long long kb);

typedef int
(*virCgroupGetMemSwapHardLimitCB)(virCgroup *group,
                                  unsigned long long *kb);

typedef int
(*virCgroupGetMemSwapUsageCB)(virCgroup *group,
                              unsigned long long *kb);

typedef int
(*virCgroupAllowDeviceCB)(virCgroup *group,
                          char type,
                          int major,
                          int minor,
                          int perms);

typedef int
(*virCgroupDenyDeviceCB)(virCgroup *group,
                         char type,
                         int major,
                         int minor,
                         int perms);

typedef int
(*virCgroupAllowAllDevicesCB)(virCgroup *group,
                              int perms);

typedef int
(*virCgroupDenyAllDevicesCB)(virCgroup *group);

typedef int
(*virCgroupSetCpuSharesCB)(virCgroup *group,
                           unsigned long long shares);

typedef int
(*virCgroupGetCpuSharesCB)(virCgroup *group,
                           unsigned long long *shares);

typedef int
(*virCgroupSetCpuCfsPeriodCB)(virCgroup *group,
                              unsigned long long cfs_period);

typedef int
(*virCgroupGetCpuCfsPeriodCB)(virCgroup *group,
                              unsigned long long *cfs_period);

typedef int
(*virCgroupSetCpuCfsQuotaCB)(virCgroup *group,
                             long long cfs_quota);

typedef int
(*virCgroupGetCpuCfsQuotaCB)(virCgroup *group,
                             long long *cfs_quota);

typedef bool
(*virCgroupSupportsCpuBWCB)(virCgroup *cgroup);

typedef int
(*virCgroupGetCpuacctUsageCB)(virCgroup *group,
                              unsigned long long *usage);

typedef int
(*virCgroupGetCpuacctPercpuUsageCB)(virCgroup *group,
                                    char **usage);

typedef int
(*virCgroupGetCpuacctStatCB)(virCgroup *group,
                             unsigned long long *user,
                             unsigned long long *sys);

typedef int
(*virCgroupSetFreezerStateCB)(virCgroup *group,
                              const char *state);

typedef int
(*virCgroupGetFreezerStateCB)(virCgroup *group,
                              char **state);

typedef int
(*virCgroupSetCpusetMemsCB)(virCgroup *group,
                            const char *mems);

typedef int
(*virCgroupGetCpusetMemsCB)(virCgroup *group,
                            char **mems);

typedef int
(*virCgroupSetCpusetMemoryMigrateCB)(virCgroup *group,
                                     bool migrate);

typedef int
(*virCgroupGetCpusetMemoryMigrateCB)(virCgroup *group,
                                     bool *migrate);

typedef int
(*virCgroupSetCpusetCpusCB)(virCgroup *group,
                            const char *cpus);

typedef int
(*virCgroupGetCpusetCpusCB)(virCgroup *group,
                            char **cpus);

struct _virCgroupBackend {
    virCgroupBackendType type;

    /* Mandatory callbacks that need to be implemented for every backend. */
    virCgroupAvailableCB available;
    virCgroupValidateMachineGroupCB validateMachineGroup;
    virCgroupCopyMountsCB copyMounts;
    virCgroupCopyPlacementCB copyPlacement;
    virCgroupDetectMountsCB detectMounts;
    virCgroupDetectPlacementCB detectPlacement;
    virCgroupSetPlacementCB setPlacement;
    virCgroupValidatePlacementCB validatePlacement;
    virCgroupStealPlacementCB stealPlacement;
    virCgroupDetectControllersCB detectControllers;
    virCgroupHasControllerCB hasController;
    virCgroupGetAnyControllerCB getAnyController;
    virCgroupPathOfControllerCB pathOfController;
    virCgroupMakeGroupCB makeGroup;
    virCgroupExistsCB exists;
    virCgroupRemoveCB remove;
    virCgroupAddTaskCB addTask;
    virCgroupHasEmptyTasksCB hasEmptyTasks;
    virCgroupKillRecursiveCB killRecursive;
    virCgroupBindMountCB bindMount;
    virCgroupSetOwnerCB setOwner;

    /* Optional cgroup controller specific callbacks. */
    virCgroupSetBlkioWeightCB setBlkioWeight;
    virCgroupGetBlkioWeightCB getBlkioWeight;
    virCgroupGetBlkioIoServicedCB getBlkioIoServiced;
    virCgroupGetBlkioIoDeviceServicedCB getBlkioIoDeviceServiced;
    virCgroupSetBlkioDeviceWeightCB setBlkioDeviceWeight;
    virCgroupGetBlkioDeviceWeightCB getBlkioDeviceWeight;
    virCgroupSetBlkioDeviceReadIopsCB setBlkioDeviceReadIops;
    virCgroupGetBlkioDeviceReadIopsCB getBlkioDeviceReadIops;
    virCgroupSetBlkioDeviceWriteIopsCB setBlkioDeviceWriteIops;
    virCgroupGetBlkioDeviceWriteIopsCB getBlkioDeviceWriteIops;
    virCgroupSetBlkioDeviceReadBpsCB setBlkioDeviceReadBps;
    virCgroupGetBlkioDeviceReadBpsCB getBlkioDeviceReadBps;
    virCgroupSetBlkioDeviceWriteBpsCB setBlkioDeviceWriteBps;
    virCgroupGetBlkioDeviceWriteBpsCB getBlkioDeviceWriteBps;

    virCgroupSetMemoryCB setMemory;
    virCgroupGetMemoryStatCB getMemoryStat;
    virCgroupGetMemoryUsageCB getMemoryUsage;
    virCgroupSetMemoryHardLimitCB setMemoryHardLimit;
    virCgroupGetMemoryHardLimitCB getMemoryHardLimit;
    virCgroupSetMemorySoftLimitCB setMemorySoftLimit;
    virCgroupGetMemorySoftLimitCB getMemorySoftLimit;
    virCgroupSetMemSwapHardLimitCB setMemSwapHardLimit;
    virCgroupGetMemSwapHardLimitCB getMemSwapHardLimit;
    virCgroupGetMemSwapUsageCB getMemSwapUsage;

    virCgroupAllowDeviceCB allowDevice;
    virCgroupDenyDeviceCB denyDevice;
    virCgroupAllowAllDevicesCB allowAllDevices;
    virCgroupDenyAllDevicesCB denyAllDevices;

    virCgroupSetCpuSharesCB setCpuShares;
    virCgroupGetCpuSharesCB getCpuShares;
    virCgroupSetCpuCfsPeriodCB setCpuCfsPeriod;
    virCgroupGetCpuCfsPeriodCB getCpuCfsPeriod;
    virCgroupSetCpuCfsQuotaCB setCpuCfsQuota;
    virCgroupGetCpuCfsQuotaCB getCpuCfsQuota;
    virCgroupSupportsCpuBWCB supportsCpuBW;

    virCgroupGetCpuacctUsageCB getCpuacctUsage;
    virCgroupGetCpuacctPercpuUsageCB getCpuacctPercpuUsage;
    virCgroupGetCpuacctStatCB getCpuacctStat;

    virCgroupSetFreezerStateCB setFreezerState;
    virCgroupGetFreezerStateCB getFreezerState;

    virCgroupSetCpusetMemsCB setCpusetMems;
    virCgroupGetCpusetMemsCB getCpusetMems;
    virCgroupSetCpusetMemoryMigrateCB setCpusetMemoryMigrate;
    virCgroupGetCpusetMemoryMigrateCB getCpusetMemoryMigrate;
    virCgroupSetCpusetCpusCB setCpusetCpus;
    virCgroupGetCpusetCpusCB getCpusetCpus;
};
typedef struct _virCgroupBackend virCgroupBackend;

void
virCgroupBackendRegister(virCgroupBackend *backend);

virCgroupBackend **
virCgroupBackendGetAll(void);

virCgroupBackend *
virCgroupBackendForController(virCgroup *group,
                              unsigned int controller);

#define VIR_CGROUP_BACKEND_CALL(group, controller, func, ret, ...) \
    do { \
        virCgroupBackend *backend = virCgroupBackendForController(group, controller); \
        if (!backend) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           _("failed to get cgroup backend for '%1$s' controller '%2$u'"), \
                           #func, controller); \
            return ret; \
        } \
        if (!backend->func) { \
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, \
                           _("operation '%1$s' not supported for backend '%2$s'"), \
                           #func, virCgroupBackendTypeToString(backend->type)); \
            return ret; \
        } \
        return backend->func(group, ##__VA_ARGS__); \
    } while (0)
