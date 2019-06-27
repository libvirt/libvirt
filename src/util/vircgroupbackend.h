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
#include "virhash.h"

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

typedef bool
(*virCgroupAvailableCB)(void);

typedef bool
(*virCgroupValidateMachineGroupCB)(virCgroupPtr group,
                                   const char *name,
                                   const char *drivername,
                                   const char *machinename);

typedef int
(*virCgroupCopyMountsCB)(virCgroupPtr group,
                         virCgroupPtr parent);

typedef int
(*virCgroupCopyPlacementCB)(virCgroupPtr group,
                            const char *path,
                            virCgroupPtr parent);

typedef int
(*virCgroupDetectMountsCB)(virCgroupPtr group,
                           const char *mntType,
                           const char *mntOpts,
                           const char *mntDir);

typedef int
(*virCgroupDetectPlacementCB)(virCgroupPtr group,
                              const char *path,
                              const char *controllers,
                              const char *selfpath);

typedef int
(*virCgroupValidatePlacementCB)(virCgroupPtr group,
                                pid_t pid);

typedef char *
(*virCgroupStealPlacementCB)(virCgroupPtr group);

typedef int
(*virCgroupDetectControllersCB)(virCgroupPtr group,
                                int controllers);

typedef bool
(*virCgroupHasControllerCB)(virCgroupPtr cgroup,
                            int controller);

typedef int
(*virCgroupGetAnyControllerCB)(virCgroupPtr group);

typedef int
(*virCgroupPathOfControllerCB)(virCgroupPtr group,
                               int controller,
                               const char *key,
                               char **path);

typedef int
(*virCgroupMakeGroupCB)(virCgroupPtr parent,
                        virCgroupPtr group,
                        bool create,
                        unsigned int flags);

typedef int
(*virCgroupRemoveCB)(virCgroupPtr group);

typedef int
(*virCgroupAddTaskCB)(virCgroupPtr group,
                      pid_t pid,
                      unsigned int flags);

typedef int
(*virCgroupHasEmptyTasksCB)(virCgroupPtr cgroup,
                            int controller);

typedef int
(*virCgroupKillRecursiveCB)(virCgroupPtr group,
                            int signum,
                            virHashTablePtr pids);

typedef int
(*virCgroupBindMountCB)(virCgroupPtr group,
                        const char *oldroot,
                        const char *mountopts);

typedef int
(*virCgroupSetOwnerCB)(virCgroupPtr cgroup,
                       uid_t uid,
                       gid_t gid,
                       int controllers);

typedef int
(*virCgroupSetBlkioWeightCB)(virCgroupPtr group,
                             unsigned int weight);

typedef int
(*virCgroupGetBlkioWeightCB)(virCgroupPtr group,
                             unsigned int *weight);

typedef int
(*virCgroupGetBlkioIoServicedCB)(virCgroupPtr group,
                                 long long *bytes_read,
                                 long long *bytes_write,
                                 long long *requests_read,
                                 long long *requests_write);

typedef int
(*virCgroupGetBlkioIoDeviceServicedCB)(virCgroupPtr group,
                                       const char *path,
                                       long long *bytes_read,
                                       long long *bytes_write,
                                       long long *requests_read,
                                       long long *requests_write);

typedef int
(*virCgroupSetBlkioDeviceWeightCB)(virCgroupPtr group,
                                   const char *path,
                                   unsigned int weight);

typedef int
(*virCgroupGetBlkioDeviceWeightCB)(virCgroupPtr group,
                                   const char *path,
                                   unsigned int *weight);

typedef int
(*virCgroupSetBlkioDeviceReadIopsCB)(virCgroupPtr group,
                                     const char *path,
                                     unsigned int riops);

typedef int
(*virCgroupGetBlkioDeviceReadIopsCB)(virCgroupPtr group,
                                     const char *path,
                                     unsigned int *riops);

typedef int
(*virCgroupSetBlkioDeviceWriteIopsCB)(virCgroupPtr group,
                                      const char *path,
                                      unsigned int wiops);

typedef int
(*virCgroupGetBlkioDeviceWriteIopsCB)(virCgroupPtr group,
                                      const char *path,
                                      unsigned int *wiops);

typedef int
(*virCgroupSetBlkioDeviceReadBpsCB)(virCgroupPtr group,
                                    const char *path,
                                    unsigned long long rbps);

typedef int
(*virCgroupGetBlkioDeviceReadBpsCB)(virCgroupPtr group,
                                    const char *path,
                                    unsigned long long *rbps);

typedef int
(*virCgroupSetBlkioDeviceWriteBpsCB)(virCgroupPtr group,
                                     const char *path,
                                     unsigned long long wbps);

typedef int
(*virCgroupGetBlkioDeviceWriteBpsCB)(virCgroupPtr group,
                                     const char *path,
                                     unsigned long long *wbps);

typedef int
(*virCgroupSetMemoryCB)(virCgroupPtr group,
                        unsigned long long kb);

typedef int
(*virCgroupGetMemoryStatCB)(virCgroupPtr group,
                            unsigned long long *cache,
                            unsigned long long *activeAnon,
                            unsigned long long *inactiveAnon,
                            unsigned long long *activeFile,
                            unsigned long long *inactiveFile,
                            unsigned long long *unevictable);

typedef int
(*virCgroupGetMemoryUsageCB)(virCgroupPtr group,
                             unsigned long *kb);

typedef int
(*virCgroupSetMemoryHardLimitCB)(virCgroupPtr group,
                                 unsigned long long kb);

typedef int
(*virCgroupGetMemoryHardLimitCB)(virCgroupPtr group,
                                 unsigned long long *kb);

typedef int
(*virCgroupSetMemorySoftLimitCB)(virCgroupPtr group,
                                 unsigned long long kb);

typedef int
(*virCgroupGetMemorySoftLimitCB)(virCgroupPtr group,
                                 unsigned long long *kb);

typedef int
(*virCgroupSetMemSwapHardLimitCB)(virCgroupPtr group,
                                  unsigned long long kb);

typedef int
(*virCgroupGetMemSwapHardLimitCB)(virCgroupPtr group,
                                  unsigned long long *kb);

typedef int
(*virCgroupGetMemSwapUsageCB)(virCgroupPtr group,
                              unsigned long long *kb);

typedef int
(*virCgroupAllowDeviceCB)(virCgroupPtr group,
                          char type,
                          int major,
                          int minor,
                          int perms);

typedef int
(*virCgroupDenyDeviceCB)(virCgroupPtr group,
                         char type,
                         int major,
                         int minor,
                         int perms);

typedef int
(*virCgroupAllowAllDevicesCB)(virCgroupPtr group,
                              int perms);

typedef int
(*virCgroupDenyAllDevicesCB)(virCgroupPtr group);

typedef int
(*virCgroupSetCpuSharesCB)(virCgroupPtr group,
                           unsigned long long shares);

typedef int
(*virCgroupGetCpuSharesCB)(virCgroupPtr group,
                           unsigned long long *shares);

typedef int
(*virCgroupSetCpuCfsPeriodCB)(virCgroupPtr group,
                              unsigned long long cfs_period);

typedef int
(*virCgroupGetCpuCfsPeriodCB)(virCgroupPtr group,
                              unsigned long long *cfs_period);

typedef int
(*virCgroupSetCpuCfsQuotaCB)(virCgroupPtr group,
                             long long cfs_quota);

typedef int
(*virCgroupGetCpuCfsQuotaCB)(virCgroupPtr group,
                             long long *cfs_quota);

typedef bool
(*virCgroupSupportsCpuBWCB)(virCgroupPtr cgroup);

typedef int
(*virCgroupGetCpuacctUsageCB)(virCgroupPtr group,
                              unsigned long long *usage);

typedef int
(*virCgroupGetCpuacctPercpuUsageCB)(virCgroupPtr group,
                                    char **usage);

typedef int
(*virCgroupGetCpuacctStatCB)(virCgroupPtr group,
                             unsigned long long *user,
                             unsigned long long *sys);

typedef int
(*virCgroupSetFreezerStateCB)(virCgroupPtr group,
                              const char *state);

typedef int
(*virCgroupGetFreezerStateCB)(virCgroupPtr group,
                              char **state);

typedef int
(*virCgroupSetCpusetMemsCB)(virCgroupPtr group,
                            const char *mems);

typedef int
(*virCgroupGetCpusetMemsCB)(virCgroupPtr group,
                            char **mems);

typedef int
(*virCgroupSetCpusetMemoryMigrateCB)(virCgroupPtr group,
                                     bool migrate);

typedef int
(*virCgroupGetCpusetMemoryMigrateCB)(virCgroupPtr group,
                                     bool *migrate);

typedef int
(*virCgroupSetCpusetCpusCB)(virCgroupPtr group,
                            const char *cpus);

typedef int
(*virCgroupGetCpusetCpusCB)(virCgroupPtr group,
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
    virCgroupValidatePlacementCB validatePlacement;
    virCgroupStealPlacementCB stealPlacement;
    virCgroupDetectControllersCB detectControllers;
    virCgroupHasControllerCB hasController;
    virCgroupGetAnyControllerCB getAnyController;
    virCgroupPathOfControllerCB pathOfController;
    virCgroupMakeGroupCB makeGroup;
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
typedef virCgroupBackend *virCgroupBackendPtr;

void
virCgroupBackendRegister(virCgroupBackendPtr backend);

virCgroupBackendPtr *
virCgroupBackendGetAll(void);

virCgroupBackendPtr
virCgroupBackendForController(virCgroupPtr group,
                              unsigned int controller);

#define VIR_CGROUP_BACKEND_CALL(group, controller, func, ret, ...) \
    virCgroupBackendPtr backend = virCgroupBackendForController(group, controller); \
    if (!backend) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       _("failed to get cgroup backend for '%s'"), #func); \
        return ret; \
    } \
    if (!backend->func) { \
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, \
                       _("operation '%s' not supported"), #func); \
        return ret; \
    } \
    return backend->func(group, ##__VA_ARGS__);
