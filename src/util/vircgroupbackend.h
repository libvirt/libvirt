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

#ifndef __VIR_CGROUP_BACKEND_H__
# define __VIR_CGROUP_BACKEND_H__

# include "internal.h"

# include "vircgroup.h"

# define CGROUP_MAX_VAL 512

typedef enum {
    VIR_CGROUP_NONE = 0, /* create subdir under each cgroup if possible. */
    VIR_CGROUP_MEM_HIERACHY = 1 << 0, /* call virCgroupSetMemoryUseHierarchy
                                       * before creating subcgroups and
                                       * attaching tasks
                                       */
} virCgroupBackendFlags;

typedef enum {
    VIR_CGROUP_BACKEND_TYPE_V1 = 0,
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
};
typedef struct _virCgroupBackend virCgroupBackend;
typedef virCgroupBackend *virCgroupBackendPtr;

void
virCgroupBackendRegister(virCgroupBackendPtr backend);

virCgroupBackendPtr *
virCgroupBackendGetAll(void);

#endif /* __VIR_CGROUP_BACKEND_H__ */
