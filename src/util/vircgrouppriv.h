/*
 * vircgrouppriv.h: methods for managing control cgroups
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRCGROUPPRIV_H_ALLOW
# error "vircgrouppriv.h may only be included by vircgroup.c or its test suite"
#endif /* LIBVIRT_VIRCGROUPPRIV_H_ALLOW */

#pragma once

#include "vircgroup.h"
#include "vircgroupbackend.h"

struct _virCgroupV1Controller {
    int type;
    char *mountPoint;
    /* If mountPoint holds several controllers co-mounted,
     * then linkPoint is path of the symlink to the mountPoint
     * for just the one controller
     */
    char *linkPoint;
    char *placement;
};
typedef struct _virCgroupV1Controller virCgroupV1Controller;

struct _virCgroupV2Devices {
    int mapfd;
    int progfd;
    ssize_t count;
    ssize_t max;
};
typedef struct _virCgroupV2Devices virCgroupV2Devices;

struct _virCgroupV2Controller {
    int controllers;
    char *mountPoint;
    char *placement;
    virCgroupV2Devices devices;
};
typedef struct _virCgroupV2Controller virCgroupV2Controller;

struct _virCgroup {
    virCgroupBackend *backends[VIR_CGROUP_BACKEND_TYPE_LAST];

    virCgroupV1Controller legacy[VIR_CGROUP_CONTROLLER_LAST];
    virCgroupV2Controller unified;

    char *unitName;
    virCgroup *nested;
};

#define virCgroupGetNested(cgroup) \
    (cgroup->nested ? cgroup->nested : cgroup)

int virCgroupSetValueDBus(const char *unitName,
                          const char *key,
                          GVariant *value);

int virCgroupSetValueRaw(const char *path,
                         const char *value);

int virCgroupGetValueRaw(const char *path,
                         char **value);

int virCgroupSetValueStr(virCgroup *group,
                         int controller,
                         const char *key,
                         const char *value);

int virCgroupGetValueStr(virCgroup *group,
                         int controller,
                         const char *key,
                         char **value);

int virCgroupSetValueU64(virCgroup *group,
                         int controller,
                         const char *key,
                         unsigned long long int value);

int virCgroupGetValueU64(virCgroup *group,
                         int controller,
                         const char *key,
                         unsigned long long int *value);

int virCgroupSetValueI64(virCgroup *group,
                         int controller,
                         const char *key,
                         long long int value);

int virCgroupGetValueI64(virCgroup *group,
                         int controller,
                         const char *key,
                         long long int *value);

int virCgroupPartitionEscape(char **path);

char *virCgroupGetBlockDevString(const char *path);

int virCgroupGetValueForBlkDev(const char *str,
                               const char *devPath,
                               char **value);

int virCgroupNewPartition(const char *path,
                          bool create,
                          int controllers,
                          virCgroup **group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

int virCgroupNewDomainPartition(virCgroup *partition,
                                const char *driver,
                                const char *name,
                                virCgroup **group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int virCgroupRemoveRecursively(char *grppath);


int virCgroupKillRecursiveInternal(virCgroup *group,
                                   int signum,
                                   GHashTable *pids,
                                   const char *taskFile,
                                   bool dormdir);
