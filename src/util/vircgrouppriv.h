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
typedef virCgroupV1Controller *virCgroupV1ControllerPtr;

struct _virCgroupV2Controller {
    int controllers;
    char *mountPoint;
    char *placement;
};
typedef struct _virCgroupV2Controller virCgroupV2Controller;
typedef virCgroupV2Controller *virCgroupV2ControllerPtr;

struct _virCgroup {
    char *path;

    virCgroupBackendPtr backends[VIR_CGROUP_BACKEND_TYPE_LAST];

    virCgroupV1Controller legacy[VIR_CGROUP_CONTROLLER_LAST];
    virCgroupV2Controller unified;
};

int virCgroupSetValueRaw(const char *path,
                         const char *value);

int virCgroupGetValueRaw(const char *path,
                         char **value);

int virCgroupSetValueStr(virCgroupPtr group,
                         int controller,
                         const char *key,
                         const char *value);

int virCgroupGetValueStr(virCgroupPtr group,
                         int controller,
                         const char *key,
                         char **value);

int virCgroupSetValueU64(virCgroupPtr group,
                         int controller,
                         const char *key,
                         unsigned long long int value);

int virCgroupGetValueU64(virCgroupPtr group,
                         int controller,
                         const char *key,
                         unsigned long long int *value);

int virCgroupSetValueI64(virCgroupPtr group,
                         int controller,
                         const char *key,
                         long long int value);

int virCgroupGetValueI64(virCgroupPtr group,
                         int controller,
                         const char *key,
                         long long int *value);

int virCgroupPartitionEscape(char **path);

char *virCgroupGetBlockDevString(const char *path);

int virCgroupGetValueForBlkDev(const char *str,
                               const char *devPath,
                               char **value);

int virCgroupNew(pid_t pid,
                 const char *path,
                 virCgroupPtr parent,
                 int controllers,
                 virCgroupPtr *group);

int virCgroupNewPartition(const char *path,
                          bool create,
                          int controllers,
                          virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

int virCgroupNewDomainPartition(virCgroupPtr partition,
                                const char *driver,
                                const char *name,
                                bool create,
                                virCgroupPtr *group)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int virCgroupRemoveRecursively(char *grppath);


int virCgroupKillRecursiveInternal(virCgroupPtr group,
                                   int signum,
                                   virHashTablePtr pids,
                                   int controller,
                                   const char *taskFile,
                                   bool dormdir);
