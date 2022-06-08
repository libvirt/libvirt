/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_cgroup.c: LXC cgroup helpers
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
#include "virusb.h"

virCgroup *virLXCCgroupCreate(virDomainDef *def,
                                pid_t initpid,
                                size_t nnicindexes,
                                int *nicindexes);
virCgroup *virLXCCgroupJoin(virDomainDef *def);
int virLXCCgroupSetup(virDomainDef *def,
                      virCgroup *cgroup,
                      virBitmap *nodemask);

struct virLXCMeminfo {
    unsigned long long memtotal;
    unsigned long long memusage;
    unsigned long long cached;
    unsigned long long active_anon;
    unsigned long long inactive_anon;
    unsigned long long active_file;
    unsigned long long inactive_file;
    unsigned long long unevictable;
    unsigned long long swaptotal;
    unsigned long long swapusage;
};

int virLXCCgroupGetMeminfo(struct virLXCMeminfo *meminfo);

int
virLXCSetupHostUSBDeviceCgroup(virUSBDevice *dev,
                               const char *path,
                               void *opaque);

int
virLXCTeardownHostUSBDeviceCgroup(virUSBDevice *dev,
                                  const char *path,
                                  void *opaque);
