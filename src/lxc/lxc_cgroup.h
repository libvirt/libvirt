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
#include "lxc_fuse.h"
#include "virusb.h"

virCgroupPtr virLXCCgroupCreate(virDomainDefPtr def,
                                pid_t initpid,
                                size_t nnicindexes,
                                int *nicindexes);
virCgroupPtr virLXCCgroupJoin(virDomainDefPtr def);
int virLXCCgroupSetup(virDomainDefPtr def,
                      virCgroupPtr cgroup,
                      virBitmapPtr nodemask);

int virLXCCgroupGetMeminfo(virLXCMeminfoPtr meminfo);

int
virLXCSetupHostUSBDeviceCgroup(virUSBDevicePtr dev,
                               const char *path,
                               void *opaque);

int
virLXCTeardownHostUSBDeviceCgroup(virUSBDevicePtr dev,
                                  const char *path,
                                  void *opaque);
