/*
 * nodeinfo.h: Helper routines for OS specific node information
 *
 * Copyright (C) 2006-2008, 2011-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NODEINFO_H__
# define __VIR_NODEINFO_H__

# include "capabilities.h"

int nodeGetInfo(const char *sysfs_prefix, virNodeInfoPtr nodeinfo);
int nodeCapsInitNUMA(const char *sysfs_prefix, virCapsPtr caps);

int nodeGetCPUStats(int cpuNum,
                    virNodeCPUStatsPtr params,
                    int *nparams,
                    unsigned int flags);
int nodeGetMemoryStats(const char *sysfs_prefix,
                       int cellNum,
                       virNodeMemoryStatsPtr params,
                       int *nparams,
                       unsigned int flags);
int nodeGetCellsFreeMemory(unsigned long long *freeMems,
                           int startCell,
                           int maxCells);
int nodeGetMemory(unsigned long long *mem,
                  unsigned long long *freeMem);

virBitmapPtr nodeGetPresentCPUBitmap(const char *sysfs_prefix);
virBitmapPtr nodeGetOnlineCPUBitmap(const char *sysfs_prefix);
int nodeGetCPUCount(const char *sysfs_prefix);
int nodeGetThreadsPerSubcore(virArch arch);

int nodeGetMemoryParameters(virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags);

int nodeSetMemoryParameters(virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags);

int nodeGetCPUMap(const char *sysfs_prefix,
                  unsigned char **cpumap,
                  unsigned int *online,
                  unsigned int flags);

int nodeGetFreePages(unsigned int npages,
                     unsigned int *pages,
                     int startCell,
                     unsigned int cellCount,
                     unsigned long long *counts);

int nodeAllocPages(unsigned int npages,
                   unsigned int *pageSizes,
                   unsigned long long *pageCounts,
                   int startCell,
                   unsigned int cellCount,
                   bool add);
#endif /* __VIR_NODEINFO_H__*/
