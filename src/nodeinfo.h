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

int nodeGetInfo(virNodeInfoPtr nodeinfo);
int nodeCapsInitNUMA(virCapsPtr caps);

int nodeGetCPUStats(int cpuNum,
                    virNodeCPUStatsPtr params,
                    int *nparams,
                    unsigned int flags);
int nodeGetMemoryStats(int cellNum,
                       virNodeMemoryStatsPtr params,
                       int *nparams,
                       unsigned int flags);
int nodeGetCellsFreeMemory(unsigned long long *freeMems,
                           int startCell,
                           int maxCells);
unsigned long long nodeGetFreeMemory(void);

virBitmapPtr nodeGetCPUBitmap(int *max_id);
int nodeGetCPUCount(void);

int nodeGetMemoryParameters(virTypedParameterPtr params,
                            int *nparams,
                            unsigned int flags);

int nodeSetMemoryParameters(virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags);

int nodeGetCPUMap(unsigned char **cpumap,
                  unsigned int *online,
                  unsigned int flags);

#endif /* __VIR_NODEINFO_H__*/
