/*
 * nodeinfo.c: Helper routines for OS specific node information
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NODEINFO_H__
# define __VIR_NODEINFO_H__

# include "libvirt/libvirt.h"
# include "capabilities.h"

int nodeGetInfo(virConnectPtr conn, virNodeInfoPtr nodeinfo);
int nodeCapsInitNUMA(virCapsPtr caps);

int nodeGetCPUStats(virConnectPtr conn,
                    int cpuNum,
                    virNodeCPUStatsPtr params,
                    int *nparams,
                    unsigned int flags);
int nodeGetMemoryStats(virConnectPtr conn,
                       int cellNum,
                       virNodeMemoryStatsPtr params,
                       int *nparams,
                       unsigned int flags);
int nodeGetCellsFreeMemory(virConnectPtr conn,
                           unsigned long long *freeMems,
                           int startCell,
                           int maxCells);
unsigned long long nodeGetFreeMemory(virConnectPtr conn);

char *nodeGetCPUmap(virConnectPtr conn,
                    int *max_id,
                    const char *mapname);
#endif /* __VIR_NODEINFO_H__*/
