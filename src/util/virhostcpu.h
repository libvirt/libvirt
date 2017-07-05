/*
 * virhostcpu.h: helper APIs for host CPU info
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#ifndef __VIR_HOSTCPU_H__
# define __VIR_HOSTCPU_H__

# include "internal.h"
# include "virarch.h"
# include "virbitmap.h"


int virHostCPUGetStats(int cpuNum,
                       virNodeCPUStatsPtr params,
                       int *nparams,
                       unsigned int flags);

bool virHostCPUHasBitmap(void);
virBitmapPtr virHostCPUGetPresentBitmap(void);
virBitmapPtr virHostCPUGetOnlineBitmap(void);
int virHostCPUGetCount(void);
int virHostCPUGetThreadsPerSubcore(virArch arch) ATTRIBUTE_MOCKABLE;

int virHostCPUGetMap(unsigned char **cpumap,
                     unsigned int *online,
                     unsigned int flags);
int virHostCPUGetInfo(virArch hostarch,
                      unsigned int *cpus,
                      unsigned int *mhz,
                      unsigned int *nodes,
                      unsigned int *sockets,
                      unsigned int *cores,
                      unsigned int *threads);

int virHostCPUGetKVMMaxVCPUs(void) ATTRIBUTE_MOCKABLE;

int virHostCPUStatsAssign(virNodeCPUStatsPtr param,
                          const char *name,
                          unsigned long long value);

# ifdef __linux__
int virHostCPUGetSocket(unsigned int cpu, unsigned int *socket);
int virHostCPUGetCore(unsigned int cpu, unsigned int *core);

virBitmapPtr virHostCPUGetSiblingsList(unsigned int cpu);
# endif

int virHostCPUGetOnline(unsigned int cpu, bool *online);

#endif /* __VIR_HOSTCPU_H__*/
