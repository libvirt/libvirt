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
 */

#pragma once

#include "internal.h"
#include "virarch.h"
#include "virbitmap.h"
#include "virenum.h"


typedef struct _virHostCPUTscInfo virHostCPUTscInfo;
struct _virHostCPUTscInfo {
    unsigned long long frequency;
    virTristateBool scaling;
};


int virHostCPUGetStats(int cpuNum,
                       virNodeCPUStatsPtr params,
                       int *nparams,
                       unsigned int flags);

bool virHostCPUHasBitmap(void);
virBitmap *virHostCPUGetPresentBitmap(void);
virBitmap *virHostCPUGetOnlineBitmap(void);
virBitmap *virHostCPUGetAvailableCPUsBitmap(void);

int virHostCPUGetCount(void);
int virHostCPUGetThreadsPerSubcore(virArch arch) G_NO_INLINE;

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


int virHostCPUGetKVMMaxVCPUs(void) G_NO_INLINE;

int virHostCPUStatsAssign(virNodeCPUStatsPtr param,
                          const char *name,
                          unsigned long long value);

#ifdef __linux__
int virHostCPUGetSocket(unsigned int cpu, unsigned int *socket);
int virHostCPUGetDie(unsigned int cpu, unsigned int *die);
int virHostCPUGetCore(unsigned int cpu, unsigned int *core);

virBitmap *virHostCPUGetSiblingsList(unsigned int cpu);
#endif

int virHostCPUGetOnline(unsigned int cpu, bool *online);

unsigned int
virHostCPUGetMicrocodeVersion(virArch hostArch) G_NO_INLINE;

int virHostCPUGetMSR(unsigned long index,
                     uint64_t *msr);

struct kvm_cpuid2 *virHostCPUGetCPUID(void);

virHostCPUTscInfo *virHostCPUGetTscInfo(void);

int virHostCPUGetSignature(char **signature);

int virHostCPUGetPhysAddrSize(const virArch hostArch,
                              unsigned int *size);

int virHostCPUGetHaltPollTime(pid_t pid,
                              unsigned long long *haltPollSuccess,
                              unsigned long long *haltPollFail);

void virHostCPUX86GetCPUID(uint32_t leaf,
                           uint32_t extended,
                           uint32_t *eax,
                           uint32_t *ebx,
                           uint32_t *ecx,
                           uint32_t *edx);
