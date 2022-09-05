/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_domain.h: header file for domain manager's Cloud-Hypervisor driver functions
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

#include "ch_conf.h"
#include "ch_monitor.h"
#include "virchrdev.h"
#include "vircgroup.h"
#include "virdomainjob.h"


typedef struct _virCHDomainObjPrivate virCHDomainObjPrivate;
struct _virCHDomainObjPrivate {
    virChrdevs *chrdevs;
    virCHDriver *driver;
    virCHMonitor *monitor;
    char *machineName;
    virBitmap *autoCpuset;
    virBitmap *autoNodeset;
    virCgroup *cgroup;
};

#define CH_DOMAIN_PRIVATE(vm) \
    ((virCHDomainObjPrivate*)(vm)->privateData)

virCHMonitor *virCHDomainGetMonitor(virDomainObj *vm);

typedef struct _virCHDomainVcpuPrivate virCHDomainVcpuPrivate;
struct _virCHDomainVcpuPrivate {
    virObject parent;

    pid_t tid; /* vcpu thread id */
    virTristateBool halted;
};

#define CH_DOMAIN_VCPU_PRIVATE(vcpu) \
    ((virCHDomainVcpuPrivate *) (vcpu)->privateData)

extern virDomainXMLPrivateDataCallbacks virCHDriverPrivateDataCallbacks;
extern virDomainDefParserConfig virCHDriverDomainDefParserConfig;

void
virCHDomainRemoveInactive(virCHDriver *driver,
                          virDomainObj *vm);

int
virCHDomainRefreshThreadInfo(virDomainObj *vm);

pid_t
virCHDomainGetVcpuPid(virDomainObj *vm,
                      unsigned int vcpuid);
bool
virCHDomainHasVcpuPids(virDomainObj *vm);

char *
virCHDomainGetMachineName(virDomainObj *vm);

virDomainObj *
virCHDomainObjFromDomain(virDomainPtr domain);
