/*
 * cpu.h: internal functions for CPU manipulation
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#ifndef __VIR_CPU_H__
#define __VIR_CPU_H__

#include "virterror_internal.h"
#include "datatypes.h"
#include "conf/cpu_conf.h"
#include "cpu_x86_data.h"


#define virCPUReportError(conn, code, fmt...)                           \
        virReportErrorHelper(conn, VIR_FROM_CPU, code, __FILE__,        \
                             __FUNCTION__, __LINE__, fmt)


union cpuData {
    struct cpuX86Data x86;
    /* generic driver needs no data */
};


typedef virCPUCompareResult
(*cpuArchCompare)   (virCPUDefPtr host,
                     virCPUDefPtr cpu);

typedef int
(*cpuArchDecode)    (virCPUDefPtr cpu,
                     const union cpuData *data,
                     unsigned int nmodels,
                     const char **models);

typedef int
(*cpuArchEncode)    (const virCPUDefPtr cpu,
                     union cpuData **forced,
                     union cpuData **required,
                     union cpuData **optional,
                     union cpuData **disabled,
                     union cpuData **forbidden);

typedef void
(*cpuArchDataFree)  (union cpuData *data);

typedef union cpuData *
(*cpuArchNodeData)  (void);

typedef virCPUCompareResult
(*cpuArchGuestData) (virCPUDefPtr host,
                     virCPUDefPtr guest,
                     union cpuData **data);


struct cpuArchDriver {
    const char *name;
    const char **arch;
    unsigned int narch;
    cpuArchCompare      compare;
    cpuArchDecode       decode;
    cpuArchEncode       encode;
    cpuArchDataFree     free;
    cpuArchNodeData     nodeData;
    cpuArchGuestData    guestData;
};


extern virCPUCompareResult
cpuCompareXML(virConnectPtr conn,
              virCPUDefPtr host,
              const char *xml);

extern virCPUCompareResult
cpuCompare  (virConnectPtr conn,
             virCPUDefPtr host,
             virCPUDefPtr cpu);

extern int
cpuDecode   (virConnectPtr conn,
             virCPUDefPtr cpu,
             const union cpuData *data,
             unsigned int nmodels,
             const char **models);

extern int
cpuEncode   (virConnectPtr conn,
             const char *arch,
             const virCPUDefPtr cpu,
             union cpuData **forced,
             union cpuData **required,
             union cpuData **optional,
             union cpuData **disabled,
             union cpuData **forbidden);

extern void
cpuDataFree (virConnectPtr conn,
             const char *arch,
             union cpuData *data);

extern union cpuData *
cpuNodeData (virConnectPtr conn,
             const char *arch);

extern virCPUCompareResult
cpuGuestData(virConnectPtr conn,
             virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data);

#endif /* __VIR_CPU_H__ */
