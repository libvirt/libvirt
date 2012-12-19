/*
 * cpu.h: internal functions for CPU manipulation
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#ifndef __VIR_CPU_H__
# define __VIR_CPU_H__

# include "virerror.h"
# include "datatypes.h"
# include "virarch.h"
# include "conf/cpu_conf.h"
# include "cpu_x86_data.h"
# include "cpu_ppc_data.h"


union cpuData {
    struct cpuX86Data x86;
    /* generic driver needs no data */
    /* PowerPC driver need data*/
    struct cpuPPCData ppc;
};


typedef virCPUCompareResult
(*cpuArchCompare)   (virCPUDefPtr host,
                     virCPUDefPtr cpu);

typedef int
(*cpuArchDecode)    (virCPUDefPtr cpu,
                     const union cpuData *data,
                     const char **models,
                     unsigned int nmodels,
                     const char *preferred);

typedef int
(*cpuArchEncode)    (const virCPUDefPtr cpu,
                     union cpuData **forced,
                     union cpuData **required,
                     union cpuData **optional,
                     union cpuData **disabled,
                     union cpuData **forbidden,
                     union cpuData **vendor);

typedef void
(*cpuArchDataFree)  (union cpuData *data);

typedef union cpuData *
(*cpuArchNodeData)  (void);

typedef virCPUCompareResult
(*cpuArchGuestData) (virCPUDefPtr host,
                     virCPUDefPtr guest,
                     union cpuData **data,
                     char **message);

typedef virCPUDefPtr
(*cpuArchBaseline)  (virCPUDefPtr *cpus,
                     unsigned int ncpus,
                     const char **models,
                     unsigned int nmodels);

typedef int
(*cpuArchUpdate)    (virCPUDefPtr guest,
                     const virCPUDefPtr host);

typedef int
(*cpuArchHasFeature) (const union cpuData *data,
                      const char *feature);


struct cpuArchDriver {
    const char *name;
    const virArch *arch;
    unsigned int narch;
    cpuArchCompare      compare;
    cpuArchDecode       decode;
    cpuArchEncode       encode;
    cpuArchDataFree     free;
    cpuArchNodeData     nodeData;
    cpuArchGuestData    guestData;
    cpuArchBaseline     baseline;
    cpuArchUpdate       update;
    cpuArchHasFeature    hasFeature;
};


extern virCPUCompareResult
cpuCompareXML(virCPUDefPtr host,
              const char *xml);

extern virCPUCompareResult
cpuCompare  (virCPUDefPtr host,
             virCPUDefPtr cpu);

extern int
cpuDecode   (virCPUDefPtr cpu,
             const union cpuData *data,
             const char **models,
             unsigned int nmodels,
             const char *preferred);

extern int
cpuEncode   (virArch arch,
             const virCPUDefPtr cpu,
             union cpuData **forced,
             union cpuData **required,
             union cpuData **optional,
             union cpuData **disabled,
             union cpuData **forbidden,
             union cpuData **vendor);

extern void
cpuDataFree (virArch arch,
             union cpuData *data);

extern union cpuData *
cpuNodeData (virArch arch);

extern virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data,
             char **msg);

extern char *
cpuBaselineXML(const char **xmlCPUs,
               unsigned int ncpus,
               const char **models,
               unsigned int nmodels);

extern virCPUDefPtr
cpuBaseline (virCPUDefPtr *cpus,
             unsigned int ncpus,
             const char **models,
             unsigned int nmodels);

extern int
cpuUpdate   (virCPUDefPtr guest,
             const virCPUDefPtr host);

extern int
cpuHasFeature(virArch arch,
              const union cpuData *data,
              const char *feature);


bool
cpuModelIsAllowed(const char *model,
                  const char **models,
                  unsigned int nmodels);

#endif /* __VIR_CPU_H__ */
