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


typedef struct _virCPUData virCPUData;
typedef virCPUData *virCPUDataPtr;
struct _virCPUData {
    virArch arch;
    union {
        struct cpuX86Data *x86;
        struct cpuPPCData ppc;
        /* generic driver needs no data */
    } data;
};


typedef virCPUCompareResult
(*cpuArchCompare)   (virCPUDefPtr host,
                     virCPUDefPtr cpu);

typedef int
(*cpuArchDecode)    (virCPUDefPtr cpu,
                     const virCPUDataPtr data,
                     const char **models,
                     unsigned int nmodels,
                     const char *preferred);

typedef int
(*cpuArchEncode)    (virArch arch,
                     const virCPUDefPtr cpu,
                     virCPUDataPtr *forced,
                     virCPUDataPtr *required,
                     virCPUDataPtr *optional,
                     virCPUDataPtr *disabled,
                     virCPUDataPtr *forbidden,
                     virCPUDataPtr *vendor);

typedef void
(*cpuArchDataFree)  (virCPUDataPtr data);

typedef virCPUDataPtr
(*cpuArchNodeData)  (void);

typedef virCPUCompareResult
(*cpuArchGuestData) (virCPUDefPtr host,
                     virCPUDefPtr guest,
                     virCPUDataPtr *data,
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
(*cpuArchHasFeature) (const virCPUDataPtr data,
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
             const virCPUDataPtr data,
             const char **models,
             unsigned int nmodels,
             const char *preferred);

extern int
cpuEncode   (virArch arch,
             const virCPUDefPtr cpu,
             virCPUDataPtr *forced,
             virCPUDataPtr *required,
             virCPUDataPtr *optional,
             virCPUDataPtr *disabled,
             virCPUDataPtr *forbidden,
             virCPUDataPtr *vendor);

extern void
cpuDataFree (virCPUDataPtr data);

extern virCPUDataPtr
cpuNodeData (virArch arch);

extern virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             virCPUDataPtr *data,
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
cpuHasFeature(const virCPUDataPtr data,
              const char *feature);


bool
cpuModelIsAllowed(const char *model,
                  const char **models,
                  unsigned int nmodels);

#endif /* __VIR_CPU_H__ */
