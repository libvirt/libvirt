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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#ifndef __VIR_CPU_H__
# define __VIR_CPU_H__

# include "virterror_internal.h"
# include "datatypes.h"
# include "conf/cpu_conf.h"
# include "cpu_x86_data.h"


# define virCPUReportError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_CPU, code, __FILE__,             \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


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
                     union cpuData **data);

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
    const char **arch;
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
cpuEncode   (const char *arch,
             const virCPUDefPtr cpu,
             union cpuData **forced,
             union cpuData **required,
             union cpuData **optional,
             union cpuData **disabled,
             union cpuData **forbidden,
             union cpuData **vendor);

extern void
cpuDataFree (const char *arch,
             union cpuData *data);

extern union cpuData *
cpuNodeData (const char *arch);

extern virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data);

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
cpuHasFeature(const char *arch,
              const union cpuData *data,
              const char *feature);


#endif /* __VIR_CPU_H__ */
