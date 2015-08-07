/*
 * cpu.h: internal functions for CPU manipulation
 *
 * Copyright (C) 2009-2010, 2013 Red Hat, Inc.
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
# include "cpu_ppc64_data.h"


typedef struct _virCPUData virCPUData;
typedef virCPUData *virCPUDataPtr;
struct _virCPUData {
    virArch arch;
    union {
        virCPUx86Data *x86;
        virCPUppc64Data *ppc64;
        /* generic driver needs no data */
    } data;
};


typedef virCPUCompareResult
(*cpuArchCompare)   (virCPUDefPtr host,
                     virCPUDefPtr cpu,
                     bool failIncompatible);

typedef int
(*cpuArchDecode)    (virCPUDefPtr cpu,
                     const virCPUData *data,
                     const char **models,
                     unsigned int nmodels,
                     const char *preferred,
                     unsigned int flags);

typedef int
(*cpuArchEncode)    (virArch arch,
                     const virCPUDef *cpu,
                     virCPUDataPtr *forced,
                     virCPUDataPtr *required,
                     virCPUDataPtr *optional,
                     virCPUDataPtr *disabled,
                     virCPUDataPtr *forbidden,
                     virCPUDataPtr *vendor);

typedef void
(*cpuArchDataFree)  (virCPUDataPtr data);

typedef virCPUDataPtr
(*cpuArchNodeData)  (virArch arch);

typedef virCPUCompareResult
(*cpuArchGuestData) (virCPUDefPtr host,
                     virCPUDefPtr guest,
                     virCPUDataPtr *data,
                     char **message);

typedef virCPUDefPtr
(*cpuArchBaseline)  (virCPUDefPtr *cpus,
                     unsigned int ncpus,
                     const char **models,
                     unsigned int nmodels,
                     unsigned int flags);

typedef int
(*cpuArchUpdate)    (virCPUDefPtr guest,
                     const virCPUDef *host);

typedef int
(*cpuArchHasFeature) (const virCPUData *data,
                      const char *feature);

typedef char *
(*cpuArchDataFormat)(const virCPUData *data);

typedef virCPUDataPtr
(*cpuArchDataParse) (const char *xmlStr);

typedef int
(*cpuArchGetModels) (char ***models);

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
    cpuArchDataFormat   dataFormat;
    cpuArchDataParse    dataParse;
    cpuArchGetModels    getModels;
};


extern virCPUCompareResult
cpuCompareXML(virCPUDefPtr host,
              const char *xml,
              bool failIncompatible)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

extern virCPUCompareResult
cpuCompare  (virCPUDefPtr host,
             virCPUDefPtr cpu,
             bool failIncompatible)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

extern int
cpuDecode   (virCPUDefPtr cpu,
             const virCPUData *data,
             const char **models,
             unsigned int nmodels,
             const char *preferred)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

extern int
cpuEncode   (virArch arch,
             const virCPUDef *cpu,
             virCPUDataPtr *forced,
             virCPUDataPtr *required,
             virCPUDataPtr *optional,
             virCPUDataPtr *disabled,
             virCPUDataPtr *forbidden,
             virCPUDataPtr *vendor)
    ATTRIBUTE_NONNULL(2);

extern void
cpuDataFree (virCPUDataPtr data);

extern virCPUDataPtr
cpuNodeData (virArch arch);

extern virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             virCPUDataPtr *data,
             char **msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

extern char *
cpuBaselineXML(const char **xmlCPUs,
               unsigned int ncpus,
               const char **models,
               unsigned int nmodels,
               unsigned int flags);

extern virCPUDefPtr
cpuBaseline (virCPUDefPtr *cpus,
             unsigned int ncpus,
             const char **models,
             unsigned int nmodels,
             unsigned int flags)
    ATTRIBUTE_NONNULL(1);

extern int
cpuUpdate   (virCPUDefPtr guest,
             const virCPUDef *host)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

extern int
cpuHasFeature(const virCPUData *data,
              const char *feature)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


bool
cpuModelIsAllowed(const char *model,
                  const char **models,
                  unsigned int nmodels)
    ATTRIBUTE_NONNULL(1);

extern int
cpuGetModels(const char *arch, char ***models)
    ATTRIBUTE_NONNULL(1);

/* cpuDataFormat and cpuDataParse are implemented for unit tests only and
 * have no real-life usage
 */
char *cpuDataFormat(const virCPUData *data)
    ATTRIBUTE_NONNULL(1);
virCPUDataPtr cpuDataParse(virArch arch,
                           const char *xmlStr)
    ATTRIBUTE_NONNULL(2);

#endif /* __VIR_CPU_H__ */
