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
# include "cpu_conf.h"
# include "cpu_x86_data.h"
# include "cpu_ppc64_data.h"


typedef struct _virCPUData virCPUData;
typedef virCPUData *virCPUDataPtr;
struct _virCPUData {
    virArch arch;
    union {
        virCPUx86Data x86;
        virCPUppc64Data ppc64;
        /* generic driver needs no data */
    } data;
};


typedef virCPUCompareResult
(*virCPUArchCompare)(virCPUDefPtr host,
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

typedef int
(*virCPUArchGetHost)(virCPUDefPtr cpu,
                     const char **models,
                     unsigned int nmodels);

typedef virCPUDefPtr
(*cpuArchBaseline)  (virCPUDefPtr *cpus,
                     unsigned int ncpus,
                     const char **models,
                     unsigned int nmodels,
                     unsigned int flags);

typedef int
(*virCPUArchUpdate)(virCPUDefPtr guest,
                    const virCPUDef *host);

typedef int
(*virCPUArchUpdateLive)(virCPUDefPtr cpu,
                        virCPUDataPtr dataEnabled,
                        virCPUDataPtr dataDisabled);

typedef int
(*virCPUArchCheckFeature)(const virCPUDef *cpu,
                          const char *feature);

typedef int
(*virCPUArchDataCheckFeature)(const virCPUData *data,
                              const char *feature);

typedef char *
(*virCPUArchDataFormat)(const virCPUData *data);

typedef virCPUDataPtr
(*virCPUArchDataParse)(xmlXPathContextPtr ctxt);

typedef int
(*virCPUArchGetModels)(char ***models);

typedef int
(*virCPUArchTranslate)(virCPUDefPtr cpu,
                       const char **models,
                       unsigned int nmodels);

typedef int
(*virCPUArchConvertLegacy)(virCPUDefPtr cpu);

struct cpuArchDriver {
    const char *name;
    const virArch *arch;
    unsigned int narch;
    virCPUArchCompare   compare;
    cpuArchDecode       decode;
    cpuArchEncode       encode;
    cpuArchDataFree     dataFree;
    virCPUArchGetHost   getHost;
    cpuArchBaseline     baseline;
    virCPUArchUpdate    update;
    virCPUArchUpdateLive updateLive;
    virCPUArchCheckFeature checkFeature;
    virCPUArchDataCheckFeature dataCheckFeature;
    virCPUArchDataFormat dataFormat;
    virCPUArchDataParse dataParse;
    virCPUArchGetModels getModels;
    virCPUArchTranslate translate;
    virCPUArchConvertLegacy convertLegacy;
};


virCPUCompareResult
virCPUCompareXML(virArch arch,
                 virCPUDefPtr host,
                 const char *xml,
                 bool failIncompatible);

virCPUCompareResult
virCPUCompare(virArch arch,
              virCPUDefPtr host,
              virCPUDefPtr cpu,
              bool failIncompatible)
    ATTRIBUTE_NONNULL(3);

int
cpuDecode   (virCPUDefPtr cpu,
             const virCPUData *data,
             const char **models,
             unsigned int nmodels,
             const char *preferred)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
cpuEncode   (virArch arch,
             const virCPUDef *cpu,
             virCPUDataPtr *forced,
             virCPUDataPtr *required,
             virCPUDataPtr *optional,
             virCPUDataPtr *disabled,
             virCPUDataPtr *forbidden,
             virCPUDataPtr *vendor)
    ATTRIBUTE_NONNULL(2);

virCPUDataPtr
virCPUDataNew(virArch arch);

void
virCPUDataFree(virCPUDataPtr data);

virCPUDefPtr
virCPUGetHost(virArch arch,
              virCPUType type,
              virNodeInfoPtr nodeInfo,
              const char **models,
              unsigned int nmodels);

virCPUDefPtr
virCPUProbeHost(virArch arch);

char *
cpuBaselineXML(const char **xmlCPUs,
               unsigned int ncpus,
               const char **models,
               unsigned int nmodels,
               unsigned int flags);

virCPUDefPtr
cpuBaseline (virCPUDefPtr *cpus,
             unsigned int ncpus,
             const char **models,
             unsigned int nmodels,
             unsigned int flags);

int
virCPUUpdate(virArch arch,
             virCPUDefPtr guest,
             const virCPUDef *host)
    ATTRIBUTE_NONNULL(2);

int
virCPUUpdateLive(virArch arch,
                 virCPUDefPtr cpu,
                 virCPUDataPtr dataEnabled,
                 virCPUDataPtr dataDisabled)
    ATTRIBUTE_NONNULL(2);

int
virCPUCheckFeature(virArch arch,
                   const virCPUDef *cpu,
                   const char *feature)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);


int
virCPUDataCheckFeature(const virCPUData *data,
                       const char *feature)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


bool
virCPUModelIsAllowed(const char *model,
                     const char **models,
                     unsigned int nmodels)
    ATTRIBUTE_NONNULL(1);

int
virCPUGetModels(virArch arch, char ***models);

int
virCPUTranslate(virArch arch,
                virCPUDefPtr cpu,
                const char **models,
                unsigned int nmodels)
    ATTRIBUTE_NONNULL(2);

int
virCPUConvertLegacy(virArch arch,
                    virCPUDefPtr cpu)
    ATTRIBUTE_NONNULL(2);

/* virCPUDataFormat and virCPUDataParse are implemented for unit tests only and
 * have no real-life usage
 */
char *virCPUDataFormat(const virCPUData *data)
    ATTRIBUTE_NONNULL(1);
virCPUDataPtr virCPUDataParse(const char *xmlStr)
    ATTRIBUTE_NONNULL(1);

#endif /* __VIR_CPU_H__ */
