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
 */

#pragma once

#include "virerror.h"
#include "datatypes.h"
#include "virarch.h"
#include "domain_capabilities.h"
#include "cpu_conf.h"
#include "cpu_x86_data.h"
#include "cpu_ppc64_data.h"


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
                     virDomainCapsCPUModelsPtr models);

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
                     virDomainCapsCPUModelsPtr models);

typedef virCPUDefPtr
(*virCPUArchBaseline)(virCPUDefPtr *cpus,
                      unsigned int ncpus,
                      virDomainCapsCPUModelsPtr models,
                      const char **features,
                      bool migratable);

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
                       virDomainCapsCPUModelsPtr models);

typedef int
(*virCPUArchConvertLegacy)(virCPUDefPtr cpu);

typedef int
(*virCPUArchExpandFeatures)(virCPUDefPtr cpu);

typedef virCPUDefPtr
(*virCPUArchCopyMigratable)(virCPUDefPtr cpu);

typedef int
(*virCPUArchValidateFeatures)(virCPUDefPtr cpu);

typedef int
(*virCPUArchDataAddFeature)(virCPUDataPtr cpuData,
                            const char *name);

struct cpuArchDriver {
    const char *name;
    const virArch *arch;
    unsigned int narch;
    virCPUArchCompare   compare;
    cpuArchDecode       decode;
    cpuArchEncode       encode;
    cpuArchDataFree     dataFree;
    virCPUArchGetHost   getHost;
    virCPUArchBaseline baseline;
    virCPUArchUpdate    update;
    virCPUArchUpdateLive updateLive;
    virCPUArchCheckFeature checkFeature;
    virCPUArchDataCheckFeature dataCheckFeature;
    virCPUArchDataFormat dataFormat;
    virCPUArchDataParse dataParse;
    virCPUArchGetModels getModels;
    virCPUArchTranslate translate;
    virCPUArchConvertLegacy convertLegacy;
    virCPUArchExpandFeatures expandFeatures;
    virCPUArchCopyMigratable copyMigratable;
    virCPUArchValidateFeatures validateFeatures;
    virCPUArchDataAddFeature dataAddFeature;
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
             virDomainCapsCPUModelsPtr models)
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

bool
virCPUGetHostIsSupported(virArch arch);

virCPUDefPtr
virCPUGetHost(virArch arch,
              virCPUType type,
              virNodeInfoPtr nodeInfo,
              virDomainCapsCPUModelsPtr models);

virCPUDefPtr
virCPUProbeHost(virArch arch);

virCPUDefPtr
virCPUBaseline(virArch arch,
               virCPUDefPtr *cpus,
               unsigned int ncpus,
               virDomainCapsCPUModelsPtr models,
               const char **features,
               bool migratable);

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
                     virDomainCapsCPUModelsPtr models)
    ATTRIBUTE_NONNULL(1);

int
virCPUGetModels(virArch arch, char ***models);

int
virCPUTranslate(virArch arch,
                virCPUDefPtr cpu,
                virDomainCapsCPUModelsPtr models)
    ATTRIBUTE_NONNULL(2);

int
virCPUConvertLegacy(virArch arch,
                    virCPUDefPtr cpu)
    ATTRIBUTE_NONNULL(2);

int
virCPUExpandFeatures(virArch arch,
                     virCPUDefPtr cpu);

virCPUDefPtr
virCPUCopyMigratable(virArch arch,
                     virCPUDefPtr cpu);

int
virCPUValidateFeatures(virArch arch,
                       virCPUDefPtr cpu)
    ATTRIBUTE_NONNULL(2);

int
virCPUDataAddFeature(virCPUDataPtr cpuData,
                     const char *name);

/* virCPUDataFormat and virCPUDataParse are implemented for unit tests only and
 * have no real-life usage
 */
char *virCPUDataFormat(const virCPUData *data)
    ATTRIBUTE_NONNULL(1);
virCPUDataPtr virCPUDataParse(const char *xmlStr)
    ATTRIBUTE_NONNULL(1);
