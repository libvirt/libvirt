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

#include "datatypes.h"
#include "virarch.h"
#include "domain_capabilities.h"
#include "cpu_conf.h"
#include "cpu_x86_data.h"
#include "cpu_ppc64_data.h"
#include "cpu_arm_data.h"


typedef struct _virCPUData virCPUData;
struct _virCPUData {
    virArch arch;
    union {
        virCPUx86Data x86;
        virCPUppc64Data ppc64;
        virCPUarmData arm;
        /* generic driver needs no data */
    } data;
};


typedef virCPUCompareResult
(*virCPUArchCompare)(virCPUDef *host,
                     virCPUDef *cpu,
                     bool failIncompatible);

typedef int
(*cpuArchDecode)    (virCPUDef *cpu,
                     const virCPUData *data,
                     virDomainCapsCPUModels *models);

typedef int
(*cpuArchEncode)    (virArch arch,
                     const virCPUDef *cpu,
                     virCPUData **forced,
                     virCPUData **required,
                     virCPUData **optional,
                     virCPUData **disabled,
                     virCPUData **forbidden,
                     virCPUData **vendor);

typedef virCPUData *
(*cpuArchDataCopyNew)(virCPUData *data);

typedef void
(*cpuArchDataFree)  (virCPUData *data);

typedef int
(*virCPUArchGetHost)(virCPUDef *cpu,
                     virDomainCapsCPUModels *models);

typedef virCPUDef *
(*virCPUArchBaseline)(virCPUDef **cpus,
                      unsigned int ncpus,
                      virDomainCapsCPUModels *models,
                      const char **features,
                      bool migratable);

typedef int
(*virCPUArchUpdate)(virCPUDef *guest,
                    const virCPUDef *host,
                    bool relative);

typedef int
(*virCPUArchUpdateLive)(virCPUDef *cpu,
                        virCPUData *dataEnabled,
                        virCPUData *dataDisabled);

typedef int
(*virCPUArchCheckFeature)(const virCPUDef *cpu,
                          const char *feature);

typedef int
(*virCPUArchDataCheckFeature)(const virCPUData *data,
                              const char *feature);

typedef char *
(*virCPUArchDataFormat)(const virCPUData *data);

typedef virCPUData *
(*virCPUArchDataParse)(xmlNodePtr node);

typedef int
(*virCPUArchGetModels)(char ***models);

typedef const char *
(*virCPUArchGetVendorForModel)(const char *model);

typedef int
(*virCPUArchTranslate)(virCPUDef *cpu,
                       virDomainCapsCPUModels *models);

typedef int
(*virCPUArchConvertLegacy)(virCPUDef *cpu);

typedef int
(*virCPUArchExpandFeatures)(virCPUDef *cpu);

typedef virCPUDef *
(*virCPUArchCopyMigratable)(virCPUDef *cpu);

typedef int
(*virCPUArchValidateFeatures)(virCPUDef *cpu);

typedef int
(*virCPUArchDataAddFeature)(virCPUData *cpuData,
                            const char *name);

typedef virCPUCompareResult
(*virCPUArchDataIsIdentical)(const virCPUData *a,
                             const virCPUData *b);

typedef virCPUData *
(*virCPUArchDataGetHost)(void);

struct cpuArchDriver {
    const char *name;
    const virArch *arch;
    unsigned int narch;
    virCPUArchCompare   compare;
    cpuArchDecode       decode;
    cpuArchEncode       encode;
    cpuArchDataCopyNew  dataCopyNew;
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
    virCPUArchGetVendorForModel getVendorForModel;
    virCPUArchTranslate translate;
    virCPUArchConvertLegacy convertLegacy;
    virCPUArchExpandFeatures expandFeatures;
    virCPUArchCopyMigratable copyMigratable;
    virCPUArchValidateFeatures validateFeatures;
    virCPUArchDataAddFeature dataAddFeature;
    virCPUArchDataIsIdentical dataIsIdentical;
    virCPUArchDataGetHost dataGetHost;
};


virCPUCompareResult
virCPUCompareXML(virArch arch,
                 virCPUDef *host,
                 const char *xml,
                 bool failIncompatible,
                 bool validateXML);

virCPUCompareResult
virCPUCompare(virArch arch,
              virCPUDef *host,
              virCPUDef *cpu,
              bool failIncompatible)
    ATTRIBUTE_NONNULL(3);

int
cpuDecode   (virCPUDef *cpu,
             const virCPUData *data,
             virDomainCapsCPUModels *models)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
cpuEncode   (virArch arch,
             const virCPUDef *cpu,
             virCPUData **forced,
             virCPUData **required,
             virCPUData **optional,
             virCPUData **disabled,
             virCPUData **forbidden,
             virCPUData **vendor)
    ATTRIBUTE_NONNULL(2);

virCPUData *
virCPUDataNew(virArch arch);

virCPUData *
virCPUDataNewCopy(virCPUData *data);

void
virCPUDataFree(virCPUData *data);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUData, virCPUDataFree);

bool
virCPUGetHostIsSupported(virArch arch);

virCPUDef *
virCPUGetHost(virArch arch,
              virCPUType type,
              virNodeInfoPtr nodeInfo,
              virDomainCapsCPUModels *models);

virCPUDef *
virCPUProbeHost(virArch arch) G_NO_INLINE;

virCPUDef *
virCPUBaseline(virArch arch,
               virCPUDef **cpus,
               unsigned int ncpus,
               virDomainCapsCPUModels *models,
               const char **features,
               bool migratable);

int
virCPUUpdate(virArch arch,
             virCPUDef *guest,
             const virCPUDef *host)
    ATTRIBUTE_NONNULL(2);

int
virCPUUpdateLive(virArch arch,
                 virCPUDef *cpu,
                 virCPUData *dataEnabled,
                 virCPUData *dataDisabled)
    ATTRIBUTE_NONNULL(2);

int
virCPUCheckFeature(virArch arch,
                   const virCPUDef *cpu,
                   const char *feature)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);


int
virCPUCheckForbiddenFeatures(virCPUDef *guest,
                             const virCPUDef *host)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


int
virCPUDataCheckFeature(const virCPUData *data,
                       const char *feature)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);


bool
virCPUModelIsAllowed(const char *model,
                     virDomainCapsCPUModels *models)
    ATTRIBUTE_NONNULL(1);

int
virCPUGetModels(virArch arch, char ***models);

const char *
virCPUGetVendorForModel(virArch arch,
                        const char *model);

int
virCPUTranslate(virArch arch,
                virCPUDef *cpu,
                virDomainCapsCPUModels *models)
    ATTRIBUTE_NONNULL(2);

int
virCPUConvertLegacy(virArch arch,
                    virCPUDef *cpu)
    ATTRIBUTE_NONNULL(2);

int
virCPUExpandFeatures(virArch arch,
                     virCPUDef *cpu);

virCPUDef *
virCPUCopyMigratable(virArch arch,
                     virCPUDef *cpu);

int
virCPUValidateFeatures(virArch arch,
                       virCPUDef *cpu)
    ATTRIBUTE_NONNULL(2);

int
virCPUDataAddFeature(virCPUData *cpuData,
                     const char *name);

virCPUCompareResult
virCPUDataIsIdentical(const virCPUData *a,
                      const virCPUData *b);

virCPUData*
virCPUDataGetHost(void);

bool
virCPUArchIsSupported(virArch arch);

/* virCPUDataFormat and virCPUDataParse are implemented for unit tests only and
 * have no real-life usage
 */
char *virCPUDataFormat(const virCPUData *data)
    ATTRIBUTE_NONNULL(1);
virCPUData *virCPUDataParse(const char *xmlStr)
    ATTRIBUTE_NONNULL(1);
virCPUData *virCPUDataParseNode(xmlNodePtr node)
    ATTRIBUTE_NONNULL(1);
