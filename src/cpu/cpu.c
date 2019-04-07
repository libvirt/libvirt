/*
 * cpu.c: internal functions for CPU manipulation
 *
 * Copyright (C) 2009-2013 Red Hat, Inc.
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

#include <config.h>

#include "virlog.h"
#include "viralloc.h"
#include "virxml.h"
#include "cpu.h"
#include "cpu_map.h"
#include "cpu_x86.h"
#include "cpu_ppc64.h"
#include "cpu_s390.h"
#include "cpu_arm.h"
#include "capabilities.h"
#include "virstring.h"


#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu");

static struct cpuArchDriver *drivers[] = {
    &cpuDriverX86,
    &cpuDriverPPC64,
    &cpuDriverS390,
    &cpuDriverArm,
};


static struct cpuArchDriver *
cpuGetSubDriver(virArch arch)
{
    size_t i;
    size_t j;

    if (arch == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("undefined hardware architecture"));
        return NULL;
    }

    for (i = 0; i < ARRAY_CARDINALITY(drivers); i++) {
        for (j = 0; j < drivers[i]->narch; j++) {
            if (arch == drivers[i]->arch[j])
                return drivers[i];
        }
    }

    virReportError(VIR_ERR_NO_SUPPORT,
                   _("'%s' architecture is not supported by CPU driver"),
                   virArchToString(arch));
    return NULL;
}


static struct cpuArchDriver *
cpuGetSubDriverByName(const char *name)
{
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(drivers); i++) {
        if (STREQ_NULLABLE(name, drivers[i]->name))
            return drivers[i];
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("CPU driver '%s' does not exist"),
                   name);
    return NULL;
}


/**
 * virCPUCompareXML:
 *
 * @arch: CPU architecture
 * @host: host CPU definition
 * @xml: XML description of either guest or host CPU to be compared with @host
 * @failIncompatible: return an error instead of VIR_CPU_COMPARE_INCOMPATIBLE
 *
 * Compares the CPU described by @xml with @host CPU.
 *
 * Returns VIR_CPU_COMPARE_ERROR on error, VIR_CPU_COMPARE_INCOMPATIBLE when
 * the two CPUs are incompatible, VIR_CPU_COMPARE_IDENTICAL when the two CPUs
 * are identical, VIR_CPU_COMPARE_SUPERSET when the @xml CPU is a superset of
 * the @host CPU. If @failIncompatible is true, the function will return
 * VIR_CPU_COMPARE_ERROR (and set VIR_ERR_CPU_INCOMPATIBLE error) when the
 * two CPUs are incompatible.
 */
virCPUCompareResult
virCPUCompareXML(virArch arch,
                 virCPUDefPtr host,
                 const char *xml,
                 bool failIncompatible)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;

    VIR_DEBUG("arch=%s, host=%p, xml=%s",
              virArchToString(arch), host, NULLSTR(xml));

    if (!xml) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("missing CPU definition"));
        goto cleanup;
    }

    if (!(doc = virXMLParseStringCtxt(xml, _("(CPU_definition)"), &ctxt)))
        goto cleanup;

    if (virCPUDefParseXML(ctxt, NULL, VIR_CPU_TYPE_AUTO, &cpu) < 0)
        goto cleanup;

    ret = virCPUCompare(arch, host, cpu, failIncompatible);

 cleanup:
    virCPUDefFree(cpu);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


/**
 * virCPUCompare:
 *
 * @arch: CPU architecture
 * @host: host CPU definition
 * @cpu: either guest or host CPU to be compared with @host
 * @failIncompatible: return an error instead of VIR_CPU_COMPARE_INCOMPATIBLE
 *
 * Compares the CPU described by @cpu with @host CPU.
 *
 * Returns VIR_CPU_COMPARE_ERROR on error, VIR_CPU_COMPARE_INCOMPATIBLE when
 * the two CPUs are incompatible, VIR_CPU_COMPARE_IDENTICAL when the two CPUs
 * are identical, VIR_CPU_COMPARE_SUPERSET when the @cpu CPU is a superset of
 * the @host CPU. If @failIncompatible is true, the function will return
 * VIR_CPU_COMPARE_ERROR (and set VIR_ERR_CPU_INCOMPATIBLE error) when the
 * two CPUs are incompatible.
 */
virCPUCompareResult
virCPUCompare(virArch arch,
              virCPUDefPtr host,
              virCPUDefPtr cpu,
              bool failIncompatible)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, host=%p, cpu=%p",
              virArchToString(arch), host, cpu);

    if (!(driver = cpuGetSubDriver(arch)))
        return VIR_CPU_COMPARE_ERROR;

    if (!driver->compare) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compare CPUs of %s architecture"),
                       virArchToString(arch));
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->compare(host, cpu, failIncompatible);
}


/**
 * cpuDecode:
 *
 * @cpu: CPU definition stub to be filled in
 * @data: internal CPU data to be decoded into @cpu definition
 * @models: list of CPU models that can be considered when decoding @data
 *
 * Decodes internal CPU data into a CPU definition consisting of a CPU model
 * and a list of CPU features. The @cpu model stub is supposed to have arch,
 * type, match and fallback members set, this function will add the rest. If
 * @models list is NULL, all models supported by libvirt will be considered
 * when decoding the data. In general, this function will select the model
 * closest to the CPU specified by @data.
 *
 * For VIR_ARCH_I686 and VIR_ARCH_X86_64 architectures this means the computed
 * CPU definition will have the shortest possible list of additional features.
 *
 * Returns 0 on success, -1 on error.
 */
int
cpuDecode(virCPUDefPtr cpu,
          const virCPUData *data,
          virDomainCapsCPUModelsPtr models)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("cpu=%p, data=%p, models=%p", cpu, data, models);
    if (models) {
        size_t i;
        for (i = 0; i < models->nmodels; i++)
            VIR_DEBUG("models[%zu]=%s", i, models->models[i].name);
    }

    if (cpu->type > VIR_CPU_TYPE_GUEST ||
        cpu->mode != VIR_CPU_MODE_CUSTOM) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid CPU definition stub"));
        return -1;
    }

    if ((driver = cpuGetSubDriver(data->arch)) == NULL)
        return -1;

    if (driver->decode == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot decode CPU data for %s architecture"),
                       virArchToString(cpu->arch));
        return -1;
    }

    return driver->decode(cpu, data, models);
}


/**
 * cpuEncode:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be encoded into internal CPU driver representation
 * @forced: where to store CPU data corresponding to forced features
 * @required: where to store CPU data corresponding to required features
 * @optional: where to store CPU data corresponding to optional features
 * @disabled: where to store CPU data corresponding to disabled features
 * @forbidden: where to store CPU data corresponding to forbidden features
 * @vendor: where to store CPU data corresponding to CPU vendor
 *
 * Encode CPU definition from @cpu into internal CPU driver representation.
 * Any of @forced, @required, @optional, @disabled, @forbidden and @vendor
 * arguments can be NULL in case the caller is not interested in the
 * corresponding data.
 *
 * Returns 0 on success, -1 on error.
 */
int
cpuEncode(virArch arch,
          const virCPUDef *cpu,
          virCPUDataPtr *forced,
          virCPUDataPtr *required,
          virCPUDataPtr *optional,
          virCPUDataPtr *disabled,
          virCPUDataPtr *forbidden,
          virCPUDataPtr *vendor)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, forced=%p, required=%p, "
              "optional=%p, disabled=%p, forbidden=%p, vendor=%p",
              virArchToString(arch), cpu, forced, required,
              optional, disabled, forbidden, vendor);

    if (!cpu->model) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("no guest CPU model specified"));
        return -1;
    }

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return -1;

    if (driver->encode == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot encode CPU data for %s architecture"),
                       virArchToString(arch));
        return -1;
    }

    return driver->encode(arch, cpu, forced, required,
                          optional, disabled, forbidden, vendor);
}


/**
 * virCPUDataNew:
 *
 * Returns an allocated memory for virCPUData or NULL on error.
 */
virCPUDataPtr
virCPUDataNew(virArch arch)
{
    virCPUDataPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->arch = arch;

    return data;
}


/**
 * virCPUDataFree:
 *
 * @data: CPU data structure to be freed
 *
 * Free internal CPU data.
 *
 * Returns nothing.
 */
void
virCPUDataFree(virCPUDataPtr data)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("data=%p", data);

    if (!data)
        return;

    if ((driver = cpuGetSubDriver(data->arch)) && driver->dataFree)
        driver->dataFree(data);
    else
        VIR_FREE(data);
}


/**
 * virCPUGetHostIsSupported:
 *
 * @arch: CPU architecture
 *
 * Check whether virCPUGetHost is supported for @arch.
 *
 * Returns true if virCPUGetHost is supported, false otherwise.
 */
bool
virCPUGetHostIsSupported(virArch arch)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s", virArchToString(arch));

    return (driver = cpuGetSubDriver(arch)) && driver->getHost;
}


/**
 * virCPUGetHost:
 *
 * @arch: CPU architecture
 * @type: requested type of the CPU
 * @nodeInfo: simplified CPU topology (optional)
 * @models: list of CPU models that can be considered for host CPU
 *
 * Create CPU definition describing the host's CPU.
 *
 * The @type (either VIR_CPU_TYPE_HOST or VIR_CPU_TYPE_GUEST) specifies what
 * type of CPU definition should be created. Specifically, VIR_CPU_TYPE_HOST
 * CPUs may contain only features without any policy attribute. Requesting
 * VIR_CPU_TYPE_GUEST provides better results because the CPU is allowed to
 * contain disabled features.
 *
 * If @nodeInfo is not NULL (which is only allowed for VIR_CPU_TYPE_HOST CPUs),
 * the CPU definition will have topology (sockets, cores, threads) filled in
 * according to the content of @nodeInfo. The function fails only if @nodeInfo
 * was not passed in and the assigned CPU driver was not able to detect the
 * host CPU model. In other words, a CPU definition containing just the
 * topology is a successful result even if detecting the host CPU model fails.
 *
 * It possible to limit the CPU model which may appear in the created CPU
 * definition by passing non-NULL @models list. This is useful when requesting
 * a CPU model usable on a specific hypervisor. If @models is NULL, any CPU
 * model known to libvirt may appear in the result.
 *
 * Returns host CPU definition or NULL on error.
 */
virCPUDefPtr
virCPUGetHost(virArch arch,
              virCPUType type,
              virNodeInfoPtr nodeInfo,
              virDomainCapsCPUModelsPtr models)
{
    struct cpuArchDriver *driver;
    virCPUDefPtr cpu = NULL;

    VIR_DEBUG("arch=%s, type=%s, nodeInfo=%p, models=%p",
              virArchToString(arch), virCPUTypeToString(type), nodeInfo,
              models);

    if (!(driver = cpuGetSubDriver(arch)))
        return NULL;

    if (VIR_ALLOC(cpu) < 0)
        return NULL;

    switch (type) {
    case VIR_CPU_TYPE_HOST:
        cpu->arch = arch;
        cpu->type = type;
        break;

    case VIR_CPU_TYPE_GUEST:
        if (nodeInfo) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot set topology for CPU type '%s'"),
                           virCPUTypeToString(type));
            goto error;
        }
        cpu->type = type;
        break;

    case VIR_CPU_TYPE_AUTO:
    case VIR_CPU_TYPE_LAST:
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported CPU type: %s"),
                       virCPUTypeToString(type));
        goto error;
    }

    if (nodeInfo) {
        cpu->sockets = nodeInfo->sockets;
        cpu->cores = nodeInfo->cores;
        cpu->threads = nodeInfo->threads;
    }

    /* Try to get the host CPU model, but don't really fail if nodeInfo is
     * filled in.
     */
    if (driver->getHost) {
        if (driver->getHost(cpu, models) < 0 &&
            !nodeInfo)
            goto error;
    } else if (nodeInfo) {
        VIR_DEBUG("cannot detect host CPU model for %s architecture",
                  virArchToString(arch));
    } else {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot detect host CPU model for %s architecture"),
                       virArchToString(arch));
        goto error;
    }

    return cpu;

 error:
    virCPUDefFree(cpu);
    return NULL;
}


virCPUDefPtr
virCPUProbeHost(virArch arch)
{
    virNodeInfo nodeinfo;

    if (virCapabilitiesGetNodeInfo(&nodeinfo))
        return NULL;

    return virCPUGetHost(arch, VIR_CPU_TYPE_HOST, &nodeinfo, NULL);
}


/**
 * virCPUBaseline:
 *
 * @arch: CPU architecture, use VIR_ARCH_NONE to autodetect from @cpus
 * @cpus: list of host CPU definitions
 * @ncpus: number of CPUs in @cpus
 * @models: list of CPU models that can be considered for the baseline CPU
 * @features: optional NULL terminated list of allowed features
 * @migratable: requests non-migratable features to be removed from the result
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * CPUs. If @models is NULL, all models supported by libvirt will
 * be considered when computing the baseline CPU model, otherwise the baseline
 * CPU model will be one of the provided CPU @models.
 *
 * Returns baseline CPU definition or NULL on error.
 */
virCPUDefPtr
virCPUBaseline(virArch arch,
               virCPUDefPtr *cpus,
               unsigned int ncpus,
               virDomainCapsCPUModelsPtr models,
               const char **features,
               bool migratable)
{
    struct cpuArchDriver *driver;
    size_t i;

    VIR_DEBUG("arch=%s, ncpus=%u, models=%p, features=%p, migratable=%d",
              virArchToString(arch), ncpus, models, features, migratable);
    if (cpus) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("cpus[%zu]=%p", i, cpus[i]);
    }
    if (models) {
        for (i = 0; i < models->nmodels; i++)
            VIR_DEBUG("models[%zu]=%s", i, models->models[i].name);
    }

    if (!cpus && ncpus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("nonzero ncpus doesn't match with NULL cpus"));
        return NULL;
    }

    if (ncpus < 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("no CPUs given"));
        return NULL;
    }

    for (i = 0; i < ncpus; i++) {
        if (!cpus[i]) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("invalid CPU definition at index %zu"), i);
            return NULL;
        }
        if (!cpus[i]->model) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("no CPU model specified at index %zu"), i);
            return NULL;
        }
    }

    if (arch == VIR_ARCH_NONE)
        arch = cpus[0]->arch;

    if (!(driver = cpuGetSubDriver(arch)))
        return NULL;

    if (!driver->baseline) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compute baseline CPU of %s architecture"),
                       virArchToString(arch));
        return NULL;
    }

    return driver->baseline(cpus, ncpus, models, features, migratable);
}


/**
 * virCPUUpdate:
 *
 * @arch: CPU architecture
 * @guest: guest CPU definition to be updated
 * @host: host CPU definition
 *
 * Updates @guest CPU definition according to @host CPU. This is required to
 * support guest CPU definitions specified relatively to host CPU, such as
 * CPUs with VIR_CPU_MODE_CUSTOM and optional features or
 * VIR_CPU_MATCH_MINIMUM, or CPUs with VIR_CPU_MODE_HOST_MODEL.
 * When the guest CPU was not specified relatively, the function does nothing
 * and returns success.
 *
 * Returns 0 on success, -1 on error.
 */
int
virCPUUpdate(virArch arch,
             virCPUDefPtr guest,
             const virCPUDef *host)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, guest=%p mode=%s model=%s, host=%p model=%s",
              virArchToString(arch), guest, virCPUModeTypeToString(guest->mode),
              NULLSTR(guest->model), host, NULLSTR(host ? host->model : NULL));

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (guest->mode == VIR_CPU_MODE_HOST_PASSTHROUGH)
        return 0;

    if (guest->mode == VIR_CPU_MODE_CUSTOM &&
        guest->match != VIR_CPU_MATCH_MINIMUM) {
        size_t i;
        bool optional = false;

        for (i = 0; i < guest->nfeatures; i++) {
            if (guest->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
                optional = true;
                break;
            }
        }

        if (!optional)
            return 0;
    }

    /* We get here if guest CPU is either
     *  - host-model
     *  - custom with minimum match
     *  - custom with optional features
     */
    if (!driver->update) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot update guest CPU for %s architecture"),
                       virArchToString(arch));
        return -1;
    }

    if (driver->update(guest, host) < 0)
        return -1;

    VIR_DEBUG("model=%s", NULLSTR(guest->model));
    return 0;
}


/**
 * virCPUUpdateLive:
 *
 * @arch: CPU architecture
 * @cpu: guest CPU definition to be updated
 * @dataEnabled: CPU data of the virtual CPU
 * @dataDisabled: CPU data with features requested by @cpu but disabled by the
 *                hypervisor
 *
 * Update custom mode CPU according to the virtual CPU created by the
 * hypervisor. The function refuses to update the CPU in case cpu->check is set
 * to VIR_CPU_CHECK_FULL.
 *
 * Returns -1 on error,
 *          0 when the CPU was successfully updated,
 *          1 when the operation does not make sense on the CPU or it is not
 *            supported for the given architecture.
 */
int
virCPUUpdateLive(virArch arch,
                 virCPUDefPtr cpu,
                 virCPUDataPtr dataEnabled,
                 virCPUDataPtr dataDisabled)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, dataEnabled=%p, dataDisabled=%p",
              virArchToString(arch), cpu, dataEnabled, dataDisabled);

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (!driver->updateLive)
        return 1;

    if (cpu->mode != VIR_CPU_MODE_CUSTOM)
        return 1;

    if (driver->updateLive(cpu, dataEnabled, dataDisabled) < 0)
        return -1;

    return 0;
}


/**
 * virCPUCheckFeature:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition
 * @feature: feature to be checked for
 *
 * Checks whether @feature is supported by the CPU described by @cpu.
 *
 * Returns 1 if the feature is supported, 0 if it's not supported, or
 * -1 on error.
 */
int
virCPUCheckFeature(virArch arch,
                   const virCPUDef *cpu,
                   const char *feature)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, feature=%s",
              virArchToString(arch), cpu, feature);

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (!driver->checkFeature) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot check guest CPU feature for %s architecture"),
                       virArchToString(arch));
        return -1;
    }

    return driver->checkFeature(cpu, feature);
}


/**
 * virCPUDataCheckFeature:
 *
 * @data: CPU data
 * @feature: feature to be checked for
 *
 * Checks whether @feature is supported by the CPU described by @data.
 *
 * Returns 1 if the feature is supported, 0 if it's not supported, or
 * -1 on error.
 */
int
virCPUDataCheckFeature(const virCPUData *data,
                       const char *feature)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, data=%p, feature=%s",
              virArchToString(data->arch), data, feature);

    if (!(driver = cpuGetSubDriver(data->arch)))
        return -1;

    if (!driver->dataCheckFeature) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot check guest CPU feature for %s architecture"),
                       virArchToString(data->arch));
        return -1;
    }

    return driver->dataCheckFeature(data, feature);
}


/**
 * virCPUDataFormat:
 *
 * @data: internal CPU representation
 *
 * Formats @data into XML for test purposes.
 *
 * Returns string representation of the XML describing @data or NULL on error.
 */
char *
virCPUDataFormat(const virCPUData *data)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("data=%p", data);

    if (!(driver = cpuGetSubDriver(data->arch)))
        return NULL;

    if (!driver->dataFormat) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot format %s CPU data"),
                       virArchToString(data->arch));
        return NULL;
    }

    return driver->dataFormat(data);
}


/**
 * virCPUDataParse:
 *
 * @xmlStr: XML string produced by virCPUDataFormat
 *
 * Parses XML representation of virCPUData structure for test purposes.
 *
 * Returns internal CPU data structure parsed from the XML or NULL on error.
 */
virCPUDataPtr
virCPUDataParse(const char *xmlStr)
{
    struct cpuArchDriver *driver;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDataPtr data = NULL;
    char *arch = NULL;

    VIR_DEBUG("xmlStr=%s", xmlStr);

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("CPU data"), &ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot parse CPU data"));
        goto cleanup;
    }

    if (!(arch = virXPathString("string(/cpudata/@arch)", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing CPU data architecture"));
        goto cleanup;
    }

    if (!(driver = cpuGetSubDriverByName(arch)))
        goto cleanup;

    if (!driver->dataParse) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot parse %s CPU data"), arch);
        goto cleanup;
    }

    data = driver->dataParse(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(arch);
    return data;
}


/** virCPUModelIsAllowed:
 *
 * @model: CPU model to be checked
 * @models: list of supported CPU models
 *
 * Checks whether @model can be found in the list of supported @models.
 * If @models is NULL, all models are supported.
 *
 * Returns true if @model is supported, false otherwise.
 */
bool
virCPUModelIsAllowed(const char *model,
                     virDomainCapsCPUModelsPtr models)
{
    if (!models)
        return true;

    return !!virDomainCapsCPUModelsGet(models, model);
}


/**
 * virCPUGetModels:
 *
 * @arch: CPU architecture
 * @models: where to store the NULL-terminated list of supported models
 *
 * Fetches all CPU models supported by libvirt on @archName. If there are
 * no restrictions on CPU models on @archName (i.e., the CPU model is just
 * passed directly to a hypervisor), this function returns 0 and sets
 * @models to NULL.
 *
 * Returns number of supported CPU models, 0 if any CPU model is supported,
 * or -1 on error.
 */
int
virCPUGetModels(virArch arch, char ***models)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s", virArchToString(arch));

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (!driver->getModels) {
        if (models)
            *models = NULL;
        return 0;
    }

    return driver->getModels(models);
}


/**
 * virCPUTranslate:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be translated
 * @models: list of allowed CPU models (NULL if all are allowed)
 *
 * Translates @cpu model (if allowed by @cpu->fallback) to a closest CPU model
 * from @models list.
 *
 * The function does nothing (and returns 0) if @cpu does not have to be
 * translated.
 *
 * Returns -1 on error, 0 on success.
 */
int
virCPUTranslate(virArch arch,
                virCPUDefPtr cpu,
                virDomainCapsCPUModelsPtr models)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, model=%s, models=%p",
              virArchToString(arch), cpu, NULLSTR(cpu->model), models);

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (cpu->mode == VIR_CPU_MODE_HOST_MODEL ||
        cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH)
        return 0;

    if (virCPUModelIsAllowed(cpu->model, models))
        return 0;

    if (cpu->fallback != VIR_CPU_FALLBACK_ALLOW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %s is not supported by hypervisor"),
                       cpu->model);
        return -1;
    }

    if (!driver->translate) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot translate CPU model %s to a supported model"),
                       cpu->model);
        return -1;
    }

    if (driver->translate(cpu, models) < 0)
        return -1;

    VIR_DEBUG("model=%s", NULLSTR(cpu->model));
    return 0;
}


/**
 * virCPUConvertLegacy:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be converted
 *
 * Convert legacy CPU definition into one that the corresponding cpu driver
 * will be able to work with. Currently this is only implemented by the PPC
 * driver, which needs to convert legacy POWERx_v* names into POWERx.
 *
 * Returns -1 on error, 0 on success.
 */
int
virCPUConvertLegacy(virArch arch,
                    virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, model=%s",
              virArchToString(arch), cpu, NULLSTR(cpu->model));

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (!driver->convertLegacy)
        return 0;

    if (driver->convertLegacy(cpu) < 0)
        return -1;

    VIR_DEBUG("model=%s", NULLSTR(cpu->model));
    return 0;
}


static int
virCPUFeatureCompare(const void *p1,
                     const void *p2)
{
    const virCPUFeatureDef *f1 = p1;
    const virCPUFeatureDef *f2 = p2;

    return strcmp(f1->name, f2->name);
}


/**
 * virCPUExpandFeatures:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be expanded
 *
 * Add all features implicitly enabled by the CPU model to the list of
 * features. The @cpu is expected to be either a host or a guest representation
 * of a host CPU, i.e., only VIR_CPU_FEATURE_REQUIRE and
 * VIR_CPU_FEATURE_DISABLE policies are supported.
 *
 * The updated list of features in the CPU definition is sorted.
 *
 * Return -1 on error, 0 on success.
 */
int
virCPUExpandFeatures(virArch arch,
                     virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, model=%s, nfeatures=%zu",
              virArchToString(arch), cpu, NULLSTR(cpu->model), cpu->nfeatures);

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (driver->expandFeatures &&
        driver->expandFeatures(cpu) < 0)
        return -1;

    qsort(cpu->features, cpu->nfeatures, sizeof(*cpu->features),
          virCPUFeatureCompare);

    VIR_DEBUG("nfeatures=%zu", cpu->nfeatures);
    return 0;
}


/**
 * virCPUCopyMigratable:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be copied
 *
 * Makes a copy of @cpu with all features which would block migration removed.
 * If this doesn't make sense for a given architecture, the function returns a
 * plain copy of @cpu (i.e., a copy with no features removed).
 *
 * Returns the copy of the CPU or NULL on error.
 */
virCPUDefPtr
virCPUCopyMigratable(virArch arch,
                     virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, model=%s",
              virArchToString(arch), cpu, NULLSTR(cpu->model));

    if (!(driver = cpuGetSubDriver(arch)))
        return NULL;

    if (driver->copyMigratable)
        return driver->copyMigratable(cpu);
    else
        return virCPUDefCopy(cpu);
}


/**
 * virCPUValidateFeatures:
 *
 * @arch: CPU architecture
 * @cpu: CPU definition to be checked
 *
 * Checks whether all CPU features specified in @cpu are valid.
 *
 * Returns 0 on success (all features are valid), -1 on error.
 */
int
virCPUValidateFeatures(virArch arch,
                       virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, nfeatures=%zu",
              virArchToString(arch), cpu, cpu->nfeatures);

    if (!(driver = cpuGetSubDriver(arch)))
        return -1;

    if (driver->validateFeatures)
        return driver->validateFeatures(cpu);
    else
        return 0;
}
