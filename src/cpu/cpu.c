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
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
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
#include "cpu_aarch64.h"
#include "cpu_generic.h"
#include "util/virstring.h"


#define NR_DRIVERS ARRAY_CARDINALITY(drivers)
#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu");

static struct cpuArchDriver *drivers[] = {
    &cpuDriverX86,
    &cpuDriverPPC64,
    &cpuDriverS390,
    &cpuDriverArm,
    &cpuDriverAARCH64,
    /* generic driver must always be the last one */
    &cpuDriverGeneric
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

    for (i = 0; i < NR_DRIVERS - 1; i++) {
        for (j = 0; j < drivers[i]->narch; j++) {
            if (arch == drivers[i]->arch[j])
                return drivers[i];
        }
    }

    /* use generic driver by default */
    return drivers[NR_DRIVERS - 1];
}


/**
 * cpuCompareXML:
 *
 * @host: host CPU definition
 * @xml: XML description of either guest or host CPU to be compared with @host
 *
 * Compares the CPU described by @xml with @host CPU.
 *
 * Returns VIR_CPU_COMPARE_ERROR on error, VIR_CPU_COMPARE_INCOMPATIBLE when
 * the two CPUs are incompatible, VIR_CPU_COMPARE_IDENTICAL when the two CPUs
 * are identical, VIR_CPU_COMPARE_SUPERSET when the @xml CPU is a superset of
 * the @host CPU.
 */
virCPUCompareResult
cpuCompareXML(virCPUDefPtr host,
              const char *xml,
              bool failIncompatible)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;

    VIR_DEBUG("host=%p, xml=%s", host, NULLSTR(xml));

    if (!(doc = virXMLParseStringCtxt(xml, _("(CPU_definition)"), &ctxt)))
        goto cleanup;

    cpu = virCPUDefParseXML(ctxt->node, ctxt, VIR_CPU_TYPE_AUTO);
    if (cpu == NULL)
        goto cleanup;

    ret = cpuCompare(host, cpu, failIncompatible);

 cleanup:
    virCPUDefFree(cpu);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


/**
 * cpuCompare:
 *
 * @host: host CPU definition
 * @cpu: either guest or host CPU to be compared with @host
 *
 * Compares the CPU described by @cpu with @host CPU.
 *
 * Returns VIR_CPU_COMPARE_ERROR on error, VIR_CPU_COMPARE_INCOMPATIBLE when
 * the two CPUs are incompatible, VIR_CPU_COMPARE_IDENTICAL when the two CPUs
 * are identical, VIR_CPU_COMPARE_SUPERSET when the @cpu CPU is a superset of
 * the @host CPU.
 */
virCPUCompareResult
cpuCompare(virCPUDefPtr host,
           virCPUDefPtr cpu,
           bool failIncompatible)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("host=%p, cpu=%p", host, cpu);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->compare == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compare CPUs of %s architecture"),
                       virArchToString(host->arch));
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
 * @nmodels: number of CPU models in @models
 * @preferred: CPU models that should be used if possible
 *
 * Decodes internal CPU data into a CPU definition consisting of a CPU model
 * and a list of CPU features. The @cpu model stub is supposed to have arch,
 * type, match and fallback members set, this function will add the rest. If
 * @models list is NULL, all models supported by libvirt will be considered
 * when decoding the data. In general, this function will select the model
 * closest to the CPU specified by @data unless @preferred is non-NULL, in
 * which case the @preferred model will be used as long as it is compatible
 * with @data.
 *
 * For VIR_ARCH_I686 and VIR_ARCH_X86_64 architectures this means the computed
 * CPU definition will have the shortest possible list of additional features.
 * When @preferred is non-NULL, the @preferred model will be used even if
 * other models would result in a shorter list of additional features.
 *
 * Returns 0 on success, -1 on error.
 */
int
cpuDecode(virCPUDefPtr cpu,
          const virCPUData *data,
          const char **models,
          unsigned int nmodels,
          const char *preferred)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("cpu=%p, data=%p, nmodels=%u, preferred=%s",
              cpu, data, nmodels, NULLSTR(preferred));
    if (models) {
        size_t i;
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%zu]=%s", i, NULLSTR(models[i]));
    }

    if (models == NULL && nmodels != 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("nonzero nmodels doesn't match with NULL models"));
        return -1;
    }

    if (cpu->type > VIR_CPU_TYPE_GUEST ||
        cpu->mode != VIR_CPU_MODE_CUSTOM) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid CPU definition stub"));
        return -1;
    }

    if ((driver = cpuGetSubDriver(cpu->arch)) == NULL)
        return -1;

    if (driver->decode == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot decode CPU data for %s architecture"),
                       virArchToString(cpu->arch));
        return -1;
    }

    return driver->decode(cpu, data, models, nmodels, preferred, 0);
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
 * cpuDataFree:
 *
 * @data: CPU data structure to be freed
 *
 * Free internal CPU data.
 *
 * Returns nothing.
 */
void
cpuDataFree(virCPUDataPtr data)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("data=%p", data);

    if (data == NULL)
        return;

    if ((driver = cpuGetSubDriver(data->arch)) == NULL)
        return;

    if (driver->free == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot free CPU data for %s architecture"),
                       virArchToString(data->arch));
        return;
    }

    (driver->free)(data);
}


/**
 * cpuNodeData:
 *
 * @arch: CPU architecture
 *
 * Returns CPU data for host CPU or NULL on error.
 */
virCPUDataPtr
cpuNodeData(virArch arch)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s", virArchToString(arch));

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return NULL;

    if (driver->nodeData == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot get node CPU data for %s architecture"),
                       virArchToString(arch));
        return NULL;
    }

    return driver->nodeData(arch);
}


/**
 * cpuGuestData:
 *
 * @host: host CPU definition
 * @guest: guest CPU definition
 * @data: computed guest CPU data
 * @msg: error message describing why the @guest and @host CPUs are considered
 *       incompatible
 *
 * Computes guest CPU data for the @guest CPU definition when run on the @host
 * CPU.
 *
 * Returns VIR_CPU_COMPARE_ERROR on error, VIR_CPU_COMPARE_INCOMPATIBLE when
 * the two CPUs are incompatible (@msg will describe the incompatibility),
 * VIR_CPU_COMPARE_IDENTICAL when the two CPUs are identical,
 * VIR_CPU_COMPARE_SUPERSET when the @guest CPU is a superset of the @host CPU.
 */
virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             virCPUDataPtr *data,
             char **msg)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("host=%p, guest=%p, data=%p, msg=%p", host, guest, data, msg);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->guestData == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compute guest CPU data for %s architecture"),
                       virArchToString(host->arch));
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->guestData(host, guest, data, msg);
}


/**
 * cpuBaselineXML:
 *
 * @xmlCPUs: list of host CPU XML descriptions
 * @ncpus: number of CPUs in @xmlCPUs
 * @models: list of CPU models that can be considered for the baseline CPU
 * @nmodels: number of CPU models in @models
 * @flags: bitwise-OR of virConnectBaselineCPUFlags
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * host CPUs. If @models array is NULL, all models supported by libvirt will
 * be considered when computing the baseline CPU model, otherwise the baseline
 * CPU model will be one of the provided CPU @models.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES then libvirt
 * will explicitly list all CPU features that are part of the host CPU,
 * without this flag features that are part of the CPU model will not be
 * listed.
 *
 * Returns XML description of the baseline CPU or NULL on error.
 */
char *
cpuBaselineXML(const char **xmlCPUs,
               unsigned int ncpus,
               const char **models,
               unsigned int nmodels,
               unsigned int flags)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr *cpus = NULL;
    virCPUDefPtr cpu = NULL;
    char *cpustr;
    size_t i;

    VIR_DEBUG("ncpus=%u, nmodels=%u", ncpus, nmodels);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%zu]=%s", i, NULLSTR(xmlCPUs[i]));
    }
    if (models) {
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%zu]=%s", i, NULLSTR(models[i]));
    }

    if (xmlCPUs == NULL && ncpus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("nonzero ncpus doesn't match with NULL xmlCPUs"));
        return NULL;
    }

    if (ncpus < 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("No CPUs given"));
        return NULL;
    }

    if (VIR_ALLOC_N(cpus, ncpus))
        goto error;

    for (i = 0; i < ncpus; i++) {
        if (!(doc = virXMLParseStringCtxt(xmlCPUs[i], _("(CPU_definition)"), &ctxt)))
            goto error;

        cpus[i] = virCPUDefParseXML(ctxt->node, ctxt, VIR_CPU_TYPE_HOST);
        if (cpus[i] == NULL)
            goto error;

        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(doc);
        ctxt = NULL;
        doc = NULL;
    }

    if (!(cpu = cpuBaseline(cpus, ncpus, models, nmodels, flags)))
        goto error;

    cpustr = virCPUDefFormat(cpu, NULL, false);

 cleanup:
    if (cpus) {
        for (i = 0; i < ncpus; i++)
            virCPUDefFree(cpus[i]);
        VIR_FREE(cpus);
    }
    virCPUDefFree(cpu);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return cpustr;

 error:
    cpustr = NULL;
    goto cleanup;
}


/**
 * cpuBaseline:
 *
 * @cpus: list of host CPU definitions
 * @ncpus: number of CPUs in @cpus
 * @models: list of CPU models that can be considered for the baseline CPU
 * @nmodels: number of CPU models in @models
 * @flags: bitwise-OR of virConnectBaselineCPUFlags
 *
 * Computes the most feature-rich CPU which is compatible with all given
 * host CPUs. If @models array is NULL, all models supported by libvirt will
 * be considered when computing the baseline CPU model, otherwise the baseline
 * CPU model will be one of the provided CPU @models.
 *
 * If @flags includes VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES then libvirt
 * will explicitly list all CPU features that are part of the host CPU,
 * without this flag features that are part of the CPU model will not be
 * listed.
 *
 * Returns baseline CPU definition or NULL on error.
 */
virCPUDefPtr
cpuBaseline(virCPUDefPtr *cpus,
            unsigned int ncpus,
            const char **models,
            unsigned int nmodels,
            unsigned int flags)
{
    struct cpuArchDriver *driver;
    size_t i;

    VIR_DEBUG("ncpus=%u, nmodels=%u", ncpus, nmodels);
    if (cpus) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("cpus[%zu]=%p", i, cpus[i]);
    }
    if (models) {
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%zu]=%s", i, NULLSTR(models[i]));
    }

    if (cpus == NULL && ncpus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("nonzero ncpus doesn't match with NULL cpus"));
        return NULL;
    }

    if (ncpus < 1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("No CPUs given"));
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

    if (models == NULL && nmodels != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("nonzero nmodels doesn't match with NULL models"));
        return NULL;
    }

    if ((driver = cpuGetSubDriver(cpus[0]->arch)) == NULL)
        return NULL;

    if (driver->baseline == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compute baseline CPU of %s architecture"),
                       virArchToString(cpus[0]->arch));
        return NULL;
    }

    return driver->baseline(cpus, ncpus, models, nmodels, flags);
}


/**
 * cpuUpdate:
 *
 * @guest: guest CPU definition
 * @host: host CPU definition
 *
 * Updates @guest CPU definition according to @host CPU. This is required to
 * support guest CPU definition which are relative to host CPU, such as CPUs
 * with VIR_CPU_MODE_CUSTOM and optional features or VIR_CPU_MATCH_MINIMUM, or
 * CPUs with non-custom mode (VIR_CPU_MODE_HOST_MODEL,
 * VIR_CPU_MODE_HOST_PASSTHROUGH).
 *
 * Returns 0 on success, -1 on error.
 */
int
cpuUpdate(virCPUDefPtr guest,
          const virCPUDef *host)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("guest=%p, host=%p", guest, host);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return -1;

    if (driver->update == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot update guest CPU data for %s architecture"),
                       virArchToString(host->arch));
        return -1;
    }

    return driver->update(guest, host);
}


/**
 * cpuHasFeature:
 *
 * @data: internal CPU representation
 * @feature: feature to be checked for
 *
 * Checks whether @feature is supported by the CPU described by @data.
 *
 * Returns 1 if the feature is supported, 0 if it's not supported, or
 * -1 on error.
 */
int
cpuHasFeature(const virCPUData *data,
              const char *feature)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("data=%p, feature=%s", data, feature);

    if ((driver = cpuGetSubDriver(data->arch)) == NULL)
        return -1;

    if (driver->hasFeature == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot check guest CPU data for %s architecture"),
                       virArchToString(data->arch));
        return -1;
    }

    return driver->hasFeature(data, feature);
}


/**
 * cpuDataFormat:
 *
 * @data: internal CPU representation
 *
 * Formats @data into XML for test purposes.
 *
 * Returns string representation of the XML describing @data or NULL on error.
 */
char *
cpuDataFormat(const virCPUData *data)
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
 * cpuDataParse:
 *
 * @arch: CPU architecture
 * @xmlStr: XML string produced by cpuDataFormat
 *
 * Parses XML representation of virCPUData structure for test purposes.
 *
 * Returns internal CPU data structure parsed from the XML or NULL on error.
 */
virCPUDataPtr
cpuDataParse(virArch arch,
             const char *xmlStr)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, xmlStr=%s", virArchToString(arch), xmlStr);

    if (!(driver = cpuGetSubDriver(arch)))
        return NULL;

    if (!driver->dataParse) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot parse %s CPU data"),
                       virArchToString(arch));
        return NULL;
    }

    return driver->dataParse(xmlStr);
}

bool
cpuModelIsAllowed(const char *model,
                  const char **models,
                  unsigned int nmodels)
{
    size_t i;

    if (!models || !nmodels)
        return true;

    for (i = 0; i < nmodels; i++) {
        if (models[i] && STREQ(models[i], model))
            return true;
    }
    return false;
}

/**
 * cpuGetModels:
 *
 * @archName: CPU architecture string
 * @models: where to store the list of supported models
 *
 * Fetches all CPU models supported by libvirt on @archName.
 *
 * Returns number of supported CPU models or -1 on error.
 */
int
cpuGetModels(const char *archName, char ***models)
{
    struct cpuArchDriver *driver;
    virArch arch;

    VIR_DEBUG("arch=%s", archName);

    arch = virArchFromString(archName);
    if (arch == VIR_ARCH_NONE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cannot find architecture %s"),
                       archName);
        return -1;
    }

    driver = cpuGetSubDriver(arch);
    if (driver == NULL) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cannot find a driver for the architecture %s"),
                       archName);
        return -1;
    }

    if (!driver->getModels) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("CPU driver for %s has no CPU model support"),
                       virArchToString(arch));
        return -1;
    }

    return driver->getModels(models);
}
