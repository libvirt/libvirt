/*
 * cpu.c: internal functions for CPU manipulation
 *
 * Copyright (C) 2009-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "logging.h"
#include "memory.h"
#include "xml.h"
#include "cpu.h"
#include "cpu_x86.h"
#include "cpu_powerpc.h"
#include "cpu_s390.h"
#include "cpu_arm.h"
#include "cpu_generic.h"


#define NR_DRIVERS ARRAY_CARDINALITY(drivers)
#define VIR_FROM_THIS VIR_FROM_CPU

static struct cpuArchDriver *drivers[] = {
    &cpuDriverX86,
    &cpuDriverPowerPC,
    &cpuDriverS390,
    &cpuDriverArm,
    /* generic driver must always be the last one */
    &cpuDriverGeneric
};


static struct cpuArchDriver *
cpuGetSubDriver(const char *arch)
{
    unsigned int i;
    unsigned int j;

    if (arch == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("undefined hardware architecture"));
        return NULL;
    }

    for (i = 0; i < NR_DRIVERS - 1; i++) {
        for (j = 0; j < drivers[i]->narch; j++) {
            if (STREQ(arch, drivers[i]->arch[j]))
                return drivers[i];
        }
    }

    /* use generic driver by default */
    return drivers[NR_DRIVERS - 1];
}


virCPUCompareResult
cpuCompareXML(virCPUDefPtr host,
              const char *xml)
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

    if (!cpu->model) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("no CPU model specified"));
        goto cleanup;
    }

    ret = cpuCompare(host, cpu);

cleanup:
    virCPUDefFree(cpu);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


virCPUCompareResult
cpuCompare(virCPUDefPtr host,
           virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("host=%p, cpu=%p", host, cpu);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->compare == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compare CPUs of %s architecture"),
                       host->arch);
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->compare(host, cpu);
}


int
cpuDecode(virCPUDefPtr cpu,
          const union cpuData *data,
          const char **models,
          unsigned int nmodels,
          const char *preferred)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("cpu=%p, data=%p, nmodels=%u, preferred=%s",
              cpu, data, nmodels, NULLSTR(preferred));
    if (models) {
        unsigned int i;
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%u]=%s", i, NULLSTR(models[i]));
    }

    if (models == NULL && nmodels != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("nonzero nmodels doesn't match with NULL models"));
        return -1;
    }

    if (cpu == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid CPU definition"));
        return -1;
    }

    if ((driver = cpuGetSubDriver(cpu->arch)) == NULL)
        return -1;

    if (driver->decode == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot decode CPU data for %s architecture"),
                       cpu->arch);
        return -1;
    }

    return driver->decode(cpu, data, models, nmodels, preferred);
}


int
cpuEncode(const char *arch,
          const virCPUDefPtr cpu,
          union cpuData **forced,
          union cpuData **required,
          union cpuData **optional,
          union cpuData **disabled,
          union cpuData **forbidden,
          union cpuData **vendor)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, cpu=%p, forced=%p, required=%p, "
              "optional=%p, disabled=%p, forbidden=%p, vendor=%p",
              NULLSTR(arch), cpu, forced, required,
              optional, disabled, forbidden, vendor);

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return -1;

    if (driver->encode == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot encode CPU data for %s architecture"),
                       arch);
        return -1;
    }

    return driver->encode(cpu, forced, required,
                          optional, disabled, forbidden, vendor);
}


void
cpuDataFree(const char *arch,
            union cpuData *data)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, data=%p", NULLSTR(arch), data);

    if (data == NULL)
        return;

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return;

    if (driver->free == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot free CPU data for %s architecture"),
                       arch);
        return;
    }

    (driver->free)(data);
}


union cpuData *
cpuNodeData(const char *arch)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s", NULLSTR(arch));

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return NULL;

    if (driver->nodeData == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot get node CPU data for %s architecture"),
                       arch);
        return NULL;
    }

    return driver->nodeData();
}


virCPUCompareResult
cpuGuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data,
             char **msg)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("host=%p, guest=%p, data=%p, msg=%p", host, guest, data, msg);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->guestData == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot compute guest CPU data for %s architecture"),
                       host->arch);
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->guestData(host, guest, data, msg);
}


char *
cpuBaselineXML(const char **xmlCPUs,
               unsigned int ncpus,
               const char **models,
               unsigned int nmodels)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr *cpus = NULL;
    virCPUDefPtr cpu = NULL;
    char *cpustr;
    unsigned int i;

    VIR_DEBUG("ncpus=%u, nmodels=%u", ncpus, nmodels);
    if (xmlCPUs) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("xmlCPUs[%u]=%s", i, NULLSTR(xmlCPUs[i]));
    }
    if (models) {
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%u]=%s", i, NULLSTR(models[i]));
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
        goto no_memory;

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

    if (!(cpu = cpuBaseline(cpus, ncpus, models, nmodels)))
        goto error;

    cpustr = virCPUDefFormat(cpu, 0);

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

no_memory:
    virReportOOMError();
error:
    cpustr = NULL;
    goto cleanup;
}


virCPUDefPtr
cpuBaseline(virCPUDefPtr *cpus,
            unsigned int ncpus,
            const char **models,
            unsigned int nmodels)
{
    struct cpuArchDriver *driver;
    unsigned int i;

    VIR_DEBUG("ncpus=%u, nmodels=%u", ncpus, nmodels);
    if (cpus) {
        for (i = 0; i < ncpus; i++)
            VIR_DEBUG("cpus[%u]=%p", i, cpus[i]);
    }
    if (models) {
        for (i = 0; i < nmodels; i++)
            VIR_DEBUG("models[%u]=%s", i, NULLSTR(models[i]));
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
                       cpus[0]->arch);
        return NULL;
    }

    return driver->baseline(cpus, ncpus, models, nmodels);
}


int
cpuUpdate(virCPUDefPtr guest,
          const virCPUDefPtr host)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("guest=%p, host=%p", guest, host);

    if ((driver = cpuGetSubDriver(host->arch)) == NULL)
        return -1;

    if (driver->update == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot update guest CPU data for %s architecture"),
                       host->arch);
        return -1;
    }

    return driver->update(guest, host);
}

int
cpuHasFeature(const char *arch,
              const union cpuData *data,
              const char *feature)
{
    struct cpuArchDriver *driver;

    VIR_DEBUG("arch=%s, data=%p, feature=%s",
              arch, data, feature);

    if ((driver = cpuGetSubDriver(arch)) == NULL)
        return -1;

    if (driver->hasFeature == NULL) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("cannot check guest CPU data for %s architecture"),
                       arch);
        return -1;
    }

    return driver->hasFeature(data, feature);
}
