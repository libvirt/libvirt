/*
 * cpu.c: internal functions for CPU manipulation
 *
 * Copyright (C) 2009 Red Hat, Inc.
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

#include <config.h>

#include "xml.h"
#include "cpu.h"
#include "cpu_x86.h"
#include "cpu_generic.h"


#define NR_DRIVERS ARRAY_CARDINALITY(drivers)
#define VIR_FROM_THIS VIR_FROM_CPU

static struct cpuArchDriver *drivers[] = {
    &cpuDriverX86,
    /* generic driver must always be the last one */
    &cpuDriverGeneric
};


static struct cpuArchDriver *
cpuGetSubDriver(virConnectPtr conn,
                const char *arch)
{
    unsigned int i;
    unsigned int j;

    if (arch == NULL) {
        virCPUReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
cpuCompareXML(virConnectPtr conn,
              virCPUDefPtr host,
              const char *xml)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;

    doc = xmlParseMemory(xml, strlen(xml));

    if (doc == NULL || (ctxt = xmlXPathNewContext(doc)) == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = xmlDocGetRootElement(doc);

    cpu = virCPUDefParseXML(conn, ctxt->node, ctxt, VIR_CPU_TYPE_AUTO);
    if (cpu == NULL)
        goto cleanup;

    ret = cpuCompare(conn, host, cpu);

cleanup:
    virCPUDefFree(cpu);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return ret;
}


virCPUCompareResult
cpuCompare(virConnectPtr conn,
           virCPUDefPtr host,
           virCPUDefPtr cpu)
{
    struct cpuArchDriver *driver;

    if ((driver = cpuGetSubDriver(conn, host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->compare == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot compare CPUs of %s architecture"),
                host->arch);
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->compare(host, cpu);
}


int
cpuDecode(virConnectPtr conn,
          virCPUDefPtr cpu,
          const union cpuData *data,
          unsigned int nmodels,
          const char **models)
{
    struct cpuArchDriver *driver;

    if (cpu == NULL) {
        virCPUReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          "%s", _("invalid CPU definition"));
        return -1;
    }

    if ((driver = cpuGetSubDriver(conn, cpu->arch)) == NULL)
        return -1;

    if (driver->decode == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot decode CPU data for %s architecture"),
                cpu->arch);
        return -1;
    }

    return driver->decode(cpu, data, nmodels, models);
}


int
cpuEncode(virConnectPtr conn,
          const char *arch,
          const virCPUDefPtr cpu,
          union cpuData **forced,
          union cpuData **required,
          union cpuData **optional,
          union cpuData **disabled,
          union cpuData **forbidden)
{
    struct cpuArchDriver *driver;

    if ((driver = cpuGetSubDriver(conn, arch)) == NULL)
        return -1;

    if (driver->encode == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot encode CPU data for %s architecture"),
                arch);
        return -1;
    }

    return driver->encode(cpu, forced, required,
                          optional, disabled, forbidden);
}


void
cpuDataFree(virConnectPtr conn,
            const char *arch,
            union cpuData *data)
{
    struct cpuArchDriver *driver;

    if (data == NULL)
        return;

    if ((driver = cpuGetSubDriver(conn, arch)) == NULL)
        return;

    if (driver->free == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot free CPU data for %s architecture"),
                arch);
        return;
    }

    driver->free(data);
}


union cpuData *
cpuNodeData(virConnectPtr conn,
            const char *arch)
{
    struct cpuArchDriver *driver;

    if ((driver = cpuGetSubDriver(conn, arch)) == NULL)
        return NULL;

    if (driver->nodeData == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot get node CPU data for %s architecture"),
                arch);
        return NULL;
    }

    return driver->nodeData();
}


virCPUCompareResult
cpuGuestData(virConnectPtr conn,
             virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data)
{
    struct cpuArchDriver *driver;

    if ((driver = cpuGetSubDriver(conn, host->arch)) == NULL)
        return VIR_CPU_COMPARE_ERROR;

    if (driver->guestData == NULL) {
        virCPUReportError(conn, VIR_ERR_NO_SUPPORT,
                _("cannot compute guest CPU data for %s architecture"),
                host->arch);
        return VIR_CPU_COMPARE_ERROR;
    }

    return driver->guestData(host, guest, data);
}
