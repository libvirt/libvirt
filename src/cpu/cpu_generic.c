/*
 * cpu_generic.c: CPU manipulation driver for architectures which are not
 * handled by their own driver
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

#include "viralloc.h"
#include "virhash.h"
#include "cpu.h"
#include "cpu_generic.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU


static virHashTablePtr
genericHashFeatures(virCPUDefPtr cpu)
{
    virHashTablePtr hash;
    size_t i;

    if ((hash = virHashCreate(cpu->nfeatures, NULL)) == NULL)
        return NULL;

    for (i = 0; i < cpu->nfeatures; i++) {
        if (virHashAddEntry(hash,
                            cpu->features[i].name,
                            cpu->features + i)) {
            virHashFree(hash);
            return NULL;
        }
    }

    return hash;
}


static virCPUCompareResult
genericCompare(virCPUDefPtr host,
               virCPUDefPtr cpu)
{
    virHashTablePtr hash;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;
    size_t i;
    unsigned int reqfeatures;

    if (((cpu->arch != VIR_ARCH_NONE) &&
         (host->arch != cpu->arch)) ||
        STRNEQ(host->model, cpu->model))
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    if ((hash = genericHashFeatures(host)) == NULL)
        goto cleanup;

    reqfeatures = 0;
    for (i = 0; i < cpu->nfeatures; i++) {
        void *hval = virHashLookup(hash, cpu->features[i].name);

        if (hval) {
            if (cpu->type == VIR_CPU_TYPE_GUEST &&
                cpu->features[i].policy == VIR_CPU_FEATURE_FORBID) {
                ret = VIR_CPU_COMPARE_INCOMPATIBLE;
                goto cleanup;
            }
            reqfeatures++;
        }
        else {
            if (cpu->type == VIR_CPU_TYPE_HOST ||
                cpu->features[i].policy == VIR_CPU_FEATURE_REQUIRE) {
                ret = VIR_CPU_COMPARE_INCOMPATIBLE;
                goto cleanup;
            }
        }
    }

    if (host->nfeatures > reqfeatures) {
        if (cpu->type == VIR_CPU_TYPE_GUEST &&
            cpu->match == VIR_CPU_MATCH_STRICT)
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        else
            ret = VIR_CPU_COMPARE_SUPERSET;
    }
    else
        ret = VIR_CPU_COMPARE_IDENTICAL;

 cleanup:
    virHashFree(hash);
    return ret;
}


static virCPUDefPtr
genericBaseline(virCPUDefPtr *cpus,
                unsigned int ncpus,
                const char **models,
                unsigned int nmodels,
                unsigned int flags)
{
    virCPUDefPtr cpu = NULL;
    virCPUFeatureDefPtr features = NULL;
    unsigned int nfeatures;
    unsigned int count;
    size_t i, j;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    if (!cpuModelIsAllowed(cpus[0]->model, models, nmodels)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %s is not supported by hypervisor"),
                       cpus[0]->model);
        goto error;
    }

    if (VIR_ALLOC(cpu) < 0 ||
        VIR_STRDUP(cpu->model, cpus[0]->model) < 0 ||
        VIR_ALLOC_N(features, cpus[0]->nfeatures) < 0)
        goto error;

    cpu->arch = cpus[0]->arch;
    cpu->type = VIR_CPU_TYPE_HOST;

    count = nfeatures = cpus[0]->nfeatures;
    for (i = 0; i < nfeatures; i++)
        features[i].name = cpus[0]->features[i].name;

    for (i = 1; i < ncpus; i++) {
        virHashTablePtr hash;

        if (cpu->arch != cpus[i]->arch) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CPUs have incompatible architectures: '%s' != '%s'"),
                           virArchToString(cpu->arch),
                           virArchToString(cpus[i]->arch));
            goto error;
        }

        if (STRNEQ(cpu->model, cpus[i]->model)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CPU models don't match: '%s' != '%s'"),
                           cpu->model, cpus[i]->model);
            goto error;
        }

        if (!(hash = genericHashFeatures(cpus[i])))
            goto error;

        for (j = 0; j < nfeatures; j++) {
            if (features[j].name &&
                !virHashLookup(hash, features[j].name)) {
                features[j].name = NULL;
                count--;
            }
        }

        virHashFree(hash);
    }

    if (VIR_ALLOC_N(cpu->features, count) < 0)
        goto error;
    cpu->nfeatures = count;

    j = 0;
    for (i = 0; i < nfeatures; i++) {
        if (!features[i].name)
            continue;

        if (VIR_STRDUP(cpu->features[j++].name, features[i].name) < 0)
            goto error;
    }

 cleanup:
    VIR_FREE(features);

    return cpu;

 error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


struct cpuArchDriver cpuDriverGeneric = {
    .name = "generic",
    .arch = NULL,
    .narch = 0,
    .compare    = genericCompare,
    .decode     = NULL,
    .encode     = NULL,
    .free       = NULL,
    .nodeData   = NULL,
    .guestData  = NULL,
    .baseline   = genericBaseline,
    .update     = NULL,
};
