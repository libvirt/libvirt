/*
 * cpu_generic.c: CPU manipulation driver for architectures which are not
 * handled by their own driver
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

#include "hash.h"
#include "cpu.h"
#include "cpu_generic.h"


#define VIR_FROM_THIS VIR_FROM_CPU


static virHashTablePtr
genericHashFeatures(virCPUDefPtr cpu)
{
    virHashTablePtr hash;
    unsigned int i;

    if ((hash = virHashCreate(cpu->nfeatures)) == NULL)
        return NULL;

    for (i = 0; i < cpu->nfeatures; i++) {
        if (virHashAddEntry(hash,
                            cpu->features[i].name,
                            cpu->features + i)) {
            virHashFree(hash, NULL);
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
    unsigned int i;
    unsigned int reqfeatures;

    if ((cpu->arch && STRNEQ(host->arch, cpu->arch)) ||
        STRNEQ(host->model, cpu->model))
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    if ((hash = genericHashFeatures(host)) == NULL) {
        virReportOOMError(NULL);
        goto cleanup;
    }

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
    virHashFree(hash, NULL);
    return ret;
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
    .guestData  = NULL
};
