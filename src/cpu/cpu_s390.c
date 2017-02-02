/*
 * cpu_s390.c: CPU driver for s390(x) CPUs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright IBM Corp. 2012
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
 *      Thang Pham <thang.pham@us.ibm.com>
 */

#include <config.h>

#include "viralloc.h"
#include "virstring.h"
#include "cpu.h"


#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_S390, VIR_ARCH_S390X };

static virCPUCompareResult
virCPUs390Compare(virCPUDefPtr host ATTRIBUTE_UNUSED,
                  virCPUDefPtr cpu ATTRIBUTE_UNUSED,
                  bool failMessages ATTRIBUTE_UNUSED)
{
    /* s390 relies on Qemu to perform all runability checking. Return
     * VIR_CPU_COMPARE_IDENTICAL to bypass Libvirt checking.
     */
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUs390Update(virCPUDefPtr guest,
                 const virCPUDef *host)
{
     virCPUDefPtr updated = NULL;
     int ret = -1;
     size_t i;

     if (guest->match == VIR_CPU_MATCH_MINIMUM) {
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("match mode %s not supported"),
                        virCPUMatchTypeToString(guest->match));
         goto cleanup;
     }

     if (guest->mode != VIR_CPU_MODE_HOST_MODEL) {
         ret = 0;
         goto cleanup;
     }

     if (!host) {
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("unknown host CPU model"));
         goto cleanup;
     }

     if (!(updated = virCPUDefCopyWithoutModel(guest)))
         goto cleanup;

     updated->mode = VIR_CPU_MODE_CUSTOM;
     if (virCPUDefCopyModel(updated, host, true) < 0)
         goto cleanup;

     for (i = 0; i < guest->nfeatures; i++) {
         if (guest->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
             virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("only cpu feature policies 'require' and "
                              "'disable' are supported for %s"),
                            guest->features[i].name);
             goto cleanup;
        }

        if (virCPUDefUpdateFeature(updated,
                                   guest->features[i].name,
                                   guest->features[i].policy) < 0)
            goto cleanup;
     }

     virCPUDefStealModel(guest, updated, false);
     guest->mode = VIR_CPU_MODE_CUSTOM;
     guest->match = VIR_CPU_MATCH_EXACT;
     ret = 0;

 cleanup:
     virCPUDefFree(updated);
     return ret;
}

struct cpuArchDriver cpuDriverS390 = {
    .name = "s390",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = virCPUs390Compare,
    .decode     = NULL,
    .encode     = NULL,
    .nodeData   = NULL,
    .baseline   = NULL,
    .update     = virCPUs390Update,
};
