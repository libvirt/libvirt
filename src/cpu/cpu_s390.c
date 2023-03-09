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
 */

#include <config.h>

#include "cpu.h"


#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_S390, VIR_ARCH_S390X };

static virCPUCompareResult
virCPUs390Compare(virCPUDef *host G_GNUC_UNUSED,
                  virCPUDef *cpu G_GNUC_UNUSED,
                  bool failMessages G_GNUC_UNUSED)
{
    /* s390 relies on QEMU to perform all runability checking. Return
     * VIR_CPU_COMPARE_IDENTICAL to bypass Libvirt checking.
     */
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUs390Update(virCPUDef *guest,
                 const virCPUDef *host,
                 bool relative)
{
    g_autoptr(virCPUDef) updated = virCPUDefCopyWithoutModel(guest);
    size_t i;

    if (!relative)
        return 0;

    if (guest->mode == VIR_CPU_MODE_CUSTOM) {
        if (guest->match == VIR_CPU_MATCH_MINIMUM) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("match mode %1$s not supported"),
                           virCPUMatchTypeToString(guest->match));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("optional CPU features are not supported"));
        }
        return -1;
    }

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        return -1;
    }

    updated->mode = VIR_CPU_MODE_CUSTOM;
    virCPUDefCopyModel(updated, host, true);

    for (i = 0; i < guest->nfeatures; i++) {
       if (virCPUDefUpdateFeature(updated,
                                  guest->features[i].name,
                                  guest->features[i].policy) < 0)
           return -1;
    }

    virCPUDefStealModel(guest, updated, false);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}


static int
virCPUs390ValidateFeatures(virCPUDef *cpu)
{
    size_t i;

    for (i = 0; i < cpu->nfeatures; i++) {
        if (cpu->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("only cpu feature policies 'require' and 'disable' are supported for %1$s"),
                           cpu->features[i].name);
            return -1;
        }
    }

    return 0;
}


static const char *
virCPUs390GetVendorForModel(const char *modelName)
{
    if (STRPREFIX(modelName, "z") || STRPREFIX(modelName, "gen"))
        return "IBM";

    return NULL;
}


struct cpuArchDriver cpuDriverS390 = {
    .name = "s390",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare    = virCPUs390Compare,
    .decode     = NULL,
    .encode     = NULL,
    .baseline   = NULL,
    .update     = virCPUs390Update,
    .validateFeatures = virCPUs390ValidateFeatures,
    .getVendorForModel = virCPUs390GetVendorForModel,
};
