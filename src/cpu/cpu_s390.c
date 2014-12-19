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

static virCPUDataPtr
s390NodeData(virArch arch)
{
    virCPUDataPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->arch = arch;

    return data;
}


static int
s390Decode(virCPUDefPtr cpu,
           const virCPUData *data ATTRIBUTE_UNUSED,
           const char **models ATTRIBUTE_UNUSED,
           unsigned int nmodels ATTRIBUTE_UNUSED,
           const char *preferred ATTRIBUTE_UNUSED,
           unsigned int flags)
{

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, -1);

    if (cpu->model == NULL &&
        VIR_STRDUP(cpu->model, "host") < 0)
        return -1;

    return 0;
}

static void
s390DataFree(virCPUDataPtr data)
{
    VIR_FREE(data);
}

struct cpuArchDriver cpuDriverS390 = {
    .name = "s390",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = NULL,
    .decode     = s390Decode,
    .encode     = NULL,
    .free       = s390DataFree,
    .nodeData   = s390NodeData,
    .guestData  = NULL,
    .baseline   = NULL,
    .update     = NULL,
    .hasFeature = NULL,
};
