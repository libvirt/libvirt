/*
 * cpu_powerpc.h: CPU driver for PowerPC CPUs
 *
 * Copyright (C) Copyright (C) IBM Corporation, 2010
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
 *      Anton Blanchard <anton@au.ibm.com>
 *      Prerna Saxena <prerna@linux.vnet.ibm.com>
 */

#include <config.h>

#include "memory.h"
#include "cpu.h"


#define VIR_FROM_THIS VIR_FROM_CPU

static const char *archs[] = { "ppc64" };

static union cpuData *
PowerPCNodeData(void)
{
    union cpuData *data;

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return NULL;
    }

    return data;
}


static int
PowerPCDecode(virCPUDefPtr cpu ATTRIBUTE_UNUSED,
              const union cpuData *data ATTRIBUTE_UNUSED,
              const char **models ATTRIBUTE_UNUSED,
              unsigned int nmodels ATTRIBUTE_UNUSED,
              const char *preferred ATTRIBUTE_UNUSED)
{
        return 0;
}

static void
PowerPCDataFree(union cpuData *data)
{
   if (data == NULL)
       return;

   VIR_FREE(data);
}

struct cpuArchDriver cpuDriverPowerPC = {
    .name = "ppc64",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = NULL,
    .decode     = PowerPCDecode,
    .encode     = NULL,
    .free       = PowerPCDataFree,
    .nodeData   = PowerPCNodeData,
    .guestData  = NULL,
    .baseline   = NULL,
    .update     = NULL,
    .hasFeature = NULL,
};
