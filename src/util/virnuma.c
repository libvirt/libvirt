/*
 * virnuma.c: helper APIs for managing numa
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include "virnuma.h"
#include "vircommand.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#if HAVE_NUMAD
char *
virNumaGetAutoPlacementAdvice(unsigned short vcpus,
                              unsigned long long balloon)
{
    virCommandPtr cmd = NULL;
    char *output = NULL;

    cmd = virCommandNewArgList(NUMAD, "-w", NULL);
    virCommandAddArgFormat(cmd, "%d:%llu", vcpus,
                           VIR_DIV_UP(balloon, 1024));

    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to query numad for the "
                         "advisory nodeset"));

    virCommandFree(cmd);
    return output;
}
#else
char *
virNumaGetAutoPlacementAdvice(unsigned short vcpus ATTRIBUTE_UNUSED,
                              unsigned long long balloon ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("numad is not available on this host"));
    return NULL;
}
#endif
