/*
 * openvz_util.c: core driver methods for managing OpenVZ VEs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) 2012 Guido Günther
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

#include <unistd.h>

#include "internal.h"

#include "virerror.h"
#include "vircommand.h"
#include "datatypes.h"
#include "viralloc.h"

#include "openvz_conf.h"
#include "openvz_util.h"

#define VIR_FROM_THIS VIR_FROM_OPENVZ

long
openvzKBPerPages(void)
{
    static long kb_per_pages = 0;

    if (kb_per_pages == 0) {
        kb_per_pages = sysconf(_SC_PAGESIZE);
        if (kb_per_pages > 0) {
            kb_per_pages /= 1024;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Can't determine page size"));
            kb_per_pages = 0;
            return -1;
        }
    }
    return kb_per_pages;
}

char*
openvzVEGetStringParam(virDomainPtr domain, const char* param)
{
    int len;
    char *output = NULL;

    virCommandPtr cmd = virCommandNewArgList(VZLIST,
                                             "-o",
                                             param,
                                             domain->name,
                                             "-H", NULL);

    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0) {
        VIR_FREE(output);
        /* virCommandRun sets the virError */
        goto cleanup;
    }

    /* delete trailing newline */
    len = strlen(output);
    if (len && output[len - 1] == '\n')
        output[len - 1] = '\0';

 cleanup:
    virCommandFree(cmd);
    return output;
}
