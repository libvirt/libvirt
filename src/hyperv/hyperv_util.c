
/*
 * hyperv_util.c: utility functions for the Microsoft Hyper-V driver
 *
 * Copyright (C) 2011 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "hyperv_private.h"
#include "hyperv_util.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV



int
hypervParseUri(hypervParsedUri **parsedUri, virURIPtr uri)
{
    int result = -1;
    int i;

    if (parsedUri == NULL || *parsedUri != NULL) {
        HYPERV_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*parsedUri) < 0) {
        virReportOOMError();
        return -1;
    }

    for (i = 0; i < uri->paramsCount; i++) {
        virURIParamPtr queryParam = &uri->params[i];

        if (STRCASEEQ(queryParam->name, "transport")) {
            VIR_FREE((*parsedUri)->transport);

            (*parsedUri)->transport = strdup(queryParam->value);

            if ((*parsedUri)->transport == NULL) {
                virReportOOMError();
                goto cleanup;
            }

            if (STRNEQ((*parsedUri)->transport, "http") &&
                STRNEQ((*parsedUri)->transport, "https")) {
                HYPERV_ERROR(VIR_ERR_INVALID_ARG,
                             _("Query parameter 'transport' has unexpected value "
                               "'%s' (should be http|https)"),
                             (*parsedUri)->transport);
                goto cleanup;
            }
        } else {
            VIR_WARN("Ignoring unexpected query parameter '%s'",
                     queryParam->name);
        }
    }

    if ((*parsedUri)->transport == NULL) {
        (*parsedUri)->transport = strdup("https");

        if ((*parsedUri)->transport == NULL) {
            virReportOOMError();
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    if (result < 0) {
        hypervFreeParsedUri(parsedUri);
    }

    return result;
}



void
hypervFreeParsedUri(hypervParsedUri **parsedUri)
{
    if (parsedUri == NULL || *parsedUri == NULL) {
        return;
    }

    VIR_FREE((*parsedUri)->transport);

    VIR_FREE(*parsedUri);
}
