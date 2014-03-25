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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "hyperv_private.h"
#include "hyperv_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV

VIR_LOG_INIT("hyperv.hyperv_util");

int
hypervParseUri(hypervParsedUri **parsedUri, virURIPtr uri)
{
    int result = -1;
    size_t i;

    if (parsedUri == NULL || *parsedUri != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*parsedUri) < 0)
        return -1;

    for (i = 0; i < uri->paramsCount; i++) {
        virURIParamPtr queryParam = &uri->params[i];

        if (STRCASEEQ(queryParam->name, "transport")) {
            VIR_FREE((*parsedUri)->transport);

            if (VIR_STRDUP((*parsedUri)->transport, queryParam->value) < 0)
                goto cleanup;

            if (STRNEQ((*parsedUri)->transport, "http") &&
                STRNEQ((*parsedUri)->transport, "https")) {
                virReportError(VIR_ERR_INVALID_ARG,
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

    if (!(*parsedUri)->transport &&
        VIR_STRDUP((*parsedUri)->transport, "https") < 0)
        goto cleanup;

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
