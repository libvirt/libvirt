
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
#include "qparams.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "hyperv_private.h"
#include "hyperv_util.h"

#define VIR_FROM_THIS VIR_FROM_HYPERV



int
hypervParseUri(hypervParsedUri **parsedUri, xmlURIPtr uri)
{
    int result = -1;
    struct qparam_set *queryParamSet = NULL;
    struct qparam *queryParam = NULL;
    int i;

    if (parsedUri == NULL || *parsedUri != NULL) {
        HYPERV_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_ALLOC(*parsedUri) < 0) {
        virReportOOMError();
        return -1;
    }

#ifdef HAVE_XMLURI_QUERY_RAW
    queryParamSet = qparam_query_parse(uri->query_raw);
#else
    queryParamSet = qparam_query_parse(uri->query);
#endif

    if (queryParamSet == NULL) {
        goto cleanup;
    }

    for (i = 0; i < queryParamSet->n; i++) {
        queryParam = &queryParamSet->p[i];

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

    if (queryParamSet != NULL) {
        free_qparam_set(queryParamSet);
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
