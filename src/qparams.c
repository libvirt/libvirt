/* Copyright (C) 2007 Red Hat, Inc.
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
 *    Richard W.M. Jones <rjones@redhat.com>
 *
 * Utility functions to help parse and assemble query strings.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <libxml/uri.h>

#include "virterror_internal.h"
#include "buf.h"
#include "memory.h"
#include "qparams.h"

#define qparam_report_oom(void)                                              \
        virReportErrorHelper(NULL, VIR_FROM_NONE, VIR_ERR_NO_MEMORY,       \
                               __FILE__, __FUNCTION__, __LINE__, NULL)

struct qparam_set *
new_qparam_set (int init_alloc, ...)
{
    va_list args;
    struct qparam_set *ps;
    const char *pname, *pvalue;

    if (init_alloc <= 0) init_alloc = 1;

    if (VIR_ALLOC(ps) < 0) {
        qparam_report_oom();
        return NULL;
    }
    ps->n = 0;
    ps->alloc = init_alloc;
    if (VIR_ALLOC_N(ps->p, ps->alloc) < 0) {
        VIR_FREE (ps);
        qparam_report_oom();
        return NULL;
    }

    va_start (args, init_alloc);
    while ((pname = va_arg (args, char *)) != NULL) {
        pvalue = va_arg (args, char *);

        if (append_qparam (ps, pname, pvalue) == -1) {
            free_qparam_set (ps);
            return NULL;
        }
    }
    va_end (args);

    return ps;
}

int
append_qparams (struct qparam_set *ps, ...)
{
    va_list args;
    const char *pname, *pvalue;

    va_start (args, ps);
    while ((pname = va_arg (args, char *)) != NULL) {
        pvalue = va_arg (args, char *);

        if (append_qparam (ps, pname, pvalue) == -1)
            return -1;
    }
    va_end (args);

    return 0;
}

/* Ensure there is space to store at least one more parameter
 * at the end of the set.
 */
static int
grow_qparam_set (struct qparam_set *ps)
{
    if (ps->n >= ps->alloc) {
        if (VIR_REALLOC_N(ps->p, ps->alloc * 2) < 0) {
            qparam_report_oom();
            return -1;
        }
        ps->alloc *= 2;
    }

    return 0;
}

int
append_qparam (struct qparam_set *ps,
               const char *name, const char *value)
{
    char *pname, *pvalue;

    pname = strdup (name);
    if (!pname) {
        qparam_report_oom();
        return -1;
    }

    pvalue = strdup (value);
    if (!pvalue) {
        VIR_FREE (pname);
        qparam_report_oom();
        return -1;
    }

    if (grow_qparam_set (ps) == -1) {
        VIR_FREE (pname);
        VIR_FREE (pvalue);
        return -1;
    }

    ps->p[ps->n].name = pname;
    ps->p[ps->n].value = pvalue;
    ps->p[ps->n].ignore = 0;
    ps->n++;

    return 0;
}

char *
qparam_get_query (const struct qparam_set *ps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int i, amp = 0;

    for (i = 0; i < ps->n; ++i) {
        if (!ps->p[i].ignore) {
            if (amp) virBufferAddChar (&buf, '&');
            virBufferStrcat (&buf, ps->p[i].name, "=", NULL);
            virBufferURIEncodeString (&buf, ps->p[i].value);
            amp = 1;
        }
    }

    if (virBufferError(&buf)) {
        qparam_report_oom();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}

void
free_qparam_set (struct qparam_set *ps)
{
    int i;

    for (i = 0; i < ps->n; ++i) {
        VIR_FREE (ps->p[i].name);
        VIR_FREE (ps->p[i].value);
    }
    VIR_FREE (ps->p);
    VIR_FREE (ps);
}

struct qparam_set *
qparam_query_parse (const char *query)
{
    struct qparam_set *ps;
    const char *end, *eq;

    ps = new_qparam_set (0, NULL);
    if (!ps) {
        qparam_report_oom();
        return NULL;
    }

    if (!query || query[0] == '\0') return ps;

    while (*query) {
        char *name = NULL, *value = NULL;

        /* Find the next separator, or end of the string. */
        end = strchr (query, '&');
        if (!end)
            end = strchr (query, ';');
        if (!end)
            end = query + strlen (query);

        /* Find the first '=' character between here and end. */
        eq = strchr (query, '=');
        if (eq && eq >= end) eq = NULL;

        /* Empty section (eg. "&&"). */
        if (end == query)
            goto next;

        /* If there is no '=' character, then we have just "name"
         * and consistent with CGI.pm we assume value is "".
         */
        else if (!eq) {
            name = xmlURIUnescapeString (query, end - query, NULL);
            if (!name) goto out_of_memory;
        }
        /* Or if we have "name=" here (works around annoying
         * problem when calling xmlURIUnescapeString with len = 0).
         */
        else if (eq+1 == end) {
            name = xmlURIUnescapeString (query, eq - query, NULL);
            if (!name) goto out_of_memory;
        }
        /* If the '=' character is at the beginning then we have
         * "=value" and consistent with CGI.pm we _ignore_ this.
         */
        else if (query == eq)
            goto next;

        /* Otherwise it's "name=value". */
        else {
            name = xmlURIUnescapeString (query, eq - query, NULL);
            if (!name)
                goto out_of_memory;
            value = xmlURIUnescapeString (eq+1, end - (eq+1), NULL);
            if (!value) {
                VIR_FREE(name);
                goto out_of_memory;
            }
        }

        /* Append to the parameter set. */
        if (append_qparam (ps, name, value ? value : "") == -1) {
            VIR_FREE(name);
            VIR_FREE(value);
            goto out_of_memory;
        }
        VIR_FREE(name);
        VIR_FREE(value);

    next:
        query = end;
        if (*query) query ++; /* skip '&' separator */
    }

    return ps;

 out_of_memory:
    qparam_report_oom();
    free_qparam_set (ps);
    return NULL;
}
