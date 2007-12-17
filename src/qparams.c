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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "buf.h"

#include "qparams.h"

struct qparam_set *
new_qparam_set (int init_alloc, ...)
{
    va_list args;
    struct qparam_set *ps;
    const char *pname, *pvalue;

    if (init_alloc <= 0) init_alloc = 1;

    ps = malloc (sizeof (*ps));
    if (!ps) return NULL;
    ps->n = 0;
    ps->alloc = init_alloc;
    ps->p = malloc (init_alloc * sizeof (ps->p[0]));
    if (!ps->p) {
        free (ps);
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
    struct qparam *old_p;

    if (ps->n >= ps->alloc) {
        old_p = ps->p;
        ps->p = realloc (ps->p, 2 * ps->alloc * sizeof (ps->p[0]));
        if (!ps->p) {
            ps->p = old_p;
            perror ("realloc");
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
    if (!pname)
        return -1;

    pvalue = strdup (value);
    if (!pvalue) {
        free (pname);
        return -1;
    }

    if (grow_qparam_set (ps) == -1) {
        free (pname);
        free (pvalue);
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
    virBufferPtr buf;
    int i, amp = 0;

    buf = virBufferNew (100);
    for (i = 0; i < ps->n; ++i) {
        if (!ps->p[i].ignore) {
            if (amp) virBufferAddChar (buf, '&');
            virBufferStrcat (buf, ps->p[i].name, "=", NULL);
            virBufferURIEncodeString (buf, ps->p[i].value);
            amp = 1;
        }
    }

    return virBufferContentAndFree (buf);
}

void
free_qparam_set (struct qparam_set *ps)
{
    int i;

    for (i = 0; i < ps->n; ++i) {
        free (ps->p[i].name);
        free (ps->p[i].value);
    }
    free (ps);
}

struct qparam_set *
qparam_query_parse (const char *query)
{
    struct qparam_set *ps;
    const char *name, *value, *end, *eq;

    ps = new_qparam_set (0, NULL);
    if (!ps) return NULL;

    if (!query || query[0] == '\0') return ps;

    while (*query) {
        /* Find the next separator, or end of the string. */
        end = strchr (query, '&');
        if (!end) end = query + strlen (query);

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
            value = "";
            if (!name) goto out_of_memory;
        }
        /* Or if we have "name=" here (works around annoying
         * problem when calling xmlURIUnescapeString with len = 0).
         */
        else if (eq+1 == end) {
            name = xmlURIUnescapeString (query, eq - query, NULL);
            value = "";
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
            value = xmlURIUnescapeString (eq+1, end - (eq+1), NULL);
            if (!name || !value) goto out_of_memory;
        }

        /* Append to the parameter set. */
        if (append_qparam (ps, name, value) == -1) goto out_of_memory;

    next:
        query = end;
        if (*query) query ++; /* skip '&' separator */
    }

    return ps;

 out_of_memory:
    free_qparam_set (ps);
    return NULL;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
