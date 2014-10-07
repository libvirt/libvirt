/*
 * viruri.c: URI parsing wrappers for libxml2 functions
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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

#include "viruri.h"

#include "viralloc.h"
#include "virerror.h"
#include "virbuffer.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_URI

static int
virURIParamAppend(virURIPtr uri,
                  const char *name,
                  const char *value)
{
    char *pname = NULL;
    char *pvalue = NULL;

    if (VIR_STRDUP(pname, name) < 0 || VIR_STRDUP(pvalue, value) < 0)
        goto error;

    if (VIR_RESIZE_N(uri->params, uri->paramsAlloc, uri->paramsCount, 1) < 0)
        goto error;

    uri->params[uri->paramsCount].name = pname;
    uri->params[uri->paramsCount].value = pvalue;
    uri->params[uri->paramsCount].ignore = 0;
    uri->paramsCount++;

    return 0;

 error:
    VIR_FREE(pname);
    VIR_FREE(pvalue);
    return -1;
}


static int
virURIParseParams(virURIPtr uri)
{
    const char *end, *eq;
    const char *query = uri->query;

    if (!query || query[0] == '\0')
        return 0;

    while (*query) {
        char *name = NULL, *value = NULL;

        /* Find the next separator, or end of the string. */
        end = strchr(query, '&');
        if (!end)
            end = strchr(query, ';');
        if (!end)
            end = query + strlen(query);

        /* Find the first '=' character between here and end. */
        eq = strchr(query, '=');
        if (eq && eq >= end) eq = NULL;

        if (end == query) {
            /* Empty section (eg. "&&"). */
            goto next;
        } else if (!eq) {
            /* If there is no '=' character, then we have just "name"
             * and consistent with CGI.pm we assume value is "".
             */
            name = xmlURIUnescapeString(query, end - query, NULL);
            if (!name) goto no_memory;
        } else if (eq+1 == end) {
            /* Or if we have "name=" here (works around annoying
             * problem when calling xmlURIUnescapeString with len = 0).
             */
            name = xmlURIUnescapeString(query, eq - query, NULL);
            if (!name) goto no_memory;
        } else if (query == eq) {
            /* If the '=' character is at the beginning then we have
             * "=value" and consistent with CGI.pm we _ignore_ this.
             */
            goto next;
        } else {
            /* Otherwise it's "name=value". */
            name = xmlURIUnescapeString(query, eq - query, NULL);
            if (!name)
                goto no_memory;
            value = xmlURIUnescapeString(eq+1, end - (eq+1), NULL);
            if (!value) {
                VIR_FREE(name);
                goto no_memory;
            }
        }

        /* Append to the parameter set. */
        if (virURIParamAppend(uri, name, value ? value : "") < 0) {
            VIR_FREE(name);
            VIR_FREE(value);
            return -1;
        }
        VIR_FREE(name);
        VIR_FREE(value);

    next:
        query = end;
        if (*query) query ++; /* skip '&' separator */
    }

    return 0;

 no_memory:
    virReportOOMError();
    return -1;
}

/**
 * virURIParse:
 * @uri: URI to parse
 *
 * Wrapper for xmlParseURI
 *
 * Unfortunately there are few things that should be managed after
 * parsing the URI. Fortunately there is only one thing now and its
 * removing of square brackets around IPv6 addresses.
 *
 * @returns the parsed uri object with some fixes
 */
virURIPtr
virURIParse(const char *uri)
{
    xmlURIPtr xmluri;
    virURIPtr ret = NULL;

    xmluri = xmlParseURI(uri);

    if (!xmluri) {
        /* libxml2 does not tell us what failed. Grr :-( */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse URI %s"), uri);
        return NULL;
    }

    if (VIR_ALLOC(ret) < 0)
        goto error;

    if (VIR_STRDUP(ret->scheme, xmluri->scheme) < 0)
        goto error;
    if (VIR_STRDUP(ret->server, xmluri->server) < 0)
        goto error;
    ret->port = xmluri->port;
    if (VIR_STRDUP(ret->path, xmluri->path) < 0)
        goto error;
#ifdef HAVE_XMLURI_QUERY_RAW
    if (VIR_STRDUP(ret->query, xmluri->query_raw) < 0)
        goto error;
#else
    if (VIR_STRDUP(ret->query, xmluri->query) < 0)
        goto error;
#endif
    if (VIR_STRDUP(ret->fragment, xmluri->fragment) < 0)
        goto error;
    if (VIR_STRDUP(ret->user, xmluri->user) < 0)
        goto error;

    /* Strip square bracket from an IPv6 address.
     * The function modifies the string in-place. Even after such
     * modification, it is OK to free the URI with xmlFreeURI. */
    virStringStripIPv6Brackets(ret->server);

    if (virURIParseParams(ret) < 0)
        goto error;

    xmlFreeURI(xmluri);

    return ret;

 error:
    xmlFreeURI(xmluri);
    virURIFree(ret);
    return NULL;
}

/**
 * virURIFormat:
 * @uri: URI to format
 *
 * Wrapper for xmlSaveUri
 *
 * This function constructs back everything that @ref virURIParse
 * changes after parsing
 *
 * @returns the constructed uri as a string
 */
char *
virURIFormat(virURIPtr uri)
{
    xmlURI xmluri;
    char *tmpserver = NULL;
    char *ret;

    memset(&xmluri, 0, sizeof(xmluri));

    xmluri.scheme = uri->scheme;
    xmluri.server = uri->server;
    xmluri.port = uri->port;
    xmluri.path = uri->path;
#ifdef HAVE_XMLURI_QUERY_RAW
    xmluri.query_raw = uri->query;
#else
    xmluri.query = uri->query;
#endif
    xmluri.fragment = uri->fragment;
    xmluri.user = uri->user;

    /* First check: does it make sense to do anything */
    if (xmluri.server != NULL &&
        strchr(xmluri.server, ':') != NULL) {

        if (virAsprintf(&tmpserver, "[%s]", xmluri.server) < 0)
            return NULL;

        xmluri.server = tmpserver;
    }

    /*
     * This helps libxml2 deal with the difference
     * between uri:/absolute/path and uri:///absolute/path.
     */
    if (!xmluri.server && !xmluri.port)
        xmluri.port = -1;

    ret = (char *)xmlSaveUri(&xmluri);
    if (!ret) {
        virReportOOMError();
        goto cleanup;
    }

 cleanup:
    VIR_FREE(tmpserver);

    return ret;
}


char *virURIFormatParams(virURIPtr uri)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    bool amp = false;

    for (i = 0; i < uri->paramsCount; ++i) {
        if (!uri->params[i].ignore) {
            if (amp) virBufferAddChar(&buf, '&');
            virBufferStrcat(&buf, uri->params[i].name, "=", NULL);
            virBufferURIEncodeString(&buf, uri->params[i].value);
            amp = true;
        }
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

/**
 * virURIFree:
 * @uri: uri to free
 *
 * Frees the URI
 */
void virURIFree(virURIPtr uri)
{
    size_t i;

    if (!uri)
        return;

    VIR_FREE(uri->scheme);
    VIR_FREE(uri->server);
    VIR_FREE(uri->user);
    VIR_FREE(uri->path);
    VIR_FREE(uri->query);
    VIR_FREE(uri->fragment);

    for (i = 0; i < uri->paramsCount; i++) {
        VIR_FREE(uri->params[i].name);
        VIR_FREE(uri->params[i].value);
    }
    VIR_FREE(uri->params);

    VIR_FREE(uri);
}
