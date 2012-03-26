/*
 * viruri.c: URI parsing wrappers for libxml2 functions
 *
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 */

#include <config.h>

#include "viruri.h"

#include "memory.h"
#include "util.h"
#include "virterror_internal.h"
#include "buf.h"

#define VIR_FROM_THIS VIR_FROM_URI

#define virURIReportError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


static int
virURIParamAppend(virURIPtr uri,
                  const char *name,
                  const char *value)
{
    char *pname = NULL;
    char *pvalue = NULL;

    if (!(pname = strdup(name)))
        goto no_memory;
    if (!(pvalue = strdup (value)))
        goto no_memory;

    if (VIR_RESIZE_N(uri->params, uri->paramsAlloc, uri->paramsCount, 1) < 0)
        goto no_memory;

    uri->params[uri->paramsCount].name = pname;
    uri->params[uri->paramsCount].value = pvalue;
    uri->params[uri->paramsCount].ignore = 0;
    uri->paramsCount++;

    return 0;

no_memory:
    VIR_FREE(pname);
    VIR_FREE(pvalue);
    virReportOOMError();
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
            if (!name) goto no_memory;
        }
        /* Or if we have "name=" here (works around annoying
         * problem when calling xmlURIUnescapeString with len = 0).
         */
        else if (eq+1 == end) {
            name = xmlURIUnescapeString (query, eq - query, NULL);
            if (!name) goto no_memory;
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
                goto no_memory;
            value = xmlURIUnescapeString (eq+1, end - (eq+1), NULL);
            if (!value) {
                VIR_FREE(name);
                goto no_memory;
            }
        }

        /* Append to the parameter set. */
        if (virURIParamAppend(uri, name, value ? value : "") < 0) {
            VIR_FREE(name);
            VIR_FREE(value);
            goto no_memory;
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
        virURIReportError(VIR_ERR_INTERNAL_ERROR,
                          "Unable to parse URI %s", uri);
        return NULL;
    }

    if (VIR_ALLOC(ret) < 0)
        goto no_memory;

    if (xmluri->scheme &&
        !(ret->scheme = strdup(xmluri->scheme)))
        goto no_memory;
    if (xmluri->server &&
        !(ret->server = strdup(xmluri->server)))
        goto no_memory;
    ret->port = xmluri->port;
    if (xmluri->path &&
        !(ret->path = strdup(xmluri->path)))
        goto no_memory;
#ifdef HAVE_XMLURI_QUERY_RAW
    if (xmluri->query_raw &&
        !(ret->query = strdup(xmluri->query_raw)))
        goto no_memory;
#else
    if (xmluri->query &&
        !(ret->query = strdup(xmluri->query)))
        goto no_memory;
#endif
    if (xmluri->fragment &&
        !(ret->fragment = strdup(xmluri->fragment)))
        goto no_memory;


    /* First check: does it even make sense to jump inside */
    if (ret->server != NULL &&
        ret->server[0] == '[') {
        size_t length = strlen(ret->server);

        /* We want to modify the server string only if there are
         * square brackets on both ends and inside there is IPv6
         * address. Otherwise we could make a mistake by modifying
         * something other than an IPv6 address. */
        if (ret->server[length - 1] == ']' && strchr(ret->server, ':')) {
            memmove(&ret->server[0], &ret->server[1], length - 2);
            ret->server[length - 2] = '\0';
        }
        /* Even after such modification, it is completely ok to free
         * the uri with xmlFreeURI() */
    }

    if (virURIParseParams(ret) < 0)
        goto error;

    xmlFreeURI(xmluri);

    return ret;

no_memory:
    virReportOOMError();
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

    /* First check: does it make sense to do anything */
    if (xmluri.server != NULL &&
        strchr(xmluri.server, ':') != NULL) {

        if (virAsprintf(&tmpserver, "[%s]", xmluri.server) < 0) {
            virReportOOMError();
            return NULL;
        }

        xmluri.server = tmpserver;
    }

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
    int i, amp = 0;

    for (i = 0; i < uri->paramsCount; ++i) {
        if (!uri->params[i].ignore) {
            if (amp) virBufferAddChar (&buf, '&');
            virBufferStrcat (&buf, uri->params[i].name, "=", NULL);
            virBufferURIEncodeString (&buf, uri->params[i].value);
            amp = 1;
        }
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

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

    for (i = 0 ; i < uri->paramsCount ; i++) {
        VIR_FREE(uri->params[i].name);
        VIR_FREE(uri->params[i].value);
    }
    VIR_FREE(uri->params);

    VIR_FREE(uri);
}
