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

#define VIR_FROM_THIS VIR_FROM_URI

#define virURIReportError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


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

    xmlFreeURI(xmluri);

    return ret;

no_memory:
    virReportOOMError();
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
    xmluri.query = uri->query;
    xmluri.fragment = uri->fragment;

    /* First check: does it make sense to do anything */
    if (xmluri.server != NULL &&
        strchr(xmluri.server, ':') != NULL) {

        if (virAsprintf(&tmpserver, "[%s]", xmluri.server) < 0)
            return NULL;

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


/**
 * virURIFree:
 * @uri: uri to free
 *
 * Frees the URI
 */
void virURIFree(virURIPtr uri)
{
    if (!uri)
        return;

    VIR_FREE(uri->scheme);
    VIR_FREE(uri->server);
    VIR_FREE(uri->path);
    VIR_FREE(uri->query);
    VIR_FREE(uri);
}
