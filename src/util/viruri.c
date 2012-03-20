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
    virURIPtr ret = xmlParseURI(uri);

    /* First check: does it even make sense to jump inside */
    if (ret != NULL &&
        ret->server != NULL &&
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

    return ret;
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
virURIFormat(xmlURIPtr uri)
{
    char *backupserver = NULL;
    char *tmpserver = NULL;
    char *ret;

    /* First check: does it make sense to do anything */
    if (uri != NULL &&
        uri->server != NULL &&
        strchr(uri->server, ':') != NULL) {

        backupserver = uri->server;
        if (virAsprintf(&tmpserver, "[%s]", uri->server) < 0)
            return NULL;

        uri->server = tmpserver;
    }

    ret = (char *) xmlSaveUri(uri);

    /* Put the fixed version back */
    if (tmpserver) {
        uri->server = backupserver;
        VIR_FREE(tmpserver);
    }

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
    xmlFreeURI(uri);
}
