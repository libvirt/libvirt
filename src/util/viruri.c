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

#include <libxml/uri.h>

#include "viruri.h"

#include "viralloc.h"
#include "virerror.h"
#include "virbuffer.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_URI

VIR_LOG_INIT("util.uri");

static void
virURIParamAppend(virURI *uri,
                  const char *name,
                  const char *value)
{
    char *pname = NULL;
    char *pvalue = NULL;

    pname = g_strdup(name);
    pvalue = g_strdup(value);

    VIR_RESIZE_N(uri->params, uri->paramsAlloc, uri->paramsCount, 1);

    uri->params[uri->paramsCount].name = pname;
    uri->params[uri->paramsCount].value = pvalue;
    uri->params[uri->paramsCount].ignore = false;
    uri->paramsCount++;

    return;
}


static int
virURIParseParams(virURI *uri)
{
    const char *end, *eq;
    const char *query = uri->query;

    if (!query || query[0] == '\0')
        return 0;

    while (*query) {
        g_autofree char *name = NULL;
        g_autofree char *value = NULL;

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
            if (!name)
                return -1;
        } else if (eq+1 == end) {
            /* Or if we have "name=" here (works around annoying
             * problem when calling xmlURIUnescapeString with len = 0).
             */
            name = xmlURIUnescapeString(query, eq - query, NULL);
            if (!name)
                return -1;
        } else if (query == eq) {
            /* If the '=' character is at the beginning then we have
             * "=value" and consistent with CGI.pm we _ignore_ this.
             */
            goto next;
        } else {
            /* Otherwise it's "name=value". */
            name = xmlURIUnescapeString(query, eq - query, NULL);
            if (!name)
                return -1;
            value = xmlURIUnescapeString(eq+1, end - (eq+1), NULL);
            if (!value)
                return -1;
        }

        /* Append to the parameter set. */
        virURIParamAppend(uri, name, NULLSTR_EMPTY(value));

    next:
        query = end;
        if (*query) query ++; /* skip '&' separator */
    }

    return 0;
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
virURI *
virURIParse(const char *uri)
{
    xmlURIPtr xmluri;
    virURI *ret = NULL;

    xmluri = xmlParseURI(uri);

    if (!xmluri) {
        /* libxml2 does not tell us what failed. Grr :-( */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse URI %1$s"), uri);
        return NULL;
    }

    ret = g_new0(virURI, 1);

    ret->scheme = g_strdup(xmluri->scheme);
    ret->server = g_strdup(xmluri->server);
    /* xmluri->port value is not defined if server was
     * not given. Modern versions libxml2 fill port
     * differently to old versions in this case, so
     * don't rely on it. eg libxml2 git commit:
     *   beb7281055dbf0ed4d041022a67c6c5cfd126f25
     */
    if (!ret->server || STREQ(ret->server, ""))
        ret->port = 0;
    else
        ret->port = xmluri->port;
    ret->path = g_strdup(xmluri->path);
    ret->query = g_strdup(xmluri->query_raw);
    ret->fragment = g_strdup(xmluri->fragment);
    ret->user = g_strdup(xmluri->user);

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
 * changes after parsing. It aborts on error.
 *
 * @returns the constructed uri as a string
 */
char *
virURIFormat(virURI *uri)
{
    xmlURI xmluri = { 0 };
    g_autofree char *tmpserver = NULL;
    char *ret;

    xmluri.scheme = uri->scheme;
    xmluri.server = uri->server;
    xmluri.port = uri->port;
    xmluri.path = uri->path;
    xmluri.query_raw = uri->query;
    xmluri.fragment = uri->fragment;
    xmluri.user = uri->user;

    /* First check: does it make sense to do anything */
    if (xmluri.server != NULL &&
        strchr(xmluri.server, ':') != NULL) {

        tmpserver = g_strdup_printf("[%s]", xmluri.server);

        xmluri.server = tmpserver;
    }

    /*
     * This helps libxml2 deal with the difference
     * between uri:/absolute/path and uri:///absolute/path.
     */
    if (!xmluri.server && !xmluri.port)
        xmluri.port = -1;

    /* xmlSaveUri can fail only on OOM condition if argument is non-NULL */
    if (!(ret = (char *)xmlSaveUri(&xmluri)))
        abort();

    return ret;
}


char *virURIFormatParams(virURI *uri)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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

    return virBufferContentAndReset(&buf);
}

/**
 * virURIFree:
 * @uri: uri to free
 *
 * Frees the URI
 */
void virURIFree(virURI *uri)
{
    size_t i;

    if (!uri)
        return;

    g_free(uri->scheme);
    g_free(uri->server);
    g_free(uri->user);
    g_free(uri->path);
    g_free(uri->query);
    g_free(uri->fragment);

    for (i = 0; i < uri->paramsCount; i++) {
        g_free(uri->params[i].name);
        g_free(uri->params[i].value);
    }
    g_free(uri->params);

    g_free(uri);
}


#define URI_ALIAS_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

static int
virURIFindAliasMatch(char *const*aliases, const char *alias,
                     char **uri)
{
    size_t alias_len;

    alias_len = strlen(alias);
    while (*aliases) {
        char *offset;
        size_t safe;

        if (!(offset = strchr(*aliases, '='))) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Malformed 'uri_aliases' config entry '%1$s', expected 'alias=uri://host/path'"),
                           *aliases);
            return -1;
        }

        safe = strspn(*aliases, URI_ALIAS_CHARS);
        if (safe < (offset - *aliases)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Malformed 'uri_aliases' config entry '%1$s', aliases may only contain 'a-Z, 0-9, _, -'"),
                           *aliases);
            return -1;
        }

        if (alias_len == (offset - *aliases) &&
            STREQLEN(*aliases, alias, alias_len)) {
            VIR_DEBUG("Resolved alias '%s' to '%s'",
                      alias, offset+1);
            *uri = g_strdup(offset + 1);
            return 0;
        }

        aliases++;
    }

    VIR_DEBUG("No alias found for '%s', continuing...",
              alias);
    return 0;
}


/**
 * virURIResolveAlias:
 * @conf: configuration file handler
 * @alias: URI alias to be resolved
 * @uri: URI object reference where the resolved URI should be stored
 *
 * Resolves @alias to a canonical URI according to our configuration
 * file.
 *
 * Returns 0 on success, -1 on error.
 */
int
virURIResolveAlias(virConf *conf, const char *alias, char **uri)
{
    int ret = -1;
    g_auto(GStrv) aliases = NULL;

    *uri = NULL;

    if (virConfGetValueStringList(conf, "uri_aliases", false, &aliases) < 0)
        return -1;

    if (aliases && *aliases) {
        ret = virURIFindAliasMatch(aliases, alias, uri);
    } else {
        ret = 0;
    }

    return ret;
}


/**
 * virURIGetParam:
 * @uri: URI to get parameter from
 * @name: name of the parameter
 *
 * For parsed @uri, find parameter with name @name and return its value. The
 * string comparison is case insensitive, by design.
 *
 * Returns: a value on success, or
 *          NULL on error (with error reported)
 */
const char *
virURIGetParam(virURI *uri, const char *name)
{
    size_t i;

    for (i = 0; i < uri->paramsCount; i++) {
        if (STRCASEEQ(uri->params[i].name, name))
            return uri->params[i].value;
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("Missing URI parameter '%1$s'"), name);
    return NULL;
}


/**
 * virURICheckUnixSocket:
 * @uri: URI to check
 *
 * Check if the URI looks like it refers to a non-standard socket path.  In such
 * scenario the socket might be proxied to a remote server even though the URI
 * looks like it is only local.
 *
 * The "socket" parameter is looked for in case insensitive manner, by design.
 *
 * Returns: true if the URI might be proxied to a remote server
 */
bool
virURICheckUnixSocket(virURI *uri)
{
    size_t i = 0;

    if (!uri->scheme)
        return false;

    if (STRNEQ_NULLABLE(strchr(uri->scheme, '+'), "+unix"))
        return false;

    for (i = 0; i < uri->paramsCount; i++) {
        if (STRCASEEQ(uri->params[i].name, "socket"))
            return true;
    }

    return false;
}


void
virURIParamsSetIgnore(virURI *uri,
                      bool ignore,
                      const char *names[])
{
    size_t i;

    for (i = 0; i < uri->paramsCount; i++) {
        size_t j;

        for (j = 0; names[j]; j++) {
            if (STRCASEEQ(uri->params[i].name, names[j]))
                uri->params[i].ignore = ignore;
        }
    }
}
