/*
 * esx_util.c: utility functions for the VMware ESX driver
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright (C) 2009-2011 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2009 Maximilian Wilhelm <max@rfc2324.org>
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

#include <netdb.h>

#include "internal.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "vmx.h"
#include "esx_private.h"
#include "esx_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX

VIR_LOG_INIT("esx.esx_util");

int
esxUtil_ParseUri(esxUtil_ParsedUri **parsedUri, virURIPtr uri)
{
    int result = -1;
    size_t i;
    int noVerify;
    int autoAnswer;
    char *tmp;

    ESX_VI_CHECK_ARG_LIST(parsedUri);

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
        } else if (STRCASEEQ(queryParam->name, "vcenter")) {
            VIR_FREE((*parsedUri)->vCenter);

            if (VIR_STRDUP((*parsedUri)->vCenter, queryParam->value) < 0)
                goto cleanup;
        } else if (STRCASEEQ(queryParam->name, "no_verify")) {
            if (virStrToLong_i(queryParam->value, NULL, 10, &noVerify) < 0 ||
                (noVerify != 0 && noVerify != 1)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Query parameter 'no_verify' has unexpected value "
                                 "'%s' (should be 0 or 1)"), queryParam->value);
                goto cleanup;
            }

            (*parsedUri)->noVerify = noVerify != 0;
        } else if (STRCASEEQ(queryParam->name, "auto_answer")) {
            if (virStrToLong_i(queryParam->value, NULL, 10, &autoAnswer) < 0 ||
                (autoAnswer != 0 && autoAnswer != 1)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("Query parameter 'auto_answer' has unexpected "
                                 "value '%s' (should be 0 or 1)"), queryParam->value);
                goto cleanup;
            }

            (*parsedUri)->autoAnswer = autoAnswer != 0;
        } else if (STRCASEEQ(queryParam->name, "proxy")) {
            /* Expected format: [<type>://]<hostname>[:<port>] */
            (*parsedUri)->proxy = true;
            (*parsedUri)->proxy_type = CURLPROXY_HTTP;
            VIR_FREE((*parsedUri)->proxy_hostname);
            (*parsedUri)->proxy_port = 1080;

            if ((tmp = STRSKIP(queryParam->value, "http://"))) {
                (*parsedUri)->proxy_type = CURLPROXY_HTTP;
            } else if ((tmp = STRSKIP(queryParam->value, "socks://")) ||
                       (tmp = STRSKIP(queryParam->value, "socks5://"))) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS5;
            } else if ((tmp = STRSKIP(queryParam->value, "socks4://"))) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS4;
            } else if ((tmp = STRSKIP(queryParam->value, "socks4a://"))) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS4A;
            } else if ((tmp = strstr(queryParam->value, "://"))) {
                *tmp = '\0';

                virReportError(VIR_ERR_INVALID_ARG,
                               _("Query parameter 'proxy' contains unexpected "
                                 "type '%s' (should be (http|socks(|4|4a|5))"),
                               queryParam->value);
                goto cleanup;
            } else {
                tmp = queryParam->value;
            }

            if (VIR_STRDUP((*parsedUri)->proxy_hostname, tmp) < 0)
                goto cleanup;

            if ((tmp = strchr((*parsedUri)->proxy_hostname, ':'))) {
                if (tmp == (*parsedUri)->proxy_hostname) {
                    virReportError(VIR_ERR_INVALID_ARG, "%s",
                                   _("Query parameter 'proxy' doesn't contain a "
                                     "hostname"));
                    goto cleanup;
                }

                *tmp++ = '\0';

                if (virStrToLong_i(tmp, NULL, 10,
                                   &(*parsedUri)->proxy_port) < 0 ||
                    (*parsedUri)->proxy_port < 1 ||
                    (*parsedUri)->proxy_port > 65535) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("Query parameter 'proxy' has unexpected "
                                     "port value '%s' (should be [1..65535])"),
                                   tmp);
                    goto cleanup;
                }
            }
        } else {
            VIR_WARN("Ignoring unexpected query parameter '%s'",
                     queryParam->name);
        }
    }

    if (VIR_STRDUP((*parsedUri)->path, uri->path) < 0)
        goto cleanup;

    if (!(*parsedUri)->transport &&
        VIR_STRDUP((*parsedUri)->transport, "https") < 0)
        goto cleanup;

    result = 0;

 cleanup:
    if (result < 0)
        esxUtil_FreeParsedUri(parsedUri);

    return result;
}




void
esxUtil_FreeParsedUri(esxUtil_ParsedUri **parsedUri)
{
    if (!parsedUri || !(*parsedUri))
        return;

    VIR_FREE((*parsedUri)->transport);
    VIR_FREE((*parsedUri)->vCenter);
    VIR_FREE((*parsedUri)->proxy_hostname);
    VIR_FREE((*parsedUri)->path);

    VIR_FREE(*parsedUri);
}



int
esxUtil_ParseVirtualMachineIDString(const char *id_string, int *id)
{
    /* Try to parse an integer from the complete string. */
    if (virStrToLong_i(id_string, NULL, 10, id) == 0)
        return 0;

    /*
     * If that fails try to parse an integer from the string tail
     * assuming the naming scheme Virtual Center seems to use.
     */
    if (STRPREFIX(id_string, "vm-")) {
        if (virStrToLong_i(id_string + 3, NULL, 10, id) == 0)
            return 0;
    }

    return -1;
}



int
esxUtil_ParseDatastorePath(const char *datastorePath, char **datastoreName,
                           char **directoryName, char **directoryAndFileName)
{
    int result = -1;
    char *copyOfDatastorePath = NULL;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *preliminaryDatastoreName = NULL;
    char *preliminaryDirectoryAndFileName = NULL;

    if ((datastoreName && *datastoreName) ||
        (directoryName && *directoryName) ||
        (directoryAndFileName && *directoryAndFileName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (VIR_STRDUP(copyOfDatastorePath, datastorePath) < 0)
        goto cleanup;

    /* Expected format: '[<datastore>] <path>' where <path> is optional */
    if (!(tmp = STRSKIP(copyOfDatastorePath, "[")) || *tmp == ']' ||
        !(preliminaryDatastoreName = strtok_r(tmp, "]", &saveptr))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Datastore path '%s' doesn't have expected format "
                         "'[<datastore>] <path>'"), datastorePath);
        goto cleanup;
    }

    if (datastoreName &&
        VIR_STRDUP(*datastoreName, preliminaryDatastoreName) < 0) {
        goto cleanup;
    }

    preliminaryDirectoryAndFileName = strtok_r(NULL, "", &saveptr);

    if (!preliminaryDirectoryAndFileName) {
        preliminaryDirectoryAndFileName = (char *)"";
    } else {
        preliminaryDirectoryAndFileName +=
          strspn(preliminaryDirectoryAndFileName, " ");
    }

    if (directoryAndFileName &&
        VIR_STRDUP(*directoryAndFileName, preliminaryDirectoryAndFileName) < 0) {
        goto cleanup;
    }

    if (directoryName) {
        /* Split <path> into <directory>/<file> and remove /<file> */
        tmp = strrchr(preliminaryDirectoryAndFileName, '/');

        if (tmp)
            *tmp = '\0';

        if (VIR_STRDUP(*directoryName, preliminaryDirectoryAndFileName) < 0)
            goto cleanup;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        if (datastoreName)
            VIR_FREE(*datastoreName);

        if (directoryName)
            VIR_FREE(*directoryName);

        if (directoryAndFileName)
            VIR_FREE(*directoryAndFileName);
    }

    VIR_FREE(copyOfDatastorePath);

    return result;
}



int
esxUtil_ResolveHostname(const char *hostname,
                        char *ipAddress, size_t ipAddress_length)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int errcode;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    errcode = getaddrinfo(hostname, NULL, &hints, &result);

    if (errcode != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("IP address lookup for host '%s' failed: %s"), hostname,
                       gai_strerror(errcode));
        return -1;
    }

    if (!result) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No IP address for host '%s' found: %s"), hostname,
                       gai_strerror(errcode));
        return -1;
    }

    errcode = getnameinfo(result->ai_addr, result->ai_addrlen, ipAddress,
                          ipAddress_length, NULL, 0, NI_NUMERICHOST);

    if (errcode != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Formatting IP address for host '%s' failed: %s"), hostname,
                       gai_strerror(errcode));
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    return 0;
}



int
esxUtil_ReformatUuid(const char *input, char *output)
{
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDParse(input, uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not parse UUID from string '%s'"),
                       input);
        return -1;
    }

    virUUIDFormat(uuid, output);

    return 0;
}



char *
esxUtil_EscapeBase64(const char *string)
{
    /* 'normal' characters don't get base64 encoded */
    static const char *normal =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'(),. _-";

    /* VMware uses ',' instead of the path separator '/' in the base64 alphabet */
    static const char *base64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    virBuffer buffer = VIR_BUFFER_INITIALIZER;
    const char *tmp1 = string;
    size_t length;
    unsigned char c1, c2, c3;

    /* Escape sequences of non-'normal' characters as base64 without padding */
    while (*tmp1 != '\0') {
        length = strspn(tmp1, normal);

        if (length > 0) {
            virBufferAdd(&buffer, tmp1, length);

            tmp1 += length;
        } else {
            length = strcspn(tmp1, normal);

            virBufferAddChar(&buffer, '+');

            while (length > 0) {
                c1 = *tmp1++;
                c2 = length > 1 ? *tmp1++ : 0;
                c3 = length > 2 ? *tmp1++ : 0;

                virBufferAddChar(&buffer, base64[(c1 >> 2) & 0x3f]);
                virBufferAddChar(&buffer, base64[((c1 << 4) + (c2 >> 4)) & 0x3f]);

                if (length > 1)
                    virBufferAddChar(&buffer, base64[((c2 << 2) + (c3 >> 6)) & 0x3f]);

                if (length > 2)
                    virBufferAddChar(&buffer, base64[c3 & 0x3f]);

                length -= length > 3 ? 3 : length;
            }

            if (*tmp1 != '\0')
                virBufferAddChar(&buffer, '-');
        }
    }

    if (virBufferCheckError(&buffer) < 0)
        return NULL;

    return virBufferContentAndReset(&buffer);
}



void
esxUtil_ReplaceSpecialWindowsPathChars(char *string)
{
    /* '/' and '\\' are missing on purpose */
    static const char *specials = "\"*<>:|?";

    char *tmp = string;
    size_t length;

    while (*tmp != '\0') {
        length = strspn(tmp, specials);

        while (length > 0) {
            *tmp++ = '_';
            --length;
        }

        if (*tmp != '\0')
            ++tmp;
    }
}



char *
esxUtil_EscapeDatastoreItem(const char *string)
{
    char *replaced;
    char *escaped1;
    char *escaped2 = NULL;

    if (VIR_STRDUP(replaced, string) < 0)
        return NULL;

    esxUtil_ReplaceSpecialWindowsPathChars(replaced);

    escaped1 = virVMXEscapeHexPercent(replaced);

    if (!escaped1)
        goto cleanup;

    escaped2 = esxUtil_EscapeBase64(escaped1);

 cleanup:
    VIR_FREE(replaced);
    VIR_FREE(escaped1);

    return escaped2;
}



char *
esxUtil_EscapeForXml(const char *string)
{
    virBuffer buffer = VIR_BUFFER_INITIALIZER;

    virBufferEscapeString(&buffer, "%s", string);

    if (virBufferCheckError(&buffer) < 0)
        return NULL;

    return virBufferContentAndReset(&buffer);
}
