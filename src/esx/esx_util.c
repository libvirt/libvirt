
/*
 * esx_util.c: utility functions for the VMware ESX driver
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <netdb.h>

#include "internal.h"
#include "datatypes.h"
#include "qparams.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "esx_private.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX



int
esxUtil_ParseUri(esxUtil_ParsedUri **parsedUri, xmlURIPtr uri)
{
    int result = -1;
    struct qparam_set *queryParamSet = NULL;
    struct qparam *queryParam = NULL;
    int i;
    int noVerify;
    int autoAnswer;
    char *tmp;
    char *saveptr;

    if (parsedUri == NULL || *parsedUri != NULL) {
        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
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
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'transport' has unexpected value "
                            "'%s' (should be http|https)"),
                          (*parsedUri)->transport);
                goto cleanup;
            }
        } else if (STRCASEEQ(queryParam->name, "vcenter")) {
            VIR_FREE((*parsedUri)->vCenter);

            (*parsedUri)->vCenter = strdup(queryParam->value);

            if ((*parsedUri)->vCenter == NULL) {
                virReportOOMError();
                goto cleanup;
            }
        } else if (STRCASEEQ(queryParam->name, "no_verify")) {
            if (virStrToLong_i(queryParam->value, NULL, 10, &noVerify) < 0 ||
                (noVerify != 0 && noVerify != 1)) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'no_verify' has unexpected value "
                            "'%s' (should be 0 or 1)"), queryParam->value);
                goto cleanup;
            }

            (*parsedUri)->noVerify = noVerify != 0;
        } else if (STRCASEEQ(queryParam->name, "auto_answer")) {
            if (virStrToLong_i(queryParam->value, NULL, 10, &autoAnswer) < 0 ||
                (autoAnswer != 0 && autoAnswer != 1)) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
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

            if ((tmp = STRSKIP(queryParam->value, "http://")) != NULL) {
                (*parsedUri)->proxy_type = CURLPROXY_HTTP;
            } else if ((tmp = STRSKIP(queryParam->value, "socks://")) != NULL ||
                       (tmp = STRSKIP(queryParam->value, "socks5://")) != NULL) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS5;
            } else if ((tmp = STRSKIP(queryParam->value, "socks4://")) != NULL) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS4;
            } else if ((tmp = STRSKIP(queryParam->value, "socks4a://")) != NULL) {
                (*parsedUri)->proxy_type = CURLPROXY_SOCKS4A;
            } else if ((tmp = strstr(queryParam->value, "://")) != NULL) {
                *tmp = '\0';

                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'proxy' contains unexpected "
                            "type '%s' (should be (http|socks(|4|4a|5))"),
                          queryParam->value);
                goto cleanup;
            } else {
                tmp = queryParam->value;
            }

            (*parsedUri)->proxy_hostname = strdup(tmp);

            if ((*parsedUri)->proxy_hostname == NULL) {
                virReportOOMError();
                goto cleanup;
            }

            if ((tmp = strchr((*parsedUri)->proxy_hostname, ':')) != NULL) {
                if (tmp == (*parsedUri)->proxy_hostname) {
                    ESX_ERROR(VIR_ERR_INVALID_ARG, "%s",
                              _("Query parameter 'proxy' doesn't contain a "
                                "hostname"));
                    goto cleanup;
                }

                *tmp++ = '\0';

                if (virStrToLong_i(tmp, NULL, 10,
                                   &(*parsedUri)->proxy_port) < 0 ||
                    (*parsedUri)->proxy_port < 1 ||
                    (*parsedUri)->proxy_port > 65535) {
                    ESX_ERROR(VIR_ERR_INVALID_ARG,
                              _("Query parameter 'proxy' has unexpected port"
                                "value '%s' (should be [1..65535])"), tmp);
                    goto cleanup;
                }
            }
        } else {
            VIR_WARN("Ignoring unexpected query parameter '%s'",
                     queryParam->name);
        }
    }

    /* Expected format: [/]<datacenter>/<computeresource>[/<hostsystem>] */
    if (uri->path != NULL) {
        tmp = strdup(uri->path);

        if (tmp == NULL) {
            virReportOOMError();
            goto cleanup;
        }

        if (esxVI_String_DeepCopyValue(&(*parsedUri)->path_datacenter,
                                       strtok_r(tmp, "/", &saveptr)) < 0 ||
            esxVI_String_DeepCopyValue(&(*parsedUri)->path_computeResource,
                                       strtok_r(NULL, "/", &saveptr)) < 0 ||
            esxVI_String_DeepCopyValue(&(*parsedUri)->path_hostSystem,
                                       strtok_r(NULL, "", &saveptr)) < 0) {
            VIR_FREE(tmp);
            goto cleanup;
        }

        VIR_FREE(tmp);
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
        esxUtil_FreeParsedUri(parsedUri);
    }

    if (queryParamSet != NULL) {
        free_qparam_set(queryParamSet);
    }

    return result;
}




void
esxUtil_FreeParsedUri(esxUtil_ParsedUri **parsedUri)
{
    if (parsedUri == NULL || *parsedUri == NULL) {
        return;
    }

    VIR_FREE((*parsedUri)->transport);
    VIR_FREE((*parsedUri)->vCenter);
    VIR_FREE((*parsedUri)->proxy_hostname);
    VIR_FREE((*parsedUri)->path_datacenter);
    VIR_FREE((*parsedUri)->path_computeResource);
    VIR_FREE((*parsedUri)->path_hostSystem);

    VIR_FREE(*parsedUri);
}



int
esxUtil_ParseVirtualMachineIDString(const char *id_string, int *id)
{
    /* Try to parse an integer from the complete string. */
    if (virStrToLong_i(id_string, NULL, 10, id) == 0) {
        return 0;
    }

    /*
     * If that fails try to parse an integer from the string tail
     * assuming the naming scheme Virtual Center seems to use.
     */
    if (STRPREFIX(id_string, "vm-")) {
        if (virStrToLong_i(id_string + 3, NULL, 10, id) == 0) {
            return 0;
        }
    }

    return -1;
}



int
esxUtil_ParseDatastorePath(const char *datastorePath, char **datastoreName,
                           char **directoryName, char **fileName)
{
    int result = -1;
    char *copyOfDatastorePath = NULL;
    char *tmp = NULL;
    char *saveptr = NULL;
    char *preliminaryDatastoreName = NULL;
    char *directoryAndFileName = NULL;
    char *separator = NULL;

    if (datastoreName == NULL || *datastoreName != NULL ||
        directoryName == NULL || *directoryName != NULL ||
        fileName == NULL || *fileName != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (esxVI_String_DeepCopyValue(&copyOfDatastorePath, datastorePath) < 0) {
        goto cleanup;
    }

    /* Expected format: '[<datastore>] <path>' */
    if ((tmp = STRSKIP(copyOfDatastorePath, "[")) == NULL ||
        (preliminaryDatastoreName = strtok_r(tmp, "]", &saveptr)) == NULL ||
        (directoryAndFileName = strtok_r(NULL, "", &saveptr)) == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Datastore path '%s' doesn't have expected format "
                    "'[<datastore>] <path>'"), datastorePath);
        goto cleanup;
    }

    if (esxVI_String_DeepCopyValue(datastoreName,
                                   preliminaryDatastoreName) < 0) {
        goto cleanup;
    }

    directoryAndFileName += strspn(directoryAndFileName, " ");

    /* Split <path> into <directory>/<file>, where <directory> is optional */
    separator = strrchr(directoryAndFileName, '/');

    if (separator != NULL) {
        *separator++ = '\0';

        if (*separator == '\0') {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Datastore path '%s' doesn't reference a file"),
                      datastorePath);
            goto cleanup;
        }

        if (esxVI_String_DeepCopyValue(directoryName,
                                       directoryAndFileName) < 0 ||
            esxVI_String_DeepCopyValue(fileName, separator) < 0) {
            goto cleanup;
        }
    } else {
        if (esxVI_String_DeepCopyValue(fileName, directoryAndFileName) < 0) {
            goto cleanup;
        }
    }

    result = 0;

  cleanup:
    if (result < 0) {
        VIR_FREE(*datastoreName);
        VIR_FREE(*directoryName);
        VIR_FREE(*fileName);
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

    memset(&hints, 0, sizeof (hints));

    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    errcode = getaddrinfo(hostname, NULL, &hints, &result);

    if (errcode != 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("IP address lookup for host '%s' failed: %s"), hostname,
                  gai_strerror(errcode));
        return -1;
    }

    if (result == NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("No IP address for host '%s' found: %s"), hostname,
                  gai_strerror(errcode));
        return -1;
    }

    errcode = getnameinfo(result->ai_addr, result->ai_addrlen, ipAddress,
                          ipAddress_length, NULL, 0, NI_NUMERICHOST);

    if (errcode != 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Formating IP address for host '%s' failed: %s"), hostname,
                  gai_strerror(errcode));
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    return 0;
}



int
esxUtil_GetConfigString(virConfPtr conf, const char *name, char **string,
                        bool optional)
{
    virConfValuePtr value;

    *string = NULL;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        }

        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Missing essential config entry '%s'"), name);
        return -1;
    }

    if (value->type != VIR_CONF_STRING) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Config entry '%s' must be a string"), name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        }

        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Missing essential config entry '%s'"), name);
        return -1;
    }

    *string = strdup(value->str);

    if (*string == NULL) {
        virReportOOMError();
        return -1;
    }

    return 0;
}



int
esxUtil_GetConfigUUID(virConfPtr conf, const char *name, unsigned char *uuid,
                      bool optional)
{
    virConfValuePtr value;

    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type != VIR_CONF_STRING) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Config entry '%s' must be a string"), name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (virUUIDParse(value->str, uuid) < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not parse UUID from string '%s'"), value->str);
        return -1;
    }

    return 0;
}



int
esxUtil_GetConfigLong(virConfPtr conf, const char *name, long long *number,
                      long long default_, bool optional)
{
    virConfValuePtr value;

    *number = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          _("Missing essential config entry '%s'"), name);
                return -1;
            }
        }

        if (STREQ(value->str, "unlimited")) {
            *number = -1;
        } else if (virStrToLong_ll(value->str, NULL, 10, number) < 0) {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Config entry '%s' must represent an integer value"),
                      name);
            return -1;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Config entry '%s' must be a string"), name);
        return -1;
    }

    return 0;
}



int
esxUtil_GetConfigBoolean(virConfPtr conf, const char *name, bool *boolean_,
                         bool default_, bool optional)
{
    virConfValuePtr value;

    *boolean_ = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Missing essential config entry '%s'"), name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                          _("Missing essential config entry '%s'"), name);
                return -1;
            }
        }

        if (STRCASEEQ(value->str, "true")) {
            *boolean_ = 1;
        } else if (STRCASEEQ(value->str, "false")) {
            *boolean_ = 0;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Config entry '%s' must represent a boolean value "
                        "(true|false)"), name);
            return -1;
        }
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Config entry '%s' must be a string"), name);
        return -1;
    }

    return 0;
}
