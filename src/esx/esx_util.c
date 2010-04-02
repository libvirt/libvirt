
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

/* AI_ADDRCONFIG is missing on some systems. */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif



int
esxUtil_ParseQuery(xmlURIPtr uri, char **transport, char **vCenter,
                   int *noVerify, int *autoAnswer)
{
    int result = 0;
    int i;
    struct qparam_set *queryParamSet = NULL;
    struct qparam *queryParam = NULL;

    if (transport != NULL) {
        *transport = NULL;
    }

    if (vCenter != NULL) {
        *vCenter = NULL;
    }

    if (noVerify != NULL) {
        *noVerify = 0;
    }

    if (autoAnswer != NULL) {
        *autoAnswer = 0;
    }

#ifdef HAVE_XMLURI_QUERY_RAW
    queryParamSet = qparam_query_parse(uri->query_raw);
#else
    queryParamSet = qparam_query_parse(uri->query);
#endif

    if (queryParamSet == NULL) {
        goto failure;
    }

    for (i = 0; i < queryParamSet->n; i++) {
        queryParam = &queryParamSet->p[i];

        if (STRCASEEQ(queryParam->name, "transport")) {
            if (transport == NULL) {
                continue;
            }

            *transport = strdup(queryParam->value);

            if (*transport == NULL) {
                virReportOOMError();
                goto failure;
            }

            if (STRNEQ(*transport, "http") && STRNEQ(*transport, "https")) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'transport' has unexpected value "
                            "'%s' (should be http|https)"), *transport);
                goto failure;
            }
        } else if (STRCASEEQ(queryParam->name, "vcenter")) {
            if (vCenter == NULL) {
                continue;
            }

            *vCenter = strdup(queryParam->value);

            if (*vCenter == NULL) {
                virReportOOMError();
                goto failure;
            }
        } else if (STRCASEEQ(queryParam->name, "no_verify")) {
            if (noVerify == NULL) {
                continue;
            }

            if (virStrToLong_i(queryParam->value, NULL, 10, noVerify) < 0 ||
                (*noVerify != 0 && *noVerify != 1)) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'no_verify' has unexpected value "
                            "'%s' (should be 0 or 1)"), queryParam->value);
                goto failure;
            }
        } else if (STRCASEEQ(queryParam->name, "auto_answer")) {
            if (autoAnswer == NULL) {
                continue;
            }

            if (virStrToLong_i(queryParam->value, NULL, 10, autoAnswer) < 0 ||
                (*autoAnswer != 0 && *autoAnswer != 1)) {
                ESX_ERROR(VIR_ERR_INVALID_ARG,
                          _("Query parameter 'auto_answer' has unexpected "
                            "value '%s' (should be 0 or 1)"), queryParam->value);
                goto failure;
            }
        } else {
            VIR_WARN("Ignoring unexpected query parameter '%s'",
                     queryParam->name);
        }
    }

    if (transport != NULL && *transport == NULL) {
        *transport = strdup("https");

        if (*transport == NULL) {
            virReportOOMError();
            goto failure;
        }
    }

  cleanup:
    if (queryParamSet != NULL) {
        free_qparam_set(queryParamSet);
    }

    return result;

  failure:
    if (transport != NULL) {
        VIR_FREE(*transport);
    }

    if (vCenter != NULL) {
        VIR_FREE(*vCenter);
    }

    result = -1;

    goto cleanup;
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
esxUtil_ParseDatastoreRelatedPath(const char *datastoreRelatedPath,
                                  char **datastoreName,
                                  char **directoryName, char **fileName)
{
    int result = 0;
    char *directoryAndFileName = NULL;
    char *separator = NULL;

    if (datastoreName == NULL || *datastoreName != NULL ||
        directoryName == NULL || *directoryName != NULL ||
        fileName == NULL || *fileName != NULL) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    /*
     * Parse string as '[<datastore>] <path>'. '%as' is similar to '%s', but
     * sscanf() will allocate the memory for the string, so the caller doesn't
     * need to preallocate a buffer that's large enough.
     *
     * The s in '%as' can be replaced with a character set, e.g. [a-z].
     *
     * '%a[^]%]' matches <datastore>. '[^]%]' excludes ']' from the accepted
     * characters, otherwise sscanf() wont match what it should.
     *
     * '%a[^\n]' matches <path>. '[^\n]' excludes '\n' from the accepted
     * characters, otherwise sscanf() would only match up to the first space,
     * but spaces are valid in <path>.
     */
    if (sscanf(datastoreRelatedPath, "[%a[^]%]] %a[^\n]", datastoreName,
               &directoryAndFileName) != 2) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Datastore related path '%s' doesn't have expected format "
                    "'[<datastore>] <path>'"), datastoreRelatedPath);
        goto failure;
    }

    /* Split <path> into <directory>/<file>, where <directory> is optional */
    separator = strrchr(directoryAndFileName, '/');

    if (separator != NULL) {
        *separator++ = '\0';

        *directoryName = directoryAndFileName;
        directoryAndFileName = NULL;

        if (*separator == '\0') {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Datastore related path '%s' doesn't reference a file"),
                      datastoreRelatedPath);
            goto failure;
        }

        *fileName = strdup(separator);

        if (*fileName == NULL) {
            virReportOOMError();
            goto failure;
        }
    } else {
        *fileName = directoryAndFileName;
        directoryAndFileName = NULL;
    }

  cleanup:
    VIR_FREE(directoryAndFileName);

    return result;

  failure:
    VIR_FREE(*datastoreName);
    VIR_FREE(*directoryName);
    VIR_FREE(*fileName);

    result = -1;

    goto cleanup;
}



int
esxUtil_ResolveHostname(const char *hostname,
                        char *ipAddress, size_t ipAddress_length)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int errcode;

    memset(&hints, 0, sizeof(struct addrinfo));

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
                        int optional)
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
                      int optional)
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
                      long long default_, int optional)
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
esxUtil_GetConfigBoolean(virConfPtr conf, const char *name, int *boolean_,
                         int default_, int optional)
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
