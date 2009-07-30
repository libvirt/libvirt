
/*
 * esx_util.c: utility methods for the VMware ESX driver
 *
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
#include "virterror_internal.h"
#include "datatypes.h"
#include "qparams.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX

#define ESX_ERROR(conn, code, fmt...)                                         \
    virReportErrorHelper (conn, VIR_FROM_ESX, code, __FILE__, __FUNCTION__,   \
                          __LINE__, fmt)

/* AI_ADDRCONFIG is missing on some systems. */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif


char *
esxUtil_RequestUsername(virConnectAuthPtr auth, const char *default_username,
                        const char *server)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt = NULL;

    memset(&cred, 0, sizeof(virConnectCredential));

    if (virAsprintf(&prompt, "Enter username for %s [%s]", server,
                    default_username) < 0) {
        return NULL;
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_AUTHNAME) {
            continue;
        }

        cred.type = VIR_CRED_AUTHNAME;
        cred.prompt = prompt;
        cred.challenge = NULL;
        cred.defresult = default_username;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            VIR_FREE(cred.result);
        }

        break;
    }

    VIR_FREE(prompt);

    return cred.result;
}



char *
esxUtil_RequestPassword(virConnectAuthPtr auth, const char *username,
                        const char *server)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt;

    memset(&cred, 0, sizeof(virConnectCredential));

    if (virAsprintf(&prompt, "Enter %s password for %s", username,
                    server) < 0) {
        return NULL;
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_PASSPHRASE &&
            auth->credtype[ncred] != VIR_CRED_NOECHOPROMPT) {
            continue;
        }

        cred.type = auth->credtype[ncred];
        cred.prompt = prompt;
        cred.challenge = NULL;
        cred.defresult = NULL;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            VIR_FREE(cred.result);
        }

        break;
    }

    VIR_FREE(prompt);

    return cred.result;
}



int
esxUtil_ParseQuery(virConnectPtr conn, char **transport, char **vcenter,
                   int *noVerify)
{
    int result = 0;
    int i;
    struct qparam_set *queryParamSet = NULL;
    struct qparam *queryParam = NULL;

    if (transport != NULL) {
        *transport = NULL;
    }

    if (vcenter != NULL) {
        *vcenter = NULL;
    }

#ifdef HAVE_XMLURI_QUERY_RAW
    queryParamSet = qparam_query_parse(conn->uri->query_raw);
#else
    queryParamSet = qparam_query_parse(conn->uri->query);
#endif

    if (queryParamSet == NULL) {
        goto failure;
    }

    for (i = 0; i < queryParamSet->n; i++) {
        queryParam = &queryParamSet->p[i];

        if (STRCASEEQ(queryParam->name, "transport") && transport != NULL) {
            *transport = strdup(queryParam->value);

            if (*transport == NULL) {
                virReportOOMError(conn);
                goto failure;
            }

            if (STRNEQ(*transport, "http") && STRNEQ(*transport, "https")) {
                ESX_ERROR(conn, VIR_ERR_INVALID_ARG,
                          "Query parameter 'transport' has unexpected value "
                          "'%s' (should be http|https)", *transport);
                goto failure;
            }
        } else if (STRCASEEQ(queryParam->name, "vcenter") && vcenter != NULL) {
            *vcenter = strdup(queryParam->value);

            if (*vcenter == NULL) {
                virReportOOMError(conn);
                goto failure;
            }
        } else if (STRCASEEQ(queryParam->name, "no_verify") &&
                   noVerify != NULL) {
            if (virStrToLong_i(queryParam->value, NULL, 10, noVerify) < 0 ||
                (*noVerify != 0 && *noVerify != 1)) {
                ESX_ERROR(conn, VIR_ERR_INVALID_ARG,
                          "Query parameter 'no_verify' has unexpected value "
                          "'%s' (should be 0 or 1)", queryParam->value);
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
            virReportOOMError(conn);
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

    if (vcenter != NULL) {
        VIR_FREE(*vcenter);
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
esxUtil_ResolveHostname(virConnectPtr conn, const char *hostname,
                        char *ip_address, size_t ip_address_length)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    int errcode;

    memset(&hints, 0, sizeof (struct addrinfo));

    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;

    errcode = getaddrinfo(hostname, NULL, &hints, &result);

    if (errcode != 0) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "IP address lookup for host '%s' failed: %s", hostname,
                  gai_strerror(errcode));
        return -1;
    }

    if (result == NULL) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "No IP address for host '%s' found: %s", hostname,
                  gai_strerror(errcode));
        return -1;
    }

    errcode = getnameinfo(result->ai_addr, result->ai_addrlen, ip_address,
                          ip_address_length, NULL, 0, NI_NUMERICHOST);

    if (errcode != 0) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Formating IP address for host '%s' failed: %s", hostname,
                  gai_strerror(errcode));
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    return 0;
}



int
esxUtil_GetConfigString(virConnectPtr conn, virConfPtr conf, const char *name,
                        char **string, int optional)
{
    virConfValuePtr value;

    *string = NULL;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        }

        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Missing essential config entry '%s'", name);
        return -1;
    }

    if (value->type != VIR_CONF_STRING) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Config entry '%s' must be a string", name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        }

        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Missing essential config entry '%s'", name);
        return -1;
    }

    *string = strdup(value->str);

    if (*string == NULL) {
        virReportOOMError(conn);
        return -1;
    }

    return 0;
}



int
esxUtil_GetConfigUUID(virConnectPtr conn, virConfPtr conf, const char *name,
                      unsigned char *uuid, int optional)
{
    virConfValuePtr value;

    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Missing essential config entry '%s'", name);
            return -1;
        }
    }

    if (value->type != VIR_CONF_STRING) {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Config entry '%s' must be a string", name);
        return -1;
    }

    if (value->str == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Missing essential config entry '%s'", name);
            return -1;
        }
    }

    virUUIDParse(value->str, uuid);

    return 0;
}



int
esxUtil_GetConfigLong(virConnectPtr conn, virConfPtr conf, const char *name,
                      long long *number, long long default_, int optional)
{
    virConfValuePtr value;

    *number = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Missing essential config entry '%s'", name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Missing essential config entry '%s'", name);
                return -1;
            }
        }

        if (STREQ(value->str, "unlimited")) {
            *number = -1;
        } else if (virStrToLong_ll(value->str, NULL, 10, number) < 0) {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Config entry '%s' must represent an integer value",
                      name);
            return -1;
        }
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Config entry '%s' must be a string", name);
        return -1;
    }

    return 0;
}



int
esxUtil_GetConfigBoolean(virConnectPtr conn, virConfPtr conf,
                         const char *name, int *boolval, int default_,
                         int optional)
{
    virConfValuePtr value;

    *boolval = default_;
    value = virConfGetValue(conf, name);

    if (value == NULL) {
        if (optional) {
            return 0;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Missing essential config entry '%s'", name);
            return -1;
        }
    }

    if (value->type == VIR_CONF_STRING) {
        if (value->str == NULL) {
            if (optional) {
                return 0;
            } else {
                ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                          "Missing essential config entry '%s'", name);
                return -1;
            }
        }

        if (STRCASEEQ(value->str, "true")) {
            *boolval = 1;
        } else if (STRCASEEQ(value->str, "false")) {
            *boolval = 0;
        } else {
            ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                      "Config entry '%s' must represent a boolean value "
                      "(true|false)", name);
            return -1;
        }
    } else {
        ESX_ERROR(conn, VIR_ERR_INTERNAL_ERROR,
                  "Config entry '%s' must be a string", name);
        return -1;
    }

    return 0;
}



int
esxUtil_EqualSuffix(const char *string, const char* suffix)
{
    int difference = (int)strlen(string) - (int)strlen(suffix);

    if (difference < 0) {
        return -1;
    } else {
        return STRCASEEQ(string + difference, suffix);
    }
}
