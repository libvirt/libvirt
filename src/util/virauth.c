/*
 * virauth.c: authentication related utility functions
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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


#include "virauth.h"
#include "virutil.h"
#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "configmake.h"
#include "virauthconfig.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_AUTH

VIR_LOG_INIT("util.auth");

int
virAuthGetConfigFilePathURI(virURIPtr uri,
                            char **path)
{
    size_t i;
    const char *authenv = virGetEnvBlockSUID("LIBVIRT_AUTH_FILE");
    VIR_AUTOFREE(char *) userdir = NULL;

    *path = NULL;

    VIR_DEBUG("Determining auth config file path");

    if (authenv) {
        VIR_DEBUG("Using path from env '%s'", authenv);
        if (VIR_STRDUP(*path, authenv) < 0)
            return -1;
        return 0;
    }

    if (uri) {
        for (i = 0; i < uri->paramsCount; i++) {
            if (STREQ_NULLABLE(uri->params[i].name, "authfile") &&
                uri->params[i].value) {
                VIR_DEBUG("Using path from URI '%s'", uri->params[i].value);
                if (VIR_STRDUP(*path, uri->params[i].value) < 0)
                    return -1;
                return 0;
            }
        }
    }

    if (!(userdir = virGetUserConfigDirectory()))
        return -1;

    if (virAsprintf(path, "%s/auth.conf", userdir) < 0)
        return -1;

    VIR_DEBUG("Checking for readability of '%s'", *path);
    if (access(*path, R_OK) == 0)
        goto done;

    VIR_FREE(*path);

    if (VIR_STRDUP(*path, SYSCONFDIR "/libvirt/auth.conf") < 0)
        return -1;

    VIR_DEBUG("Checking for readability of '%s'", *path);
    if (access(*path, R_OK) == 0)
        goto done;

    VIR_FREE(*path);

 done:
    VIR_DEBUG("Using auth file '%s'", NULLSTR(*path));

    return 0;
}


int
virAuthGetConfigFilePath(virConnectPtr conn,
                         char **path)
{
    return virAuthGetConfigFilePathURI(conn ? conn->uri : NULL, path);
}


static int
virAuthGetCredential(const char *servicename,
                     const char *hostname,
                     const char *credname,
                     const char *path,
                     char **value)
{
    VIR_AUTOPTR(virAuthConfig) config = NULL;
    const char *tmp;

    *value = NULL;

    if (path == NULL)
        return 0;

    if (!(config = virAuthConfigNew(path)))
        return -1;

    if (virAuthConfigLookup(config,
                            servicename,
                            hostname,
                            credname,
                            &tmp) < 0)
        return -1;

    if (VIR_STRDUP(*value, tmp) < 0)
        return -1;

    return 0;
}


char *
virAuthGetUsernamePath(const char *path,
                       virConnectAuthPtr auth,
                       const char *servicename,
                       const char *defaultUsername,
                       const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    VIR_AUTOFREE(char *) prompt = NULL;
    char *ret = NULL;

    if (virAuthGetCredential(servicename, hostname, "username", path, &ret) < 0)
        return NULL;
    if (ret != NULL)
        return ret;

    if (!auth) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Missing authentication credentials"));
        return NULL;
    }

    memset(&cred, 0, sizeof(virConnectCredential));

    if (defaultUsername != NULL) {
        if (virAsprintf(&prompt, _("Enter username for %s [%s]"), hostname,
                        defaultUsername) < 0) {
            return NULL;
        }
    } else {
        if (virAsprintf(&prompt, _("Enter username for %s"), hostname) < 0)
            return NULL;
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_AUTHNAME)
            continue;

        if (!auth->cb) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Missing authentication callback"));
            return NULL;
        }

        cred.type = VIR_CRED_AUTHNAME;
        cred.prompt = prompt;
        cred.challenge = hostname;
        cred.defresult = defaultUsername;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("Username request failed"));
            VIR_FREE(cred.result);
        }

        return cred.result;
    }

    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("Missing VIR_CRED_AUTHNAME credential type"));
    return NULL;
}


char *
virAuthGetUsername(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   const char *servicename,
                   const char *defaultUsername,
                   const char *hostname)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (virAuthGetConfigFilePath(conn, &path) < 0)
        return NULL;

    return virAuthGetUsernamePath(path, auth, servicename,
                                  defaultUsername, hostname);
}


char *
virAuthGetPasswordPath(const char *path,
                       virConnectAuthPtr auth,
                       const char *servicename,
                       const char *username,
                       const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    VIR_AUTOFREE(char *) prompt = NULL;
    char *ret = NULL;

    if (virAuthGetCredential(servicename, hostname, "password", path, &ret) < 0)
        return NULL;
    if (ret != NULL)
        return ret;

    if (!auth) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Missing authentication credentials"));
        return NULL;
    }

    memset(&cred, 0, sizeof(virConnectCredential));

    if (virAsprintf(&prompt, _("Enter %s's password for %s"), username,
                    hostname) < 0) {
        return NULL;
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_PASSPHRASE &&
            auth->credtype[ncred] != VIR_CRED_NOECHOPROMPT) {
            continue;
        }

        if (!auth->cb) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Missing authentication callback"));
            return NULL;
        }

        cred.type = auth->credtype[ncred];
        cred.prompt = prompt;
        cred.challenge = hostname;
        cred.defresult = NULL;
        cred.result = NULL;
        cred.resultlen = 0;

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("Password request failed"));
            VIR_FREE(cred.result);
        }

        return cred.result;
    }

    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("Missing VIR_CRED_PASSPHRASE or VIR_CRED_NOECHOPROMPT "
                     "credential type"));
    return NULL;
}


char *
virAuthGetPassword(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   const char *servicename,
                   const char *username,
                   const char *hostname)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (virAuthGetConfigFilePath(conn, &path) < 0)
        return NULL;

    return virAuthGetPasswordPath(path, auth, servicename, username, hostname);
}
