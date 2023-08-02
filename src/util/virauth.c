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
#include "viralloc.h"
#include "virutil.h"
#include "virlog.h"
#include "datatypes.h"
#include "virerror.h"
#include "configmake.h"
#include "virauthconfig.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_AUTH

VIR_LOG_INIT("util.auth");

int
virAuthGetConfigFilePathURI(virURI *uri,
                            char **path)
{
    size_t i;
    const char *authenv = getenv("LIBVIRT_AUTH_FILE");
    g_autofree char *userdir = NULL;

    *path = NULL;

    VIR_DEBUG("Determining auth config file path");

    if (authenv) {
        VIR_DEBUG("Using path from env '%s'", authenv);
        *path = g_strdup(authenv);
        return 0;
    }

    if (uri) {
        for (i = 0; i < uri->paramsCount; i++) {
            if (STREQ_NULLABLE(uri->params[i].name, "authfile") &&
                uri->params[i].value) {
                VIR_DEBUG("Using path from URI '%s'", uri->params[i].value);
                *path = g_strdup(uri->params[i].value);
                return 0;
            }
        }
    }

    userdir = virGetUserConfigDirectory();

    *path = g_strdup_printf("%s/auth.conf", userdir);

    VIR_DEBUG("Checking for readability of '%s'", *path);
    if (access(*path, R_OK) == 0)
        goto done;

    VIR_FREE(*path);

    *path = g_strdup(SYSCONFDIR "/libvirt/auth.conf");

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


int
virAuthGetCredential(const char *servicename,
                     const char *hostname,
                     const char *credname,
                     const char *path,
                     char **value)
{
    g_autoptr(virAuthConfig) config = NULL;

    *value = NULL;

    if (path == NULL)
        return 0;

    if (!(config = virAuthConfigNew(path)))
        return -1;

    if (virAuthConfigLookup(config,
                            servicename,
                            hostname,
                            credname,
                            value) < 0)
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
    virConnectCredential cred = { 0 };
    g_autofree char *prompt = NULL;
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

    if (defaultUsername != NULL) {
        prompt = g_strdup_printf(_("Enter username for %1$s [%2$s]"), hostname,
                                 defaultUsername);
    } else {
        prompt = g_strdup_printf(_("Enter username for %1$s"), hostname);
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

        if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0 ||
            !cred.result) {
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
    g_autofree char *path = NULL;

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
    g_autoptr(virConnectCredential) cred = NULL;
    g_autofree char *prompt = NULL;
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

    prompt = g_strdup_printf(_("Enter %1$s's password for %2$s"), username, hostname);

    if (!(cred = virAuthAskCredential(auth, prompt, false)))
        return NULL;

    return g_steal_pointer(&cred->result);
}


char *
virAuthGetPassword(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   const char *servicename,
                   const char *username,
                   const char *hostname)
{
    g_autofree char *path = NULL;

    if (virAuthGetConfigFilePath(conn, &path) < 0)
        return NULL;

    return virAuthGetPasswordPath(path, auth, servicename, username, hostname);
}


void
virAuthConnectCredentialFree(virConnectCredential *cred)
{
    if (cred->result) {
        virSecureErase(cred->result, cred->resultlen);
        g_free(cred->result);
    }
    g_free(cred);
}


/**
 * virAuthAskCredential:
 * @auth: authentication callback data
 * @prompt: question string to ask the user
 * @echo: false if user's reply should be considered sensitive and not echoed
 *
 * Invoke the authentication callback for the connection @auth and ask the user
 * the question in @prompt. If @echo is false user's reply should be collected
 * as sensitive (user's input not printed on screen).
 */
virConnectCredential *
virAuthAskCredential(virConnectAuthPtr auth,
                     const char *prompt,
                     bool echo)
{
    g_autoptr(virConnectCredential) ret = g_new0(virConnectCredential, 1);
    size_t i;

    ret->type = -1;

    for (i = 0; i < auth->ncredtype; ++i) {
        int type = auth->credtype[i];
        if (echo) {
            if (type == VIR_CRED_ECHOPROMPT) {
                ret->type = type;
                break;
            }
        } else {
            if (type == VIR_CRED_PASSPHRASE ||
                type == VIR_CRED_NOECHOPROMPT) {
                ret->type = type;
                break;
            }
        }
    }

    if (ret->type == -1) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("no suitable callback authentication callback was found"));
        return NULL;
    }

    ret->prompt = prompt;

    if (auth->cb(ret, 1, auth->cbdata) < 0 ||
        !ret->result) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("failed to retrieve user response for authentication callback"));
        return NULL;
    }

    return g_steal_pointer(&ret);
}
