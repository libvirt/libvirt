/*
 * virauth.c: authentication related utility functions
 *
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <stdlib.h>

#include "virauth.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "configmake.h"
#include "virauthconfig.h"

#define VIR_FROM_THIS VIR_FROM_AUTH


int virAuthGetConfigFilePath(virConnectPtr conn,
                             char **path)
{
    int ret = -1;
    size_t i;
    const char *authenv = getenv("LIBVIRT_AUTH_FILE");
    char *userdir = NULL;

    *path = NULL;

    VIR_DEBUG("Determining auth config file path");

    if (authenv) {
        VIR_DEBUG("Using path from env '%s'", authenv);
        if (!(*path = strdup(authenv)))
            goto no_memory;
        return 0;
    }

    for (i = 0 ; i < conn->uri->paramsCount ; i++) {
        if (STREQ_NULLABLE(conn->uri->params[i].name, "authfile") &&
            conn->uri->params[i].value) {
            VIR_DEBUG("Using path from URI '%s'",
                      conn->uri->params[i].value);
            if (!(*path = strdup(conn->uri->params[i].value)))
                goto no_memory;
            return 0;
        }
    }

    if (!(userdir = virGetUserDirectory(geteuid())))
        goto cleanup;

    if (virAsprintf(path, "%s/.libvirt/auth.conf", userdir) < 0)
        goto no_memory;

    VIR_DEBUG("Checking for readability of '%s'", *path);
    if (access(*path, R_OK) == 0)
        goto done;

    VIR_FREE(*path);

    if (!(*path = strdup(SYSCONFDIR "/libvirt/auth.conf")))
        goto no_memory;

    VIR_DEBUG("Checking for readability of '%s'", *path);
    if (access(*path, R_OK) == 0)
        goto done;

    VIR_FREE(*path);

done:
    ret = 0;

    VIR_DEBUG("Using auth file '%s'", NULLSTR(*path));
cleanup:
    VIR_FREE(userdir);

    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}


static int
virAuthGetCredential(virConnectPtr conn,
                     const char *servicename,
                     const char *credname,
                     char **value)
{
    int ret = -1;
    char *path = NULL;
    virAuthConfigPtr config = NULL;
    const char *tmp;

    *value = NULL;

    if (virAuthGetConfigFilePath(conn, &path) < 0)
        goto cleanup;

    if (path == NULL) {
        ret = 0;
        goto cleanup;
    }

    if (!(config = virAuthConfigNew(path)))
        goto cleanup;

    if (virAuthConfigLookup(config,
                            servicename,
                            conn->uri->server,
                            credname,
                            &tmp) < 0)
        goto cleanup;

    if (tmp &&
        !(*value = strdup(tmp))) {
        virReportOOMError();
        goto cleanup;
    }

    ret = 0;

cleanup:
    virAuthConfigFree(config);
    VIR_FREE(path);
    return ret;
}


char *
virAuthGetUsername(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   const char *servicename,
                   const char *defaultUsername,
                   const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt;
    char *ret = NULL;

    if (virAuthGetCredential(conn, servicename, "username", &ret) < 0)
        return NULL;
    if (ret != NULL)
        return ret;

    memset(&cred, 0, sizeof(virConnectCredential));

    if (defaultUsername != NULL) {
        if (virAsprintf(&prompt, _("Enter username for %s [%s]"), hostname,
                        defaultUsername) < 0) {
            return NULL;
        }
    } else {
        if (virAsprintf(&prompt, _("Enter username for %s"), hostname) < 0) {
            return NULL;
        }
    }

    for (ncred = 0; ncred < auth->ncredtype; ncred++) {
        if (auth->credtype[ncred] != VIR_CRED_AUTHNAME) {
            continue;
        }

        cred.type = VIR_CRED_AUTHNAME;
        cred.prompt = prompt;
        cred.challenge = hostname;
        cred.defresult = defaultUsername;
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
virAuthGetPassword(virConnectPtr conn,
                   virConnectAuthPtr auth,
                   const char *servicename,
                   const char *username,
                   const char *hostname)
{
    unsigned int ncred;
    virConnectCredential cred;
    char *prompt;
    char *ret = NULL;

    if (virAuthGetCredential(conn, servicename, "password", &ret) < 0)
        return NULL;
    if (ret != NULL)
        return ret;

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

        cred.type = auth->credtype[ncred];
        cred.prompt = prompt;
        cred.challenge = hostname;
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
