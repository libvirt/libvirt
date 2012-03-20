/*
 * virauthconfig.c: authentication config handling
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virauthconfig.h"

#include "virkeyfile.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"


struct _virAuthConfig {
    virKeyFilePtr keyfile;
    char *path;
};

#define VIR_FROM_THIS VIR_FROM_NONE

#define virAuthReportError(code, ...)                                   \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


virAuthConfigPtr virAuthConfigNew(const char *path)
{
    virAuthConfigPtr auth;

    if (VIR_ALLOC(auth) < 0) {
        virReportOOMError();
        goto error;
    }

    if (!(auth->path = strdup(path))) {
        virReportOOMError();
        goto error;
    }

    if (!(auth->keyfile = virKeyFileNew()))
        goto error;

    if (virKeyFileLoadFile(auth->keyfile, path) < 0)
        goto error;

    return auth;

error:
    virAuthConfigFree(auth);
    return NULL;
}


virAuthConfigPtr virAuthConfigNewData(const char *path,
                                      const char *data,
                                      size_t len)
{
    virAuthConfigPtr auth;

    if (VIR_ALLOC(auth) < 0) {
        virReportOOMError();
        goto error;
    }

    if (!(auth->path = strdup(path))) {
        virReportOOMError();
        goto error;
    }

    if (!(auth->keyfile = virKeyFileNew()))
        goto error;

    if (virKeyFileLoadData(auth->keyfile, path, data, len) < 0)
        goto error;

    return auth;

error:
    virAuthConfigFree(auth);
    return NULL;
}


void virAuthConfigFree(virAuthConfigPtr auth)
{
    if (!auth)
        return;

    virKeyFileFree(auth->keyfile);
    VIR_FREE(auth->path);
    VIR_FREE(auth);
}


int virAuthConfigLookup(virAuthConfigPtr auth,
                        const char *service,
                        const char *hostname,
                        const char *credname,
                        const char **value)
{
    char *authgroup = NULL;
    char *credgroup = NULL;
    const char *authcred;
    int ret = -1;

    *value = NULL;

    VIR_DEBUG("Lookup '%s' '%s' '%s'", service, NULLSTR(hostname), credname);

    if (!hostname)
        hostname = "localhost";

    if (virAsprintf(&authgroup, "auth-%s-%s", service, hostname) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!virKeyFileHasGroup(auth->keyfile, authgroup)) {
        ret = 0;
        goto cleanup;
    }

    if (!(authcred = virKeyFileGetValueString(auth->keyfile, authgroup, "credentials"))) {
        virAuthReportError(VIR_ERR_CONF_SYNTAX,
                           _("Missing item 'credentials' in group '%s' in '%s'"),
                           authgroup, auth->path);
        goto cleanup;
    }

    if (virAsprintf(&credgroup, "credentials-%s", authcred) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!virKeyFileHasGroup(auth->keyfile, credgroup)) {
        virAuthReportError(VIR_ERR_CONF_SYNTAX,
                           _("Missing group 'credentials-%s' referenced from group '%s' in '%s'"),
                           authcred, authgroup, auth->path);
        goto cleanup;
    }

    if (!virKeyFileHasValue(auth->keyfile, credgroup, credname)) {
        ret = 0;
        goto cleanup;
    }

    *value = virKeyFileGetValueString(auth->keyfile, credgroup, credname);

    ret = 0;

cleanup:
    VIR_FREE(authgroup);
    VIR_FREE(credgroup);
    return ret;
}
