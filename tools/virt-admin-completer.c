/*
 * virt-admin-completer.c: virt-admin completer callbacks
 *
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "virt-admin-completer.h"
#include "internal.h"
#include "virt-admin.h"
#include "viralloc.h"
#include "virstring.h"


char **
vshAdmServerCompleter(vshControl *ctl,
                      const vshCmd *cmd G_GNUC_UNUSED,
                      unsigned int flags)
{
    vshAdmControlPtr priv = ctl->privData;
    virAdmServerPtr *srvs = NULL;
    int nsrvs = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virAdmConnectIsAlive(priv->conn) <= 0)
        return NULL;

    /* Obtain a list of available servers on the daemon */
    if ((nsrvs = virAdmConnectListServers(priv->conn, &srvs, 0)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nsrvs + 1) < 0)
        goto error;

    for (i = 0; i < nsrvs; i++) {
        const char *name = virAdmServerGetName(srvs[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virAdmServerFree(srvs[i]);
    }
    VIR_FREE(srvs);

    return ret;

 error:
    for (; i < nsrvs; i++)
        virAdmServerFree(srvs[i]);
    VIR_FREE(srvs);
    for (i = 0; i < nsrvs; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return ret;
}
