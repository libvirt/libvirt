/*
 * virsh-completer-nwfilter.c: virsh completer callbacks related to nwfilters
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "virsh-completer-nwfilter.h"
#include "viralloc.h"
#include "virsh.h"
#include "virstring.h"

char **
virshNWFilterNameCompleter(vshControl *ctl,
                           const vshCmd *cmd G_GNUC_UNUSED,
                           unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNWFilterPtr *nwfilters = NULL;
    int nnwfilters = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nnwfilters = virConnectListAllNWFilters(priv->conn, &nwfilters, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, nnwfilters + 1) < 0)
        goto cleanup;

    for (i = 0; i < nnwfilters; i++) {
        const char *name = virNWFilterGetName(nwfilters[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < nnwfilters; i++)
        virNWFilterFree(nwfilters[i]);
    VIR_FREE(nwfilters);
    return ret;
}


char **
virshNWFilterBindingNameCompleter(vshControl *ctl,
                                  const vshCmd *cmd G_GNUC_UNUSED,
                                  unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNWFilterBindingPtr *bindings = NULL;
    int nbindings = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nbindings = virConnectListAllNWFilterBindings(priv->conn, &bindings, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, nbindings + 1) < 0)
        goto cleanup;

    for (i = 0; i < nbindings; i++) {
        const char *name = virNWFilterBindingGetPortDev(bindings[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < nbindings; i++)
        virNWFilterBindingFree(bindings[i]);
    VIR_FREE(bindings);
    return ret;
}
