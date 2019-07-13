/*
 * virsh-completer-volume.c: virsh completer callbacks related to volumes
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

#include "virsh-completer-volume.h"
#include "viralloc.h"
#include "virsh-pool.h"
#include "virsh.h"
#include "virstring.h"

char **
virshStorageVolNameCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr *vols = NULL;
    int rc;
    int nvols = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return NULL;

    if ((rc = virStoragePoolListAllVolumes(pool, &vols, flags)) < 0)
        goto cleanup;
    nvols = rc;

    if (VIR_ALLOC_N(tmp, nvols + 1) < 0)
        goto cleanup;

    for (i = 0; i < nvols; i++) {
        const char *name = virStorageVolGetName(vols[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);

 cleanup:
    virStoragePoolFree(pool);
    for (i = 0; i < nvols; i++)
        virStorageVolFree(vols[i]);
    VIR_FREE(vols);
    return ret;
}
