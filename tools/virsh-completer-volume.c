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
#include "virsh-util.h"
#include "virsh-pool.h"
#include "virsh.h"
#include "virsh-volume.h"

char **
virshStorageVolNameCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags)
{
    virshControl *priv = ctl->privData;
    g_autoptr(virshStoragePool) pool = NULL;
    virStorageVolPtr *vols = NULL;
    int rc;
    int nvols = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(pool = virshCommandOptPool(ctl, cmd, "pool", NULL)))
        return NULL;

    if ((rc = virStoragePoolListAllVolumes(pool, &vols, flags)) < 0)
        goto cleanup;
    nvols = rc;

    tmp = g_new0(char *, nvols + 1);

    for (i = 0; i < nvols; i++) {
        const char *name = virStorageVolGetName(vols[i]);

        tmp[i] = g_strdup(name);
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < nvols; i++)
        virshStorageVolFree(vols[i]);
    g_free(vols);
    return ret;
}

char **
virshStorageVolKeyCompleter(vshControl *ctl,
                            const vshCmd *cmd G_GNUC_UNUSED,
                            unsigned int flags)
{
    virshControl *priv = ctl->privData;
    struct virshStoragePoolList *list = NULL;
    virStorageVolPtr *vols = NULL;
    int rc;
    int nvols = 0;
    size_t i = 0, j = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    list = virshStoragePoolListCollect(ctl, VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE);
    if (!list)
        goto cleanup;

    for (i = 0; i < list->npools; i++) {
        if ((rc = virStoragePoolListAllVolumes(list->pools[i], &vols, 0)) < 0)
            goto cleanup;

        tmp = g_renew(char *, tmp, nvols + rc + 1);
        memset(&tmp[nvols], 0, sizeof(*tmp) * (rc + 1));

        for (j = 0; j < rc; j++) {
            const char *key = virStorageVolGetKey(vols[j]);
            tmp[nvols] = g_strdup(key);
            nvols++;
            virshStorageVolFree(vols[j]);
        }

        g_free(vols);
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    virshStoragePoolListFree(list);
    return ret;
}

char **
virshStorageVolWipeAlgorithmCompleter(vshControl *ctl G_GNUC_UNUSED,
                                      const vshCmd *cmd G_GNUC_UNUSED,
                                      unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_STORAGE_VOL_WIPE_ALG_LAST,
                             virshStorageVolWipeAlgorithmTypeToString);
}
