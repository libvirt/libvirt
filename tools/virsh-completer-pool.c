/*
 * virsh-completer-pool.c: virsh completer callbacks related to pools
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

#include "virsh-completer-pool.h"
#include "conf/storage_conf.h"
#include "viralloc.h"
#include "virsh-pool.h"
#include "virsh.h"
#include "virstring.h"

char **
virshStoragePoolNameCompleter(vshControl *ctl,
                              const vshCmd *cmd ATTRIBUTE_UNUSED,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virStoragePoolPtr *pools = NULL;
    int npools = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((npools = virConnectListAllStoragePools(priv->conn, &pools, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, npools + 1) < 0)
        goto cleanup;

    for (i = 0; i < npools; i++) {
        const char *name = virStoragePoolGetName(pools[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);

 cleanup:
    for (i = 0; i < npools; i++)
        virStoragePoolFree(pools[i]);
    VIR_FREE(pools);
    return ret;
}


char **
virshPoolEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                            const vshCmd *cmd ATTRIBUTE_UNUSED,
                            unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(tmp, VIR_STORAGE_POOL_EVENT_ID_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_STORAGE_POOL_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virshPoolEventCallbacks[i].name) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshPoolTypeCompleter(vshControl *ctl,
                       const vshCmd *cmd,
                       unsigned int flags)
{
    VIR_AUTOSTRINGLIST tmp = NULL;
    const char *type_str = NULL;
    size_t i = 0;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "type", &type_str) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, VIR_STORAGE_POOL_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_STORAGE_POOL_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virStoragePoolTypeToString(i)) < 0)
            return NULL;
    }

    return virshCommaStringListComplete(type_str, (const char **)tmp);
}
