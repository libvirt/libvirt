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
#include "virsh-util.h"
#include "conf/storage_conf.h"
#include "virsh-pool.h"
#include "virsh.h"

char **
virshStoragePoolNameCompleter(vshControl *ctl,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    virshControl *priv = ctl->privData;
    virStoragePoolPtr *pools = NULL;
    int npools = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE |
                  VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((npools = virConnectListAllStoragePools(priv->conn, &pools, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, npools + 1);

    for (i = 0; i < npools; i++) {
        const char *name = virStoragePoolGetName(pools[i]);

        tmp[i] = g_strdup(name);
    }

    ret = g_steal_pointer(&tmp);

    for (i = 0; i < npools; i++)
        virshStoragePoolFree(pools[i]);
    g_free(pools);
    return ret;
}


char **
virshPoolEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                            const vshCmd *cmd G_GNUC_UNUSED,
                            unsigned int flags)
{
    size_t i = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    tmp = g_new0(char *, VIR_STORAGE_POOL_EVENT_ID_LAST + 1);

    for (i = 0; i < VIR_STORAGE_POOL_EVENT_ID_LAST; i++)
        tmp[i] = g_strdup(virshPoolEventCallbacks[i].name);

    return g_steal_pointer(&tmp);
}


char **
virshPoolTypeCompleter(vshControl *ctl,
                       const vshCmd *cmd,
                       unsigned int flags)
{
    g_auto(GStrv) tmp = NULL;
    const char *type_str = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "type", &type_str) < 0)
        return NULL;

    tmp = virshEnumComplete(VIR_STORAGE_POOL_LAST,
                            virStoragePoolTypeToString);

    return virshCommaStringListComplete(type_str, (const char **)tmp);
}
