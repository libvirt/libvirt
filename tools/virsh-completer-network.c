/*
 * virsh-completer-network.c: virsh completer callbacks related to networks
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

#include "virsh-completer-network.h"
#include "viralloc.h"
#include "virsh-network.h"
#include "virsh.h"
#include "virstring.h"

char **
virshNetworkNameCompleter(vshControl *ctl,
                          const vshCmd *cmd G_GNUC_UNUSED,
                          unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNetworkPtr *nets = NULL;
    int nnets = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_INACTIVE |
                  VIR_CONNECT_LIST_NETWORKS_ACTIVE |
                  VIR_CONNECT_LIST_NETWORKS_PERSISTENT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nnets = virConnectListAllNetworks(priv->conn, &nets, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, nnets + 1) < 0)
        goto cleanup;

    for (i = 0; i < nnets; i++) {
        const char *name = virNetworkGetName(nets[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < nnets; i++)
        virNetworkFree(nets[i]);
    VIR_FREE(nets);
    return ret;
}


char **
virshNetworkEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                               const vshCmd *cmd G_GNUC_UNUSED,
                               unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(tmp, VIR_NETWORK_EVENT_ID_LAST + 1) < 0)
        goto cleanup;

    for (i = 0; i < VIR_NETWORK_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virshNetworkEventCallbacks[i].name) < 0)
            goto cleanup;
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    return ret;
}


char **
virshNetworkPortUUIDCompleter(vshControl *ctl,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNetworkPtr net = NULL;
    virNetworkPortPtr *ports = NULL;
    int nports = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(net = virshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    if ((nports = virNetworkListAllPorts(net, &ports, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, nports + 1) < 0)
        goto error;

    for (i = 0; i < nports; i++) {
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virNetworkPortGetUUIDString(ports[i], uuid) < 0 ||
            VIR_STRDUP(ret[i], uuid) < 0)
            goto error;

        virNetworkPortFree(ports[i]);
    }
    VIR_FREE(ports);

    return ret;

 error:
    for (; i < nports; i++)
        virNetworkPortFree(ports[i]);
    VIR_FREE(ports);
    for (i = 0; i < nports; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}
