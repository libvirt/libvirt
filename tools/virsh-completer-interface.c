/*
 * virsh-completer-interface.c: virsh completer callbacks related to interfaces
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

#include "virsh-completer-interface.h"
#include "virsh-util.h"
#include "virsh.h"

typedef const char *
(*virInterfaceStringCallback)(virInterfacePtr iface);

static char **
virshInterfaceStringHelper(vshControl *ctl,
                           const vshCmd *cmd G_GNUC_UNUSED,
                           unsigned int flags,
                           virInterfaceStringCallback cb)
{
    virshControl *priv = ctl->privData;
    virInterfacePtr *ifaces = NULL;
    int nifaces = 0;
    size_t i = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(VIR_CONNECT_LIST_INTERFACES_ACTIVE |
                  VIR_CONNECT_LIST_INTERFACES_INACTIVE,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nifaces = virConnectListAllInterfaces(priv->conn, &ifaces, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, nifaces + 1);

    for (i = 0; i < nifaces; i++) {
        const char *name = (cb)(ifaces[i]);

        tmp[i] = g_strdup(name);
    }

    for (i = 0; i < nifaces; i++)
        virshInterfaceFree(ifaces[i]);
    g_free(ifaces);

    return g_steal_pointer(&tmp);
}


char **
virshInterfaceNameCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags)
{
    return virshInterfaceStringHelper(ctl, cmd, flags, virInterfaceGetName);
}


char **
virshInterfaceMacCompleter(vshControl *ctl,
                           const vshCmd *cmd,
                           unsigned int flags)
{
    return virshInterfaceStringHelper(ctl, cmd, flags,
                                      virInterfaceGetMACString);
}
