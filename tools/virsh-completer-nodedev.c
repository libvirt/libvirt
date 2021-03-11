/*
 * virsh-completer-nodedev.c: virsh completer callbacks related to nodedev
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

#include "virsh-completer-nodedev.h"
#include "conf/node_device_conf.h"
#include "viralloc.h"
#include "virsh-nodedev.h"
#include "virsh.h"
#include "virstring.h"

char **
virshNodeDeviceNameCompleter(vshControl *ctl,
                             const vshCmd *cmd G_GNUC_UNUSED,
                             unsigned int flags)
{
    virshControl *priv = ctl->privData;
    virNodeDevicePtr *devs = NULL;
    int ndevs = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndevs = virConnectListAllNodeDevices(priv->conn, &devs, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, ndevs + 1);

    for (i = 0; i < ndevs; i++) {
        const char *name = virNodeDeviceGetName(devs[i]);

        tmp[i] = g_strdup(name);
    }

    ret = g_steal_pointer(&tmp);

    for (i = 0; i < ndevs; i++)
        virNodeDeviceFree(devs[i]);
    g_free(devs);
    return ret;
}


char **
virshNodeDeviceEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                                  const vshCmd *cmd G_GNUC_UNUSED,
                                  unsigned int flags)
{
    size_t i = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    tmp = g_new0(char *, VIR_NODE_DEVICE_EVENT_ID_LAST + 1);

    for (i = 0; i < VIR_NODE_DEVICE_EVENT_ID_LAST; i++)
        tmp[i] = g_strdup(virshNodeDeviceEventCallbacks[i].name);

    return g_steal_pointer(&tmp);
}


char **
virshNodeDeviceCapabilityNameCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags)
{
    g_auto(GStrv) tmp = NULL;
    const char *cap_str = NULL;
    size_t i = 0;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "cap", &cap_str) < 0)
        return NULL;

    tmp = g_new0(char *, VIR_NODE_DEV_CAP_LAST + 1);

    for (i = 0; i < VIR_NODE_DEV_CAP_LAST; i++)
        tmp[i] = g_strdup(virNodeDevCapTypeToString(i));

    return virshCommaStringListComplete(cap_str, (const char **)tmp);
}
