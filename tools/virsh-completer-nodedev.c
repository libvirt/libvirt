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
                             const vshCmd *cmd ATTRIBUTE_UNUSED,
                             unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virNodeDevicePtr *devs = NULL;
    int ndevs = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndevs = virConnectListAllNodeDevices(priv->conn, &devs, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, ndevs + 1) < 0)
        goto cleanup;

    for (i = 0; i < ndevs; i++) {
        const char *name = virNodeDeviceGetName(devs[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);

 cleanup:
    for (i = 0; i < ndevs; i++)
        virNodeDeviceFree(devs[i]);
    VIR_FREE(devs);
    return ret;
}


char **
virshNodeDeviceEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                                  const vshCmd *cmd ATTRIBUTE_UNUSED,
                                  unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(tmp, VIR_NODE_DEVICE_EVENT_ID_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_NODE_DEVICE_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virshNodeDeviceEventCallbacks[i].name) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshNodeDeviceCapabilityNameCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags)
{
    VIR_AUTOSTRINGLIST tmp = NULL;
    const char *cap_str = NULL;
    size_t i = 0;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "cap", &cap_str) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, VIR_NODE_DEV_CAP_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_NODE_DEV_CAP_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virNodeDevCapTypeToString(i)) < 0)
            return NULL;
    }

    return virshCommaStringListComplete(cap_str, (const char **)tmp);
}
