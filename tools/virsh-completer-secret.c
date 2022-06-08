/*
 * virsh-completer-secret.c: virsh completer callbacks related to secret
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

#include "virsh-completer-secret.h"
#include "virsh-secret.h"
#include "virsh-util.h"
#include "virsh.h"

char **
virshSecretUUIDCompleter(vshControl *ctl,
                         const vshCmd *cmd G_GNUC_UNUSED,
                         unsigned int flags)
{
    virshControl *priv = ctl->privData;
    virSecretPtr *secrets = NULL;
    int nsecrets = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nsecrets = virConnectListAllSecrets(priv->conn, &secrets, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, nsecrets + 1);

    for (i = 0; i < nsecrets; i++) {
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virSecretGetUUIDString(secrets[i], uuid) < 0)
            goto cleanup;
        tmp[i] = g_strdup(uuid);
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < nsecrets; i++)
        virshSecretFree(secrets[i]);
    g_free(secrets);
    return ret;
}


char **
virshSecretEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    size_t i;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    tmp = g_new0(char *, VIR_SECRET_EVENT_ID_LAST + 1);

    for (i = 0; i < VIR_SECRET_EVENT_ID_LAST; i++)
        tmp[i] = g_strdup(virshSecretEventCallbacks[i].name);

    return g_steal_pointer(&tmp);
}
