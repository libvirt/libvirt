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
#include "viralloc.h"
#include "virsh-secret.h"
#include "virsh.h"
#include "virstring.h"

char **
virshSecretUUIDCompleter(vshControl *ctl,
                         const vshCmd *cmd ATTRIBUTE_UNUSED,
                         unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virSecretPtr *secrets = NULL;
    int nsecrets = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((nsecrets = virConnectListAllSecrets(priv->conn, &secrets, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, nsecrets + 1) < 0)
        goto cleanup;

    for (i = 0; i < nsecrets; i++) {
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virSecretGetUUIDString(secrets[i], uuid) < 0 ||
            VIR_STRDUP(tmp[i], uuid) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);

 cleanup:
    for (i = 0; i < nsecrets; i++)
        virSecretFree(secrets[i]);
    VIR_FREE(secrets);
    return ret;
}


char **
virshSecretEventNameCompleter(vshControl *ctl ATTRIBUTE_UNUSED,
                              const vshCmd *cmd ATTRIBUTE_UNUSED,
                              unsigned int flags)
{
    size_t i;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(tmp, VIR_SECRET_EVENT_ID_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_SECRET_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virshSecretEventCallbacks[i].name) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}
