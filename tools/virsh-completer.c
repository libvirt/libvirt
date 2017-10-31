/*
 * virsh-completer.c: virsh completer callbacks
 *
 * Copyright (C) 2017 Red Hat, Inc.
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
 *
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "virsh-completer.h"
#include "virsh.h"
#include "virsh-util.h"
#include "internal.h"
#include "viralloc.h"
#include "virstring.h"


char **
virshDomainNameCompleter(vshControl *ctl,
                         const vshCmd *cmd ATTRIBUTE_UNUSED,
                         unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virDomainPtr *domains = NULL;
    int ndomains = 0;
    size_t i = 0;
    char **ret = NULL;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_ACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_INACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_PERSISTENT |
                  VIR_CONNECT_LIST_DOMAINS_TRANSIENT |
                  VIR_CONNECT_LIST_DOMAINS_RUNNING |
                  VIR_CONNECT_LIST_DOMAINS_PAUSED |
                  VIR_CONNECT_LIST_DOMAINS_SHUTOFF |
                  VIR_CONNECT_LIST_DOMAINS_OTHER |
                  VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE |
                  VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE |
                  VIR_CONNECT_LIST_DOMAINS_AUTOSTART |
                  VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART |
                  VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT |
                  VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndomains = virConnectListAllDomains(priv->conn, &domains, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret, ndomains + 1) < 0)
        goto error;

    for (i = 0; i < ndomains; i++) {
        const char *name = virDomainGetName(domains[i]);

        if (VIR_STRDUP(ret[i], name) < 0)
            goto error;

        virshDomainFree(domains[i]);
    }
    VIR_FREE(domains);

    return ret;

 error:
    for (; i < ndomains; i++)
        virshDomainFree(domains[i]);
    VIR_FREE(domains);
    for (i = 0; i < ndomains; i++)
        VIR_FREE(ret[i]);
    VIR_FREE(ret);
    return NULL;
}
