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
#include "virxml.h"


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


char **
virshDomainInterfaceCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ninterfaces;
    xmlNodePtr *interfaces = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    char **ret = NULL;

    virCheckFlags(VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (vshCommandOptBool(cmd, "config"))
        domainXMLFlags = VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXML(ctl, cmd, domainXMLFlags, &xmldoc, &ctxt) < 0)
        goto error;

    ninterfaces = virXPathNodeSet("./devices/interface", ctxt, &interfaces);
    if (ninterfaces < 0)
        goto error;

    if (VIR_ALLOC_N(ret, ninterfaces + 1) < 0)
        goto error;

    for (i = 0; i < ninterfaces; i++) {
        ctxt->node = interfaces[i];

        if (!(flags & VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC) &&
            (ret[i] = virXPathString("string(./target/@dev)", ctxt)))
            continue;

        /* In case we are dealing with inactive domain XML there's no
         * <target dev=''/>. Offer MAC addresses then. */
        if (!(ret[i] = virXPathString("string(./mac/@address)", ctxt)))
            goto error;
    }

    VIR_FREE(interfaces);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;

 error:
    VIR_FREE(interfaces);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    virStringListFree(ret);
    return NULL;
}
