/*
 * virsh-completer-domain.c: virsh completer callbacks related to domains
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

#include "virsh-completer-domain.h"
#include "viralloc.h"
#include "virmacaddr.h"
#include "virsh-domain.h"
#include "virsh-util.h"
#include "virsh.h"
#include "virstring.h"
#include "virxml.h"

char **
virshDomainNameCompleter(vshControl *ctl,
                         const vshCmd *cmd G_GNUC_UNUSED,
                         unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    virDomainPtr *domains = NULL;
    int ndomains = 0;
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_ACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_INACTIVE |
                  VIR_CONNECT_LIST_DOMAINS_OTHER |
                  VIR_CONNECT_LIST_DOMAINS_PAUSED |
                  VIR_CONNECT_LIST_DOMAINS_PERSISTENT |
                  VIR_CONNECT_LIST_DOMAINS_RUNNING |
                  VIR_CONNECT_LIST_DOMAINS_SHUTOFF,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndomains = virConnectListAllDomains(priv->conn, &domains, flags)) < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, ndomains + 1) < 0)
        goto cleanup;

    for (i = 0; i < ndomains; i++) {
        const char *name = virDomainGetName(domains[i]);

        if (VIR_STRDUP(tmp[i], name) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, tmp);

 cleanup:
    for (i = 0; i < ndomains; i++)
        virshDomainFree(domains[i]);
    VIR_FREE(domains);
    return ret;
}


char **
virshDomainInterfaceCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    VIR_AUTOPTR(xmlDoc) xmldoc = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    int ninterfaces;
    g_autofree xmlNodePtr *interfaces = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (vshCommandOptBool(cmd, "config"))
        domainXMLFlags = VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXML(ctl, cmd, domainXMLFlags, &xmldoc, &ctxt) < 0)
        return NULL;

    ninterfaces = virXPathNodeSet("./devices/interface", ctxt, &interfaces);
    if (ninterfaces < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, ninterfaces + 1) < 0)
        return NULL;

    for (i = 0; i < ninterfaces; i++) {
        ctxt->node = interfaces[i];

        if (!(flags & VIRSH_DOMAIN_INTERFACE_COMPLETER_MAC) &&
            (tmp[i] = virXPathString("string(./target/@dev)", ctxt)))
            continue;

        /* In case we are dealing with inactive domain XML there's no
         * <target dev=''/>. Offer MAC addresses then. */
        if (!(tmp[i] = virXPathString("string(./mac/@address)", ctxt)))
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshDomainDiskTargetCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    VIR_AUTOPTR(xmlDoc) xmldoc = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *disks = NULL;
    int ndisks;
    size_t i;
    VIR_AUTOSTRINGLIST tmp = NULL;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xmldoc, &ctxt) < 0)
        return NULL;

    ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks);
    if (ndisks < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, ndisks + 1) < 0)
        return NULL;

    for (i = 0; i < ndisks; i++) {
        ctxt->node = disks[i];
        if (!(tmp[i] = virXPathString("string(./target/@dev)", ctxt)))
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshDomainEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    size_t i = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (VIR_ALLOC_N(tmp, VIR_DOMAIN_EVENT_ID_LAST + 1) < 0)
        return NULL;

    for (i = 0; i < VIR_DOMAIN_EVENT_ID_LAST; i++) {
        if (VIR_STRDUP(tmp[i], virshDomainEventCallbacks[i].name) < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshDomainInterfaceStateCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    const char *iface = NULL;
    char **ret = NULL;
    VIR_AUTOPTR(xmlDoc) xml = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    virMacAddr macaddr;
    char macstr[VIR_MAC_STRING_BUFLEN] = "";
    int ninterfaces;
    g_autofree xmlNodePtr *interfaces = NULL;
    g_autofree char *xpath = NULL;
    g_autofree char *state = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, flags, &xml, &ctxt) < 0)
        return NULL;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &iface) < 0)
        return NULL;

    /* normalize the mac addr */
    if (virMacAddrParse(iface, &macaddr) == 0)
        virMacAddrFormat(&macaddr, macstr);

    if (virAsprintf(&xpath, "/domain/devices/interface[(mac/@address = '%s') or "
                            "                          (target/@dev = '%s')]",
                           macstr, iface) < 0)
        return NULL;

    if ((ninterfaces = virXPathNodeSet(xpath, ctxt, &interfaces)) < 0)
        return NULL;

    if (ninterfaces != 1)
        return NULL;

    ctxt->node = interfaces[0];

    if (VIR_ALLOC_N(tmp, 2) < 0)
        return NULL;

    if ((state = virXPathString("string(./link/@state)", ctxt)) &&
        STREQ(state, "down")) {
        if (VIR_STRDUP(tmp[0], "up") < 0)
            return NULL;
    } else {
        if (VIR_STRDUP(tmp[0], "down") < 0)
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshDomainDeviceAliasCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    VIR_AUTOPTR(xmlDoc) xmldoc = NULL;
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    int naliases;
    g_autofree xmlNodePtr *aliases = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (vshCommandOptBool(cmd, "config"))
        domainXMLFlags = VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXML(ctl, cmd, domainXMLFlags, &xmldoc, &ctxt) < 0)
        return NULL;

    naliases = virXPathNodeSet("./devices//alias/@name", ctxt, &aliases);
    if (naliases < 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, naliases + 1) < 0)
        return NULL;

    for (i = 0; i < naliases; i++) {
        if (!(tmp[i] = virXMLNodeContentString(aliases[i])))
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshDomainShutdownModeCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int flags)
{
    const char *modes[] = {"acpi", "agent", "initctl", "signal", "paravirt", NULL};
    const char *mode = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "mode", &mode) < 0)
        return NULL;

    return virshCommaStringListComplete(mode, modes);
}
