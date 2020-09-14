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
#include "virsh-domain-monitor.h"
#include "virsh-util.h"
#include "virsh.h"
#include "virstring.h"
#include "virxml.h"
#include "virperf.h"

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
                  VIR_CONNECT_LIST_DOMAINS_SHUTOFF |
                  VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE |
                  VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT |
                  VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndomains = virConnectListAllDomains(priv->conn, &domains, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, ndomains + 1);

    for (i = 0; i < ndomains; i++) {
        const char *name = virDomainGetName(domains[i]);

        tmp[i] = g_strdup(name);
    }

    ret = g_steal_pointer(&tmp);

    for (i = 0; i < ndomains; i++)
        virshDomainFree(domains[i]);
    g_free(domains);
    return ret;
}


char **
virshDomainUUIDCompleter(vshControl *ctl,
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
                  VIR_CONNECT_LIST_DOMAINS_SHUTOFF |
                  VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE |
                  VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT |
                  VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT,
                  NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if ((ndomains = virConnectListAllDomains(priv->conn, &domains, flags)) < 0)
        return NULL;

    tmp = g_new0(char *, ndomains + 1);

    for (i = 0; i < ndomains; i++) {
        char uuid[VIR_UUID_STRING_BUFLEN];

        if (virDomainGetUUIDString(domains[i], uuid) < 0)
            goto cleanup;

        tmp[i] = g_strdup(uuid);
    }

    ret = g_steal_pointer(&tmp);

 cleanup:
    for (i = 0; i < ndomains; i++)
        virshDomainFree(domains[i]);
    g_free(domains);
    return ret;
}


char **
virshDomainInterfaceCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int ninterfaces;
    g_autofree xmlNodePtr *interfaces = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
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

    tmp = g_new0(char *, ninterfaces + 1);

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

    return g_steal_pointer(&tmp);
}


char **
virshDomainDiskTargetCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *disks = NULL;
    int ndisks;
    size_t i;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xmldoc, &ctxt) < 0)
        return NULL;

    ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks);
    if (ndisks < 0)
        return NULL;

    tmp = g_new0(char *, ndisks + 1);

    for (i = 0; i < ndisks; i++) {
        ctxt->node = disks[i];
        if (!(tmp[i] = virXPathString("string(./target/@dev)", ctxt)))
            return NULL;
    }

    return g_steal_pointer(&tmp);
}


char **
virshDomainEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    size_t i = 0;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    tmp = g_new0(char *, VIR_DOMAIN_EVENT_ID_LAST + 1);

    for (i = 0; i < VIR_DOMAIN_EVENT_ID_LAST; i++)
        tmp[i] = g_strdup(virshDomainEventCallbacks[i].name);

    return g_steal_pointer(&tmp);
}


char **
virshDomainInterfaceStateCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    const char *iface = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
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

    xpath = g_strdup_printf("/domain/devices/interface[(mac/@address = '%s') or "
                            "                          (target/@dev = '%s')]", macstr,
                            iface);

    if ((ninterfaces = virXPathNodeSet(xpath, ctxt, &interfaces)) < 0)
        return NULL;

    if (ninterfaces != 1)
        return NULL;

    ctxt->node = interfaces[0];

    tmp = g_new0(char *, 2);

    if ((state = virXPathString("string(./link/@state)", ctxt)) &&
        STREQ(state, "down")) {
        tmp[0] = g_strdup("up");
    } else {
        tmp[0] = g_strdup("down");
    }

    return g_steal_pointer(&tmp);
}


char **
virshDomainDeviceAliasCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int naliases;
    g_autofree xmlNodePtr *aliases = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
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

    tmp = g_new0(char *, naliases + 1);

    for (i = 0; i < naliases; i++) {
        if (!(tmp[i] = virXMLNodeContentString(aliases[i])))
            return NULL;
    }

    return g_steal_pointer(&tmp);
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


char **
virshDomainInterfaceAddrSourceCompleter(vshControl *ctl G_GNUC_UNUSED,
                                        const vshCmd *cmd G_GNUC_UNUSED,
                                        unsigned int flags)
{
    char **ret = NULL;
    size_t i;

    virCheckFlags(0, NULL);

    ret = g_new0(typeof(*ret), VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LAST + 1);

    for (i = 0; i < VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LAST; i++)
        ret[i] = g_strdup(virshDomainInterfaceAddressesSourceTypeToString(i));

    return ret;
}


char **
virshDomainHostnameSourceCompleter(vshControl *ctl G_GNUC_UNUSED,
                                   const vshCmd *cmd G_GNUC_UNUSED,
                                   unsigned int flags)
{
    char **ret = NULL;
    size_t i;

    virCheckFlags(0, NULL);

    ret = g_new0(typeof(*ret), VIRSH_DOMAIN_HOSTNAME_SOURCE_LAST + 1);

    for (i = 0; i < VIRSH_DOMAIN_HOSTNAME_SOURCE_LAST; i++)
        ret[i] = g_strdup(virshDomainHostnameSourceTypeToString(i));

    return ret;
}


char **
virshDomainPerfEnableCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    size_t i = 0;
    VIR_AUTOSTRINGLIST events = NULL;
    const char *event = NULL;

    virCheckFlags(0, NULL);

    events = g_new0(char *, VIR_PERF_EVENT_LAST + 1);

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++)
        events[i] = g_strdup(virPerfEventTypeToString(i));

    if (vshCommandOptStringQuiet(ctl, cmd, "enable", &event) < 0)
        return NULL;

    return virshCommaStringListComplete(event, (const char **)events);
}


char **
virshDomainPerfDisableCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags)
{
    size_t i = 0;
    VIR_AUTOSTRINGLIST events = NULL;
    const char *event = NULL;

    virCheckFlags(0, NULL);

    events = g_new0(char *, VIR_PERF_EVENT_LAST + 1);

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++)
        events[i] = g_strdup(virPerfEventTypeToString(i));

    if (vshCommandOptStringQuiet(ctl, cmd, "disable", &event) < 0)
        return NULL;

    return virshCommaStringListComplete(event, (const char **)events);
}


char **
virshDomainIOThreadIdCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags)
{
    virDomainPtr dom = NULL;
    size_t niothreads = 0;
    g_autofree virDomainIOThreadInfoPtr *info = NULL;
    size_t i;
    int rc;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if ((rc = virDomainGetIOThreadInfo(dom, &info, flags)) < 0)
        goto cleanup;

    niothreads = rc;

    tmp = g_new0(char *, niothreads + 1);

    for (i = 0; i < niothreads; i++)
        tmp[i] = g_strdup_printf("%u", info[i]->iothread_id);

    ret = g_steal_pointer(&tmp);

 cleanup:
    virshDomainFree(dom);
    return ret;
}


char **
virshDomainVcpuCompleter(vshControl *ctl,
                         const vshCmd *cmd,
                         unsigned int flags)
{
    virDomainPtr dom = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int nvcpus = 0;
    unsigned int id;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                 &xml, &ctxt) < 0)
        goto cleanup;

    /* Query the max rather than the current vcpu count */
    if (virXPathInt("string(/domain/vcpu)", ctxt, &nvcpus) < 0)
        goto cleanup;

    tmp = g_new0(char *, nvcpus + 1);

    for (id = 0; id < nvcpus; id++)
        tmp[id] = g_strdup_printf("%u", id);

    ret = g_steal_pointer(&tmp);

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virshDomainFree(dom);
    return ret;
}


char **
virshDomainVcpulistCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags)
{
    virDomainPtr dom = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int nvcpus = 0;
    unsigned int id;
    VIR_AUTOSTRINGLIST vcpulist = NULL;
    const char *vcpuid = NULL;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "vcpulist", &vcpuid) < 0)
        goto cleanup;

    if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                 &xml, &ctxt) < 0)
        goto cleanup;

    /* Query the max rather than the current vcpu count */
    if (virXPathInt("string(/domain/vcpu)", ctxt, &nvcpus) < 0)
        goto cleanup;

    vcpulist = g_new0(char *, nvcpus + 1);

    for (id = 0; id < nvcpus; id++)
        vcpulist[id] = g_strdup_printf("%u", id);

    ret = virshCommaStringListComplete(vcpuid, (const char **)vcpulist);

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virshDomainFree(dom);
    return ret;
}


char **
virshDomainCpulistCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags)
{
    virshControlPtr priv = ctl->privData;
    size_t i;
    int cpunum;
    g_autofree unsigned char *cpumap = NULL;
    unsigned int online;
    VIR_AUTOSTRINGLIST cpulist = NULL;
    const char *cpuid = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "cpulist", &cpuid) < 0)
        return NULL;

    if ((cpunum = virNodeGetCPUMap(priv->conn, &cpumap, &online, 0)) < 0)
        return NULL;

    cpulist = g_new0(char *, cpunum + 1);

    for (i = 0; i < cpunum; i++)
        cpulist[i] = g_strdup_printf("%zu", i);

    return virshCommaStringListComplete(cpuid, (const char **)cpulist);
}
