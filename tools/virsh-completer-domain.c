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
#include "virxml.h"
#include "virperf.h"
#include "virbitmap.h"
#include "virkeycode.h"
#include "virglibutil.h"
#include "virkeynametable_linux.h"
#include "virkeynametable_osx.h"
#include "virkeynametable_win32.h"
#include "conf/storage_conf.h"
#include "conf/numa_conf.h"

char **
virshDomainNameCompleter(vshControl *ctl,
                         const vshCmd *cmd G_GNUC_UNUSED,
                         unsigned int flags)
{
    virshControl *priv = ctl->privData;
    virDomainPtr *domains = NULL;
    int ndomains = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

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
    virshControl *priv = ctl->privData;
    virDomainPtr *domains = NULL;
    int ndomains = 0;
    size_t i = 0;
    char **ret = NULL;
    g_auto(GStrv) tmp = NULL;

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
    virshControl *priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int ninterfaces;
    g_autofree xmlNodePtr *interfaces = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    g_auto(GStrv) tmp = NULL;

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
    virshControl *priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *disks = NULL;
    int ndisks;
    size_t i;
    g_auto(GStrv) tmp = NULL;

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


static char **
virshDomainDiskTargetListCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   const char *argname)
{
    const char *curval = NULL;
    g_auto(GStrv) targets = virshDomainDiskTargetCompleter(ctl, cmd, 0);

    if (vshCommandOptStringQuiet(ctl, cmd, argname, &curval) < 0)
        return NULL;

    if (!targets)
        return NULL;

    return virshCommaStringListComplete(curval, (const char **) targets);
}


char **
virshDomainMigrateDisksCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int completeflags G_GNUC_UNUSED)
{
    return virshDomainDiskTargetListCompleter(ctl, cmd, "migrate-disks");
}


char **
virshDomainUndefineStorageDisksCompleter(vshControl *ctl,
                                 const vshCmd *cmd,
                                 unsigned int completeflags G_GNUC_UNUSED)
{
    return virshDomainDiskTargetListCompleter(ctl, cmd, "storage");
}


static GSList *
virshDomainBlockjobBaseTopCompleteDisk(const char *target,
                                       xmlXPathContext *ctxt)
{
    g_autofree xmlNodePtr *indexlist = NULL;
    int nindexlist = 0;
    size_t i;
    GSList *ret = NULL;

    if ((nindexlist = virXPathNodeSet("./source|./backingStore",
                                      ctxt, &indexlist)) < 0)
        return NULL;

    ret = g_slist_prepend(ret, g_strdup(target));

    for (i = 0; i < nindexlist; i++) {
        g_autofree char *idx = virXMLPropString(indexlist[i], "index");

        if (!idx)
            continue;

        ret = g_slist_prepend(ret, g_strdup_printf("%s[%s]", target, idx));
    }

    return ret;
}


char **
virshDomainBlockjobBaseTopCompleter(vshControl *ctl,
                                    const vshCmd *cmd,
                                    unsigned int flags)
{
    virshControl *priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *disks = NULL;
    int ndisks;
    size_t i;
    const char *path = NULL;
    g_autoptr(virGSListString) list = NULL;
    GSList *n;
    GStrv ret = NULL;
    size_t nelems;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xmldoc, &ctxt) < 0)
        return NULL;

    ignore_value(vshCommandOptStringQuiet(ctl, cmd, "path", &path));

    if ((ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks)) <= 0)
        return NULL;

    for (i = 0; i < ndisks; i++) {
        g_autofree char *disktarget = NULL;

        ctxt->node = disks[i];
        disktarget = virXPathString("string(./target/@dev)", ctxt);

        if (STREQ_NULLABLE(path, disktarget))
            break;
    }

    if (i == ndisks)
        path = NULL;

    for (i = 0; i < ndisks; i++) {
        g_autofree char *disktarget = NULL;
        GSList *tmplist;

        ctxt->node = disks[i];

        if (!(disktarget = virXPathString("string(./target/@dev)", ctxt)))
            return NULL;

        if (path && STRNEQ(path, disktarget))
            continue;

        /* note that ctxt->node moved */
        if ((tmplist = virshDomainBlockjobBaseTopCompleteDisk(disktarget, ctxt)))
            list = g_slist_concat(tmplist, list);
    }

    list = g_slist_reverse(list);
    nelems = g_slist_length(list);
    ret = g_new0(char *, nelems + 1);
    i = 0;

    for (n = list; n; n = n->next)
        ret[i++] = g_strdup(n->data);

    return ret;
}

char **
virshDomainInterfaceStateCompleter(vshControl *ctl,
                                   const vshCmd *cmd,
                                   unsigned int flags)
{
    virshControl *priv = ctl->privData;
    const char *iface = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    virMacAddr macaddr;
    char macstr[VIR_MAC_STRING_BUFLEN] = "";
    int ninterfaces;
    g_autofree xmlNodePtr *interfaces = NULL;
    g_autofree char *xpath = NULL;
    g_autofree char *state = NULL;
    g_auto(GStrv) tmp = NULL;

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
    virshControl *priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int naliases;
    g_autofree xmlNodePtr *aliases = NULL;
    size_t i;
    unsigned int domainXMLFlags = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (vshCommandOptBool(cmd, "config"))
        domainXMLFlags = VIR_DOMAIN_XML_INACTIVE;

    if (virshDomainGetXML(ctl, cmd, domainXMLFlags, &xmldoc, &ctxt) < 0)
        return NULL;

    naliases = virXPathNodeSet("/domain/devices//alias[@name]", ctxt, &aliases);
    if (naliases < 0)
        return NULL;

    tmp = g_new0(char *, naliases + 1);

    for (i = 0; i < naliases; i++) {
        if (!(tmp[i] = virXMLPropString(aliases[i], "name")))
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
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LAST,
                             virshDomainInterfaceAddressesSourceTypeToString);
}


char **
virshDomainInterfaceSourceModeCompleter(vshControl *ctl G_GNUC_UNUSED,
                                        const vshCmd *cmd G_GNUC_UNUSED,
                                        unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIRSH_DOMAIN_INTERFACE_SOURCE_MODE_LAST,
                             virshDomainInterfaceSourceModeTypeToString);
}


char **
virshDomainHostnameSourceCompleter(vshControl *ctl G_GNUC_UNUSED,
                                   const vshCmd *cmd G_GNUC_UNUSED,
                                   unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIRSH_DOMAIN_HOSTNAME_SOURCE_LAST,
                             virshDomainHostnameSourceTypeToString);
}


char **
virshDomainPerfEnableCompleter(vshControl *ctl,
                              const vshCmd *cmd,
                              unsigned int flags)
{
    g_auto(GStrv) events = NULL;
    const char *event = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "enable", &event) < 0)
        return NULL;

    events = virshEnumComplete(VIR_PERF_EVENT_LAST,
                               virPerfEventTypeToString);

    return virshCommaStringListComplete(event, (const char **)events);
}


char **
virshDomainPerfDisableCompleter(vshControl *ctl,
                                const vshCmd *cmd,
                                unsigned int flags)
{
    g_auto(GStrv) events = NULL;
    const char *event = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "disable", &event) < 0)
        return NULL;

    events = virshEnumComplete(VIR_PERF_EVENT_LAST,
                               virPerfEventTypeToString);

    return virshCommaStringListComplete(event, (const char **)events);
}


char **
virshDomainIOThreadIdCompleter(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags)
{
    g_autoptr(virshDomain) dom = NULL;
    size_t niothreads = 0;
    g_autofree virDomainIOThreadInfoPtr *info = NULL;
    size_t i;
    int rc;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if ((rc = virDomainGetIOThreadInfo(dom, &info, flags)) < 0)
        return NULL;

    niothreads = rc;

    tmp = g_new0(char *, niothreads + 1);

    for (i = 0; i < niothreads; i++)
        tmp[i] = g_strdup_printf("%u", info[i]->iothread_id);

    return g_steal_pointer(&tmp);
}


char **
virshDomainVcpuCompleter(vshControl *ctl,
                         const vshCmd *cmd,
                         unsigned int flags)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int nvcpus = 0;
    unsigned int id;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                 &xml, &ctxt) < 0)
        return NULL;

    /* Query the max rather than the current vcpu count */
    if (virXPathInt("string(/domain/vcpu)", ctxt, &nvcpus) < 0)
        return NULL;

    tmp = g_new0(char *, nvcpus + 1);

    for (id = 0; id < nvcpus; id++)
        tmp[id] = g_strdup_printf("%u", id);

    return g_steal_pointer(&tmp);
}


char **
virshDomainVcpulistCompleter(vshControl *ctl,
                             const vshCmd *cmd,
                             unsigned int flags)
{
    g_autoptr(virshDomain) dom = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int nvcpus = 0;
    unsigned int id;
    g_auto(GStrv) vcpulist = NULL;
    const char *vcpuid = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "vcpulist", &vcpuid) < 0)
        return NULL;

    if (virshDomainGetXMLFromDom(ctl, dom, VIR_DOMAIN_XML_INACTIVE,
                                 &xml, &ctxt) < 0)
        return NULL;

    /* Query the max rather than the current vcpu count */
    if (virXPathInt("string(/domain/vcpu)", ctxt, &nvcpus) < 0)
        return NULL;

    vcpulist = g_new0(char *, nvcpus + 1);

    for (id = 0; id < nvcpus; id++)
        vcpulist[id] = g_strdup_printf("%u", id);

    return virshCommaStringListComplete(vcpuid, (const char **)vcpulist);
}


char **
virshDomainCpulistCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags)
{
    virshControl *priv = ctl->privData;
    size_t i;
    int cpunum;
    g_autofree unsigned char *cpumap = NULL;
    unsigned int online;
    g_auto(GStrv) cpulist = NULL;
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


char **
virshDomainVcpulistViaAgentCompleter(vshControl *ctl,
                                     const vshCmd *cmd,
                                     unsigned int flags)
{
    g_autoptr(virshDomain) dom = NULL;
    bool enable = vshCommandOptBool(cmd, "enable");
    bool disable = vshCommandOptBool(cmd, "disable");
    virTypedParameterPtr params = NULL;
    unsigned int nparams = 0;
    size_t i;
    int nvcpus;
    g_auto(GStrv) cpulist = NULL;
    const char *vcpuid = NULL;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "cpulist", &vcpuid) < 0)
        goto cleanup;

    /* retrieve vcpu count from the guest instead of the hypervisor */
    if ((nvcpus = virDomainGetVcpusFlags(dom,
                                         VIR_DOMAIN_VCPU_GUEST |
                                         VIR_DOMAIN_VCPU_MAXIMUM)) < 0)
        goto cleanup;

    if (!enable && !disable) {
        cpulist = g_new0(char *, nvcpus + 1);
        for (i = 0; i < nvcpus; i++)
            cpulist[i] = g_strdup_printf("%zu", i);
    } else {
        g_autofree char *onlineVcpuStr = NULL;
        g_autofree char *offlinableVcpuStr = NULL;
        g_autofree unsigned char *onlineVcpumap = NULL;
        g_autofree unsigned char *offlinableVcpumap = NULL;
        g_autoptr(virBitmap) onlineVcpus = NULL;
        g_autoptr(virBitmap) offlinableVcpus = NULL;
        size_t j = 0;
        int lastcpu;
        int dummy;

        if (virDomainGetGuestVcpus(dom, &params, &nparams, 0) < 0)
            goto cleanup;

        onlineVcpuStr = vshGetTypedParamValue(ctl, &params[1]);
        if (!(onlineVcpus = virBitmapParseUnlimited(onlineVcpuStr)))
            goto cleanup;

        if (virBitmapToData(onlineVcpus, &onlineVcpumap, &dummy) < 0)
            goto cleanup;

        if (enable) {
            offlinableVcpuStr = vshGetTypedParamValue(ctl, &params[2]);

            if (!(offlinableVcpus = virBitmapParseUnlimited(offlinableVcpuStr)))
                goto cleanup;

            if (virBitmapToData(offlinableVcpus, &offlinableVcpumap, &dummy) < 0)
                goto cleanup;

            lastcpu = virBitmapLastSetBit(offlinableVcpus);
            cpulist = g_new0(char *, nvcpus - virBitmapCountBits(onlineVcpus) + 1);
            for (i = 0; i < nvcpus - virBitmapCountBits(onlineVcpus); i++) {
                while (j <= lastcpu) {
                    if (VIR_CPU_USED(onlineVcpumap, j) != 0 ||
                        VIR_CPU_USED(offlinableVcpumap, j) == 0) {
                        j += 1;
                        continue;
                    } else {
                        break;
                    }
                }

                cpulist[i] = g_strdup_printf("%zu", j++);
            }
        } else if (disable) {
            lastcpu = virBitmapLastSetBit(onlineVcpus);
            cpulist = g_new0(char *, virBitmapCountBits(onlineVcpus) + 1);
            for (i = 0; i < virBitmapCountBits(onlineVcpus); i++) {
                while (j <= lastcpu) {
                    if (VIR_CPU_USED(onlineVcpumap, j) == 0) {
                        j += 1;
                        continue;
                    } else {
                        break;
                    }
                }

                cpulist[i] = g_strdup_printf("%zu", j++);
            }
        }
    }

    ret = virshCommaStringListComplete(vcpuid, (const char **)cpulist);

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}


char **
virshDomainConsoleCompleter(vshControl *ctl,
                            const vshCmd *cmd,
                            unsigned int flags)
{
    virshControl *priv = ctl->privData;
    g_autoptr(xmlDoc) xmldoc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int nserials;
    int nparallels;
    g_autofree xmlNodePtr *serials = NULL;
    g_autofree xmlNodePtr *parallels = NULL;
    size_t i;
    size_t offset = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (virshDomainGetXML(ctl, cmd, 0, &xmldoc, &ctxt) < 0)
        return NULL;

    nserials = virXPathNodeSet("./devices/serial", ctxt, &serials);
    if (nserials < 0)
        return NULL;

    nparallels = virXPathNodeSet("./devices/parallel", ctxt, &parallels);
    if (nparallels < 0)
        return NULL;

    tmp = g_new0(char *, nserials + nparallels + 1);

    for (i = 0; i < nserials + nparallels; i++) {
        g_autofree char *type = NULL;


        if (i < nserials)
            ctxt->node = serials[i];
        else
            ctxt->node = parallels[i - nserials];

        type = virXPathString("string(./@type)", ctxt);
        if (STRNEQ(type, "pty"))
            continue;

        tmp[offset++] = virXPathString("string(./alias/@name)", ctxt);
    }

    return g_steal_pointer(&tmp);
}


char **
virshDomainSignalCompleter(vshControl *ctl G_GNUC_UNUSED,
                           const vshCmd *cmd G_GNUC_UNUSED,
                           unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_PROCESS_SIGNAL_LAST,
                             virshDomainProcessSignalTypeToString);
}


char **
virshDomainLifecycleCompleter(vshControl *ctl G_GNUC_UNUSED,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_LIFECYCLE_LAST,
                             virshDomainLifecycleTypeToString);
}


char **
virshDomainLifecycleActionCompleter(vshControl *ctl G_GNUC_UNUSED,
                                    const vshCmd *cmd G_GNUC_UNUSED,
                                    unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_LIFECYCLE_ACTION_LAST,
                             virshDomainLifecycleActionTypeToString);
}


char **
virshCodesetNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                          const vshCmd *cmd G_GNUC_UNUSED,
                          unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_KEYCODE_SET_LAST,
                             virKeycodeSetTypeToString);
}


char **
virshKeycodeNameCompleter(vshControl *ctl,
                          const vshCmd *cmd,
                          unsigned int flags)
{
    g_auto(GStrv) tmp = NULL;
    size_t i = 0;
    size_t j = 0;
    const char *codeset_option;
    int codeset;
    const char **names = NULL;
    size_t len;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "codeset", &codeset_option) <= 0)
        codeset_option = "linux";

    if (STREQ(codeset_option, "rfb"))
        codeset_option = "qnum";

    codeset = virKeycodeSetTypeFromString(codeset_option);

    if (codeset < 0)
        return NULL;

    switch ((virKeycodeSet) codeset) {
    case VIR_KEYCODE_SET_LINUX:
        names = virKeyNameTable_linux;
        len = virKeyNameTable_linux_len;
        break;
    case VIR_KEYCODE_SET_OSX:
        names = virKeyNameTable_osx;
        len = virKeyNameTable_osx_len;
        break;
    case VIR_KEYCODE_SET_WIN32:
        names = virKeyNameTable_win32;
        len = virKeyNameTable_win32_len;
        break;
    case VIR_KEYCODE_SET_XT:
    case VIR_KEYCODE_SET_ATSET1:
    case VIR_KEYCODE_SET_ATSET2:
    case VIR_KEYCODE_SET_ATSET3:
    case VIR_KEYCODE_SET_XT_KBD:
    case VIR_KEYCODE_SET_USB:
    case VIR_KEYCODE_SET_QNUM:
    case VIR_KEYCODE_SET_LAST:
        break;
    }

    if (!names)
        return NULL;

    tmp = g_new0(char *, len + 1);

    for (i = 0; i < len; i++) {
        if (!names[i])
            continue;

        tmp[j] = g_strdup(names[i]);
        j++;
    }

    tmp = g_renew(char *, tmp, j + 1);

    return g_steal_pointer(&tmp);
}


char **
virshDomainFSMountpointsCompleter(vshControl *ctl,
                                  const vshCmd *cmd,
                                  unsigned int flags)
{
    g_auto(GStrv) tmp = NULL;
    g_autoptr(virshDomain) dom = NULL;
    int rc = -1;
    size_t i;
    virDomainFSInfoPtr *info = NULL;
    size_t ninfos = 0;
    char **ret = NULL;

    virCheckFlags(0, NULL);

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return NULL;

    rc = virDomainGetFSInfo(dom, &info, 0);
    if (rc <= 0) {
        goto cleanup;
    }
    ninfos = rc;

    tmp = g_new0(char *, ninfos + 1);
    for (i = 0; i < ninfos; i++) {
        tmp[i] = g_strdup(info[i]->mountpoint);
    }
    ret = g_steal_pointer(&tmp);

 cleanup:
    if (info) {
        for (i = 0; i < ninfos; i++)
            virDomainFSInfoFree(info[i]);
        VIR_FREE(info);
    }
    return ret;
}


char **
virshDomainCoreDumpFormatCompleter(vshControl *ctl G_GNUC_UNUSED,
                                   const vshCmd *cmd G_GNUC_UNUSED,
                                   unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_CORE_DUMP_FORMAT_LAST,
                             virshDomainCoreDumpFormatTypeToString);
}


char **
virshDomainMigrateCompMethodsCompleter(vshControl *ctl,
                                       const vshCmd *cmd,
                                       unsigned int flags)
{
    const char *methods[] = {"xbzrle", "mt",  NULL};
    const char *method = NULL;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringQuiet(ctl, cmd, "comp-methods", &method) < 0)
        return NULL;

    return virshCommaStringListComplete(method, methods);
}


char **
virshDomainStorageFileFormatCompleter(vshControl *ctl G_GNUC_UNUSED,
                                      const vshCmd *cmd G_GNUC_UNUSED,
                                      unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_STORAGE_FILE_LAST,
                             virStorageFileFormatTypeToString);
}


char **
virshDomainNumatuneModeCompleter(vshControl *ctl G_GNUC_UNUSED,
                                 const vshCmd *cmd G_GNUC_UNUSED,
                                 unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_NUMATUNE_MEM_LAST,
                             virDomainNumatuneMemModeTypeToString);
}


char **
virshDomainDirtyRateCalcModeCompleter(vshControl *ctl G_GNUC_UNUSED,
                                      const vshCmd *cmd G_GNUC_UNUSED,
                                      unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIRSH_DOMAIN_DIRTYRATE_CALC_MODE_LAST,
                             virshDomainDirtyRateCalcModeTypeToString);
}
