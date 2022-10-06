/*
 * virsh-completer-host.c: virsh completer callbacks related to host
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

#include "virsh-completer-host.h"
#include "virsh.h"
#include "virstring.h"
#include "virxml.h"
#include "virutil.h"
#include "virsh-host.h"
#include "conf/domain_conf.h"
#include "virarch.h"

static char *
virshPagesizeNodeToString(xmlNodePtr node)
{
    g_autofree char *pagesize = NULL;
    g_autofree char *unit = NULL;
    unsigned long long byteval = 0;
    const char *suffix = NULL;
    double size = 0;
    char *ret;

    pagesize = virXMLPropString(node, "size");
    unit = virXMLPropString(node, "unit");
    if (virStrToLong_ull(pagesize, NULL, 10, &byteval) < 0)
        return NULL;
    if (virScaleInteger(&byteval, unit, 1024, ULLONG_MAX) < 0)
        return NULL;
    size = vshPrettyCapacity(byteval, &suffix);
    ret = g_strdup_printf("%.0f%s", size, suffix);
    return ret;
}

char **
virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                 const vshCmd *cmd G_GNUC_UNUSED,
                                 unsigned int flags)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    virshControl *priv = ctl->privData;
    int npages = 0;
    g_autofree xmlNodePtr *pages = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    size_t i = 0;
    const char *cellnum = NULL;
    bool cellno = vshCommandOptBool(cmd, "cellno");
    g_autofree char *path = NULL;
    g_autofree char *cap_xml = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(cap_xml = virConnectGetCapabilities(priv->conn)))
        return NULL;

    if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt)))
        return NULL;

    if (cellno && vshCommandOptStringQuiet(ctl, cmd, "cellno", &cellnum) > 0) {
        path = g_strdup_printf("/capabilities/host/topology/cells/cell[@id=\"%s\"]/pages",
                               cellnum);
    } else {
        path = g_strdup("/capabilities/host/cpu/pages");
    }

    npages = virXPathNodeSet(path, ctxt, &pages);
    if (npages <= 0)
        return NULL;

    tmp = g_new0(char *, npages + 1);

    for (i = 0; i < npages; i++) {
        if (!(tmp[i] = virshPagesizeNodeToString(pages[i])))
            return NULL;
    }

    return g_steal_pointer(&tmp);
}


char **
virshCellnoCompleter(vshControl *ctl,
                     const vshCmd *cmd G_GNUC_UNUSED,
                     unsigned int flags)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    virshControl *priv = ctl->privData;
    int ncells = 0;
    g_autofree xmlNodePtr *cells = NULL;
    g_autoptr(xmlDoc) doc = NULL;
    size_t i = 0;
    g_autofree char *cap_xml = NULL;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(cap_xml = virConnectGetCapabilities(priv->conn)))
        return NULL;

    if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt)))
        return NULL;

    ncells = virXPathNodeSet("/capabilities/host/topology/cells/cell", ctxt, &cells);
    if (ncells <= 0)
        return NULL;

    tmp = g_new0(char *, ncells + 1);

    for (i = 0; i < ncells; i++) {
        if (!(tmp[i] = virXMLPropString(cells[i], "id")))
            return NULL;
    }

    return g_steal_pointer(&tmp);
}


char **
virshNodeCpuCompleter(vshControl *ctl,
                      const vshCmd *cmd G_GNUC_UNUSED,
                      unsigned int flags)
{
    virshControl *priv = ctl->privData;
    g_auto(GStrv) tmp = NULL;
    size_t i;
    int cpunum;
    size_t offset = 0;
    unsigned int online;
    g_autofree unsigned char *cpumap = NULL;

    virCheckFlags(0, NULL);

    if ((cpunum = virNodeGetCPUMap(priv->conn, &cpumap, &online, 0)) < 0)
        return NULL;

    tmp = g_new0(char *, online + 1);

    for (i = 0; i < cpunum; i++) {
        if (VIR_CPU_USED(cpumap, i) == 0)
            continue;

        tmp[offset++] = g_strdup_printf("%zu", i);
    }

    return g_steal_pointer(&tmp);
}


char **
virshNodeSuspendTargetCompleter(vshControl *ctl G_GNUC_UNUSED,
                                const vshCmd *cmd G_GNUC_UNUSED,
                                unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_NODE_SUSPEND_TARGET_LAST,
                             virshNodeSuspendTargetTypeToString);
}


char **
virshDomainVirtTypeCompleter(vshControl *ctl G_GNUC_UNUSED,
                             const vshCmd *cmd G_GNUC_UNUSED,
                             unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_DOMAIN_VIRT_LAST,
                             virDomainVirtTypeToString);
}


char **
virshArchCompleter(vshControl *ctl G_GNUC_UNUSED,
                   const vshCmd *cmd G_GNUC_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virshEnumComplete(VIR_ARCH_LAST,
                             (const char *(*)(int))virArchToString);
}


char **
virshCPUModelCompleter(vshControl *ctl,
                       const vshCmd *cmd,
                       unsigned int flags)
{
    virshControl *priv = ctl->privData;
    const char *virttype = NULL;
    const char *emulator = NULL;
    const char *arch = NULL;
    const char *machine = NULL;
    g_autofree char *domcaps = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_auto(GStrv) models = NULL;
    int nmodels = 0;
    size_t i;

    virCheckFlags(0, NULL);

    if (vshCommandOptStringReq(ctl, cmd, "virttype", &virttype) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "emulator", &emulator) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "arch", &arch) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "machine", &machine) < 0)
        return NULL;

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(domcaps = virConnectGetDomainCapabilities(priv->conn, emulator, arch,
                                                    machine, virttype, 0)))
        return NULL;

    if (!(xml = virXMLParseStringCtxt(domcaps, _("domain capabilities"), &ctxt)))
        return NULL;

    nmodels = virXPathNodeSet("/domainCapabilities/cpu/mode[@name='custom']/model",
                              ctxt, &nodes);
    if (nmodels <= 0)
        return NULL;

    models = g_new0(char *, nmodels + 1);

    for (i = 0; i < nmodels; i++)
        models[i] = virXMLNodeContentString(nodes[i]);

    return g_steal_pointer(&models);
}
