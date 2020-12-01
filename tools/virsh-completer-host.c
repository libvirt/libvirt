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
#include "viralloc.h"
#include "virsh.h"
#include "virstring.h"
#include "virxml.h"
#include "virutil.h"

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
    if (virScaleInteger(&byteval, unit, 1024, UINT_MAX) < 0)
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
    virshControlPtr priv = ctl->privData;
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
    virshControlPtr priv = ctl->privData;
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
    virshControlPtr priv = ctl->privData;
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
