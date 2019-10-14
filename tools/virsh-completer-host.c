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
    VIR_AUTOFREE(char *) pagesize = NULL;
    VIR_AUTOFREE(char *) unit = NULL;
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
    if (virAsprintf(&ret, "%.0f%s", size, suffix) < 0)
        return NULL;
    return ret;
}

char **
virshAllocpagesPagesizeCompleter(vshControl *ctl,
                                 const vshCmd *cmd G_GNUC_UNUSED,
                                 unsigned int flags)
{
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    virshControlPtr priv = ctl->privData;
    unsigned int npages = 0;
    VIR_AUTOFREE(xmlNodePtr *) pages = NULL;
    VIR_AUTOPTR(xmlDoc) doc = NULL;
    size_t i = 0;
    const char *cellnum = NULL;
    bool cellno = vshCommandOptBool(cmd, "cellno");
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) cap_xml = NULL;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

    virCheckFlags(0, NULL);

    if (!priv->conn || virConnectIsAlive(priv->conn) <= 0)
        return NULL;

    if (!(cap_xml = virConnectGetCapabilities(priv->conn)))
        return NULL;

    if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt)))
        return NULL;

    if (cellno && vshCommandOptStringQuiet(ctl, cmd, "cellno", &cellnum) > 0) {
        if (virAsprintf(&path,
                        "/capabilities/host/topology/cells/cell[@id=\"%s\"]/pages",
                        cellnum) < 0)
            return NULL;
    } else {
        if (virAsprintf(&path, "/capabilities/host/cpu/pages") < 0)
            return NULL;
    }

    npages = virXPathNodeSet(path, ctxt, &pages);
    if (npages <= 0)
        return NULL;

    if (VIR_ALLOC_N(tmp, npages + 1) < 0)
        return NULL;

    for (i = 0; i < npages; i++) {
        if (!(tmp[i] = virshPagesizeNodeToString(pages[i])))
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}


char **
virshCellnoCompleter(vshControl *ctl,
                     const vshCmd *cmd G_GNUC_UNUSED,
                     unsigned int flags)
{
    VIR_AUTOPTR(xmlXPathContext) ctxt = NULL;
    virshControlPtr priv = ctl->privData;
    unsigned int ncells = 0;
    VIR_AUTOFREE(xmlNodePtr *) cells = NULL;
    VIR_AUTOPTR(xmlDoc) doc = NULL;
    size_t i = 0;
    VIR_AUTOFREE(char *) cap_xml = NULL;
    char **ret = NULL;
    VIR_AUTOSTRINGLIST tmp = NULL;

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

    if (VIR_ALLOC_N(tmp, ncells + 1))
        return NULL;

    for (i = 0; i < ncells; i++) {
        if (!(tmp[i] = virXMLPropString(cells[i], "id")))
            return NULL;
    }

    VIR_STEAL_PTR(ret, tmp);
    return ret;
}
