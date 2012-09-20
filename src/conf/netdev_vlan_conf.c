/*
 * Copyright (C) 2009-2012 Red Hat, Inc.
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
 * Authors:
 *     Laine Stump <laine@redhat.com>
 */

#include <config.h>

#include "netdev_vlan_conf.h"
#include "virterror_internal.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_NONE

int
virNetDevVlanParse(xmlNodePtr node, xmlXPathContextPtr ctxt, virNetDevVlanPtr def)
{
    int ret = -1;
    xmlNodePtr save = ctxt->node;
    const char *trunk;
    xmlNodePtr *tagNodes = NULL;
    int nTags, ii;

    ctxt->node = node;

    nTags = virXPathNodeSet("./tag", ctxt, &tagNodes);
    if (nTags < 0)
        goto error;

    if (nTags == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing tag id - each <vlan> must have "
                         "at least one <tag id='n'/> subelement"));
        goto error;
    }

    if (VIR_ALLOC_N(def->tag, nTags) < 0) {
        virReportOOMError();
        goto error;
    }

    for (ii = 0; ii < nTags; ii++) {
        unsigned long id;

        ctxt->node = tagNodes[ii];
        if (virXPathULong("string(./@id)", ctxt, &id) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing or invalid vlan tag id attribute"));
            goto error;
        }
        if (id > 4095) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("vlan tag id %lu too large (maximum 4095)"), id);
            goto error;
        }
        def->tag[ii] = id;
    }

    def->nTags = nTags;

    /* now that we know how many tags there are, look for an explicit
     * trunk setting.
     */
    if (nTags > 1)
        def->trunk = true;

    ctxt->node = node;
    if ((trunk = virXPathString("string(./@trunk)", ctxt)) != NULL) {
        def->trunk = STRCASEEQ(trunk, "yes");
        if (!def->trunk) {
            if (nTags > 1) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid \"trunk='%s'\" in <vlan> - trunk='yes' "
                                 "is required for more than one vlan tag"), trunk);
                goto error;
            }
            /* allow (but discard) "trunk='no' if there is a single tag */
            if (STRCASENEQ(trunk, "no")) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid \"trunk='%s'\" in <vlan> "
                                 "- must be yes or no"), trunk);
                goto error;
            }
        }
    }

    ret = 0;
error:
    ctxt->node = save;
    VIR_FREE(tagNodes);
    if (ret < 0)
        virNetDevVlanClear(def);
    return ret;
}

int
virNetDevVlanFormat(virNetDevVlanPtr def, virBufferPtr buf)
{
    int ii;

    if (def->nTags == 0)
        return 0;

    if (!def->tag) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing vlan tag data"));
        return -1;
    }

    virBufferAsprintf(buf, "<vlan%s>\n", def->trunk ? " trunk='yes'" : "");
    for (ii = 0; ii < def->nTags; ii++) {
        virBufferAsprintf(buf, "  <tag id='%u'/>\n", def->tag[ii]);
    }
    virBufferAddLit(buf, "</vlan>\n");
    return 0;
}
