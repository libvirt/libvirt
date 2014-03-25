/*
 * Copyright (C) 2009-2014 Red Hat, Inc.
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
 *     James Robson <jrobson@websense.com>
 */

#include <config.h>

#include "netdev_vlan_conf.h"
#include "virerror.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_ENUM_IMPL(virNativeVlanMode, VIR_NATIVE_VLAN_MODE_LAST,
              "default", "tagged", "untagged")

int
virNetDevVlanParse(xmlNodePtr node, xmlXPathContextPtr ctxt, virNetDevVlanPtr def)
{
    int ret = -1;
    xmlNodePtr save = ctxt->node;
    char *trunk = NULL;
    char *nativeMode = NULL;
    xmlNodePtr *tagNodes = NULL;
    int nTags;
    size_t i;

    ctxt->node = node;

    nTags = virXPathNodeSet("./tag", ctxt, &tagNodes);
    if (nTags < 0)
        goto cleanup;

    if (nTags == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing tag id - each <vlan> must have "
                         "at least one <tag id='n'/> subelement"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(def->tag, nTags) < 0)
        goto cleanup;

    def->nativeMode = 0;
    def->nativeTag = 0;
    for (i = 0; i < nTags; i++) {
        unsigned long id;

        ctxt->node = tagNodes[i];
        if (virXPathULong("string(./@id)", ctxt, &id) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing or invalid vlan tag id attribute"));
            goto cleanup;
        }
        if (id > 4095) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("vlan tag id %lu too large (maximum 4095)"), id);
            goto cleanup;
        }
        if ((nativeMode = virXPathString("string(./@nativeMode)", ctxt))) {
            if (def->nativeMode != 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("duplicate native vlan setting"));
                goto cleanup;
            }
            if ((def->nativeMode
                 = virNativeVlanModeTypeFromString(nativeMode)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid \"nativeMode='%s'\" "
                                 "in vlan <tag> element"),
                               nativeMode);
                goto cleanup;
            }
            VIR_FREE(nativeMode);
            def->nativeTag = id;
        }
        def->tag[i] = id;
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
                goto cleanup;
            }
            if (def->nativeMode != 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("invalid configuration in <vlan> - \"trunk='no'\" is "
                                 "not allowed with a native vlan id"));
                goto cleanup;
            }
            /* allow (but discard) "trunk='no' if there is a single tag */
            if (STRCASENEQ(trunk, "no")) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("invalid \"trunk='%s'\" in <vlan> "
                                 "- must be yes or no"), trunk);
                goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    ctxt->node = save;
    VIR_FREE(tagNodes);
    VIR_FREE(trunk);
    VIR_FREE(nativeMode);
    if (ret < 0)
        virNetDevVlanClear(def);
    return ret;
}

int
virNetDevVlanFormat(const virNetDevVlan *def, virBufferPtr buf)
{
    size_t i;

    if (!(def && def->nTags))
        return 0;

    if (!def->tag) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing vlan tag data"));
        return -1;
    }

    virBufferAsprintf(buf, "<vlan%s>\n", def->trunk ? " trunk='yes'" : "");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < def->nTags; i++) {
        if (def->nativeMode != VIR_NATIVE_VLAN_MODE_DEFAULT &&
            def->nativeTag == def->tag[i]) {
            /* check the nativeMode in case we get <tag id='0'/>*/
            const char *mode = virNativeVlanModeTypeToString(def->nativeMode);
            if (!mode) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Bad value for nativeMode"));
            }
            virBufferAsprintf(buf, "<tag id='%u' nativeMode='%s'/>\n",
                              def->tag[i], mode);
        } else {
            virBufferAsprintf(buf, "<tag id='%u'/>\n", def->tag[i]);
        }
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</vlan>\n");
    return 0;
}
