/*
 * numatune_conf.c
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

#include <config.h>

#include "numatune_conf.h"

#include "domain_conf.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_ENUM_IMPL(virDomainNumatuneMemMode,
              VIR_DOMAIN_NUMATUNE_MEM_LAST,
              "strict",
              "preferred",
              "interleave");

VIR_ENUM_IMPL(virDomainNumatunePlacement,
              VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST,
              "default",
              "static",
              "auto");

struct _virDomainNumatune {
    struct {
        virBitmapPtr nodeset;
        virDomainNumatuneMemMode mode;
        virDomainNumatunePlacement placement;
    } memory;               /* pinning for all the memory */

    /* Future NUMA tuning related stuff should go here. */
};


int
virDomainNumatuneParseXML(virDomainDefPtr def,
                          xmlXPathContextPtr ctxt)
{
    char *tmp = NULL;
    int mode = -1;
    int n = 0;
    int placement = -1;
    int ret = -1;
    virBitmapPtr nodeset = NULL;
    xmlNodePtr node = NULL;

    if (virXPathInt("count(./numatune)", ctxt, &n) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot extract numatune nodes"));
        goto cleanup;
    } else if (n > 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one numatune is supported"));
        goto cleanup;
    }

    node = virXPathNode("./numatune/memory[1]", ctxt);

    if (def->numatune) {
        virDomainNumatuneFree(def->numatune);
        def->numatune = NULL;
    }

    if (!node && def->placement_mode != VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO)
        return 0;

    if (!node) {
        /* We know that def->placement_mode is "auto" if we're here */
        if (virDomainNumatuneSet(def, VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO,
                                 -1, NULL) < 0)
            goto cleanup;
        return 0;
    }

    tmp = virXMLPropString(node, "mode");
    if (tmp) {
        mode = virDomainNumatuneMemModeTypeFromString(tmp);
        if (mode < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory tuning mode '%s'"),
                           tmp);
            goto cleanup;
        }
    }
    VIR_FREE(tmp);

    tmp = virXMLPropString(node, "placement");
    if (tmp) {
        placement = virDomainNumatunePlacementTypeFromString(tmp);
        if (placement < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory placement mode '%s'"),
                           tmp);
            goto cleanup;
        }
    }
    VIR_FREE(tmp);

    tmp = virXMLPropString(node, "nodeset");
    if (tmp && virBitmapParse(tmp, 0, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
        goto cleanup;
    VIR_FREE(tmp);

    if (virDomainNumatuneSet(def, placement, mode, nodeset) < 0)
        goto cleanup;

    if (!n) {
        ret = 0;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBitmapFree(nodeset);
    VIR_FREE(tmp);
    return ret;
}

int
virDomainNumatuneFormatXML(virBufferPtr buf,
                           virDomainNumatunePtr numatune)
{
    const char *tmp = NULL;
    char *nodeset = NULL;

    if (!numatune)
        return 0;

    virBufferAddLit(buf, "<numatune>\n");
    virBufferAdjustIndent(buf, 2);

    tmp = virDomainNumatuneMemModeTypeToString(numatune->memory.mode);
    virBufferAsprintf(buf, "<memory mode='%s' ", tmp);

    if (numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC) {
        if (!(nodeset = virBitmapFormat(numatune->memory.nodeset)))
            return -1;
        virBufferAsprintf(buf, "nodeset='%s'/>\n", nodeset);
        VIR_FREE(nodeset);
    } else if (numatune->memory.placement) {
        tmp = virDomainNumatunePlacementTypeToString(numatune->memory.placement);
        virBufferAsprintf(buf, "placement='%s'/>\n", tmp);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</numatune>\n");
    return 0;
}

void
virDomainNumatuneFree(virDomainNumatunePtr numatune)
{
    if (!numatune)
        return;

    virBitmapFree(numatune->memory.nodeset);

    VIR_FREE(numatune);
}

virDomainNumatuneMemMode
virDomainNumatuneGetMode(virDomainNumatunePtr numatune)
{
    return numatune ? numatune->memory.mode : 0;
}

virBitmapPtr
virDomainNumatuneGetNodeset(virDomainNumatunePtr numatune,
                            virBitmapPtr auto_nodeset)
{
    if (!numatune)
        return NULL;

    if (numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO)
        return auto_nodeset;

    /*
     * This weird logic has the same meaning as switch with
     * auto/static/default, but can be more readably changed later.
     */
    if (numatune->memory.placement != VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC)
        return NULL;

    return numatune->memory.nodeset;
}

char *
virDomainNumatuneFormatNodeset(virDomainNumatunePtr numatune,
                               virBitmapPtr auto_nodeset)
{
    return virBitmapFormat(virDomainNumatuneGetNodeset(numatune,
                                                       auto_nodeset));
}

int
virDomainNumatuneMaybeFormatNodeset(virDomainNumatunePtr numatune,
                                    virBitmapPtr auto_nodeset,
                                    char **mask)
{
    *mask = NULL;

    if (!numatune)
        return 0;

    if (numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO &&
        !auto_nodeset) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Advice from numad is needed in case of "
                         "automatic numa placement"));
        return -1;
    }

    *mask = virDomainNumatuneFormatNodeset(numatune, auto_nodeset);
    if (!*mask)
        return -1;

    return 0;
}

int
virDomainNumatuneSet(virDomainDefPtr def,
                     int placement,
                     int mode,
                     virBitmapPtr nodeset)
{
    bool create = !def->numatune;  /* Whether we are creating new struct */
    int ret = -1;
    virDomainNumatunePtr numatune = NULL;

    /* No need to do anything in this case */
    if (mode == -1 && placement == -1 && !nodeset)
        return 0;

    /* Range checks */
    if (mode != -1 &&
        (mode < 0 || mode >= VIR_DOMAIN_NUMATUNE_MEM_LAST)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported numatune mode '%d'"),
                       mode);
        goto cleanup;
    }
    if (placement != -1 &&
        (placement < 0 || placement >= VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported numatune placement '%d'"),
                       mode);
        goto cleanup;
    }

    if (create && VIR_ALLOC(def->numatune) < 0)
        goto cleanup;
    numatune = def->numatune;

    if (create) {
        /* Defaults for new struct */
        if (mode == -1)
            mode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;

        if (placement == -1)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT;
    }

    if (mode != -1)
        numatune->memory.mode = mode;
    if (nodeset) {
        virBitmapFree(numatune->memory.nodeset);
        numatune->memory.nodeset = virBitmapNewCopy(nodeset);
        if (!numatune->memory.nodeset)
            goto cleanup;
        if (placement == -1)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC;
    }

    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT) {
        if (numatune->memory.nodeset ||
            def->placement_mode == VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC;
        else
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO;
    }

    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC &&
        !numatune->memory.nodeset) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nodeset for NUMA memory tuning must be set "
                         "if 'placement' is 'static'"));
        goto cleanup;
    }

    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO) {
        virBitmapFree(numatune->memory.nodeset);
        numatune->memory.nodeset = NULL;
        if (!def->cpumask)
            def->placement_mode = VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO;
    }

    if (placement != -1)
        numatune->memory.placement = placement;

    ret = 0;
 cleanup:
    return ret;
}

bool
virDomainNumatuneEquals(virDomainNumatunePtr n1,
                        virDomainNumatunePtr n2)
{
    if (!n1 && !n2)
        return true;

    if (!n1 || !n2)
        return false;

    if (n1->memory.mode != n2->memory.mode)
        return false;

    if (n1->memory.placement != n2->memory.placement)
        return false;

    return virBitmapEqual(n1->memory.nodeset, n2->memory.nodeset);
}

bool
virDomainNumatuneHasPlacementAuto(virDomainNumatunePtr numatune)
{
    if (!numatune)
        return false;

    if (numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO)
        return true;

    return false;
}
