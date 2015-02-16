/*
 * numa_conf.c
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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

#include "numa_conf.h"

#include "domain_conf.h"
#include "viralloc.h"
#include "virnuma.h"
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

VIR_ENUM_IMPL(virNumaMemAccess, VIR_NUMA_MEM_ACCESS_LAST,
              "default",
              "shared",
              "private");

typedef struct _virDomainNumaNode virDomainNumaNode;
typedef virDomainNumaNode *virDomainNumaNodePtr;

struct _virDomainNuma {
    struct {
        bool specified;
        virBitmapPtr nodeset;
        virDomainNumatuneMemMode mode;
        virDomainNumatunePlacement placement;
    } memory;               /* pinning for all the memory */

    struct _virDomainNumaNode {
        virBitmapPtr nodeset;
        virDomainNumatuneMemMode mode;
    } *mem_nodes;           /* fine tuning per guest node */
    size_t nmem_nodes;

    /* Future NUMA tuning related stuff should go here. */
};


inline bool
virDomainNumatuneNodeSpecified(virDomainNumaPtr numatune,
                               int cellid)
{
    if (numatune &&
        cellid >= 0 &&
        cellid < numatune->nmem_nodes)
        return numatune->mem_nodes[cellid].nodeset;

    return false;
}

static int
virDomainNumatuneNodeParseXML(virDomainNumaPtr *numatunePtr,
                              size_t ncells,
                              xmlXPathContextPtr ctxt)
{
    char *tmp = NULL;
    int n = 0;
    int ret = -1;
    size_t i = 0;
    virDomainNumaPtr numatune = *numatunePtr;
    xmlNodePtr *nodes = NULL;

    if ((n = virXPathNodeSet("./numatune/memnode", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract memnode nodes"));
        goto cleanup;
    }

    if (!n)
        return 0;

    if (numatune && numatune->memory.specified &&
        numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Per-node binding is not compatible with "
                         "automatic NUMA placement."));
        goto cleanup;
    }

    if (!ncells) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Element 'memnode' is invalid without "
                         "any guest NUMA cells"));
        goto cleanup;
    }

    VIR_FREE(numatune->mem_nodes);
    if (VIR_ALLOC_N(numatune->mem_nodes, ncells) < 0)
        goto cleanup;

    numatune->nmem_nodes = ncells;

    for (i = 0; i < n; i++) {
        int mode = 0;
        unsigned int cellid = 0;
        virDomainNumaNodePtr mem_node = NULL;
        xmlNodePtr cur_node = nodes[i];

        tmp = virXMLPropString(cur_node, "cellid");
        if (!tmp) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing required cellid attribute "
                             "in memnode element"));
            goto cleanup;
        }
        if (virStrToLong_uip(tmp, NULL, 10, &cellid) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid cellid attribute in memnode element: %s"),
                           tmp);
            goto cleanup;
        }
        VIR_FREE(tmp);

        if (cellid >= numatune->nmem_nodes) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Argument 'cellid' in memnode element must "
                             "correspond to existing guest's NUMA cell"));
            goto cleanup;
        }

        mem_node = &numatune->mem_nodes[cellid];

        if (mem_node->nodeset) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple memnode elements with cellid %u"),
                           cellid);
            goto cleanup;
        }

        tmp = virXMLPropString(cur_node, "mode");
        if (!tmp) {
            mem_node->mode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;
        } else {
            if ((mode = virDomainNumatuneMemModeTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Invalid mode attribute in memnode element"));
                goto cleanup;
            }
            VIR_FREE(tmp);
            mem_node->mode = mode;
        }

        tmp = virXMLPropString(cur_node, "nodeset");
        if (!tmp) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing required nodeset attribute "
                             "in memnode element"));
            goto cleanup;
        }
        if (virBitmapParse(tmp, 0, &mem_node->nodeset,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;
        VIR_FREE(tmp);
    }

    ret = 0;
 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    return ret;
}

int
virDomainNumatuneParseXML(virDomainNumaPtr *numatunePtr,
                          bool placement_static,
                          size_t ncells,
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

    if (!placement_static && !node)
        placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO;

    if (node) {
        if ((tmp = virXMLPropString(node, "mode")) &&
            (mode = virDomainNumatuneMemModeTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory tuning mode '%s'"), tmp);
            goto cleanup;
        }
        VIR_FREE(tmp);

        if ((tmp = virXMLPropString(node, "placement")) &&
            (placement = virDomainNumatunePlacementTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory placement mode '%s'"), tmp);
            goto cleanup;
        }
        VIR_FREE(tmp);

        if ((tmp = virXMLPropString(node, "nodeset")) &&
            virBitmapParse(tmp, 0, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;
        VIR_FREE(tmp);
    }

    if (virDomainNumatuneSet(numatunePtr,
                             placement_static,
                             placement,
                             mode,
                             nodeset) < 0)
        goto cleanup;

    if (virDomainNumatuneNodeParseXML(numatunePtr, ncells, ctxt) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(nodeset);
    VIR_FREE(tmp);
    return ret;
}

int
virDomainNumatuneFormatXML(virBufferPtr buf,
                           virDomainNumaPtr numatune)
{
    const char *tmp = NULL;
    char *nodeset = NULL;
    bool nodesetSpecified = false;
    size_t i = 0;

    if (!numatune)
        return 0;

    for (i = 0; i < numatune->nmem_nodes; i++) {
        if (numatune->mem_nodes[i].nodeset) {
            nodesetSpecified = true;
            break;
        }
    }

    if (!nodesetSpecified && !numatune->memory.specified)
        return 0;

    virBufferAddLit(buf, "<numatune>\n");
    virBufferAdjustIndent(buf, 2);

    if (numatune->memory.specified) {
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
    }

    for (i = 0; i < numatune->nmem_nodes; i++) {
        virDomainNumaNodePtr mem_node = &numatune->mem_nodes[i];

        if (!mem_node->nodeset)
            continue;

        if (!(nodeset = virBitmapFormat(mem_node->nodeset)))
            return -1;

        virBufferAsprintf(buf,
                          "<memnode cellid='%zu' mode='%s' nodeset='%s'/>\n",
                          i,
                          virDomainNumatuneMemModeTypeToString(mem_node->mode),
                          nodeset);
        VIR_FREE(nodeset);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</numatune>\n");
    return 0;
}

void
virDomainNumaFree(virDomainNumaPtr numa)
{
    size_t i = 0;

    if (!numa)
        return;

    virBitmapFree(numa->memory.nodeset);
    for (i = 0; i < numa->nmem_nodes; i++)
        virBitmapFree(numa->mem_nodes[i].nodeset);
    VIR_FREE(numa->mem_nodes);

    VIR_FREE(numa);
}

virDomainNumatuneMemMode
virDomainNumatuneGetMode(virDomainNumaPtr numatune,
                         int cellid)
{
    if (!numatune)
        return 0;

    if (virDomainNumatuneNodeSpecified(numatune, cellid))
        return numatune->mem_nodes[cellid].mode;

    if (numatune->memory.specified)
        return numatune->memory.mode;

    return 0;
}

virBitmapPtr
virDomainNumatuneGetNodeset(virDomainNumaPtr numatune,
                            virBitmapPtr auto_nodeset,
                            int cellid)
{
    if (!numatune)
        return NULL;

    if (numatune->memory.specified &&
        numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO)
        return auto_nodeset;

    if (virDomainNumatuneNodeSpecified(numatune, cellid))
        return numatune->mem_nodes[cellid].nodeset;

    if (!numatune->memory.specified)
        return NULL;

    return numatune->memory.nodeset;
}

char *
virDomainNumatuneFormatNodeset(virDomainNumaPtr numatune,
                               virBitmapPtr auto_nodeset,
                               int cellid)
{
    return virBitmapFormat(virDomainNumatuneGetNodeset(numatune,
                                                       auto_nodeset,
                                                       cellid));
}


int
virDomainNumatuneMaybeGetNodeset(virDomainNumaPtr numatune,
                                 virBitmapPtr auto_nodeset,
                                 virBitmapPtr *retNodeset,
                                 int cellid)
{
    *retNodeset = NULL;

    if (!numatune)
        return 0;

    if (!virDomainNumatuneNodeSpecified(numatune, cellid) &&
        !numatune->memory.specified)
        return 0;

    if (numatune->memory.specified &&
        numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO &&
        !auto_nodeset) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Advice from numad is needed in case of "
                         "automatic numa placement"));
        return -1;
    }

    *retNodeset = virDomainNumatuneGetNodeset(numatune, auto_nodeset, cellid);

    return 0;
}


int
virDomainNumatuneMaybeFormatNodeset(virDomainNumaPtr numatune,
                                    virBitmapPtr auto_nodeset,
                                    char **mask,
                                    int cellid)
{
    virBitmapPtr nodeset;

    if (virDomainNumatuneMaybeGetNodeset(numatune, auto_nodeset, &nodeset,
                                         cellid) < 0)
        return -1;

    if (nodeset &&
        !(*mask = virBitmapFormat(nodeset)))
        return -1;

    return 0;
}

int
virDomainNumatuneSet(virDomainNumaPtr *numatunePtr,
                     bool placement_static,
                     int placement,
                     int mode,
                     virBitmapPtr nodeset)
{
    int ret = -1;
    virDomainNumaPtr numatune = *numatunePtr;

    /* No need to do anything in this case */
    if (mode == -1 && placement == -1 && !nodeset)
        return 0;

    if (!numatune->memory.specified) {
        if (mode == -1)
            mode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;
        if (placement == -1)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT;
    }

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
        if (numatune->memory.nodeset || placement_static)
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

    /* setting nodeset when placement auto is invalid */
    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO &&
        numatune->memory.nodeset) {
        virBitmapFree(numatune->memory.nodeset);
        numatune->memory.nodeset = NULL;
    }

    if (placement != -1)
        numatune->memory.placement = placement;

    numatune->memory.specified = true;

    ret = 0;

 cleanup:
    return ret;
}

static bool
virDomainNumaNodesEqual(virDomainNumaPtr n1,
                        virDomainNumaPtr n2)
{
    size_t i = 0;

    if (n1->nmem_nodes != n2->nmem_nodes)
        return false;

    for (i = 0; i < n1->nmem_nodes; i++) {
        virDomainNumaNodePtr nd1 = &n1->mem_nodes[i];
        virDomainNumaNodePtr nd2 = &n2->mem_nodes[i];

        if (!nd1->nodeset && !nd2->nodeset)
            continue;

        if (nd1->mode != nd2->mode)
            return false;

        if (!virBitmapEqual(nd1->nodeset, nd2->nodeset))
            return false;
    }

    return true;
}

bool
virDomainNumaEquals(virDomainNumaPtr n1,
                    virDomainNumaPtr n2)
{
    if (!n1 && !n2)
        return true;

    if (!n1 || !n2)
        return false;

    if (!n1->memory.specified && !n2->memory.specified)
        return virDomainNumaNodesEqual(n1, n2);

    if (!n1->memory.specified || !n2->memory.specified)
        return false;

    if (n1->memory.mode != n2->memory.mode)
        return false;

    if (n1->memory.placement != n2->memory.placement)
        return false;

    if (!virBitmapEqual(n1->memory.nodeset, n2->memory.nodeset))
        return false;

    return virDomainNumaNodesEqual(n1, n2);
}

bool
virDomainNumatuneHasPlacementAuto(virDomainNumaPtr numatune)
{
    if (!numatune)
        return false;

    if (!numatune->memory.specified)
        return false;

    if (numatune->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO)
        return true;

    return false;
}

bool
virDomainNumatuneHasPerNodeBinding(virDomainNumaPtr numatune)
{
    size_t i = 0;

    if (!numatune)
        return false;

    for (i = 0; i < numatune->nmem_nodes; i++) {
        if (numatune->mem_nodes[i].nodeset)
            return true;
    }

    return false;
}

int
virDomainNumatuneSpecifiedMaxNode(virDomainNumaPtr numatune)
{
    int ret = -1;
    virBitmapPtr nodemask = NULL;
    size_t i;
    int bit;

    if (!numatune)
        return ret;

    nodemask = virDomainNumatuneGetNodeset(numatune, NULL, -1);
    if (nodemask)
        ret = virBitmapLastSetBit(nodemask);

    for (i = 0; i < numatune->nmem_nodes; i++) {
        nodemask = numatune->mem_nodes[i].nodeset;
        if (!nodemask)
            continue;

        bit = virBitmapLastSetBit(nodemask);
        if (bit > ret)
            ret = bit;
    }

    return ret;
}

bool
virDomainNumatuneNodesetIsAvailable(virDomainNumaPtr numatune,
                                    virBitmapPtr auto_nodeset)
{
    size_t i = 0;
    virBitmapPtr b = NULL;

    if (!numatune)
        return true;

    b = virDomainNumatuneGetNodeset(numatune, auto_nodeset, -1);
    if (!virNumaNodesetIsAvailable(b))
        return false;

    for (i = 0; i < numatune->nmem_nodes; i++) {
        b = virDomainNumatuneGetNodeset(numatune, auto_nodeset, i);
        if (!virNumaNodesetIsAvailable(b))
            return false;
    }

    return true;
}


int
virDomainNumaDefCPUParseXML(virCPUDefPtr def,
                            xmlXPathContextPtr ctxt)
{
    xmlNodePtr *nodes = NULL;
    xmlNodePtr oldNode = ctxt->node;
    char *tmp = NULL;
    int n;
    size_t i;
    int ret = -1;

    /* check if NUMA definition is present */
    if (!virXPathNode("/domain/cpu/numa[1]", ctxt))
        return 0;

    if ((n = virXPathNodeSet("/domain/cpu/numa[1]/cell", ctxt, &nodes)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("NUMA topology defined without NUMA cells"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(def->cells, n) < 0)
        goto cleanup;
    def->ncells = n;

    for (i = 0; i < n; i++) {
        int rc;
        unsigned int cur_cell = i;

        /* cells are in order of parsing or explicitly numbered */
        if ((tmp = virXMLPropString(nodes[i], "id"))) {
            if (virStrToLong_uip(tmp, NULL, 10, &cur_cell) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid 'id' attribute in NUMA cell: '%s'"),
                               tmp);
                goto cleanup;
            }

            if (cur_cell >= n) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Exactly one 'cell' element per guest "
                                 "NUMA cell allowed, non-contiguous ranges or "
                                 "ranges not starting from 0 are not allowed"));
                goto cleanup;
            }
        }
        VIR_FREE(tmp);

        if (def->cells[cur_cell].cpumask) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Duplicate NUMA cell info for cell id '%u'"),
                           cur_cell);
            goto cleanup;
        }

        if (!(tmp = virXMLPropString(nodes[i], "cpus"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing 'cpus' attribute in NUMA cell"));
            goto cleanup;
        }

        if (virBitmapParse(tmp, 0, &def->cells[cur_cell].cpumask,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;

        if (virBitmapIsAllClear(def->cells[cur_cell].cpumask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("NUMA cell %d has no vCPUs assigned"), cur_cell);
            goto cleanup;
        }
        VIR_FREE(tmp);

        ctxt->node = nodes[i];
        if (virDomainParseMemory("./@memory", "./@unit", ctxt,
                                 &def->cells[cur_cell].mem, true, false) < 0)
            goto cleanup;

        if ((tmp = virXMLPropString(nodes[i], "memAccess"))) {
            if ((rc = virNumaMemAccessTypeFromString(tmp)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid 'memAccess' attribute value '%s'"),
                               tmp);
                goto cleanup;
            }

            def->cells[cur_cell].memAccess = rc;
            VIR_FREE(tmp);
        }
    }

    ret = 0;

 cleanup:
    ctxt->node = oldNode;
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    return ret;
}


int
virDomainNumaDefCPUFormat(virBufferPtr buf,
                          virCPUDefPtr def)
{
    virNumaMemAccess memAccess;
    char *cpustr;
    size_t i;

    if (def->ncells == 0)
        return 0;

    virBufferAddLit(buf, "<numa>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < def->ncells; i++) {
        memAccess = def->cells[i].memAccess;

        if (!(cpustr = virBitmapFormat(def->cells[i].cpumask)))
            return -1;

        virBufferAddLit(buf, "<cell");
        virBufferAsprintf(buf, " id='%zu'", i);
        virBufferAsprintf(buf, " cpus='%s'", cpustr);
        virBufferAsprintf(buf, " memory='%llu'", def->cells[i].mem);
        virBufferAddLit(buf, " unit='KiB'");
        if (memAccess)
            virBufferAsprintf(buf, " memAccess='%s'",
                              virNumaMemAccessTypeToString(memAccess));
        virBufferAddLit(buf, "/>\n");
        VIR_FREE(cpustr);
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</numa>\n");

    return 0;
}


unsigned int
virDomainNumaGetCPUCountTotal(virCPUDefPtr numa)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < numa->ncells; i++)
        ret += virBitmapCountBits(numa->cells[i].cpumask);

    return ret;
}


virDomainNumaPtr
virDomainNumaNew(void)
{
    virDomainNumaPtr ret = NULL;

    ignore_value(VIR_ALLOC(ret));

    return ret;
}
