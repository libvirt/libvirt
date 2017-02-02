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

VIR_ENUM_IMPL(virDomainMemoryAccess, VIR_DOMAIN_MEMORY_ACCESS_LAST,
              "default",
              "shared",
              "private")


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
        unsigned long long mem; /* memory size in KiB */
        virBitmapPtr cpumask;   /* bitmap of vCPUs corresponding to the node */
        virBitmapPtr nodeset;   /* host memory nodes where this guest node resides */
        virDomainNumatuneMemMode mode;  /* memory mode selection */
        virDomainMemoryAccess memAccess; /* shared memory access configuration */
    } *mem_nodes;           /* guest node configuration */
    size_t nmem_nodes;

    /* Future NUMA tuning related stuff should go here. */
};


bool
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
virDomainNumatuneNodeParseXML(virDomainNumaPtr numa,
                              xmlXPathContextPtr ctxt)
{
    char *tmp = NULL;
    int n = 0;
    int ret = -1;
    size_t i = 0;
    xmlNodePtr *nodes = NULL;

    if ((n = virXPathNodeSet("./numatune/memnode", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract memnode nodes"));
        goto cleanup;
    }

    if (!n)
        return 0;

    if (numa->memory.specified &&
        numa->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Per-node binding is not compatible with "
                         "automatic NUMA placement."));
        goto cleanup;
    }

    if (!numa->nmem_nodes) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Element 'memnode' is invalid without "
                         "any guest NUMA cells"));
        goto cleanup;
    }

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

        if (cellid >= numa->nmem_nodes) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Argument 'cellid' in memnode element must "
                             "correspond to existing guest's NUMA cell"));
            goto cleanup;
        }

        mem_node = &numa->mem_nodes[cellid];

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
        if (virBitmapParse(tmp, &mem_node->nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;

        if (virBitmapIsAllClear(mem_node->nodeset)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value of 'nodeset': %s"), tmp);
            goto cleanup;
        }
        VIR_FREE(tmp);
    }

    ret = 0;
 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    return ret;
}

int
virDomainNumatuneParseXML(virDomainNumaPtr numa,
                          bool placement_static,
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

        tmp = virXMLPropString(node, "nodeset");
        if (tmp) {
            if (virBitmapParse(tmp, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
                goto cleanup;

            if (virBitmapIsAllClear(nodeset)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'nodeset': %s"), tmp);
                goto cleanup;
            }

            VIR_FREE(tmp);
        }
    }

    if (virDomainNumatuneSet(numa,
                             placement_static,
                             placement,
                             mode,
                             nodeset) < 0)
        goto cleanup;

    if (virDomainNumatuneNodeParseXML(numa, ctxt) < 0)
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
    for (i = 0; i < numa->nmem_nodes; i++) {
        virBitmapFree(numa->mem_nodes[i].cpumask);
        virBitmapFree(numa->mem_nodes[i].nodeset);
    }
    VIR_FREE(numa->mem_nodes);

    VIR_FREE(numa);
}

/**
 * virDomainNumatuneGetMode:
 * @numatune: pointer to numatune definition
 * @cellid: cell selector
 * @mode: where to store the result
 *
 * Get the defined mode for domain's memory. It's safe to pass
 * NULL to @mode if the return value is the only info needed.
 *
 * Returns: 0 on success (with @mode updated)
 *         -1 if no mode was defined in XML
 */
int virDomainNumatuneGetMode(virDomainNumaPtr numatune,
                             int cellid,
                             virDomainNumatuneMemMode *mode)
{
    int ret = -1;
    virDomainNumatuneMemMode tmp_mode;

    if (!numatune)
        return ret;

    if (virDomainNumatuneNodeSpecified(numatune, cellid))
        tmp_mode = numatune->mem_nodes[cellid].mode;
    else if (numatune->memory.specified)
        tmp_mode = numatune->memory.mode;
    else
        goto cleanup;

    if (mode)
        *mode = tmp_mode;
    ret = 0;
 cleanup:
    return ret;
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
virDomainNumatuneSet(virDomainNumaPtr numa,
                     bool placement_static,
                     int placement,
                     int mode,
                     virBitmapPtr nodeset)
{
    int ret = -1;

    /* No need to do anything in this case */
    if (mode == -1 && placement == -1 && !nodeset)
        return 0;

    if (!numa->memory.specified) {
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
        numa->memory.mode = mode;

    if (nodeset) {
        virBitmapFree(numa->memory.nodeset);
        if (!(numa->memory.nodeset = virBitmapNewCopy(nodeset)))
            goto cleanup;
        if (placement == -1)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC;
    }

    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT) {
        if (numa->memory.nodeset || placement_static)
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC;
        else
            placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO;
    }

    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC &&
        !numa->memory.nodeset) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("nodeset for NUMA memory tuning must be set "
                         "if 'placement' is 'static'"));
        goto cleanup;
    }

    /* setting nodeset when placement auto is invalid */
    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO &&
        numa->memory.nodeset) {
        virBitmapFree(numa->memory.nodeset);
        numa->memory.nodeset = NULL;
    }

    if (placement != -1)
        numa->memory.placement = placement;

    numa->memory.specified = true;

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
virDomainNumaDefCPUParseXML(virDomainNumaPtr def,
                            xmlXPathContextPtr ctxt)
{
    xmlNodePtr *nodes = NULL;
    xmlNodePtr oldNode = ctxt->node;
    char *tmp = NULL;
    int n;
    size_t i;
    int ret = -1;

    /* check if NUMA definition is present */
    if (!virXPathNode("./cpu/numa[1]", ctxt))
        return 0;

    if ((n = virXPathNodeSet("./cpu/numa[1]/cell", ctxt, &nodes)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("NUMA topology defined without NUMA cells"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(def->mem_nodes, n) < 0)
        goto cleanup;
    def->nmem_nodes = n;

    for (i = 0; i < n; i++) {
        size_t j;
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

        if (def->mem_nodes[cur_cell].cpumask) {
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

        if (virBitmapParse(tmp, &def->mem_nodes[cur_cell].cpumask,
                           VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;

        if (virBitmapIsAllClear(def->mem_nodes[cur_cell].cpumask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                          _("NUMA cell %d has no vCPUs assigned"), cur_cell);
            goto cleanup;
        }
        VIR_FREE(tmp);

        for (j = 0; j < n; j++) {
            if (j == cur_cell || !def->mem_nodes[j].cpumask)
                continue;

            if (virBitmapOverlaps(def->mem_nodes[j].cpumask,
                                  def->mem_nodes[cur_cell].cpumask)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("NUMA cells %u and %zu have overlapping vCPU ids"),
                               cur_cell, j);
                goto cleanup;
            }
        }

        ctxt->node = nodes[i];
        if (virDomainParseMemory("./@memory", "./@unit", ctxt,
                                 &def->mem_nodes[cur_cell].mem, true, false) < 0)
            goto cleanup;

        if ((tmp = virXMLPropString(nodes[i], "memAccess"))) {
            if ((rc = virDomainMemoryAccessTypeFromString(tmp)) <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid 'memAccess' attribute value '%s'"),
                               tmp);
                goto cleanup;
            }

            def->mem_nodes[cur_cell].memAccess = rc;
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
                          virDomainNumaPtr def)
{
    virDomainMemoryAccess memAccess;
    char *cpustr;
    size_t ncells = virDomainNumaGetNodeCount(def);
    size_t i;

    if (ncells == 0)
        return 0;

    virBufferAddLit(buf, "<numa>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < ncells; i++) {
        memAccess = virDomainNumaGetNodeMemoryAccessMode(def, i);

        if (!(cpustr = virBitmapFormat(virDomainNumaGetNodeCpumask(def, i))))
            return -1;

        virBufferAddLit(buf, "<cell");
        virBufferAsprintf(buf, " id='%zu'", i);
        virBufferAsprintf(buf, " cpus='%s'", cpustr);
        virBufferAsprintf(buf, " memory='%llu'",
                          virDomainNumaGetNodeMemorySize(def, i));
        virBufferAddLit(buf, " unit='KiB'");
        if (memAccess)
            virBufferAsprintf(buf, " memAccess='%s'",
                              virDomainMemoryAccessTypeToString(memAccess));
        virBufferAddLit(buf, "/>\n");
        VIR_FREE(cpustr);
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</numa>\n");

    return 0;
}


unsigned int
virDomainNumaGetCPUCountTotal(virDomainNumaPtr numa)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++)
        ret += virBitmapCountBits(virDomainNumaGetNodeCpumask(numa, i));

    return ret;
}

unsigned int
virDomainNumaGetMaxCPUID(virDomainNumaPtr numa)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++) {
        int bit;

        bit = virBitmapLastSetBit(virDomainNumaGetNodeCpumask(numa, i));
        if (bit > ret)
            ret = bit;
    }

    return ret;
}


virDomainNumaPtr
virDomainNumaNew(void)
{
    virDomainNumaPtr ret = NULL;

    ignore_value(VIR_ALLOC(ret));

    return ret;
}


bool
virDomainNumaCheckABIStability(virDomainNumaPtr src,
                               virDomainNumaPtr tgt)
{
    size_t i;

    if (virDomainNumaGetNodeCount(src) != virDomainNumaGetNodeCount(tgt)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target NUMA node count '%zu' doesn't match "
                         "source '%zu'"),
                       virDomainNumaGetNodeCount(tgt),
                       virDomainNumaGetNodeCount(src));
        return false;
    }

    for (i = 0; i < virDomainNumaGetNodeCount(src); i++) {
        if (virDomainNumaGetNodeMemorySize(src, i) !=
            virDomainNumaGetNodeMemorySize(tgt, i)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Size of target NUMA node %zu (%llu) doesn't "
                             "match source (%llu)"), i,
                           virDomainNumaGetNodeMemorySize(tgt, i),
                           virDomainNumaGetNodeMemorySize(src, i));
            return false;
        }

        if (!virBitmapEqual(virDomainNumaGetNodeCpumask(src, i),
                            virDomainNumaGetNodeCpumask(tgt, i))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Processor mask of target NUMA node %zu doesn't "
                             "match source"), i);
            return false;
        }
    }

    return true;
}


size_t
virDomainNumaGetNodeCount(virDomainNumaPtr numa)
{
    if (!numa)
        return 0;

    return numa->nmem_nodes;
}


virBitmapPtr
virDomainNumaGetNodeCpumask(virDomainNumaPtr numa,
                            size_t node)
{
    return numa->mem_nodes[node].cpumask;
}


virDomainMemoryAccess
virDomainNumaGetNodeMemoryAccessMode(virDomainNumaPtr numa,
                                     size_t node)
{
    return numa->mem_nodes[node].memAccess;
}


unsigned long long
virDomainNumaGetNodeMemorySize(virDomainNumaPtr numa,
                               size_t node)
{
    return numa->mem_nodes[node].mem;
}


void
virDomainNumaSetNodeMemorySize(virDomainNumaPtr numa,
                               size_t node,
                               unsigned long long size)
{
    numa->mem_nodes[node].mem = size;
}


unsigned long long
virDomainNumaGetMemorySize(virDomainNumaPtr numa)
{
    size_t i;
    unsigned long long ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++)
        ret += numa->mem_nodes[i].mem;

    return ret;
}
