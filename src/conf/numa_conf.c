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
 */

#include <config.h>

#include "numa_conf.h"

#include "domain_conf.h"
#include "viralloc.h"
#include "virnuma.h"
#include "virstring.h"

/*
 * Distance definitions defined Conform ACPI 2.0 SLIT.
 * See include/linux/topology.h
 */
#define LOCAL_DISTANCE          10
#define REMOTE_DISTANCE         20
/* SLIT entry value is a one-byte unsigned integer. */
#define UNREACHABLE            255

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_ENUM_IMPL(virDomainNumatuneMemMode,
              VIR_DOMAIN_NUMATUNE_MEM_LAST,
              "strict",
              "preferred",
              "interleave",
              "restrictive",
);

VIR_ENUM_IMPL(virDomainNumatunePlacement,
              VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST,
              "default",
              "static",
              "auto",
);

VIR_ENUM_IMPL(virDomainMemoryAccess,
              VIR_DOMAIN_MEMORY_ACCESS_LAST,
              "default",
              "shared",
              "private",
);

VIR_ENUM_IMPL(virNumaCacheAssociativity,
              VIR_NUMA_CACHE_ASSOCIATIVITY_LAST,
              "none",
              "direct",
              "full",
);

VIR_ENUM_IMPL(virNumaCachePolicy,
              VIR_NUMA_CACHE_POLICY_LAST,
              "none",
              "writeback",
              "writethrough",
);

VIR_ENUM_IMPL(virMemoryLatency,
              VIR_MEMORY_LATENCY_LAST,
              "none",
              "access",
              "read",
              "write"
);

typedef struct _virDomainNumaNode virDomainNumaNode;

struct _virDomainNuma {
    struct {
        bool specified;
        virBitmap *nodeset;
        virDomainNumatuneMemMode mode;
        virDomainNumatunePlacement placement;
    } memory;               /* pinning for all the memory */

    struct _virDomainNumaNode {
        unsigned long long mem; /* memory size in KiB */
        virBitmap *cpumask;     /* bitmap of vCPUs corresponding to the node */
        virBitmap *nodeset;     /* host memory nodes where this guest node resides */
        virDomainNumatuneMemMode mode;  /* memory mode selection */
        virDomainMemoryAccess memAccess; /* shared memory access configuration */
        virTristateBool discard; /* discard-data for memory-backend-file */

        virNumaDistance *distances; /* remote node distances */
        size_t ndistances;

        virNumaCache *caches;
        size_t ncaches;
    } *mem_nodes;           /* guest node configuration */
    size_t nmem_nodes;

    virNumaInterconnect *interconnects;
    size_t ninterconnects;

    /* Future NUMA tuning related stuff should go here. */
};


bool
virDomainNumatuneNodeSpecified(const virDomainNuma *numatune,
                               int cellid)
{
    if (numatune &&
        cellid >= 0 &&
        cellid < numatune->nmem_nodes)
        return numatune->mem_nodes[cellid].nodeset;

    return false;
}

static int
virDomainNumatuneNodeParseXML(virDomainNuma *numa,
                              xmlXPathContextPtr ctxt)
{
    int n = 0;
    size_t i = 0;
    g_autofree xmlNodePtr *nodes = NULL;

    if ((n = virXPathNodeSet("./numatune/memnode", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot extract memnode nodes"));
        return -1;
    }

    if (!n)
        return 0;

    if (numa->memory.specified &&
        numa->memory.placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Per-node binding is not compatible with automatic NUMA placement."));
        return -1;
    }

    if (!numa->nmem_nodes) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Element 'memnode' is invalid without any guest NUMA cells"));
        return -1;
    }

    for (i = 0; i < n; i++) {
        unsigned int cellid = 0;
        virDomainNumaNode *mem_node = NULL;
        xmlNodePtr cur_node = nodes[i];
        g_autofree char *tmp = NULL;

        if (virXMLPropUInt(cur_node, "cellid", 10, VIR_XML_PROP_REQUIRED,
                           &cellid) < 0)
            return -1;

        if (cellid >= numa->nmem_nodes) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Argument 'cellid' in memnode element must correspond to existing guest's NUMA cell"));
            return -1;
        }

        mem_node = &numa->mem_nodes[cellid];

        if (mem_node->nodeset) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Multiple memnode elements with cellid %1$u"),
                           cellid);
            return -1;
        }

        if (virXMLPropEnumDefault(cur_node, "mode",
                                  virDomainNumatuneMemModeTypeFromString,
                                  VIR_XML_PROP_NONE, &mem_node->mode,
                                  VIR_DOMAIN_NUMATUNE_MEM_STRICT) < 0)
            return -1;

        tmp = virXMLPropString(cur_node, "nodeset");
        if (!tmp) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing required nodeset attribute in memnode element"));
            return -1;
        }
        if (virBitmapParse(tmp, &mem_node->nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;

        if (virBitmapIsAllClear(mem_node->nodeset)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value of 'nodeset': %1$s"), tmp);
            return -1;
        }
    }

    return 0;
}

int
virDomainNumatuneParseXML(virDomainNuma *numa,
                          bool placement_static,
                          xmlXPathContextPtr ctxt)
{
    g_autofree char *modestr = NULL;
    int mode = -1;
    g_autofree char *placementstr = NULL;
    int placement = -1;
    g_autofree char *nodesetstr = NULL;
    g_autoptr(virBitmap) nodeset = NULL;
    xmlNodePtr node = NULL;

    if (virXPathBoolean("count(./numatune) > 1", ctxt) == 1) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("only one numatune is supported"));
        return -1;
    }

    node = virXPathNode("./numatune/memory[1]", ctxt);

    if (!placement_static && !node)
        placement = VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO;

    if (node) {
        if ((modestr = virXMLPropString(node, "mode")) &&
            (mode = virDomainNumatuneMemModeTypeFromString(modestr)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory tuning mode '%1$s'"), modestr);
            return -1;
        }

        if ((placementstr = virXMLPropString(node, "placement")) &&
            (placement = virDomainNumatunePlacementTypeFromString(placementstr)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported NUMA memory placement mode '%1$s'"), placementstr);
            return -1;
        }

        if ((nodesetstr = virXMLPropString(node, "nodeset"))) {
            if (virBitmapParse(nodesetstr, &nodeset, VIR_DOMAIN_CPUMASK_LEN) < 0)
                return -1;

            if (virBitmapIsAllClear(nodeset)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid value of 'nodeset': %1$s"), nodesetstr);
                return -1;
            }
        }
    }

    if (virDomainNumatuneSet(numa,
                             placement_static,
                             placement,
                             mode,
                             nodeset) < 0)
        return -1;

    if (virDomainNumatuneNodeParseXML(numa, ctxt) < 0)
        return -1;

    return 0;
}

int
virDomainNumatuneFormatXML(virBuffer *buf,
                           virDomainNuma *numatune)
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
        virDomainNumaNode *mem_node = &numatune->mem_nodes[i];

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
virDomainNumaFree(virDomainNuma *numa)
{
    size_t i = 0;

    if (!numa)
        return;

    virBitmapFree(numa->memory.nodeset);
    for (i = 0; i < numa->nmem_nodes; i++) {
        virBitmapFree(numa->mem_nodes[i].cpumask);
        virBitmapFree(numa->mem_nodes[i].nodeset);

        if (numa->mem_nodes[i].ndistances > 0)
            g_free(numa->mem_nodes[i].distances);

        g_free(numa->mem_nodes[i].caches);
    }
    g_free(numa->mem_nodes);

    g_free(numa->interconnects);

    g_free(numa);
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
int virDomainNumatuneGetMode(virDomainNuma *numatune,
                             int cellid,
                             virDomainNumatuneMemMode *mode)
{
    virDomainNumatuneMemMode tmp_mode;

    if (!numatune)
        return -1;

    if (virDomainNumatuneNodeSpecified(numatune, cellid))
        tmp_mode = numatune->mem_nodes[cellid].mode;
    else if (numatune->memory.specified)
        tmp_mode = numatune->memory.mode;
    else
        return -1;

    if (mode)
        *mode = tmp_mode;

    return 0;
}

virBitmap *
virDomainNumatuneGetNodeset(virDomainNuma *numatune,
                            virBitmap *auto_nodeset,
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
virDomainNumatuneFormatNodeset(virDomainNuma *numatune,
                               virBitmap *auto_nodeset,
                               int cellid)
{
    return virBitmapFormat(virDomainNumatuneGetNodeset(numatune,
                                                       auto_nodeset,
                                                       cellid));
}


int
virDomainNumatuneMaybeGetNodeset(virDomainNuma *numatune,
                                 virBitmap *auto_nodeset,
                                 virBitmap **retNodeset,
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
                       _("Advice from numad is needed in case of automatic numa placement"));
        return -1;
    }

    *retNodeset = virDomainNumatuneGetNodeset(numatune, auto_nodeset, cellid);

    return 0;
}


int
virDomainNumatuneMaybeFormatNodeset(virDomainNuma *numatune,
                                    virBitmap *auto_nodeset,
                                    char **mask,
                                    int cellid)
{
    virBitmap *nodeset;

    if (virDomainNumatuneMaybeGetNodeset(numatune, auto_nodeset, &nodeset,
                                         cellid) < 0)
        return -1;

    if (nodeset &&
        !(*mask = virBitmapFormat(nodeset)))
        return -1;

    return 0;
}

int
virDomainNumatuneSet(virDomainNuma *numa,
                     bool placement_static,
                     int placement,
                     int mode,
                     virBitmap *nodeset)
{
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
                       _("Unsupported numatune mode '%1$d'"),
                       mode);
        return -1;
    }

    if (placement != -1 &&
        (placement < 0 || placement >= VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported numatune placement '%1$d'"),
                       placement);
        return -1;
    }

    if (mode != -1)
        numa->memory.mode = mode;

    if (nodeset) {
        virBitmapFree(numa->memory.nodeset);
        numa->memory.nodeset = virBitmapNewCopy(nodeset);

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
                       _("nodeset for NUMA memory tuning must be set if 'placement' is 'static'"));
        return -1;
    }

    /* setting nodeset when placement auto is invalid */
    if (placement == VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO &&
        numa->memory.nodeset) {
        g_clear_pointer(&numa->memory.nodeset, virBitmapFree);
    }

    if (placement != -1)
        numa->memory.placement = placement;

    numa->memory.specified = true;

    return 0;
}

static bool
virDomainNumaNodesEqual(virDomainNuma *n1,
                        virDomainNuma *n2)
{
    size_t i = 0;

    if (n1->nmem_nodes != n2->nmem_nodes)
        return false;

    for (i = 0; i < n1->nmem_nodes; i++) {
        virDomainNumaNode *nd1 = &n1->mem_nodes[i];
        virDomainNumaNode *nd2 = &n2->mem_nodes[i];

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
virDomainNumaEquals(virDomainNuma *n1,
                    virDomainNuma *n2)
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
virDomainNumatuneHasPlacementAuto(virDomainNuma *numatune)
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
virDomainNumatuneHasPerNodeBinding(virDomainNuma *numatune)
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
virDomainNumatuneSpecifiedMaxNode(virDomainNuma *numatune)
{
    int ret = -1;
    virBitmap *nodemask = NULL;
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
virDomainNumatuneNodesetIsAvailable(virDomainNuma *numatune,
                                    virBitmap *auto_nodeset)
{
    size_t i = 0;
    virBitmap *b = NULL;

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


static int
virDomainNumaDefNodeDistanceParseXML(virDomainNuma *def,
                                     xmlXPathContextPtr ctxt,
                                     unsigned int cur_cell)
{
    int ret = -1;
    int sibling;
    xmlNodePtr *nodes = NULL;
    size_t i, ndistances = def->nmem_nodes;

    if (ndistances == 0)
        return 0;

    /* check if NUMA distances definition is present */
    if (!virXPathNode("./distances[1]", ctxt))
        return 0;

    if ((sibling = virXPathNodeSet("./distances[1]/sibling", ctxt, &nodes)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("NUMA distances defined without siblings"));
        goto cleanup;
    }

    for (i = 0; i < sibling; i++) {
        virNumaDistance *ldist;
        virNumaDistance *rdist;
        unsigned int sibling_id, sibling_value;

        if (virXMLPropUInt(nodes[i], "id", 10, VIR_XML_PROP_REQUIRED,
                           &sibling_id) < 0)
            goto cleanup;

        /* The "id" needs to be within numa/cell range */
        if (sibling_id >= ndistances) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("'sibling_id %1$d' does not refer to a valid cell within NUMA 'cell id %2$d'"),
                           sibling_id, cur_cell);
            goto cleanup;
        }

        if (virXMLPropUInt(nodes[i], "value", 10, VIR_XML_PROP_REQUIRED,
                           &sibling_value) < 0)
            goto cleanup;

        /* Assure LOCAL_DISTANCE <= "value" <= UNREACHABLE
         * and correct LOCAL_DISTANCE setting if such applies.
         */
        if ((sibling_value < LOCAL_DISTANCE ||
             sibling_value > UNREACHABLE) ||
            (sibling_id == cur_cell &&
             sibling_value != LOCAL_DISTANCE) ||
            (sibling_id != cur_cell &&
             sibling_value == LOCAL_DISTANCE)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("'value %1$d' is invalid for 'sibling id %2$d' under NUMA 'cell id %3$d'"),
                           sibling_value, sibling_id, cur_cell);
            goto cleanup;
        }

        /* Apply the local / remote distance */
        ldist = def->mem_nodes[cur_cell].distances;
        if (!ldist) {
            ldist = g_new0(virNumaDistance, ndistances);
            ldist[cur_cell].value = LOCAL_DISTANCE;
            ldist[cur_cell].cellid = cur_cell;
            def->mem_nodes[cur_cell].ndistances = ndistances;
            def->mem_nodes[cur_cell].distances = ldist;
        }

        ldist[sibling_id].cellid = sibling_id;
        ldist[sibling_id].value = sibling_value;

        /* Apply symmetry if none given */
        rdist = def->mem_nodes[sibling_id].distances;
        if (!rdist) {
            rdist = g_new0(virNumaDistance, ndistances);
            rdist[sibling_id].value = LOCAL_DISTANCE;
            rdist[sibling_id].cellid = sibling_id;
            def->mem_nodes[sibling_id].ndistances = ndistances;
            def->mem_nodes[sibling_id].distances = rdist;
        }

        rdist[cur_cell].cellid = cur_cell;
        if (!rdist[cur_cell].value)
            rdist[cur_cell].value = sibling_value;
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        for (i = 0; i < ndistances; i++)
            VIR_FREE(def->mem_nodes[i].distances);
        def->mem_nodes[i].ndistances = 0;
    }
    VIR_FREE(nodes);

    return ret;
}


static int
virDomainNumaDefNodeCacheParseXML(virDomainNuma *def,
                                  xmlXPathContextPtr ctxt,
                                  unsigned int cur_cell)
{
    g_autofree xmlNodePtr *nodes = NULL;
    int n;
    size_t i;

    if ((n = virXPathNodeSet("./cache", ctxt, &nodes)) < 0)
        return -1;

    def->mem_nodes[cur_cell].caches = g_new0(virNumaCache, n);

    for (i = 0; i < n; i++) {
        VIR_XPATH_NODE_AUTORESTORE(ctxt)
        virNumaCache *cache = &def->mem_nodes[cur_cell].caches[i];
        unsigned long long line;

        if (virXMLPropUInt(nodes[i], "level", 10,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &cache->level) < 0)
            return -1;

        if (virXMLPropEnum(nodes[i], "associativity",
                           virNumaCacheAssociativityTypeFromString,
                           VIR_XML_PROP_REQUIRED,
                           &cache->associativity) < 0)
            return -1;

        if (virXMLPropEnum(nodes[i], "policy",
                           virNumaCachePolicyTypeFromString,
                           VIR_XML_PROP_REQUIRED,
                           &cache->policy) < 0)
            return -1;

        ctxt->node = nodes[i];
        if (virDomainParseMemory("./size/@value", "./size/unit",
                                 ctxt, &cache->size, true, false) < 0)
            return -1;

        if (virParseScaledValue("./line/@value", "./line/unit",
                                ctxt, &line, 1, ULLONG_MAX, true) < 0)
            return -1;

        cache->line = line;

        def->mem_nodes[cur_cell].ncaches++;
    }

    return 0;
}


int
virDomainNumaDefParseXML(virDomainNuma *def,
                         xmlXPathContextPtr ctxt)
{
    g_autofree xmlNodePtr *cell = NULL;
    g_autofree xmlNodePtr *interconnect = NULL;

    int n;
    size_t i, j;

    /* check if NUMA definition is present */
    if (!virXPathNode("./cpu/numa[1]", ctxt))
        return 0;

    if ((n = virXPathNodeSet("./cpu/numa[1]/cell", ctxt, &cell)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("NUMA topology defined without NUMA cells"));
        return -1;
    }

    def->mem_nodes = g_new0(struct _virDomainNumaNode, n);
    def->nmem_nodes = n;

    for (i = 0; i < n; i++) {
        VIR_XPATH_NODE_AUTORESTORE(ctxt)
        g_autofree char *tmp = NULL;
        unsigned int cur_cell;

        if (virXMLPropUIntDefault(cell[i], "id", 10, VIR_XML_PROP_NONE, &cur_cell, i) < 0)
            return -1;

        /* cells are in order of parsing or explicitly numbered */
        if (cur_cell >= n) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Exactly one 'cell' element per guest NUMA cell allowed, non-contiguous ranges or ranges not starting from 0 are not allowed"));
            return -1;
        }

        if (def->mem_nodes[cur_cell].mem) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Duplicate NUMA cell info for cell id '%1$u'"),
                           cur_cell);
            return -1;
        }

        if ((tmp = virXMLPropString(cell[i], "cpus"))) {
            g_autoptr(virBitmap) cpumask = NULL;

            if (virBitmapParse(tmp, &cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
                return -1;

            if (!virBitmapIsAllClear(cpumask))
                def->mem_nodes[cur_cell].cpumask = g_steal_pointer(&cpumask);
        }

        for (j = 0; j < n; j++) {
            if (j == cur_cell ||
                !def->mem_nodes[j].cpumask ||
                !def->mem_nodes[cur_cell].cpumask)
                continue;

            if (virBitmapOverlaps(def->mem_nodes[j].cpumask,
                                  def->mem_nodes[cur_cell].cpumask)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("NUMA cells %1$u and %2$zu have overlapping vCPU ids"),
                               cur_cell, j);
                return -1;
            }
        }

        ctxt->node = cell[i];
        if (virDomainParseMemory("./@memory", "./@unit", ctxt,
                                 &def->mem_nodes[cur_cell].mem, true, false) < 0)
            return -1;

        if (virXMLPropEnum(cell[i], "memAccess",
                           virDomainMemoryAccessTypeFromString,
                           VIR_XML_PROP_NONZERO,
                           &def->mem_nodes[cur_cell].memAccess) < 0)
            return -1;

        if (virXMLPropTristateBool(cell[i], "discard", VIR_XML_PROP_NONE,
                                   &def->mem_nodes[cur_cell].discard) < 0)
            return -1;

        /* Parse NUMA distances info */
        if (virDomainNumaDefNodeDistanceParseXML(def, ctxt, cur_cell) < 0)
            return -1;

        /* Parse cache info */
        if (virDomainNumaDefNodeCacheParseXML(def, ctxt, cur_cell) < 0)
            return -1;
    }

    if ((n = virXPathNodeSet("./cpu/numa[1]/interconnects[1]/latency|"
                             "./cpu/numa[1]/interconnects[1]/bandwidth", ctxt,
                             &interconnect)) < 0)
        return -1;

    def->interconnects = g_new0(virNumaInterconnect, n);
    for (i = 0; i < n; i++) {
        virNumaInterconnectType type;
        unsigned int initiator;
        unsigned int target;
        unsigned int cache = 0;
        virMemoryLatency accessType;
        unsigned long long value;

        if (virXMLNodeNameEqual(interconnect[i], "latency")) {
            type = VIR_NUMA_INTERCONNECT_TYPE_LATENCY;

            if (virXMLPropULongLong(interconnect[i], "value", 10,
                                    VIR_XML_PROP_REQUIRED, &value) < 0)
                return -1;
        } else if (virXMLNodeNameEqual(interconnect[i], "bandwidth")) {
            VIR_XPATH_NODE_AUTORESTORE(ctxt)
            type = VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH;

            ctxt->node = interconnect[i];

            if (virDomainParseMemory("./@value", "./@unit", ctxt, &value, true, false) < 0)
                return -1;
        } else {
            /* Ignore yet unknown child elements. */
            continue;
        }

        if (virXMLPropUInt(interconnect[i], "initiator", 10, VIR_XML_PROP_REQUIRED,
                           &initiator) < 0)
            return -1;

        if (virXMLPropUInt(interconnect[i], "target", 10, VIR_XML_PROP_REQUIRED,
                           &target) < 0)
            return -1;

        if (virXMLPropUInt(interconnect[i], "cache", 10, VIR_XML_PROP_NONE,
                           &cache) < 0)
            return -1;

        if (virXMLPropEnum(interconnect[i], "type",
                           virMemoryLatencyTypeFromString,
                           VIR_XML_PROP_REQUIRED | VIR_XML_PROP_NONZERO,
                           &accessType) < 0)
            return -1;

        def->interconnects[i] = (virNumaInterconnect) {type, initiator, target,
                                                       cache, accessType, value};
        def->ninterconnects++;
    }

    return 0;
}


int
virDomainNumaDefFormatXML(virBuffer *buf,
                          virDomainNuma *def)
{
    virDomainMemoryAccess memAccess;
    virTristateBool discard;
    size_t ncells = virDomainNumaGetNodeCount(def);
    size_t i;

    if (ncells == 0)
        return 0;

    virBufferAddLit(buf, "<numa>\n");
    virBufferAdjustIndent(buf, 2);
    for (i = 0; i < ncells; i++) {
        virBitmap *cpumask = virDomainNumaGetNodeCpumask(def, i);
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

        memAccess = virDomainNumaGetNodeMemoryAccessMode(def, i);
        discard = virDomainNumaGetNodeDiscard(def, i);

        virBufferAsprintf(&attrBuf, " id='%zu'", i);

        if (cpumask) {
            g_autofree char *cpustr = virBitmapFormat(cpumask);

            if (!cpustr)
                return -1;
            virBufferAsprintf(&attrBuf, " cpus='%s'", cpustr);
        }
        virBufferAsprintf(&attrBuf, " memory='%llu'",
                          virDomainNumaGetNodeMemorySize(def, i));
        virBufferAddLit(&attrBuf, " unit='KiB'");
        if (memAccess)
            virBufferAsprintf(&attrBuf, " memAccess='%s'",
                              virDomainMemoryAccessTypeToString(memAccess));

        if (discard)
            virBufferAsprintf(&attrBuf, " discard='%s'",
                              virTristateBoolTypeToString(discard));

        virNumaDistanceFormat(&childBuf,
                              def->mem_nodes[i].distances,
                              def->mem_nodes[i].ndistances);

        virNumaCacheFormat(&childBuf,
                           def->mem_nodes[i].caches,
                           def->mem_nodes[i].ncaches);

        virXMLFormatElement(buf, "cell", &attrBuf, &childBuf);
    }

    virNumaInterconnectFormat(buf, def->interconnects, def->ninterconnects);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</numa>\n");

    return 0;
}


int
virDomainNumaDefValidate(const virDomainNuma *def)
{
    size_t i;
    size_t j;

    if (!def)
        return 0;

    for (i = 0; i < def->nmem_nodes; i++) {
        const virDomainNumaNode *node = &def->mem_nodes[i];
        g_autoptr(virBitmap) levelsSeen = virBitmapNew(0);

        if (virDomainNumatuneNodeSpecified(def, i)) {
            if (def->memory.mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE &&
                node->mode != VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'restrictive' mode is required in memnode element when mode is 'restrictive' in memory element"));
                return -1;
            }

            if (node->mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE &&
                def->memory.mode != VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'restrictive' mode is required in memory element when mode is 'restrictive' in memnode element"));
                return -1;
            }
        }

        for (j = 0; j < node->ncaches; j++) {
            const virNumaCache *cache = &node->caches[j];

            /* Relax this if there's ever fourth layer of cache */
            if (cache->level > 3) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Ain't nobody heard of that much cache level"));
                return -1;
            }

            if (virBitmapIsBitSet(levelsSeen, cache->level)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Cache level '%1$u' already defined"),
                               cache->level);
                return -1;
            }

            virBitmapSetBitExpand(levelsSeen, cache->level);
        }
    }

    for (i = 0; i < def->ninterconnects; i++) {
        const virNumaInterconnect *l = &def->interconnects[i];

        if (l->initiator >= def->nmem_nodes) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'initiator' refers to a non-existent NUMA node"));
            return -1;
        }

        if (l->target >= def->nmem_nodes) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("'target' refers to a non-existent NUMA node"));
            return -1;
        }

        if (!def->mem_nodes[l->initiator].cpumask) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("NUMA nodes without CPUs can't be initiator"));
            return -1;
        }

        if (l->cache > 0) {
            for (j = 0; j < def->mem_nodes[l->target].ncaches; j++) {
                const virNumaCache *cache = &def->mem_nodes[l->target].caches[j];

                if (l->cache == cache->level)
                    break;
            }

            if (j == def->mem_nodes[l->target].ncaches) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("'cache' refers to a non-existent NUMA node cache"));
                return -1;
            }
        }

        for (j = 0; j < i; j++) {
            const virNumaInterconnect *ll = &def->interconnects[j];

            if (l->type == ll->type &&
                l->initiator == ll->initiator &&
                l->target == ll->target &&
                l->cache == ll->cache &&
                l->accessType == ll->accessType) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Duplicate info for NUMA latencies"));
                return -1;
            }


            if (l->initiator != l->target &&
                l->initiator == ll->target &&
                l->target == ll->initiator) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Link already defined"));
                return -1;
            }
        }
    }

    return 0;
}


unsigned int
virDomainNumaGetCPUCountTotal(virDomainNuma *numa)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++) {
        virBitmap *cpumask = virDomainNumaGetNodeCpumask(numa, i);

        if (cpumask)
            ret += virBitmapCountBits(cpumask);
    }

    return ret;
}

unsigned int
virDomainNumaGetMaxCPUID(virDomainNuma *numa)
{
    size_t i;
    unsigned int ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++) {
        virBitmap *cpumask = virDomainNumaGetNodeCpumask(numa, i);
        int bit;

        if (cpumask) {
            bit = virBitmapLastSetBit(cpumask);
            if (bit > ret)
                ret = bit;
        }
    }

    return ret;
}


virDomainNuma *
virDomainNumaNew(void)
{
    return g_new0(virDomainNuma, 1);
}


bool
virDomainNumaCheckABIStability(virDomainNuma *src,
                               virDomainNuma *tgt)
{
    size_t i;
    size_t j;

    if (virDomainNumaGetNodeCount(src) != virDomainNumaGetNodeCount(tgt)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Target NUMA node count '%1$zu' doesn't match source '%2$zu'"),
                       virDomainNumaGetNodeCount(tgt),
                       virDomainNumaGetNodeCount(src));
        return false;
    }

    for (i = 0; i < virDomainNumaGetNodeCount(src); i++) {
        if (virDomainNumaGetNodeMemorySize(src, i) !=
            virDomainNumaGetNodeMemorySize(tgt, i)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Size of target NUMA node %1$zu (%2$llu) doesn't match source (%3$llu)"),
                           i,
                           virDomainNumaGetNodeMemorySize(tgt, i),
                           virDomainNumaGetNodeMemorySize(src, i));
            return false;
        }

        if (!virBitmapEqual(virDomainNumaGetNodeCpumask(src, i),
                            virDomainNumaGetNodeCpumask(tgt, i))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Processor mask of target NUMA node %1$zu doesn't match source"),
                           i);
            return false;
        }

        for (j = 0; j < virDomainNumaGetNodeCount(src); j++) {
            if (virDomainNumaGetNodeDistance(src, i, j) !=
                virDomainNumaGetNodeDistance(tgt, i, j)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Target NUMA distance from %1$zu to %2$zu doesn't match source"),
                               i, j);

                return false;
            }
        }
    }

    return true;
}


size_t
virDomainNumaGetNodeCount(virDomainNuma *numa)
{
    if (!numa)
        return 0;

    return numa->nmem_nodes;
}


size_t
virDomainNumaSetNodeCount(virDomainNuma *numa, size_t nmem_nodes)
{
    if (!nmem_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set an empty mem_nodes set"));
        return 0;
    }

    if (numa->mem_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot alter an existing mem_nodes set"));
        return 0;
    }

    numa->mem_nodes = g_new0(struct _virDomainNumaNode, nmem_nodes);

    numa->nmem_nodes = nmem_nodes;

    return numa->nmem_nodes;
}


bool
virDomainNumaNodeDistanceIsUsingDefaults(virDomainNuma *numa,
                                         size_t node,
                                         size_t sibling)
{
    if (node >= numa->nmem_nodes ||
        sibling >= numa->nmem_nodes)
        return false;

    if (!numa->mem_nodes[node].distances)
        return true;

    if (numa->mem_nodes[node].distances[sibling].value == LOCAL_DISTANCE ||
        numa->mem_nodes[node].distances[sibling].value == REMOTE_DISTANCE)
        return true;

    return false;
}


bool
virDomainNumaNodesDistancesAreBeingSet(virDomainNuma *numa)
{
    size_t ncells = virDomainNumaGetNodeCount(numa);
    size_t i, j;

    for (i = 0; i < ncells; i++) {
        for (j = 0; j < ncells; j++) {
            if (virDomainNumaNodeDistanceIsUsingDefaults(numa, i, j))
                continue;

            return true;
        }
    }

    return false;
}


size_t
virDomainNumaGetNodeDistance(virDomainNuma *numa,
                             size_t node,
                             size_t cellid)
{
    virNumaDistance *distances = NULL;

    if (node < numa->nmem_nodes)
        distances = numa->mem_nodes[node].distances;

    /*
     * Present the configured distance value. If
     * out of range or not available set the platform
     * defined default for local and remote nodes.
     */
    if (!distances ||
        cellid >= numa->nmem_nodes ||
        !distances[cellid].value)
        return (node == cellid) ? LOCAL_DISTANCE : REMOTE_DISTANCE;

    return distances[cellid].value;
}


int
virDomainNumaSetNodeDistance(virDomainNuma *numa,
                             size_t node,
                             size_t cellid,
                             unsigned int value)
{
    virNumaDistance *distances;

    if (node >= numa->nmem_nodes) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Argument 'node' %1$zu outranges defined number of NUMA nodes"),
                       node);
        return -1;
    }

    distances = numa->mem_nodes[node].distances;
    if (!distances ||
        cellid >= numa->mem_nodes[node].ndistances) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Arguments under memnode element do not correspond with existing guest's NUMA cell"));
        return -1;
    }

    /*
     * Advanced Configuration and Power Interface
     * Specification version 6.1. Chapter 5.2.17
     * System Locality Distance Information Table
     * ... Distance values of 0-9 are reserved.
     */
    if (value < LOCAL_DISTANCE ||
        value > UNREACHABLE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Distance value of %1$d is not in valid range"),
                       value);
        return -1;
    }

    if (value == LOCAL_DISTANCE && node != cellid) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Distance value %1$d under node %2$zu is LOCAL_DISTANCE and should be set to 10"),
                       value, node);
        return -1;
    }

    distances[cellid].cellid = cellid;
    distances[cellid].value = value;

    return distances[cellid].value;
}


size_t
virDomainNumaSetNodeDistanceCount(virDomainNuma *numa,
                                  size_t node,
                                  size_t ndistances)
{
    virNumaDistance *distances;

    distances = numa->mem_nodes[node].distances;
    if (distances) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot alter an existing nmem_nodes distances set for node: %1$zu"),
                       node);
        return 0;
    }

    distances = g_new0(virNumaDistance, ndistances);

    numa->mem_nodes[node].distances = distances;
    numa->mem_nodes[node].ndistances = ndistances;

    return numa->mem_nodes[node].ndistances;
}


virBitmap *
virDomainNumaGetNodeCpumask(virDomainNuma *numa,
                            size_t node)
{
    return numa->mem_nodes[node].cpumask;
}


void
virDomainNumaSetNodeCpumask(virDomainNuma *numa,
                            size_t node,
                            virBitmap *cpumask)
{
    numa->mem_nodes[node].cpumask = cpumask;
}


virDomainMemoryAccess
virDomainNumaGetNodeMemoryAccessMode(virDomainNuma *numa,
                                     size_t node)
{
    return numa->mem_nodes[node].memAccess;
}


virTristateBool
virDomainNumaGetNodeDiscard(virDomainNuma *numa,
                            size_t node)
{
    return numa->mem_nodes[node].discard;
}


unsigned long long
virDomainNumaGetNodeMemorySize(virDomainNuma *numa,
                               size_t node)
{
    return numa->mem_nodes[node].mem;
}


void
virDomainNumaSetNodeMemorySize(virDomainNuma *numa,
                               size_t node,
                               unsigned long long size)
{
    numa->mem_nodes[node].mem = size;
}


unsigned long long
virDomainNumaGetMemorySize(virDomainNuma *numa)
{
    size_t i;
    unsigned long long ret = 0;

    for (i = 0; i < numa->nmem_nodes; i++)
        ret += numa->mem_nodes[i].mem;

    return ret;
}


int
virDomainNumaFillCPUsInNode(virDomainNuma *numa,
                            size_t node,
                            unsigned int maxCpus)
{
    g_autoptr(virBitmap) maxCPUsBitmap = virBitmapNew(maxCpus);
    size_t i;

    if (node >= virDomainNumaGetNodeCount(numa))
        return -1;

    virBitmapSetAll(maxCPUsBitmap);

    for (i = 0; i < numa->nmem_nodes; i++) {
        virBitmap *nodeCpus = virDomainNumaGetNodeCpumask(numa, i);

        if (i == node || !nodeCpus)
            continue;

        virBitmapSubtract(maxCPUsBitmap, nodeCpus);
    }

    if (!virBitmapEqual(numa->mem_nodes[node].cpumask, maxCPUsBitmap)) {
        virBitmapFree(numa->mem_nodes[node].cpumask);
        numa->mem_nodes[node].cpumask = g_steal_pointer(&maxCPUsBitmap);
    }

    return 0;
}


bool
virDomainNumaHasHMAT(const virDomainNuma *numa)
{
    size_t i;

    if (!numa)
        return false;

    if (numa->ninterconnects)
        return true;

    for (i = 0; i < numa->nmem_nodes; i++) {
        if (numa->mem_nodes[i].ncaches)
            return true;
    }

    return false;
}


size_t
virDomainNumaGetNodeCacheCount(const virDomainNuma *numa,
                               size_t node)
{
    if (!numa || node >= numa->nmem_nodes)
        return 0;

    return numa->mem_nodes[node].ncaches;
}


int
virDomainNumaGetNodeCache(const virDomainNuma *numa,
                          size_t node,
                          size_t cache,
                          unsigned int *level,
                          unsigned int *size,
                          unsigned int *line,
                          virNumaCacheAssociativity *associativity,
                          virNumaCachePolicy *policy)
{
    const virDomainNumaNode *cell;

    if (!numa || node >= numa->nmem_nodes)
        return -1;

    cell = &numa->mem_nodes[node];

    if (cache >= cell->ncaches)
        return -1;

    *level = cell->caches[cache].level;
    *size = cell->caches[cache].size;
    *line = cell->caches[cache].line;
    *associativity = cell->caches[cache].associativity;
    *policy = cell->caches[cache].policy;
    return 0;
}


ssize_t
virDomainNumaGetNodeInitiator(const virDomainNuma *numa,
                              size_t node)
{
    size_t i;
    unsigned int maxBandwidth = 0;
    ssize_t candidateBandwidth = -1;
    unsigned int minLatency = UINT_MAX;
    ssize_t candidateLatency = -1;

    if (!numa || node >= numa->nmem_nodes)
        return -1;

    /* A NUMA node which has at least one vCPU is initiator to itself by
     * definition. */
    if (numa->mem_nodes[node].cpumask)
        return node;

    /* For the rest, "NUMA node that has best performance (the lowest
     * latency or largest bandwidth) to this NUMA node." */
    for (i = 0; i < numa->ninterconnects; i++) {
        const virNumaInterconnect *l = &numa->interconnects[i];

        if (l->target != node)
            continue;

        switch (l->type) {
        case VIR_NUMA_INTERCONNECT_TYPE_LATENCY:
            if (l->value < minLatency) {
                minLatency = l->value;
                candidateLatency = l->initiator;
            }
            break;

        case VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH:
            if (l->value > maxBandwidth) {
                maxBandwidth = l->value;
                candidateBandwidth = l->initiator;
            }
            break;
        }
    }

    if (candidateLatency >= 0)
        return candidateLatency;

    return candidateBandwidth;
}


size_t
virDomainNumaGetInterconnectsCount(const virDomainNuma *numa)
{
    if (!numa)
        return 0;

    return numa->ninterconnects;
}


int
virDomainNumaGetInterconnect(const virDomainNuma *numa,
                             size_t i,
                             virNumaInterconnectType *type,
                             unsigned int *initiator,
                             unsigned int *target,
                             unsigned int *cache,
                             virMemoryLatency *accessType,
                             unsigned long *value)
{
    const virNumaInterconnect *l;

    if (!numa || i >= numa->ninterconnects)
        return -1;

    l = &numa->interconnects[i];
    *type = l->type;
    *initiator = l->initiator;
    *target = l->target;
    *cache = l->cache;
    *accessType = l->accessType;
    *value = l->value;
    return 0;
}


void
virNumaDistanceFormat(virBuffer *buf,
                      const virNumaDistance *distances,
                      size_t ndistances)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    for (i = 0; i < ndistances; i++) {
        if (distances[i].value == 0)
            continue;
        virBufferAddLit(&childBuf, "<sibling");
        virBufferAsprintf(&childBuf, " id='%d'", distances[i].cellid);
        virBufferAsprintf(&childBuf, " value='%d'", distances[i].value);
        virBufferAddLit(&childBuf, "/>\n");
    }

    virXMLFormatElement(buf, "distances", NULL, &childBuf);
}


void
virNumaCacheFormat(virBuffer *buf,
                   const virNumaCache *caches,
                   size_t ncaches)
{
    size_t i;

    for (i = 0; i < ncaches; i++) {
        const virNumaCache *cache = &caches[i];
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);

        virBufferAsprintf(&attrBuf, " level='%u'", cache->level);
        virBufferAsprintf(&attrBuf, " associativity='%s'",
                          virNumaCacheAssociativityTypeToString(cache->associativity));
        virBufferAsprintf(&attrBuf, " policy='%s'",
                          virNumaCachePolicyTypeToString(cache->policy));

        virBufferAsprintf(&childBuf,
                          "<size value='%llu' unit='KiB'/>\n",
                          cache->size);

        if (cache->line) {
            virBufferAsprintf(&childBuf,
                              "<line value='%u' unit='B'/>\n",
                              cache->line);
        }

        virXMLFormatElement(buf, "cache", &attrBuf, &childBuf);
    }
}


void
virNumaInterconnectFormat(virBuffer *buf,
                          const virNumaInterconnect *interconnects,
                          size_t ninterconnects)
{
    g_auto(virBuffer) childBuf = VIR_BUFFER_INIT_CHILD(buf);
    size_t i;

    for (i = 0; i < ninterconnects; i++) {
        const virNumaInterconnect *l = &interconnects[i];
        g_auto(virBuffer) attrBuf = VIR_BUFFER_INITIALIZER;
        const char *elem = NULL;

        switch (l->type) {
        case VIR_NUMA_INTERCONNECT_TYPE_LATENCY:
            elem = "latency";
            break;
        case VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH:
            elem = "bandwidth";
            break;
        }

        virBufferAsprintf(&attrBuf,
                          " initiator='%u' target='%u'",
                          l->initiator, l->target);

        if (l->cache > 0) {
            virBufferAsprintf(&attrBuf,
                              " cache='%u'",
                              l->cache);
        }

        virBufferAsprintf(&attrBuf,
                          " type='%s' value='%lu'",
                          virMemoryLatencyTypeToString(l->accessType),
                          l->value);

        if (l->type == VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH)
            virBufferAddLit(&attrBuf, " unit='KiB'");

        virXMLFormatElement(&childBuf, elem, &attrBuf, NULL);
    }

    virXMLFormatElement(buf, "interconnects", NULL, &childBuf);
}
