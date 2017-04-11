/*
 * virsh-host.c: Commands in "Host and Hypervisor" group.
 *
 * Copyright (C) 2005, 2007-2014 Red Hat, Inc.
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
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include <config.h>
#include "virsh-host.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virxml.h"
#include "virtypedparam.h"
#include "virstring.h"

/*
 * "capabilities" command
 */
static const vshCmdInfo info_capabilities[] = {
    {.name = "help",
     .data = N_("capabilities")
    },
    {.name = "desc",
     .data = N_("Returns capabilities of hypervisor/driver.")
    },
    {.name = NULL}
};

static bool
cmdCapabilities(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;
    virshControlPtr priv = ctl->privData;

    if ((caps = virConnectGetCapabilities(priv->conn)) == NULL) {
        vshError(ctl, "%s", _("failed to get capabilities"));
        return false;
    }
    vshPrint(ctl, "%s\n", caps);
    VIR_FREE(caps);

    return true;
}

/*
 * "domcapabilities" command
 */
static const vshCmdInfo info_domcapabilities[] = {
    {.name = "help",
     .data = N_("domain capabilities")
    },
    {.name = "desc",
     .data = N_("Returns capabilities of emulator with respect to host and libvirt.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domcapabilities[] = {
    {.name = "virttype",
     .type = VSH_OT_STRING,
     .help = N_("virtualization type (/domain/@type)"),
    },
    {.name = "emulatorbin",
     .type = VSH_OT_STRING,
     .help = N_("path to emulator binary (/domain/devices/emulator)"),
    },
    {.name = "arch",
     .type = VSH_OT_STRING,
     .help = N_("domain architecture (/domain/os/type/@arch)"),
    },
    {.name = "machine",
     .type = VSH_OT_STRING,
     .help = N_("machine type (/domain/os/type/@machine)"),
    },
    {.name = NULL}
};

static bool
cmdDomCapabilities(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    char *caps = NULL;
    const char *virttype = NULL;
    const char *emulatorbin = NULL;
    const char *arch = NULL;
    const char *machine = NULL;
    const unsigned int flags = 0; /* No flags so far */
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "virttype", &virttype) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "emulatorbin", &emulatorbin) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "arch", &arch) < 0 ||
        vshCommandOptStringReq(ctl, cmd, "machine", &machine) < 0)
        return ret;

    caps = virConnectGetDomainCapabilities(priv->conn, emulatorbin,
                                           arch, machine, virttype, flags);
    if (!caps) {
        vshError(ctl, "%s", _("failed to get emulator capabilities"));
        goto cleanup;
    }

    vshPrint(ctl, "%s\n", caps);
    ret = true;
 cleanup:
    VIR_FREE(caps);
    return ret;
}

/*
 * "freecell" command
 */
static const vshCmdInfo info_freecell[] = {
    {.name = "help",
     .data = N_("NUMA free memory")
    },
    {.name = "desc",
     .data = N_("display available free memory for the NUMA cell.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_freecell[] = {
    {.name = "cellno",
     .type = VSH_OT_INT,
     .help = N_("NUMA cell number")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("show free memory for all NUMA cells")
    },
    {.name = NULL}
};

static bool
cmdFreecell(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    int cell = -1;
    unsigned long long memory = 0;
    xmlNodePtr *nodes = NULL;
    unsigned long nodes_cnt;
    unsigned long *nodes_id = NULL;
    unsigned long long *nodes_free = NULL;
    bool all = vshCommandOptBool(cmd, "all");
    bool cellno = vshCommandOptBool(cmd, "cellno");
    size_t i;
    char *cap_xml = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virshControlPtr priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(all, cellno);

    if (cellno && vshCommandOptInt(ctl, cmd, "cellno", &cell) < 0)
        return false;

    if (all) {
        if (!(cap_xml = virConnectGetCapabilities(priv->conn))) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        xml = virXMLParseStringCtxt(cap_xml, _("(capabilities)"), &ctxt);
        if (!xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell",
                                    ctxt, &nodes);

        if (nodes_cnt == -1) {
            vshError(ctl, "%s", _("could not get information about "
                                  "NUMA topology"));
            goto cleanup;
        }

        nodes_free = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_free));
        nodes_id = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_id));

        for (i = 0; i < nodes_cnt; i++) {
            unsigned long id;
            char *val = virXMLPropString(nodes[i], "id");
            if (virStrToLong_ulp(val, NULL, 10, &id)) {
                vshError(ctl, "%s", _("conversion from string failed"));
                VIR_FREE(val);
                goto cleanup;
            }
            VIR_FREE(val);
            nodes_id[i] = id;
            if (virNodeGetCellsFreeMemory(priv->conn, &(nodes_free[i]),
                                          id, 1) != 1) {
                vshError(ctl, _("failed to get free memory for NUMA node "
                                "number: %lu"), id);
                goto cleanup;
            }
        }

        for (cell = 0; cell < nodes_cnt; cell++) {
            vshPrint(ctl, "%5lu: %10llu KiB\n", nodes_id[cell],
                    (nodes_free[cell]/1024));
            memory += nodes_free[cell];
        }

        vshPrintExtra(ctl, "--------------------\n");
        vshPrintExtra(ctl, "%5s: %10llu KiB\n", _("Total"), memory/1024);
    } else {
        if (cellno) {
            if (virNodeGetCellsFreeMemory(priv->conn, &memory, cell, 1) != 1)
                goto cleanup;

            vshPrint(ctl, "%d: %llu KiB\n", cell, (memory/1024));
        } else {
            if ((memory = virNodeGetFreeMemory(priv->conn)) == 0)
                goto cleanup;

            vshPrint(ctl, "%s: %llu KiB\n", _("Total"), (memory/1024));
        }
    }

    ret = true;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(nodes);
    VIR_FREE(nodes_free);
    VIR_FREE(nodes_id);
    VIR_FREE(cap_xml);
    return ret;
}


/*
 * "freepages" command
 */
static const vshCmdInfo info_freepages[] = {
    {.name = "help",
     .data = N_("NUMA free pages")
    },
    {.name = "desc",
     .data = N_("display available free pages for the NUMA cell.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_freepages[] = {
    {.name = "cellno",
     .type = VSH_OT_INT,
     .help = N_("NUMA cell number")
    },
    {.name = "pagesize",
     .type = VSH_OT_INT,
     .help = N_("page size (in kibibytes)")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("show free pages for all NUMA cells")
    },
    {.name = NULL}
};

static int
vshPageSizeSorter(const void *a, const void *b)
{
    unsigned int pa = *(unsigned int *)a;
    unsigned int pb = *(unsigned int *)b;

    return pa - pb;
}

static bool
cmdFreepages(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    unsigned int npages;
    unsigned int *pagesize = NULL;
    unsigned long long bytes = 0;
    unsigned int kibibytes = 0;
    int cell;
    unsigned long long *counts = NULL;
    size_t i, j;
    xmlNodePtr *nodes = NULL;
    int nodes_cnt;
    char *cap_xml = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    bool all = vshCommandOptBool(cmd, "all");
    bool cellno = vshCommandOptBool(cmd, "cellno");
    bool pagesz = vshCommandOptBool(cmd, "pagesize");
    virshControlPtr priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(all, cellno);

    if (vshCommandOptScaledInt(ctl, cmd, "pagesize", &bytes, 1024, UINT_MAX) < 0)
        goto cleanup;
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (all) {
        if (!(cap_xml = virConnectGetCapabilities(priv->conn))) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        if (!(doc = virXMLParseStringCtxt(cap_xml, _("capabilities"), &ctxt))) {
            vshError(ctl, "%s", _("unable to parse node capabilities"));
            goto cleanup;
        }

        if (!pagesz) {
            nodes_cnt = virXPathNodeSet("/capabilities/host/cpu/pages", ctxt, &nodes);

            if (nodes_cnt <= 0) {
                /* Some drivers don't export page sizes under the
                 * XPath above. Do another trick to get them. */
                nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell/pages",
                                            ctxt, &nodes);
                if (nodes_cnt <= 0) {
                    vshError(ctl, "%s", _("could not get information about "
                                          "supported page sizes"));
                    goto cleanup;
                }
            }

            pagesize = vshCalloc(ctl, nodes_cnt, sizeof(*pagesize));

            for (i = 0; i < nodes_cnt; i++) {
                char *val = virXMLPropString(nodes[i], "size");

                if (virStrToLong_uip(val, NULL, 10, &pagesize[i]) < 0) {
                    vshError(ctl, _("unable to parse page size: %s"), val);
                    VIR_FREE(val);
                    goto cleanup;
                }

                VIR_FREE(val);
            }

            /* Here, if we've done the trick few lines above,
             * @pagesize array will contain duplicates. We should
             * remove them otherwise not very nice output will be
             * produced. */
            qsort(pagesize, nodes_cnt, sizeof(*pagesize), vshPageSizeSorter);

            for (i = 0; i < nodes_cnt - 1;) {
                if (pagesize[i] == pagesize[i + 1]) {
                    memmove(pagesize + i, pagesize + i + 1,
                            (nodes_cnt - i + 1) * sizeof(*pagesize));
                    nodes_cnt--;
                } else {
                    i++;
                }
            }

            npages = nodes_cnt;
            VIR_FREE(nodes);
        } else {
            pagesize = vshMalloc(ctl, sizeof(*pagesize));
            pagesize[0] = kibibytes;
            npages = 1;
        }

        counts = vshCalloc(ctl, npages, sizeof(*counts));

        nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell",
                                    ctxt, &nodes);
        for (i = 0; i < nodes_cnt; i++) {
            char *val = virXMLPropString(nodes[i], "id");

            if (virStrToLong_i(val, NULL, 10, &cell) < 0) {
                vshError(ctl, _("unable to parse numa node id: %s"), val);
                VIR_FREE(val);
                goto cleanup;
            }
            VIR_FREE(val);

            if (virNodeGetFreePages(priv->conn, npages, pagesize,
                                    cell, 1, counts, 0) < 0)
                goto cleanup;

            vshPrint(ctl, _("Node %d:\n"), cell);
            for (j = 0; j < npages; j++)
                vshPrint(ctl, "%uKiB: %lld\n", pagesize[j], counts[j]);
            vshPrint(ctl, "%c", '\n');
        }

    } else {
        if (!cellno) {
            vshError(ctl, "%s", _("missing cellno argument"));
            goto cleanup;
        }

        if (vshCommandOptInt(ctl, cmd, "cellno", &cell) < 0)
            goto cleanup;

        if (cell < -1) {
            vshError(ctl, "%s",
                     _("cell number must be non-negative integer or -1"));
            goto cleanup;
        }

        if (!pagesz) {
            vshError(ctl, "%s", _("missing pagesize argument"));
            goto cleanup;
        }

        /* page size is expected in kibibytes */
        pagesize = vshMalloc(ctl, sizeof(*pagesize));
        pagesize[0] = kibibytes;

        counts = vshMalloc(ctl, sizeof(*counts));

        if (virNodeGetFreePages(priv->conn, 1, pagesize,
                                cell, 1, counts, 0) < 0)
            goto cleanup;

        vshPrint(ctl, "%uKiB: %lld\n", *pagesize, counts[0]);
    }

    ret = true;
 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    VIR_FREE(cap_xml);
    VIR_FREE(nodes);
    VIR_FREE(counts);
    VIR_FREE(pagesize);
    return ret;
}


/*
 * "allocpages" command
 */
static const vshCmdInfo info_allocpages[] = {
    {.name = "help",
     .data = N_("Manipulate pages pool size")
    },
    {.name = "desc",
     .data = N_("Allocate or free some pages in the pool for NUMA cell.")
    },
    {.name = NULL}
};
static const vshCmdOptDef opts_allocpages[] = {
    {.name = "pagesize",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("page size (in kibibytes)")
    },
    {.name = "pagecount",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("page count")
    },
    {.name = "cellno",
     .type = VSH_OT_INT,
     .help = N_("NUMA cell number")
    },
    {.name = "add",
     .type = VSH_OT_BOOL,
     .help = N_("instead of setting new pool size add pages to it")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("set on all NUMA cells")
    },
    {.name = NULL}
};

static bool
cmdAllocpages(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    bool add = vshCommandOptBool(cmd, "add");
    bool all = vshCommandOptBool(cmd, "all");
    bool cellno = vshCommandOptBool(cmd, "cellno");
    int startCell = -1;
    int cellCount = 1;
    unsigned int pageSizes[1];
    unsigned long long pageCounts[1], tmp;
    unsigned int flags = 0;
    char *cap_xml = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *nodes = NULL;
    virshControlPtr priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS_VAR(all, cellno);

    if (cellno && vshCommandOptInt(ctl, cmd, "cellno", &startCell) < 0)
        return false;

    if (vshCommandOptScaledInt(ctl, cmd, "pagesize", &tmp, 1024, UINT_MAX) < 0)
        return false;
    pageSizes[0] = VIR_DIV_UP(tmp, 1024);

    if (vshCommandOptULongLong(ctl, cmd, "pagecount", &pageCounts[0]) < 0)
        return false;

    flags |= add ? VIR_NODE_ALLOC_PAGES_ADD : VIR_NODE_ALLOC_PAGES_SET;

    if (all) {
        unsigned long nodes_cnt;
        size_t i;

        if (!(cap_xml = virConnectGetCapabilities(priv->conn))) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        xml = virXMLParseStringCtxt(cap_xml, _("(capabilities)"), &ctxt);
        if (!xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell",
                                    ctxt, &nodes);

        if (nodes_cnt == -1) {
            vshError(ctl, "%s", _("could not get information about "
                                  "NUMA topology"));
            goto cleanup;
        }

        for (i = 0; i < nodes_cnt; i++) {
            unsigned long id;
            char *val = virXMLPropString(nodes[i], "id");
            if (virStrToLong_ulp(val, NULL, 10, &id)) {
                vshError(ctl, "%s", _("conversion from string failed"));
                VIR_FREE(val);
                goto cleanup;
            }
            VIR_FREE(val);

            if (virNodeAllocPages(priv->conn, 1, pageSizes,
                                  pageCounts, id, 1, flags) < 0)
                goto cleanup;
        }
    } else {
        if (virNodeAllocPages(priv->conn, 1, pageSizes, pageCounts,
                              startCell, cellCount, flags) < 0)
            goto cleanup;
    }

    ret = true;
 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(nodes);
    VIR_FREE(cap_xml);
    return ret;
}


/*
 * "maxvcpus" command
 */
static const vshCmdInfo info_maxvcpus[] = {
    {.name = "help",
     .data = N_("connection vcpu maximum")
    },
    {.name = "desc",
     .data = N_("Show maximum number of virtual CPUs for guests on this connection.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_maxvcpus[] = {
    {.name = "type",
     .type = VSH_OT_STRING,
     .help = N_("domain type")
    },
    {.name = NULL}
};

static bool
cmdMaxvcpus(vshControl *ctl, const vshCmd *cmd)
{
    const char *type = NULL;
    int vcpus = -1;
    char *caps = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virshControlPtr priv = ctl->privData;
    bool ret = false;

    if (vshCommandOptStringReq(ctl, cmd, "type", &type) < 0)
        return false;

    if ((caps = virConnectGetDomainCapabilities(priv->conn, NULL, NULL, NULL,
                                                type, 0))) {
        if (!(xml = virXMLParseStringCtxt(caps, _("(domainCapabilities)"), &ctxt)))
            goto cleanup;

        ignore_value(virXPathInt("string(./vcpu[1]/@max)", ctxt, &vcpus));
    } else {
       vshResetLibvirtError();
    }

    if (vcpus < 0 && (vcpus = virConnectGetMaxVcpus(priv->conn, type)) < 0)
        goto cleanup;

    vshPrint(ctl, "%d\n", vcpus);
    ret = true;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(caps);
    return ret;
}

/*
 * "nodeinfo" command
 */
static const vshCmdInfo info_nodeinfo[] = {
    {.name = "help",
     .data = N_("node information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the node.")
    },
    {.name = NULL}
};

static bool
cmdNodeinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;
    virshControlPtr priv = ctl->privData;

    if (virNodeGetInfo(priv->conn, &info) < 0) {
        vshError(ctl, "%s", _("failed to get node information"));
        return false;
    }
    vshPrint(ctl, "%-20s %s\n", _("CPU model:"), info.model);
    vshPrint(ctl, "%-20s %d\n", _("CPU(s):"), info.cpus);
    if (info.mhz)
        vshPrint(ctl, "%-20s %d MHz\n", _("CPU frequency:"), info.mhz);
    vshPrint(ctl, "%-20s %d\n", _("CPU socket(s):"), info.sockets);
    vshPrint(ctl, "%-20s %d\n", _("Core(s) per socket:"), info.cores);
    vshPrint(ctl, "%-20s %d\n", _("Thread(s) per core:"), info.threads);
    vshPrint(ctl, "%-20s %d\n", _("NUMA cell(s):"), info.nodes);
    vshPrint(ctl, "%-20s %lu KiB\n", _("Memory size:"), info.memory);

    return true;
}

/*
 * "nodecpumap" command
 */
static const vshCmdInfo info_node_cpumap[] = {
    {.name = "help",
     .data = N_("node cpu map")
    },
    {.name = "desc",
     .data = N_("Displays the node's total number of CPUs, the number of"
                " online CPUs and the list of online CPUs.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_node_cpumap[] = {
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("return human readable output")
    },
    {.name = NULL}
};

static bool
cmdNodeCpuMap(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int cpu, cpunum;
    unsigned char *cpumap = NULL;
    unsigned int online;
    bool pretty = vshCommandOptBool(cmd, "pretty");
    bool ret = false;
    virshControlPtr priv = ctl->privData;

    cpunum = virNodeGetCPUMap(priv->conn, &cpumap, &online, 0);
    if (cpunum < 0) {
        vshError(ctl, "%s", _("Unable to get cpu map"));
        goto cleanup;
    }

    vshPrint(ctl, "%-15s %d\n", _("CPUs present:"), cpunum);
    vshPrint(ctl, "%-15s %d\n", _("CPUs online:"), online);

    vshPrint(ctl, "%-15s ", _("CPU map:"));
    if (pretty) {
        char *str = virBitmapDataToString(cpumap, VIR_CPU_MAPLEN(cpunum));

        if (!str)
            goto cleanup;
        vshPrint(ctl, "%s", str);
        VIR_FREE(str);
    } else {
        for (cpu = 0; cpu < cpunum; cpu++)
            vshPrint(ctl, "%c", VIR_CPU_USED(cpumap, cpu) ? 'y' : '-');
    }
    vshPrint(ctl, "\n");

    ret = true;

 cleanup:
    VIR_FREE(cpumap);
    return ret;
}

/*
 * "nodecpustats" command
 */
static const vshCmdInfo info_nodecpustats[] = {
    {.name = "help",
     .data = N_("Prints cpu stats of the node.")
    },
    {.name = "desc",
     .data = N_("Returns cpu stats of the node, in nanoseconds.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_node_cpustats[] = {
    {.name = "cpu",
     .type = VSH_OT_INT,
     .help = N_("prints specified cpu statistics only.")
    },
    {.name = "percent",
     .type = VSH_OT_BOOL,
     .help = N_("prints by percentage during 1 second.")
    },
    {.name = NULL}
};

typedef enum {
    VIRSH_CPU_USER,
    VIRSH_CPU_SYSTEM,
    VIRSH_CPU_IDLE,
    VIRSH_CPU_IOWAIT,
    VIRSH_CPU_INTR,
    VIRSH_CPU_USAGE,
    VIRSH_CPU_LAST
} virshCPUStats;

VIR_ENUM_DECL(virshCPUStats);
VIR_ENUM_IMPL(virshCPUStats, VIRSH_CPU_LAST,
              VIR_NODE_CPU_STATS_USER,
              VIR_NODE_CPU_STATS_KERNEL,
              VIR_NODE_CPU_STATS_IDLE,
              VIR_NODE_CPU_STATS_IOWAIT,
              VIR_NODE_CPU_STATS_INTR,
              VIR_NODE_CPU_STATS_UTILIZATION);

const char *virshCPUOutput[] = {
    N_("user:"),
    N_("system:"),
    N_("idle:"),
    N_("iowait:"),
    N_("intr:"),
    N_("usage:")
};

static bool
cmdNodeCpuStats(vshControl *ctl, const vshCmd *cmd)
{
    size_t i, j;
    bool flag_percent = vshCommandOptBool(cmd, "percent");
    int cpuNum = VIR_NODE_CPU_STATS_ALL_CPUS;
    virNodeCPUStatsPtr params;
    int nparams = 0;
    bool ret = false;
    unsigned long long cpu_stats[VIRSH_CPU_LAST] = { 0 };
    bool present[VIRSH_CPU_LAST] = { false };
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptInt(ctl, cmd, "cpu", &cpuNum) < 0)
        return false;

    if (virNodeGetCPUStats(priv->conn, cpuNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of cpu stats"));
        return false;
    }
    if (nparams == 0) {
        /* nothing to output */
        return true;
    }

    memset(cpu_stats, 0, sizeof(cpu_stats));
    params = vshCalloc(ctl, nparams, sizeof(*params));

    for (i = 0; i < 2; i++) {
        if (virNodeGetCPUStats(priv->conn, cpuNum, params, &nparams, 0) != 0) {
            vshError(ctl, "%s", _("Unable to get node cpu stats"));
            goto cleanup;
        }

        for (j = 0; j < nparams; j++) {
            int field = virshCPUStatsTypeFromString(params[j].field);

            if (field < 0)
                continue;

            if (i == 0) {
                cpu_stats[field] = params[j].value;
                present[field] = true;
            } else if (present[field]) {
                cpu_stats[field] = params[j].value - cpu_stats[field];
            }
        }

        if (present[VIRSH_CPU_USAGE] || !flag_percent)
            break;

        sleep(1);
    }

    if (!flag_percent) {
        for (i = 0; i < VIRSH_CPU_USAGE; i++) {
            if (present[i]) {
                vshPrint(ctl, "%-15s %20llu\n", _(virshCPUOutput[i]),
                         cpu_stats[i]);
            }
        }
    } else {
        if (present[VIRSH_CPU_USAGE]) {
            vshPrint(ctl, "%-15s %5.1llu%%\n",
                     _("usage:"), cpu_stats[VIRSH_CPU_USAGE]);
            vshPrint(ctl, "%-15s %5.1llu%%\n",
                     _("idle:"), 100 - cpu_stats[VIRSH_CPU_USAGE]);
        } else {
            double usage, total_time = 0;
            for (i = 0; i < VIRSH_CPU_USAGE; i++)
                total_time += cpu_stats[i];

            usage = (cpu_stats[VIRSH_CPU_USER] + cpu_stats[VIRSH_CPU_SYSTEM])
                / total_time * 100;

            vshPrint(ctl, "%-15s %5.1lf%%\n", _("usage:"), usage);
            for (i = 0; i < VIRSH_CPU_USAGE; i++) {
                if (present[i]) {
                    vshPrint(ctl, "%-15s %5.1lf%%\n", _(virshCPUOutput[i]),
                             cpu_stats[i] / total_time * 100);
                }
            }
        }
    }

    ret = true;

 cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodememstats" command
 */
static const vshCmdInfo info_nodememstats[] = {
    {.name = "help",
     .data = N_("Prints memory stats of the node.")
    },
    {.name = "desc",
     .data = N_("Returns memory stats of the node, in kilobytes.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_node_memstats[] = {
    {.name = "cell",
     .type = VSH_OT_INT,
     .help = N_("prints specified cell statistics only.")
    },
    {.name = NULL}
};

static bool
cmdNodeMemStats(vshControl *ctl, const vshCmd *cmd)
{
    int nparams = 0;
    size_t i;
    int cellNum = VIR_NODE_MEMORY_STATS_ALL_CELLS;
    virNodeMemoryStatsPtr params = NULL;
    bool ret = false;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptInt(ctl, cmd, "cell", &cellNum) < 0)
        return false;

    /* get the number of memory parameters */
    if (virNodeGetMemoryStats(priv->conn, cellNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of memory stats"));
        goto cleanup;
    }

    if (nparams == 0) {
        /* nothing to output */
        ret = true;
        goto cleanup;
    }

    /* now go get all the memory parameters */
    params = vshCalloc(ctl, nparams, sizeof(*params));
    if (virNodeGetMemoryStats(priv->conn, cellNum, params, &nparams, 0) != 0) {
        vshError(ctl, "%s", _("Unable to get memory stats"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++)
        vshPrint(ctl, "%-7s: %20llu KiB\n", params[i].field, params[i].value);

    ret = true;

 cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodesuspend" command
 */
static const vshCmdInfo info_nodesuspend[] = {
    {.name = "help",
     .data = N_("suspend the host node for a given time duration")
    },
    {.name = "desc",
     .data = N_("Suspend the host node for a given time duration "
                "and attempt to resume thereafter.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_node_suspend[] = {
    {.name = "target",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("mem(Suspend-to-RAM), disk(Suspend-to-Disk), "
                "hybrid(Hybrid-Suspend)")
    },
    {.name = "duration",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ,
     .help = N_("Suspend duration in seconds, at least 60")
    },
    {.name = NULL}
};

static bool
cmdNodeSuspend(vshControl *ctl, const vshCmd *cmd)
{
    const char *target = NULL;
    unsigned int suspendTarget;
    long long duration;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "target", &target) < 0)
        return false;

    if (vshCommandOptLongLong(ctl, cmd, "duration", &duration) < 0)
        return false;

    if (STREQ(target, "mem")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    } else if (STREQ(target, "disk")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    } else if (STREQ(target, "hybrid")) {
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    } else {
        vshError(ctl, "%s", _("Invalid target"));
        return false;
    }

    if (duration < 0) {
        vshError(ctl, "%s", _("Invalid duration"));
        return false;
    }

    if (virNodeSuspendForDuration(priv->conn, suspendTarget, duration, 0) < 0) {
        vshError(ctl, "%s", _("The host was not suspended"));
        return false;
    }
    return true;
}

/*
 * "sysinfo" command
 */
static const vshCmdInfo info_sysinfo[] = {
    {.name = "help",
     .data = N_("print the hypervisor sysinfo")
    },
    {.name = "desc",
     .data = N_("output an XML string for the hypervisor sysinfo, if available")
    },
    {.name = NULL}
};

static bool
cmdSysinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *sysinfo;
    virshControlPtr priv = ctl->privData;

    sysinfo = virConnectGetSysinfo(priv->conn, 0);
    if (sysinfo == NULL) {
        vshError(ctl, "%s", _("failed to get sysinfo"));
        return false;
    }

    vshPrint(ctl, "%s", sysinfo);
    VIR_FREE(sysinfo);

    return true;
}

/*
 * "hostname" command
 */
static const vshCmdInfo info_hostname[] = {
    {.name = "help",
     .data = N_("print the hypervisor hostname")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static bool
cmdHostname(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;
    virshControlPtr priv = ctl->privData;

    hostname = virConnectGetHostname(priv->conn);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        return false;
    }

    vshPrint(ctl, "%s\n", hostname);
    VIR_FREE(hostname);

    return true;
}

/*
 * "uri" command
 */
static const vshCmdInfo info_uri[] = {
    {.name = "help",
     .data = N_("print the hypervisor canonical URI")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static bool
cmdURI(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;
    virshControlPtr priv = ctl->privData;

    uri = virConnectGetURI(priv->conn);
    if (uri == NULL) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint(ctl, "%s\n", uri);
    VIR_FREE(uri);

    return true;
}

/*
 * "cpu-models" command
 */
static const vshCmdInfo info_cpu_models[] = {
    {.name = "help",
     .data = N_("CPU models")
    },
    {.name = "desc",
     .data = N_("Get the CPU models for an arch.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_cpu_models[] = {
    {.name = "arch",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("architecture")
    },
    {.name = NULL}
};

static bool
cmdCPUModelNames(vshControl *ctl, const vshCmd *cmd)
{
    char **models;
    size_t i;
    int nmodels;
    const char *arch = NULL;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "arch", &arch) < 0)
        return false;

    nmodels = virConnectGetCPUModelNames(priv->conn, arch, &models, 0);
    if (nmodels < 0) {
        vshError(ctl, "%s", _("failed to get CPU model names"));
        return false;
    }

    if (nmodels == 0) {
        vshPrintExtra(ctl, "%s\n", _("all CPU models are accepted"));
    } else {
        for (i = 0; i < nmodels; i++) {
            vshPrint(ctl, "%s\n", models[i]);
            VIR_FREE(models[i]);
        }
    }
    VIR_FREE(models);

    return true;
}

/*
 * "version" command
 */
static const vshCmdInfo info_version[] = {
    {.name = "help",
     .data = N_("show version")
    },
    {.name = "desc",
     .data = N_("Display the system version information.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_version[] = {
    {.name = "daemon",
     .type = VSH_OT_BOOL,
     .help = N_("report daemon version too")
    },
    {.name = NULL}
};

static bool
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long hvVersion;
    const char *hvType;
    unsigned long libVersion;
    unsigned long includeVersion;
    unsigned long apiVersion;
    unsigned long daemonVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;
    virshControlPtr priv = ctl->privData;

    hvType = virConnectGetType(priv->conn);
    if (hvType == NULL) {
        vshError(ctl, "%s", _("failed to get hypervisor type"));
        return false;
    }

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, _("Compiled against library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    ret = virGetVersion(&libVersion, hvType, &apiVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the library version"));
        return false;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, _("Using library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    major = apiVersion / 1000000;
    apiVersion %= 1000000;
    minor = apiVersion / 1000;
    rel = apiVersion % 1000;
    vshPrint(ctl, _("Using API: %s %d.%d.%d\n"), hvType,
             major, minor, rel);

    ret = virConnectGetVersion(priv->conn, &hvVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the hypervisor version"));
        return false;
    }
    if (hvVersion == 0) {
        vshPrint(ctl,
                 _("Cannot extract running %s hypervisor version\n"), hvType);
    } else {
        major = hvVersion / 1000000;
        hvVersion %= 1000000;
        minor = hvVersion / 1000;
        rel = hvVersion % 1000;

        vshPrint(ctl, _("Running hypervisor: %s %d.%d.%d\n"),
                 hvType, major, minor, rel);
    }

    if (vshCommandOptBool(cmd, "daemon")) {
        ret = virConnectGetLibVersion(priv->conn, &daemonVersion);
        if (ret < 0) {
            vshError(ctl, "%s", _("failed to get the daemon version"));
        } else {
            major = daemonVersion / 1000000;
            daemonVersion %= 1000000;
            minor = daemonVersion / 1000;
            rel = daemonVersion % 1000;
            vshPrint(ctl, _("Running against daemon: %d.%d.%d\n"),
                     major, minor, rel);
        }
    }

    return true;
}

static const vshCmdInfo info_node_memory_tune[] = {
    {"help", N_("Get or set node memory parameters")},
    {"desc", N_("Get or set node memory parameters\n"
                "    To get the memory parameters, use following command: \n\n"
                "    virsh # node-memory-tune")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_memory_tune[] = {
    {.name = "shm-pages-to-scan",
     .type = VSH_OT_INT,
     .help =  N_("number of pages to scan before the shared memory service "
                 "goes to sleep")
    },
    {.name = "shm-sleep-millisecs",
     .type = VSH_OT_INT,
     .help =  N_("number of millisecs the shared memory service should "
                 "sleep before next scan")
    },
    {.name = "shm-merge-across-nodes",
     .type = VSH_OT_INT,
     .help =  N_("Specifies if pages from different numa nodes can be merged")
    },
    {.name = NULL}
};

static bool
cmdNodeMemoryTune(vshControl *ctl, const vshCmd *cmd)
{
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    unsigned int flags = 0;
    unsigned int value;
    bool ret = false;
    int rc = -1;
    size_t i;
    virshControlPtr priv = ctl->privData;

    if ((rc = vshCommandOptUInt(ctl, cmd, "shm-pages-to-scan", &value)) < 0) {
        goto cleanup;
    } else if (rc > 0) {
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN,
                                  value) < 0)
            goto save_error;
    }

    if ((rc = vshCommandOptUInt(ctl, cmd, "shm-sleep-millisecs", &value)) < 0) {
        goto cleanup;
    } else if (rc > 0) {
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS,
                                  value) < 0)
            goto save_error;
    }

    if ((rc = vshCommandOptUInt(ctl, cmd, "shm-merge-across-nodes", &value)) < 0) {
        goto cleanup;
    } else if (rc > 0) {
        if (virTypedParamsAddUInt(&params, &nparams, &maxparams,
                                  VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES,
                                  value) < 0)
            goto save_error;
    }

    if (nparams == 0) {
        /* Get the number of memory parameters */
        if (virNodeGetMemoryParameters(priv->conn, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            ret = true;
            goto cleanup;
        }

        /* Now go get all the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virNodeGetMemoryParameters(priv->conn, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get memory parameters"));
            goto cleanup;
        }

        /* XXX: Need to sort the returned params once new parameter
         * fields not of shared memory are added.
         */
        vshPrint(ctl, _("Shared memory:\n"));
        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "\t%-15s %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        if (virNodeSetMemoryParameters(priv->conn, params, nparams, flags) != 0)
            goto error;
    }

    ret = true;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;

 save_error:
    vshSaveLibvirtError();
 error:
    vshError(ctl, "%s", _("Unable to change memory parameters"));
    goto cleanup;
}

const vshCmdDef hostAndHypervisorCmds[] = {
    {.name = "allocpages",
     .handler = cmdAllocpages,
     .opts = opts_allocpages,
     .info = info_allocpages,
     .flags = 0
    },
    {.name = "capabilities",
     .handler = cmdCapabilities,
     .opts = NULL,
     .info = info_capabilities,
     .flags = 0
    },
    {.name = "cpu-models",
     .handler = cmdCPUModelNames,
     .opts = opts_cpu_models,
     .info = info_cpu_models,
     .flags = 0
    },
    {.name = "domcapabilities",
     .handler = cmdDomCapabilities,
     .opts = opts_domcapabilities,
     .info = info_domcapabilities,
     .flags = 0
    },
    {.name = "freecell",
     .handler = cmdFreecell,
     .opts = opts_freecell,
     .info = info_freecell,
     .flags = 0
    },
    {.name = "freepages",
     .handler = cmdFreepages,
     .opts = opts_freepages,
     .info = info_freepages,
     .flags = 0
    },
    {.name = "hostname",
     .handler = cmdHostname,
     .opts = NULL,
     .info = info_hostname,
     .flags = 0
    },
    {.name = "maxvcpus",
     .handler = cmdMaxvcpus,
     .opts = opts_maxvcpus,
     .info = info_maxvcpus,
     .flags = 0
    },
    {.name = "node-memory-tune",
     .handler = cmdNodeMemoryTune,
     .opts = opts_node_memory_tune,
     .info = info_node_memory_tune,
     .flags = 0
    },
    {.name = "nodecpumap",
     .handler = cmdNodeCpuMap,
     .opts = opts_node_cpumap,
     .info = info_node_cpumap,
     .flags = 0
    },
    {.name = "nodecpustats",
     .handler = cmdNodeCpuStats,
     .opts = opts_node_cpustats,
     .info = info_nodecpustats,
     .flags = 0
    },
    {.name = "nodeinfo",
     .handler = cmdNodeinfo,
     .opts = NULL,
     .info = info_nodeinfo,
     .flags = 0
    },
    {.name = "nodememstats",
     .handler = cmdNodeMemStats,
     .opts = opts_node_memstats,
     .info = info_nodememstats,
     .flags = 0
    },
    {.name = "nodesuspend",
     .handler = cmdNodeSuspend,
     .opts = opts_node_suspend,
     .info = info_nodesuspend,
     .flags = 0
    },
    {.name = "sysinfo",
     .handler = cmdSysinfo,
     .opts = NULL,
     .info = info_sysinfo,
     .flags = 0
    },
    {.name = "uri",
     .handler = cmdURI,
     .opts = NULL,
     .info = info_uri,
     .flags = 0
    },
    {.name = "version",
     .handler = cmdVersion,
     .opts = opts_version,
     .info = info_version,
     .flags = 0
    },
    {.name = NULL}
};
