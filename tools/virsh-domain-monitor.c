/*
 * virsh-domain-monitor.c: Commands to monitor domain status
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 *  Daniel Veillard <veillard@redhat.com>
 *  Karel Zak <kzak@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 */

#include "intprops.h"

static const char *
vshDomainIOErrorToString(int error)
{
    switch ((virDomainDiskErrorCode) error) {
    case VIR_DOMAIN_DISK_ERROR_NONE:
        return _("no error");
    case VIR_DOMAIN_DISK_ERROR_UNSPEC:
        return _("unspecified error");
    case VIR_DOMAIN_DISK_ERROR_NO_SPACE:
        return _("no space");
    case VIR_DOMAIN_DISK_ERROR_LAST:
        ;
    }

    return _("unknown error");
}

/* extract description or title from domain xml */
static char *
vshGetDomainDescription(vshControl *ctl, virDomainPtr dom, bool title,
                        unsigned int flags)
{
    char *desc = NULL;
    char *domxml = NULL;
    virErrorPtr err = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int type;

    if (title)
        type = VIR_DOMAIN_METADATA_TITLE;
    else
        type = VIR_DOMAIN_METADATA_DESCRIPTION;

    if ((desc = virDomainGetMetadata(dom, type, NULL, flags))) {
        return desc;
    } else {
        err = virGetLastError();

        if (err && err->code == VIR_ERR_NO_DOMAIN_METADATA) {
            desc = vshStrdup(ctl, "");
            vshResetLibvirtError();
            return desc;
        }

        if (err && err->code != VIR_ERR_NO_SUPPORT)
            return desc;
    }

    /* fall back to xml */
    /* get domain's xml description and extract the title/description */
    if (!(domxml = virDomainGetXMLDesc(dom, flags))) {
        vshError(ctl, "%s", _("Failed to retrieve domain XML"));
        goto cleanup;
    }
    doc = virXMLParseStringCtxt(domxml, _("(domain_definition)"), &ctxt);
    if (!doc) {
        vshError(ctl, "%s", _("Couldn't parse domain XML"));
        goto cleanup;
    }
    if (title)
        desc = virXPathString("string(./title[1])", ctxt);
    else
        desc = virXPathString("string(./description[1])", ctxt);

    if (!desc)
        desc = vshStrdup(ctl, "");

cleanup:
    VIR_FREE(domxml);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return desc;
}

static const char *
vshDomainControlStateToString(int state)
{
    switch ((virDomainControlState) state) {
    case VIR_DOMAIN_CONTROL_OK:
        return N_("ok");
    case VIR_DOMAIN_CONTROL_JOB:
        return N_("background job");
    case VIR_DOMAIN_CONTROL_OCCUPIED:
        return N_("occupied");
    case VIR_DOMAIN_CONTROL_ERROR:
        return N_("error");
    default:
        ;
    }

    return N_("unknown");
}

static const char *
vshDomainStateToString(int state)
{
    /* Can't use virDomainStateTypeToString, because we want to mark
     * strings for translation.  */
    switch ((virDomainState) state) {
    case VIR_DOMAIN_RUNNING:
        return N_("running");
    case VIR_DOMAIN_BLOCKED:
        return N_("idle");
    case VIR_DOMAIN_PAUSED:
        return N_("paused");
    case VIR_DOMAIN_SHUTDOWN:
        return N_("in shutdown");
    case VIR_DOMAIN_SHUTOFF:
        return N_("shut off");
    case VIR_DOMAIN_CRASHED:
        return N_("crashed");
    case VIR_DOMAIN_PMSUSPENDED:
        return N_("pmsuspended");
    case VIR_DOMAIN_NOSTATE:
    default:
        ;/*FALLTHROUGH*/
    }
    return N_("no state");  /* = dom0 state */
}

static const char *
vshDomainStateReasonToString(int state, int reason)
{
    switch ((virDomainState) state) {
    case VIR_DOMAIN_NOSTATE:
        switch ((virDomainNostateReason) reason) {
        case VIR_DOMAIN_NOSTATE_UNKNOWN:
        case VIR_DOMAIN_NOSTATE_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_RUNNING:
        switch ((virDomainRunningReason) reason) {
        case VIR_DOMAIN_RUNNING_BOOTED:
            return N_("booted");
        case VIR_DOMAIN_RUNNING_MIGRATED:
            return N_("migrated");
        case VIR_DOMAIN_RUNNING_RESTORED:
            return N_("restored");
        case VIR_DOMAIN_RUNNING_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_RUNNING_UNPAUSED:
            return N_("unpaused");
        case VIR_DOMAIN_RUNNING_MIGRATION_CANCELED:
            return N_("migration canceled");
        case VIR_DOMAIN_RUNNING_SAVE_CANCELED:
            return N_("save canceled");
        case VIR_DOMAIN_RUNNING_WAKEUP:
            return N_("event wakeup");
        case VIR_DOMAIN_RUNNING_UNKNOWN:
        case VIR_DOMAIN_RUNNING_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_BLOCKED:
        switch ((virDomainBlockedReason) reason) {
        case VIR_DOMAIN_BLOCKED_UNKNOWN:
        case VIR_DOMAIN_BLOCKED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_PAUSED:
        switch ((virDomainPausedReason) reason) {
        case VIR_DOMAIN_PAUSED_USER:
            return N_("user");
        case VIR_DOMAIN_PAUSED_MIGRATION:
            return N_("migrating");
        case VIR_DOMAIN_PAUSED_SAVE:
            return N_("saving");
        case VIR_DOMAIN_PAUSED_DUMP:
            return N_("dumping");
        case VIR_DOMAIN_PAUSED_IOERROR:
            return N_("I/O error");
        case VIR_DOMAIN_PAUSED_WATCHDOG:
            return N_("watchdog");
        case VIR_DOMAIN_PAUSED_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_PAUSED_SHUTTING_DOWN:
            return N_("shutting down");
        case VIR_DOMAIN_PAUSED_UNKNOWN:
        case VIR_DOMAIN_PAUSED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_SHUTDOWN:
        switch ((virDomainShutdownReason) reason) {
        case VIR_DOMAIN_SHUTDOWN_USER:
            return N_("user");
        case VIR_DOMAIN_SHUTDOWN_UNKNOWN:
        case VIR_DOMAIN_SHUTDOWN_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_SHUTOFF:
        switch ((virDomainShutoffReason) reason) {
        case VIR_DOMAIN_SHUTOFF_SHUTDOWN:
            return N_("shutdown");
        case VIR_DOMAIN_SHUTOFF_DESTROYED:
            return N_("destroyed");
        case VIR_DOMAIN_SHUTOFF_CRASHED:
            return N_("crashed");
        case VIR_DOMAIN_SHUTOFF_MIGRATED:
            return N_("migrated");
        case VIR_DOMAIN_SHUTOFF_SAVED:
            return N_("saved");
        case VIR_DOMAIN_SHUTOFF_FAILED:
            return N_("failed");
        case VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_SHUTOFF_UNKNOWN:
        case VIR_DOMAIN_SHUTOFF_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_CRASHED:
        switch ((virDomainCrashedReason) reason) {
        case VIR_DOMAIN_CRASHED_UNKNOWN:
        case VIR_DOMAIN_CRASHED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_PMSUSPENDED:
        switch ((virDomainPMSuspendedReason) reason) {
        case VIR_DOMAIN_PMSUSPENDED_UNKNOWN:
        case VIR_DOMAIN_PMSUSPENDED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_LAST:
        ;
    }

    return N_("unknown");
}

/*
 * "dommemstat" command
 */
static const vshCmdInfo info_dommemstat[] = {
    {"help", N_("get memory statistics for a domain")},
    {"desc", N_("Get memory statistics for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_dommemstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomMemStat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    struct _virDomainMemoryStat stats[VIR_DOMAIN_MEMORY_STAT_NR];
    unsigned int nr_stats, i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    nr_stats = virDomainMemoryStats(dom, stats, VIR_DOMAIN_MEMORY_STAT_NR, 0);
    if (nr_stats == -1) {
        vshError(ctl, _("Failed to get memory statistics for domain %s"), name);
        virDomainFree(dom);
        return false;
    }

    for (i = 0; i < nr_stats; i++) {
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_SWAP_IN)
            vshPrint(ctl, "swap_in %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_SWAP_OUT)
            vshPrint(ctl, "swap_out %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT)
            vshPrint(ctl, "major_fault %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT)
            vshPrint(ctl, "minor_fault %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_UNUSED)
            vshPrint(ctl, "unused %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_AVAILABLE)
            vshPrint(ctl, "available %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON)
            vshPrint(ctl, "actual %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_RSS)
            vshPrint(ctl, "rss %llu\n", stats[i].val);
    }

    virDomainFree(dom);
    return true;
}

/*
 * "domblkinfo" command
 */
static const vshCmdInfo info_domblkinfo[] = {
    {"help", N_("domain block device size information")},
    {"desc", N_("Get block device size info for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblkinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomblkinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainBlockInfo info;
    virDomainPtr dom;
    bool ret = true;
    const char *device = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "device", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetBlockInfo(dom, device, &info, 0) < 0) {
        virDomainFree(dom);
        return false;
    }

    vshPrint(ctl, "%-15s %llu\n", _("Capacity:"), info.capacity);
    vshPrint(ctl, "%-15s %llu\n", _("Allocation:"), info.allocation);
    vshPrint(ctl, "%-15s %llu\n", _("Physical:"), info.physical);

    virDomainFree(dom);
    return ret;
}

/*
 * "domblklist" command
 */
static const vshCmdInfo info_domblklist[] = {
    {"help", N_("list all domain blocks")},
    {"desc", N_("Get the summary of block devices for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblklist[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0,
     N_("get inactive rather than running configuration")},
    {"details", VSH_OT_BOOL, 0,
     N_("additionally display the type and device value")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomblklist(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ndisks;
    xmlNodePtr *disks = NULL;
    int i;
    bool details = false;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    details = vshCommandOptBool(cmd, "details");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    xml = virDomainGetXMLDesc(dom, flags);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_definition)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks);
    if (ndisks < 0)
        goto cleanup;

    if (details)
        vshPrint(ctl, "%-10s %-10s %-10s %s\n", _("Type"),
                 _("Device"), _("Target"), _("Source"));
    else
        vshPrint(ctl, "%-10s %s\n", _("Target"), _("Source"));

    vshPrint(ctl, "------------------------------------------------\n");

    for (i = 0; i < ndisks; i++) {
        char *type;
        char *device;
        char *target;
        char *source;

        ctxt->node = disks[i];

        if (details) {
            type = virXPathString("string(./@type)", ctxt);
            device = virXPathString("string(./@device)", ctxt);
        }

        target = virXPathString("string(./target/@dev)", ctxt);
        if (!target) {
            vshError(ctl, "unable to query block list");
            goto cleanup;
        }
        source = virXPathString("string(./source/@file"
                                "|./source/@dev"
                                "|./source/@dir"
                                "|./source/@name)", ctxt);
        if (details) {
            vshPrint(ctl, "%-10s %-10s %-10s %s\n", type, device,
                     target, source ? source : "-");
            VIR_FREE(type);
            VIR_FREE(device);
        } else {
            vshPrint(ctl, "%-10s %s\n", target, source ? source : "-");
        }

        VIR_FREE(target);
        VIR_FREE(source);
    }

    ret = true;

cleanup:
    VIR_FREE(disks);
    virDomainFree(dom);
    VIR_FREE(xml);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;
}

/*
 * "domiflist" command
 */
static const vshCmdInfo info_domiflist[] = {
    {"help", N_("list all domain virtual interfaces")},
    {"desc", N_("Get the summary of virtual interfaces for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domiflist[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0,
     N_("get inactive rather than running configuration")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomiflist(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ninterfaces;
    xmlNodePtr *interfaces = NULL;
    int i;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    xml = virDomainGetXMLDesc(dom, flags);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_definition)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    ninterfaces = virXPathNodeSet("./devices/interface", ctxt, &interfaces);
    if (ninterfaces < 0)
        goto cleanup;

    vshPrint(ctl, "%-10s %-10s %-10s %-11s %s\n", _("Interface"), _("Type"),
             _("Source"), _("Model"), _("MAC"));
    vshPrint(ctl, "-------------------------------------------------------\n");

    for (i = 0; i < ninterfaces; i++) {
        char *type = NULL;
        char *source = NULL;
        char *target = NULL;
        char *model = NULL;
        char *mac = NULL;

        ctxt->node = interfaces[i];
        type = virXPathString("string(./@type)", ctxt);

        source = virXPathString("string(./source/@bridge"
                                "|./source/@dev"
                                "|./source/@network"
                                "|./source/@name)", ctxt);

        target = virXPathString("string(./target/@dev)", ctxt);
        model = virXPathString("string(./model/@type)", ctxt);
        mac = virXPathString("string(./mac/@address)", ctxt);

        vshPrint(ctl, "%-10s %-10s %-10s %-11s %-10s\n",
                 target ? target : "-",
                 type,
                 source ? source : "-",
                 model ? model : "-",
                 mac ? mac : "-");

        VIR_FREE(type);
        VIR_FREE(source);
        VIR_FREE(target);
        VIR_FREE(model);
        VIR_FREE(mac);
    }

    ret = true;

cleanup:
    VIR_FREE(interfaces);
    virDomainFree(dom);
    VIR_FREE(xml);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;
}

/*
 * "domif-getlink" command
 */
static const vshCmdInfo info_domif_getlink[] = {
    {"help", N_("get link state of a virtual interface")},
    {"desc", N_("Get link state of a domain's virtual interface.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domif_getlink[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device (MAC Address)")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("Get persistent interface state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfGetLink(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface = NULL;
    int flags = 0;
    char *state = NULL;
    char *value = NULL;
    virMacAddr macaddr;
    const char *element;
    const char *attr;
    bool ret = false;
    int i;
    char *desc;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlXPathObjectPtr obj = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "interface", &iface) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config"))
        flags = VIR_DOMAIN_XML_INACTIVE;

    desc = virDomainGetXMLDesc(dom, flags);
    if (desc == NULL) {
        vshError(ctl, _("Failed to get domain description xml"));
        goto cleanup;
    }

    xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), &ctxt);
    VIR_FREE(desc);
    if (!xml) {
        vshError(ctl, _("Failed to parse domain description xml"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("Failed to extract interface information or no interfaces found"));
        goto cleanup;
    }

    if (virMacAddrParse(iface, &macaddr) == 0) {
        element = "mac";
        attr = "address";
    } else {
        element = "target";
        attr = "dev";
    }

    /* find interface with matching mac addr */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;

        while (cur) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST element)) {

                value = virXMLPropString(cur, attr);

                if (STRCASEEQ(value, iface)) {
                    VIR_FREE(value);
                    goto hit;
                }
                VIR_FREE(value);
            }
            cur = cur->next;
        }
    }

    vshError(ctl, _("Interface (%s: %s) not found."), element, iface);
    goto cleanup;

hit:
    cur = obj->nodesetval->nodeTab[i]->children;
    while (cur) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "link")) {

            state = virXMLPropString(cur, "state");
            vshPrint(ctl, "%s %s", iface, state);
            VIR_FREE(state);

            goto cleanup;
        }
        cur = cur->next;
    }

    /* attribute not found */
    vshPrint(ctl, "%s default", iface);

    ret = true;
cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "domcontrol" command
 */
static const vshCmdInfo info_domcontrol[] = {
    {"help", N_("domain control interface state")},
    {"desc", N_("Returns state of a control interface to the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domcontrol[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomControl(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    virDomainControlInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetControlInfo(dom, &info, 0) < 0) {
        ret = false;
        goto cleanup;
    }

    if (info.state != VIR_DOMAIN_CONTROL_OK &&
        info.state != VIR_DOMAIN_CONTROL_ERROR) {
        vshPrint(ctl, "%s (%0.3fs)\n",
                 _(vshDomainControlStateToString(info.state)),
                 info.stateTime / 1000.0);
    } else {
        vshPrint(ctl, "%s\n",
                 _(vshDomainControlStateToString(info.state)));
    }

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "domblkstat" command
 */
static const vshCmdInfo info_domblkstat[] = {
    {"help", N_("get device block stats for a domain")},
    {"desc", N_("Get device block stats for a running domain. See man page or "
                "use --human for explanation of fields")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domblkstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {"human",  VSH_OT_BOOL, 0, N_("print a more human readable output")},
    {NULL, 0, 0, NULL}
};

struct _domblkstat_sequence {
    const char *field;  /* field name */
    const char *legacy; /* legacy name from previous releases */
    const char *human;  /* human-friendly explanation */
};

/* sequence of values for output to honor legacy format from previous
 * versions */
static const struct _domblkstat_sequence domblkstat_output[] = {
    { VIR_DOMAIN_BLOCK_STATS_READ_REQ,          "rd_req",
      N_("number of read operations:") }, /* 0 */
    { VIR_DOMAIN_BLOCK_STATS_READ_BYTES,        "rd_bytes",
      N_("number of bytes read:") }, /* 1 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_REQ,         "wr_req",
      N_("number of write operations:") }, /* 2 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES,       "wr_bytes",
      N_("number of bytes written:") }, /* 3 */
    { VIR_DOMAIN_BLOCK_STATS_ERRS,              "errs",
      N_("error count:") }, /* 4 */
    { VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ,         NULL,
      N_("number of flush operations:") }, /* 5 */
    { VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES,  NULL,
      N_("total duration of reads (ns):") }, /* 6 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES, NULL,
      N_("total duration of writes (ns):") }, /* 7 */
    { VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES, NULL,
      N_("total duration of flushes (ns):") }, /* 8 */
    { NULL, NULL, NULL }
};

#define DOMBLKSTAT_LEGACY_PRINT(ID, VALUE)              \
    if (VALUE >= 0)                                     \
        vshPrint(ctl, "%s %-*s %lld\n", device,         \
                 human ? 31 : 0,                        \
                 human ? _(domblkstat_output[ID].human) \
                 : domblkstat_output[ID].legacy,        \
                 VALUE);

static bool
cmdDomblkstat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL;
    struct _virDomainBlockStats stats;
    virTypedParameterPtr params = NULL;
    virTypedParameterPtr par = NULL;
    char *value = NULL;
    const char *field = NULL;
    int rc, nparams = 0;
    int i = 0;
    bool ret = false;
    bool human = vshCommandOptBool(cmd, "human"); /* human readable output */

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "device", &device) <= 0)
        goto cleanup;

    rc = virDomainBlockStatsFlags(dom, device, NULL, &nparams, 0);

    /* It might fail when virDomainBlockStatsFlags is not
     * supported on older libvirt, fallback to use virDomainBlockStats
     * then.
     */
    if (rc < 0) {
        /* try older API if newer is not supported */
        if (last_error->code != VIR_ERR_NO_SUPPORT)
            goto cleanup;

        vshResetLibvirtError();

        if (virDomainBlockStats(dom, device, &stats,
                                sizeof(stats)) == -1) {
            vshError(ctl, _("Failed to get block stats %s %s"),
                     name, device);
            goto cleanup;
        }

        /* human friendly output */
        if (human) {
            vshPrint(ctl, N_("Device: %s\n"), device);
            device = "";
        }

        DOMBLKSTAT_LEGACY_PRINT(0, stats.rd_req);
        DOMBLKSTAT_LEGACY_PRINT(1, stats.rd_bytes);
        DOMBLKSTAT_LEGACY_PRINT(2, stats.wr_req);
        DOMBLKSTAT_LEGACY_PRINT(3, stats.wr_bytes);
        DOMBLKSTAT_LEGACY_PRINT(4, stats.errs);
    } else {
        params = vshCalloc(ctl, nparams, sizeof(*params));

        if (virDomainBlockStatsFlags(dom, device, params, &nparams, 0) < 0) {
            vshError(ctl, _("Failed to get block stats %s %s"), name, device);
            goto cleanup;
        }

        /* set for prettier output */
        if (human) {
            vshPrint(ctl, N_("Device: %s\n"), device);
            device = "";
        }

        /* at first print all known values in desired order */
        for (i = 0; domblkstat_output[i].field != NULL; i++) {
            if (!(par = vshFindTypedParamByName(domblkstat_output[i].field,
                                                params,
                                                nparams)))
                continue;

            value = vshGetTypedParamValue(ctl, par);

            /* to print other not supported fields, mark the already printed */
            par->field[0] = '\0'; /* set the name to empty string */

            /* translate into human readable or legacy spelling */
            field = NULL;
            if (human)
                field = _(domblkstat_output[i].human);
            else
                field = domblkstat_output[i].legacy;

            /* use the provided spelling if no translation is available */
            if (!field)
                field = domblkstat_output[i].field;

            vshPrint(ctl, "%s %-*s %s\n", device,
                     human ? 31 : 0, field, value);

            VIR_FREE(value);
        }

        /* go through the fields again, for remaining fields */
        for (i = 0; i < nparams; i++) {
            if (!*params[i].field)
                continue;

            value = vshGetTypedParamValue(ctl, params+i);
            vshPrint(ctl, "%s %s %s\n", device, params[i].field, value);
            VIR_FREE(value);
        }
    }

    ret = true;

cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}
#undef DOMBLKSTAT_LEGACY_PRINT

/*
 * "domifstat" command
 */
static const vshCmdInfo info_domifstat[] = {
    {"help", N_("get network interface stats for a domain")},
    {"desc", N_("Get network interface stats for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domifstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfstat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL;
    struct _virDomainInterfaceStats stats;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "interface", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainInterfaceStats(dom, device, &stats, sizeof(stats)) == -1) {
        vshError(ctl, _("Failed to get interface stats %s %s"), name, device);
        virDomainFree(dom);
        return false;
    }

    if (stats.rx_bytes >= 0)
        vshPrint(ctl, "%s rx_bytes %lld\n", device, stats.rx_bytes);

    if (stats.rx_packets >= 0)
        vshPrint(ctl, "%s rx_packets %lld\n", device, stats.rx_packets);

    if (stats.rx_errs >= 0)
        vshPrint(ctl, "%s rx_errs %lld\n", device, stats.rx_errs);

    if (stats.rx_drop >= 0)
        vshPrint(ctl, "%s rx_drop %lld\n", device, stats.rx_drop);

    if (stats.tx_bytes >= 0)
        vshPrint(ctl, "%s tx_bytes %lld\n", device, stats.tx_bytes);

    if (stats.tx_packets >= 0)
        vshPrint(ctl, "%s tx_packets %lld\n", device, stats.tx_packets);

    if (stats.tx_errs >= 0)
        vshPrint(ctl, "%s tx_errs %lld\n", device, stats.tx_errs);

    if (stats.tx_drop >= 0)
        vshPrint(ctl, "%s tx_drop %lld\n", device, stats.tx_drop);

    virDomainFree(dom);
    return true;
}

/*
 * "domblkerror" command
 */
static const vshCmdInfo info_domblkerror[] = {
    {"help", N_("Show errors on block devices")},
    {"desc", N_("Show block device errors")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblkerror[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id, or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomBlkError(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainDiskErrorPtr disks = NULL;
    unsigned int ndisks;
    int i;
    int count;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((count = virDomainGetDiskErrors(dom, NULL, 0, 0)) < 0)
        goto cleanup;
    ndisks = count;

    if (ndisks) {
        if (VIR_ALLOC_N(disks, ndisks) < 0)
            goto cleanup;

        if ((count = virDomainGetDiskErrors(dom, disks, ndisks, 0)) == -1)
            goto cleanup;
    }

    if (count == 0) {
        vshPrint(ctl, _("No errors found\n"));
    } else {
        for (i = 0; i < count; i++) {
            vshPrint(ctl, "%s: %s\n",
                     disks[i].disk,
                     vshDomainIOErrorToString(disks[i].error));
        }
    }

    ret = true;

cleanup:
    VIR_FREE(disks);
    virDomainFree(dom);
    return ret;
}

/*
 * "dominfo" command
 */
static const vshCmdInfo info_dominfo[] = {
    {"help", N_("domain information")},
    {"desc", N_("Returns basic information about the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dominfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDominfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virSecurityModel secmodel;
    virSecurityLabelPtr seclabel;
    int persistent = 0;
    bool ret = true;
    int autostart;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];
    int has_managed_save = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%-15s %s\n", _("Id:"), "-");
    else
        vshPrint(ctl, "%-15s %d\n", _("Id:"), id);
    vshPrint(ctl, "%-15s %s\n", _("Name:"), virDomainGetName(dom));

    if (virDomainGetUUIDString(dom, &uuid[0])==0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

    if ((str = virDomainGetOSType(dom))) {
        vshPrint(ctl, "%-15s %s\n", _("OS Type:"), str);
        VIR_FREE(str);
    }

    if (virDomainGetInfo(dom, &info) == 0) {
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 _(vshDomainStateToString(info.state)));

        vshPrint(ctl, "%-15s %d\n", _("CPU(s):"), info.nrVirtCpu);

        if (info.cpuTime != 0) {
            double cpuUsed = info.cpuTime;

            cpuUsed /= 1000000000.0;

            vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
        }

        if (info.maxMem != UINT_MAX)
            vshPrint(ctl, "%-15s %lu KiB\n", _("Max memory:"),
                 info.maxMem);
        else
            vshPrint(ctl, "%-15s %s\n", _("Max memory:"),
                 _("no limit"));

        vshPrint(ctl, "%-15s %lu KiB\n", _("Used memory:"),
                 info.memory);

    } else {
        ret = false;
    }

    /* Check and display whether the domain is persistent or not */
    persistent = virDomainIsPersistent(dom);
    vshDebug(ctl, VSH_ERR_DEBUG, "Domain persistent flag value: %d\n",
             persistent);
    if (persistent < 0)
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

    /* Check and display whether the domain autostarts or not */
    if (!virDomainGetAutostart(dom, &autostart)) {
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"),
                 autostart ? _("enable") : _("disable") );
    }

    has_managed_save = virDomainHasManagedSaveImage(dom, 0);
    if (has_managed_save < 0)
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"),
                 has_managed_save ? _("yes") : _("no"));

    /* Security model and label information */
    memset(&secmodel, 0, sizeof(secmodel));
    if (virNodeGetSecurityModel(ctl->conn, &secmodel) == -1) {
        if (last_error->code != VIR_ERR_NO_SUPPORT) {
            virDomainFree(dom);
            return false;
        } else {
            vshResetLibvirtError();
        }
    } else {
        /* Only print something if a security model is active */
        if (secmodel.model[0] != '\0') {
            vshPrint(ctl, "%-15s %s\n", _("Security model:"), secmodel.model);
            vshPrint(ctl, "%-15s %s\n", _("Security DOI:"), secmodel.doi);

            /* Security labels are only valid for active domains */
            if (VIR_ALLOC(seclabel) < 0) {
                virDomainFree(dom);
                return false;
            }

            if (virDomainGetSecurityLabel(dom, seclabel) == -1) {
                virDomainFree(dom);
                VIR_FREE(seclabel);
                return false;
            } else {
                if (seclabel->label[0] != '\0')
                    vshPrint(ctl, "%-15s %s (%s)\n", _("Security label:"),
                             seclabel->label, seclabel->enforcing ? "enforcing" : "permissive");
            }

            VIR_FREE(seclabel);
        }
    }
    virDomainFree(dom);
    return ret;
}

/*
 * "domstate" command
 */
static const vshCmdInfo info_domstate[] = {
    {"help", N_("domain state")},
    {"desc", N_("Returns state about a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domstate[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"reason", VSH_OT_BOOL, 0, N_("also print reason for the state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomstate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    bool showReason = vshCommandOptBool(cmd, "reason");
    int state, reason;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = vshDomainState(ctl, dom, &reason)) < 0) {
        ret = false;
        goto cleanup;
    }

    if (showReason) {
        vshPrint(ctl, "%s (%s)\n",
                 _(vshDomainStateToString(state)),
                 vshDomainStateReasonToString(state, reason));
    } else {
        vshPrint(ctl, "%s\n",
                 _(vshDomainStateToString(state)));
    }

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "list" command
 */
static const vshCmdInfo info_list[] = {
    {"help", N_("list domains")},
    {"desc", N_("Returns list of domains.")},
    {NULL, NULL}
};

/* compare domains, pack NULLed ones at the end*/
static int
vshDomainSorter(const void *a, const void *b)
{
    virDomainPtr *da = (virDomainPtr *) a;
    virDomainPtr *db = (virDomainPtr *) b;
    unsigned int ida;
    unsigned int idb;
    unsigned int inactive = (unsigned int) -1;

    if (*da && !*db)
        return -1;

    if (!*da)
        return *db != NULL;

    ida = virDomainGetID(*da);
    idb = virDomainGetID(*db);

    if (ida == inactive && idb == inactive)
        return strcasecmp(virDomainGetName(*da), virDomainGetName(*db));

    if (ida != inactive && idb != inactive) {
        if (ida > idb)
            return 1;
        else if (ida < idb)
            return -1;
    }

    if (ida != inactive)
        return -1;
    else
        return 1;
}

struct vshDomainList {
    virDomainPtr *domains;
    size_t ndomains;
};
typedef struct vshDomainList *vshDomainListPtr;

static void
vshDomainListFree(vshDomainListPtr domlist)
{
    int i;

    if (domlist && domlist->domains) {
        for (i = 0; i < domlist->ndomains; i++) {
            if (domlist->domains[i])
                virDomainFree(domlist->domains[i]);
        }
        VIR_FREE(domlist->domains);
    }
    VIR_FREE(domlist);
}

#define MATCH(FLAG) (flags & (FLAG))
static vshDomainListPtr
vshDomainListCollect(vshControl *ctl, unsigned int flags)
{
    vshDomainListPtr list = vshMalloc(ctl, sizeof(*list));
    int i;
    int ret;
    int *ids = NULL;
    int nids = 0;
    char **names = NULL;
    int nnames = 0;
    virDomainPtr dom;
    bool success = false;
    size_t deleted = 0;
    int persistent;
    int autostart;
    int state;
    int nsnap;
    int mansave;

    /* try the list with flags support (0.9.13 and later) */
    if ((ret = virConnectListAllDomains(ctl->conn, &list->domains,
                                        flags)) >= 0) {
        list->ndomains = ret;
        goto finished;
    }

    /* check if the command is actually supported */
    if (last_error && last_error->code == VIR_ERR_NO_SUPPORT) {
        vshResetLibvirtError();
        goto fallback;
    }

    if (last_error && last_error->code ==  VIR_ERR_INVALID_ARG) {
        /* try the new API again but mask non-guaranteed flags */
        unsigned int newflags = flags & (VIR_CONNECT_LIST_DOMAINS_ACTIVE |
                                         VIR_CONNECT_LIST_DOMAINS_INACTIVE);

        vshResetLibvirtError();
        if ((ret = virConnectListAllDomains(ctl->conn, &list->domains,
                                            newflags)) >= 0) {
            list->ndomains = ret;
            goto filter;
        }
    }

    /* there was an error during the first or second call */
    vshError(ctl, "%s", _("Failed to list domains"));
    goto cleanup;


fallback:
    /* fall back to old method (0.9.12 and older) */
    vshResetLibvirtError();

    /* list active domains, if necessary */
    if (!MATCH(VIR_CONNECT_LIST_FILTERS_ACTIVE) ||
        MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE)) {
        if ((nids = virConnectNumOfDomains(ctl->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to list active domains"));
            goto cleanup;
        }

        if (nids) {
            ids = vshMalloc(ctl, sizeof(int) * nids);

            if ((nids = virConnectListDomains(ctl->conn, ids, nids)) < 0) {
                vshError(ctl, "%s", _("Failed to list active domains"));
                goto cleanup;
            }
        }
    }

    if (!MATCH(VIR_CONNECT_LIST_FILTERS_ACTIVE) ||
        MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE)) {
        if ((nnames = virConnectNumOfDefinedDomains(ctl->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive domains"));
            goto cleanup;
        }

        if (nnames) {
            names = vshMalloc(ctl, sizeof(char *) * nnames);

            if ((nnames = virConnectListDefinedDomains(ctl->conn, names,
                                                      nnames)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive domains"));
                goto cleanup;
            }
        }
    }

    list->domains = vshMalloc(ctl, sizeof(virDomainPtr) * (nids + nnames));
    list->ndomains = 0;

    /* get active domains */
    for (i = 0; i < nids; i++) {
        if (!(dom = virDomainLookupByID(ctl->conn, ids[i])))
            continue;
        list->domains[list->ndomains++] = dom;
    }

    /* get inactive domains */
    for (i = 0; i < nnames; i++) {
        if (!(dom = virDomainLookupByName(ctl->conn, names[i])))
            continue;
        list->domains[list->ndomains++] = dom;
    }

    /* truncate domains that weren't found */
    deleted = (nids + nnames) - list->ndomains;

filter:
    /* filter list the list if the list was acquired by fallback means */
    for (i = 0; i < list->ndomains; i++) {
        dom = list->domains[i];

        /* persistence filter */
        if (MATCH(VIR_CONNECT_LIST_FILTERS_PERSISTENT)) {
            if ((persistent = virDomainIsPersistent(dom)) < 0) {
                vshError(ctl, "%s", _("Failed to get domain persistence info"));
                goto cleanup;
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT) && persistent) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) && !persistent)))
                goto remove_entry;
        }

        /* domain state filter */
        if (MATCH(VIR_CONNECT_LIST_FILTERS_STATE)) {
            if (virDomainGetState(dom, &state, NULL, 0) < 0) {
                vshError(ctl, "%s", _("Failed to get domain state"));
                goto cleanup;
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
                   state == VIR_DOMAIN_RUNNING) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
                   state == VIR_DOMAIN_PAUSED) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
                   state == VIR_DOMAIN_SHUTOFF) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
                   (state != VIR_DOMAIN_RUNNING &&
                    state != VIR_DOMAIN_PAUSED &&
                    state != VIR_DOMAIN_SHUTOFF))))
                goto remove_entry;
        }

        /* autostart filter */
        if (MATCH(VIR_CONNECT_LIST_FILTERS_AUTOSTART)) {
            if (virDomainGetAutostart(dom, &autostart) < 0) {
                vshError(ctl, "%s", _("Failed to get domain autostart state"));
                goto cleanup;
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) && autostart) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART) && !autostart)))
                goto remove_entry;
        }

        /* managed save filter */
        if (MATCH(VIR_CONNECT_LIST_FILTERS_MANAGEDSAVE)) {
            if ((mansave = virDomainHasManagedSaveImage(dom, 0)) < 0) {
                vshError(ctl, "%s",
                         _("Failed to check for managed save image"));
                goto cleanup;
            }

            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) && mansave) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) && !mansave)))
                goto remove_entry;
        }

        /* snapshot filter */
        if (MATCH(VIR_CONNECT_LIST_FILTERS_SNAPSHOT)) {
            if ((nsnap = virDomainSnapshotNum(dom, 0)) < 0) {
                vshError(ctl, "%s", _("Failed to get snapshot count"));
                goto cleanup;
            }
            if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) && nsnap > 0) ||
                  (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) && nsnap == 0)))
                goto remove_entry;
        }

        /* the domain matched all filters, it may stay */
        continue;

remove_entry:
        /* the domain has to be removed as it failed one of the filters */
        virDomainFree(list->domains[i]);
        list->domains[i] = NULL;
        deleted++;
    }

finished:
    /* sort the list */
    if (list->domains && list->ndomains)
        qsort(list->domains, list->ndomains, sizeof(*list->domains),
              vshDomainSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->domains, list->ndomains, deleted);

    success = true;

cleanup:
    for (i = 0; i < nnames; i++)
        VIR_FREE(names[i]);

    if (!success) {
        vshDomainListFree(list);
        list = NULL;
    }

    VIR_FREE(names);
    VIR_FREE(ids);
    return list;
}
#undef MATCH

static const vshCmdOptDef opts_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive domains")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active domains")},
    {"transient", VSH_OT_BOOL, 0, N_("list transient domains")},
    {"persistent", VSH_OT_BOOL, 0, N_("list persistent domains")},
    {"with-snapshot", VSH_OT_BOOL, 0,
     N_("list domains with existing snapshot")},
    {"without-snapshot", VSH_OT_BOOL, 0,
     N_("list domains without a snapshot")},
    {"state-running", VSH_OT_BOOL, 0, N_("list domains in running state")},
    {"state-paused", VSH_OT_BOOL, 0, N_("list domains in paused state")},
    {"state-shutoff", VSH_OT_BOOL, 0, N_("list domains in shutoff state")},
    {"state-other", VSH_OT_BOOL, 0, N_("list domains in other states")},
    {"autostart", VSH_OT_BOOL, 0, N_("list domains with autostart enabled")},
    {"no-autostart", VSH_OT_BOOL, 0,
     N_("list domains with autostart disabled")},
    {"with-managed-save", VSH_OT_BOOL, 0,
     N_("list domains with managed save state")},
    {"without-managed-save", VSH_OT_BOOL, 0,
     N_("list domains without managed save")},
    {"uuid", VSH_OT_BOOL, 0, N_("list uuid's only")},
    {"name", VSH_OT_BOOL, 0, N_("list domain names only")},
    {"table", VSH_OT_BOOL, 0, N_("list table (default)")},
    {"managed-save", VSH_OT_BOOL, 0,
     N_("mark inactive domains with managed save state")},
    {"title", VSH_OT_BOOL, 0, N_("show short domain description")},
    {NULL, 0, 0, NULL}
};

#define FILTER(NAME, FLAG)              \
    if (vshCommandOptBool(cmd, NAME))   \
        flags |= (FLAG)
static bool
cmdList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    bool managed = vshCommandOptBool(cmd, "managed-save");
    bool optTitle = vshCommandOptBool(cmd, "title");
    bool optTable = vshCommandOptBool(cmd, "table");
    bool optUUID = vshCommandOptBool(cmd, "uuid");
    bool optName = vshCommandOptBool(cmd, "name");
    int i;
    char *title;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int state;
    bool ret = false;
    vshDomainListPtr list = NULL;
    virDomainPtr dom;
    char id_buf[INT_BUFSIZE_BOUND(unsigned int)];
    unsigned int id;
    unsigned int flags = VIR_CONNECT_LIST_DOMAINS_ACTIVE;

    /* construct filter flags */
    if (vshCommandOptBool(cmd, "inactive"))
        flags = VIR_CONNECT_LIST_DOMAINS_INACTIVE;

    if (vshCommandOptBool(cmd, "all"))
        flags = VIR_CONNECT_LIST_DOMAINS_INACTIVE |
                VIR_CONNECT_LIST_DOMAINS_ACTIVE;

    FILTER("persistent", VIR_CONNECT_LIST_DOMAINS_PERSISTENT);
    FILTER("transient",  VIR_CONNECT_LIST_DOMAINS_TRANSIENT);

    FILTER("with-managed-save",    VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE);
    FILTER("without-managed-save", VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE);

    FILTER("autostart",    VIR_CONNECT_LIST_DOMAINS_AUTOSTART);
    FILTER("no-autostart", VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART);

    FILTER("with-snapshot",    VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT);
    FILTER("without-snapshot", VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT);

    FILTER("state-running", VIR_CONNECT_LIST_DOMAINS_RUNNING);
    FILTER("state-paused",  VIR_CONNECT_LIST_DOMAINS_PAUSED);
    FILTER("state-shutoff", VIR_CONNECT_LIST_DOMAINS_SHUTOFF);
    FILTER("state-other",   VIR_CONNECT_LIST_DOMAINS_OTHER);

    if (optTable + optName + optUUID > 1) {
        vshError(ctl, "%s",
                 _("Only one argument from --table, --name and --uuid "
                   "may be specified."));
        return false;
    }

    if (!optUUID && !optName)
        optTable = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(list = vshDomainListCollect(ctl, flags)))
        goto cleanup;

    /* print table header in legacy mode */
    if (optTable) {
        if (optTitle)
            vshPrintExtra(ctl, " %-5s %-30s %-10s %-20s\n%s\n",
                          _("Id"), _("Name"), _("State"), _("Title"),
                          "-----------------------------------------"
                          "-----------------------------------------");
        else
            vshPrintExtra(ctl, " %-5s %-30s %s\n%s\n",
                          _("Id"), _("Name"), _("State"),
                          "-----------------------------------------"
                          "-----------");
    }

    for (i = 0; i < list->ndomains; i++) {
        dom = list->domains[i];
        id = virDomainGetID(dom);
        if (id != (unsigned int) -1)
            snprintf(id_buf, sizeof(id_buf), "%d", id);
        else
            ignore_value(virStrcpyStatic(id_buf, "-"));

        state = vshDomainState(ctl, dom, NULL);
        if (optTable && managed && state == VIR_DOMAIN_SHUTOFF &&
            virDomainHasManagedSaveImage(dom, 0) > 0)
            state = -2;

        if (optTable) {
            if (optTitle) {
                if (!(title = vshGetDomainDescription(ctl, dom, true, 0)))
                    goto cleanup;

                vshPrint(ctl, " %-5s %-30s %-10s %-20s\n", id_buf,
                         virDomainGetName(dom),
                         state == -2 ? _("saved") : _(vshDomainStateToString(state)),
                         title);

                VIR_FREE(title);
            } else {
                vshPrint(ctl, " %-5s %-30s %s\n", id_buf,
                         virDomainGetName(dom),
                         state == -2 ? _("saved") : _(vshDomainStateToString(state)));
            }
        } else if (optUUID) {
            if (virDomainGetUUIDString(dom, uuid) < 0) {
                vshError(ctl, "%s", _("Failed to get domain's UUID"));
                goto cleanup;
            }
            vshPrint(ctl, "%s\n", uuid);
        } else if (optName) {
            vshPrint(ctl, "%s\n", virDomainGetName(dom));
        }
    }

    ret = true;
cleanup:
    vshDomainListFree(list);
    return ret;
}
#undef FILTER

static const vshCmdDef domMonitoringCmds[] = {
    {"domblkerror", cmdDomBlkError, opts_domblkerror, info_domblkerror, 0},
    {"domblkinfo", cmdDomblkinfo, opts_domblkinfo, info_domblkinfo, 0},
    {"domblklist", cmdDomblklist, opts_domblklist, info_domblklist, 0},
    {"domblkstat", cmdDomblkstat, opts_domblkstat, info_domblkstat, 0},
    {"domcontrol", cmdDomControl, opts_domcontrol, info_domcontrol, 0},
    {"domif-getlink", cmdDomIfGetLink, opts_domif_getlink, info_domif_getlink, 0},
    {"domiflist", cmdDomiflist, opts_domiflist, info_domiflist, 0},
    {"domifstat", cmdDomIfstat, opts_domifstat, info_domifstat, 0},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo, 0},
    {"dommemstat", cmdDomMemStat, opts_dommemstat, info_dommemstat, 0},
    {"domstate", cmdDomstate, opts_domstate, info_domstate, 0},
    {"list", cmdList, opts_list, info_list, 0},
    {NULL, NULL, NULL, NULL, 0}
};
