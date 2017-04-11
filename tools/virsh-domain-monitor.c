/*
 * virsh-domain-monitor.c: Commands to monitor domain status
 *
 * Copyright (C) 2005, 2007-2016 Red Hat, Inc.
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
#include "virsh-domain-monitor.h"
#include "virsh-util.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#include "internal.h"
#include "conf/virdomainobjlist.h"
#include "intprops.h"
#include "viralloc.h"
#include "virmacaddr.h"
#include "virxml.h"
#include "virstring.h"

#define VIRSH_COMMON_OPT_DOMAIN_FULL                       \
    VIRSH_COMMON_OPT_DOMAIN(N_("domain name, id or uuid")) \

VIR_ENUM_DECL(virshDomainIOError)
VIR_ENUM_IMPL(virshDomainIOError,
              VIR_DOMAIN_DISK_ERROR_LAST,
              N_("no error"),
              N_("unspecified error"),
              N_("no space"))

static const char *
virshDomainIOErrorToString(int error)
{
    const char *str = virshDomainIOErrorTypeToString(error);
    return str ? _(str) : _("unknown error");
}

/* extract description or title from domain xml */
char *
virshGetDomainDescription(vshControl *ctl, virDomainPtr dom, bool title,
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

VIR_ENUM_DECL(virshDomainControlState)
VIR_ENUM_IMPL(virshDomainControlState,
              VIR_DOMAIN_CONTROL_LAST,
              N_("ok"),
              N_("background job"),
              N_("occupied"),
              N_("error"))

static const char *
virshDomainControlStateToString(int state)
{
    const char *str = virshDomainControlStateTypeToString(state);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainControlErrorReason)
VIR_ENUM_IMPL(virshDomainControlErrorReason,
              VIR_DOMAIN_CONTROL_ERROR_REASON_LAST,
              "",
              N_("unknown"),
              N_("monitor failure"),
              N_("internal (locking) error"))

static const char *
virshDomainControlErrorReasonToString(int reason)
{
    const char *ret = virshDomainControlErrorReasonTypeToString(reason);
    return ret ? _(ret) : _("unknown");
}

VIR_ENUM_DECL(virshDomainState)
VIR_ENUM_IMPL(virshDomainState,
              VIR_DOMAIN_LAST,
              N_("no state"),
              N_("running"),
              N_("idle"),
              N_("paused"),
              N_("in shutdown"),
              N_("shut off"),
              N_("crashed"),
              N_("pmsuspended"))

static const char *
virshDomainStateToString(int state)
{
    const char *str = virshDomainStateTypeToString(state);
    return str ? _(str) : _("no state");
}

VIR_ENUM_DECL(virshDomainNostateReason)
VIR_ENUM_IMPL(virshDomainNostateReason,
              VIR_DOMAIN_NOSTATE_LAST,
              N_("unknown"))

VIR_ENUM_DECL(virshDomainRunningReason)
VIR_ENUM_IMPL(virshDomainRunningReason,
              VIR_DOMAIN_RUNNING_LAST,
              N_("unknown"),
              N_("booted"),
              N_("migrated"),
              N_("restored"),
              N_("from snapshot"),
              N_("unpaused"),
              N_("migration canceled"),
              N_("save canceled"),
              N_("event wakeup"),
              N_("crashed"),
              N_("post-copy"))

VIR_ENUM_DECL(virshDomainBlockedReason)
VIR_ENUM_IMPL(virshDomainBlockedReason,
              VIR_DOMAIN_BLOCKED_LAST,
              N_("unknown"))

VIR_ENUM_DECL(virshDomainPausedReason)
VIR_ENUM_IMPL(virshDomainPausedReason,
              VIR_DOMAIN_PAUSED_LAST,
              N_("unknown"),
              N_("user"),
              N_("migrating"),
              N_("saving"),
              N_("dumping"),
              N_("I/O error"),
              N_("watchdog"),
              N_("from snapshot"),
              N_("shutting down"),
              N_("creating snapshot"),
              N_("crashed"),
              N_("starting up"),
              N_("post-copy"),
              N_("post-copy failed"))

VIR_ENUM_DECL(virshDomainShutdownReason)
VIR_ENUM_IMPL(virshDomainShutdownReason,
              VIR_DOMAIN_SHUTDOWN_LAST,
              N_("unknown"),
              N_("user"))

VIR_ENUM_DECL(virshDomainShutoffReason)
VIR_ENUM_IMPL(virshDomainShutoffReason,
              VIR_DOMAIN_SHUTOFF_LAST,
              N_("unknown"),
              N_("shutdown"),
              N_("destroyed"),
              N_("crashed"),
              N_("migrated"),
              N_("saved"),
              N_("failed"),
              N_("from snapshot"))

VIR_ENUM_DECL(virshDomainCrashedReason)
VIR_ENUM_IMPL(virshDomainCrashedReason,
              VIR_DOMAIN_CRASHED_LAST,
              N_("unknown"),
              N_("panicked"))

VIR_ENUM_DECL(virshDomainPMSuspendedReason)
VIR_ENUM_IMPL(virshDomainPMSuspendedReason,
              VIR_DOMAIN_PMSUSPENDED_LAST,
              N_("unknown"))

static const char *
virshDomainStateReasonToString(int state, int reason)
{
    const char *str = NULL;
    switch ((virDomainState) state) {
    case VIR_DOMAIN_NOSTATE:
        str = virshDomainNostateReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_RUNNING:
        str = virshDomainRunningReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_BLOCKED:
        str = virshDomainBlockedReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_PAUSED:
        str = virshDomainPausedReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_SHUTDOWN:
        str = virshDomainShutdownReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_SHUTOFF:
        str = virshDomainShutoffReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_CRASHED:
        str = virshDomainCrashedReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_PMSUSPENDED:
        str = virshDomainPMSuspendedReasonTypeToString(reason);
        break;
    case VIR_DOMAIN_LAST:
        ;
    }

    return str ? _(str) : _("unknown");
}

/*
 * "dommemstat" command
 */
static const vshCmdInfo info_dommemstat[] = {
    {.name = "help",
     .data = N_("get memory statistics for a domain")
    },
    {.name = "desc",
     .data = N_("Get memory statistics for a running domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dommemstat[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "period",
     .type = VSH_OT_INT,
     .flags = VSH_OFLAG_REQ_OPT,
     .help = N_("period in seconds to set collection")
    },
    VIRSH_COMMON_OPT_CONFIG(N_("affect next boot")),
    VIRSH_COMMON_OPT_LIVE(N_("affect running domain")),
    VIRSH_COMMON_OPT_CURRENT(N_("affect current domain")),
    {.name = NULL}
};

static bool
cmdDomMemStat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    virDomainMemoryStatStruct stats[VIR_DOMAIN_MEMORY_STAT_NR];
    unsigned int nr_stats;
    size_t i;
    bool ret = false;
    int rv = 0;
    int period = -1;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    VSH_EXCLUSIVE_OPTIONS_VAR(current, live);
    VSH_EXCLUSIVE_OPTIONS_VAR(current, config);
    if (config)
        flags |= VIR_DOMAIN_AFFECT_CONFIG;
    if (live)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    /* If none of the options were specified and we're active
     * then be sure to allow active modification */
    if (!current && !live && !config && virDomainIsActive(dom) == 1)
        flags |= VIR_DOMAIN_AFFECT_LIVE;

    /* Providing a period will adjust the balloon driver collection period.
     * This is not really an unsigned long, but it
     */
    if ((rv = vshCommandOptInt(ctl, cmd, "period", &period)) < 0)
        goto cleanup;
    if (rv > 0) {
        if (period < 0) {
            vshError(ctl, _("Invalid collection period value '%d'"), period);
            goto cleanup;
        }

        if (virDomainSetMemoryStatsPeriod(dom, period, flags) < 0) {
            vshError(ctl, "%s",
                     _("Unable to change balloon collection period."));
        } else {
            ret = true;
        }
        goto cleanup;
    }

    nr_stats = virDomainMemoryStats(dom, stats, VIR_DOMAIN_MEMORY_STAT_NR, 0);
    if (nr_stats == -1) {
        vshError(ctl, _("Failed to get memory statistics for domain %s"), name);
        goto cleanup;
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
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_USABLE)
            vshPrint(ctl, "usable %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON)
            vshPrint(ctl, "actual %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_RSS)
            vshPrint(ctl, "rss %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_LAST_UPDATE)
            vshPrint(ctl, "last_update %llu\n", stats[i].val);
    }

    ret = true;
 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "domblkinfo" command
 */
static const vshCmdInfo info_domblkinfo[] = {
    {.name = "help",
     .data = N_("domain block device size information")
    },
    {.name = "desc",
     .data = N_("Get block device size info for a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domblkinfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "device",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("block device")
    },
    {.name = NULL}
};

static bool
cmdDomblkinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainBlockInfo info;
    virDomainPtr dom;
    bool ret = false;
    const char *device = NULL;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "device", &device) < 0)
        goto cleanup;

    if (virDomainGetBlockInfo(dom, device, &info, 0) < 0)
        goto cleanup;

    vshPrint(ctl, "%-15s %llu\n", _("Capacity:"), info.capacity);
    vshPrint(ctl, "%-15s %llu\n", _("Allocation:"), info.allocation);
    vshPrint(ctl, "%-15s %llu\n", _("Physical:"), info.physical);

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "domblklist" command
 */
static const vshCmdInfo info_domblklist[] = {
    {.name = "help",
     .data = N_("list all domain blocks")
    },
    {.name = "desc",
     .data = N_("Get the summary of block devices for a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domblklist[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("get inactive rather than running configuration")
    },
    {.name = "details",
     .type = VSH_OT_BOOL,
     .help = N_("additionally display the type and device value")
    },
    {.name = NULL}
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
    size_t i;
    bool details = false;
    char *type = NULL;
    char *device = NULL;
    char *target = NULL;
    char *source = NULL;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    details = vshCommandOptBool(cmd, "details");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
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
        vshPrintExtra(ctl, "%-10s %-10s %-10s %s\n", _("Type"),
                      _("Device"), _("Target"), _("Source"));
    else
        vshPrintExtra(ctl, "%-10s %s\n", _("Target"), _("Source"));

    vshPrintExtra(ctl, "------------------------------------------------\n");

    for (i = 0; i < ndisks; i++) {
        ctxt->node = disks[i];

        if (details) {
            type = virXPathString("string(./@type)", ctxt);
            device = virXPathString("string(./@device)", ctxt);
            if (!type || !device) {
                vshPrint(ctl, "unable to query block list details");
                goto cleanup;
            }
        }

        target = virXPathString("string(./target/@dev)", ctxt);
        if (!target) {
            vshError(ctl, "unable to query block list");
            goto cleanup;
        }
        source = virXPathString("string(./source/@file"
                                "|./source/@dev"
                                "|./source/@dir"
                                "|./source/@name"
                                "|./source/@volume)", ctxt);
        if (details) {
            vshPrint(ctl, "%-10s %-10s %-10s %s\n", type, device,
                     target, source ? source : "-");
        } else {
            vshPrint(ctl, "%-10s %s\n", target, source ? source : "-");
        }

        VIR_FREE(source);
        VIR_FREE(target);
        VIR_FREE(device);
        VIR_FREE(type);
    }

    ret = true;

 cleanup:
    VIR_FREE(source);
    VIR_FREE(target);
    VIR_FREE(device);
    VIR_FREE(type);
    VIR_FREE(disks);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(xml);
    virshDomainFree(dom);
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
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("get inactive rather than running configuration")
    },
    {.name = NULL}
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
    size_t i;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
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

    vshPrintExtra(ctl, "%-10s %-10s %-10s %-11s %s\n", _("Interface"),
                  _("Type"), _("Source"), _("Model"), _("MAC"));
    vshPrintExtra(ctl, "-------------------------------------------------------\n");

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
    virshDomainFree(dom);
    VIR_FREE(xml);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;
}

/*
 * "domif-getlink" command
 */
static const vshCmdInfo info_domif_getlink[] = {
    {.name = "help",
     .data = N_("get link state of a virtual interface")
    },
    {.name = "desc",
     .data = N_("Get link state of a domain's virtual interface.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domif_getlink[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface device (MAC Address)")
    },
    {.name = "persistent",
     .type = VSH_OT_ALIAS,
     .help = "config"
    },
    VIRSH_COMMON_OPT_CONFIG(N_("Get persistent interface state")),
    {.name = NULL}
};

static bool
cmdDomIfGetLink(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface = NULL;
    char *state = NULL;
    char *xpath = NULL;
    virMacAddr macaddr;
    char macstr[VIR_MAC_STRING_BUFLEN] = "";
    char *desc = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *interfaces = NULL;
    int ninterfaces;
    unsigned int flags = 0;
    bool ret = false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &iface) < 0)
        return false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool(cmd, "config"))
        flags = VIR_DOMAIN_XML_INACTIVE;

    if (!(desc = virDomainGetXMLDesc(dom, flags))) {
        vshError(ctl, _("Failed to get domain description xml"));
        goto cleanup;
    }

    if (!(xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), &ctxt))) {
        vshError(ctl, _("Failed to parse domain description xml"));
        goto cleanup;
    }

    /* normalize the mac addr */
    if (virMacAddrParse(iface, &macaddr) == 0)
        virMacAddrFormat(&macaddr, macstr);

    if (virAsprintf(&xpath, "/domain/devices/interface[(mac/@address = '%s') or "
                            "                          (target/@dev = '%s')]",
                           macstr, iface) < 0)
        goto cleanup;

    if ((ninterfaces = virXPathNodeSet(xpath, ctxt, &interfaces)) < 0) {
        vshError(ctl, _("Failed to extract interface information"));
        goto cleanup;
    }

    if (ninterfaces != 1) {
        if (macstr[0])
            vshError(ctl, _("Interface (mac: %s) not found."), macstr);
        else
            vshError(ctl, _("Interface (dev: %s) not found."), iface);

        goto cleanup;
    }

    ctxt->node = interfaces[0];

    if ((state = virXPathString("string(./link/@state)", ctxt)))
        vshPrint(ctl, "%s %s", iface, state);
    else
        vshPrint(ctl, "%s up", iface);

    ret = true;

 cleanup:
    VIR_FREE(desc);
    VIR_FREE(state);
    VIR_FREE(interfaces);
    VIR_FREE(xpath);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virshDomainFree(dom);

    return ret;
}

/*
 * "domcontrol" command
 */
static const vshCmdInfo info_domcontrol[] = {
    {.name = "help",
     .data = N_("domain control interface state")
    },
    {.name = "desc",
     .data = N_("Returns state of a control interface to the domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domcontrol[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomControl(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    virDomainControlInfo info;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetControlInfo(dom, &info, 0) < 0) {
        ret = false;
        goto cleanup;
    }

    if (info.state != VIR_DOMAIN_CONTROL_OK &&
        info.state != VIR_DOMAIN_CONTROL_ERROR) {
        vshPrint(ctl, "%s (%0.3fs)\n",
                 virshDomainControlStateToString(info.state),
                 info.stateTime / 1000.0);
    } else if (info.state == VIR_DOMAIN_CONTROL_ERROR && info.details > 0) {
        vshPrint(ctl, "%s: %s\n",
                 virshDomainControlStateToString(info.state),
                 virshDomainControlErrorReasonToString(info.details));
    } else {
        vshPrint(ctl, "%s\n",
                 virshDomainControlStateToString(info.state));
    }

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "domblkstat" command
 */
static const vshCmdInfo info_domblkstat[] = {
    {.name = "help",
     .data = N_("get device block stats for a domain")
    },
    {.name = "desc",
     .data = N_("Get device block stats for a running domain. See man page or "
                "use --human for explanation of fields")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domblkstat[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "device",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("block device")
    },
    {.name = "human",
     .type = VSH_OT_BOOL,
     .help = N_("print a more human readable output")
    },
    {.name = NULL}
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
    virDomainBlockStatsStruct stats;
    virTypedParameterPtr params = NULL;
    virTypedParameterPtr par = NULL;
    char *value = NULL;
    const char *field = NULL;
    int rc, nparams = 0;
    size_t i;
    bool ret = false;
    bool human = vshCommandOptBool(cmd, "human"); /* human readable output */

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    /* device argument is optional now. if it's missing, supply empty
       string to denote 'all devices'. A NULL device arg would violate
       API contract.
     */
    if (vshCommandOptStringReq(ctl, cmd, "device", &device) < 0)
        goto cleanup;

    if (!device)
        device = "";

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
            vshError(ctl, _("Failed to get block stats for domain '%s' device '%s'"), name, device);
            goto cleanup;
        }

        /* set for prettier output */
        if (human) {
            vshPrint(ctl, N_("Device: %s\n"), device);
            device = "";
        }

        /* at first print all known values in desired order */
        for (i = 0; domblkstat_output[i].field != NULL; i++) {
            if (!(par = virTypedParamsGet(params, nparams,
                                          domblkstat_output[i].field)))
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
    virshDomainFree(dom);
    return ret;
}
#undef DOMBLKSTAT_LEGACY_PRINT

/*
 * "domifstat" command
 */
static const vshCmdInfo info_domifstat[] = {
    {.name = "help",
     .data = N_("get network interface stats for a domain")
    },
    {.name = "desc",
     .data = N_("Get network interface stats for a running domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domifstat[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "interface",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_REQ,
     .help = N_("interface device")
    },
    {.name = NULL}
};

static bool
cmdDomIfstat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL;
    virDomainInterfaceStatsStruct stats;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &device) < 0)
        goto cleanup;

    if (virDomainInterfaceStats(dom, device, &stats, sizeof(stats)) == -1) {
        vshError(ctl, _("Failed to get interface stats %s %s"), name, device);
        goto cleanup;
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

    ret = true;

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "domblkerror" command
 */
static const vshCmdInfo info_domblkerror[] = {
    {.name = "help",
     .data = N_("Show errors on block devices")
    },
    {.name = "desc",
     .data = N_("Show block device errors")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domblkerror[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
};

static bool
cmdDomBlkError(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainDiskErrorPtr disks = NULL;
    unsigned int ndisks;
    size_t i;
    int count;
    bool ret = false;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
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
                     virshDomainIOErrorToString(disks[i].error));
        }
    }

    ret = true;

 cleanup:
    VIR_FREE(disks);
    virshDomainFree(dom);
    return ret;
}

/*
 * "dominfo" command
 */
static const vshCmdInfo info_dominfo[] = {
    {.name = "help",
     .data = N_("domain information")
    },
    {.name = "desc",
     .data = N_("Returns basic information about the domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_dominfo[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = NULL}
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
    virshControlPtr priv = ctl->privData;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%-15s %s\n", _("Id:"), "-");
    else
        vshPrint(ctl, "%-15s %d\n", _("Id:"), id);
    vshPrint(ctl, "%-15s %s\n", _("Name:"), virDomainGetName(dom));

    if (virDomainGetUUIDString(dom, &uuid[0]) == 0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

    if ((str = virDomainGetOSType(dom))) {
        vshPrint(ctl, "%-15s %s\n", _("OS Type:"), str);
        VIR_FREE(str);
    }

    if (virDomainGetInfo(dom, &info) == 0) {
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 virshDomainStateToString(info.state));

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
                 autostart ? _("enable") : _("disable"));
    }

    has_managed_save = virDomainHasManagedSaveImage(dom, 0);
    if (has_managed_save < 0)
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"),
                 has_managed_save ? _("yes") : _("no"));

    /* Security model and label information */
    memset(&secmodel, 0, sizeof(secmodel));
    if (virNodeGetSecurityModel(priv->conn, &secmodel) == -1) {
        if (last_error->code != VIR_ERR_NO_SUPPORT) {
            virshDomainFree(dom);
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
                virshDomainFree(dom);
                return false;
            }

            if (virDomainGetSecurityLabel(dom, seclabel) == -1) {
                virshDomainFree(dom);
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
    virshDomainFree(dom);
    return ret;
}

/*
 * "domstate" command
 */
static const vshCmdInfo info_domstate[] = {
    {.name = "help",
     .data = N_("domain state")
    },
    {.name = "desc",
     .data = N_("Returns state about a domain.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domstate[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "reason",
     .type = VSH_OT_BOOL,
     .help = N_("also print reason for the state")
    },
    {.name = NULL}
};

static bool
cmdDomstate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    bool showReason = vshCommandOptBool(cmd, "reason");
    int state, reason;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = virshDomainState(ctl, dom, &reason)) < 0) {
        ret = false;
        goto cleanup;
    }

    if (showReason) {
        vshPrint(ctl, "%s (%s)\n",
                 virshDomainStateToString(state),
                 virshDomainStateReasonToString(state, reason));
    } else {
        vshPrint(ctl, "%s\n",
                 virshDomainStateToString(state));
    }

 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "domtime" command
 */
static const vshCmdInfo info_domtime[] = {
    {.name = "help",
     .data = N_("domain time")
    },
    {.name = "desc",
     .data = N_("Gets or sets the domain's system time")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domtime[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "now",
     .type = VSH_OT_BOOL,
     .help = N_("set to the time of the host running virsh")
    },
    {.name = "pretty",
     .type = VSH_OT_BOOL,
     .help = N_("print domain's time in human readable form")
    },
    {.name = "sync",
     .type = VSH_OT_BOOL,
     .help = N_("instead of setting given time, synchronize from domain's RTC"),
    },
    {.name = "time",
     .type = VSH_OT_INT,
     .help = N_("time to set")
    },
    {.name = NULL}
};

static bool
cmdDomTime(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    bool now = vshCommandOptBool(cmd, "now");
    bool pretty = vshCommandOptBool(cmd, "pretty");
    bool rtcSync = vshCommandOptBool(cmd, "sync");
    long long seconds = 0;
    unsigned int nseconds = 0;
    unsigned int flags = 0;
    bool doSet = false;
    int rv;

    VSH_EXCLUSIVE_OPTIONS("time", "now");
    VSH_EXCLUSIVE_OPTIONS("time", "sync");
    VSH_EXCLUSIVE_OPTIONS("now", "sync");

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    rv = vshCommandOptLongLong(ctl, cmd, "time", &seconds);

    if (rv < 0) {
        /* invalid integer format */
        goto cleanup;
    } else if (rv > 0) {
        /* valid integer to set */
        doSet = true;
    }

    if (doSet || now || rtcSync) {
        if (now && ((seconds = time(NULL)) == (time_t) -1)) {
            vshError(ctl, _("Unable to get current time"));
            goto cleanup;
        }

        if (rtcSync)
            flags |= VIR_DOMAIN_TIME_SYNC;

        if (virDomainSetTime(dom, seconds, nseconds, flags) < 0)
            goto cleanup;

    } else {
        if (virDomainGetTime(dom, &seconds, &nseconds, flags) < 0)
            goto cleanup;

        if (pretty) {
            char timestr[100];
            time_t cur_time = seconds;
            struct tm time_info;

            if (!gmtime_r(&cur_time, &time_info)) {
                vshError(ctl, _("Unable to format time"));
                goto cleanup;
            }
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &time_info);

            vshPrint(ctl, _("Time: %s"), timestr);
        } else {
            vshPrint(ctl, _("Time: %lld"), seconds);
        }
    }

    ret = true;
 cleanup:
    virshDomainFree(dom);
    return ret;
}

/*
 * "list" command
 */
static const vshCmdInfo info_list[] = {
    {.name = "help",
     .data = N_("list domains")
    },
    {.name = "desc",
     .data = N_("Returns list of domains.")
    },
    {.name = NULL}
};

/* compare domains, pack NULLed ones at the end*/
static int
virshDomainSorter(const void *a, const void *b)
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
        return vshStrcasecmp(virDomainGetName(*da), virDomainGetName(*db));

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

struct virshDomainList {
    virDomainPtr *domains;
    size_t ndomains;
};
typedef struct virshDomainList *virshDomainListPtr;

static void
virshDomainListFree(virshDomainListPtr domlist)
{
    size_t i;

    if (domlist && domlist->domains) {
        for (i = 0; i < domlist->ndomains; i++) {
            if (domlist->domains[i])
                virshDomainFree(domlist->domains[i]);
        }
        VIR_FREE(domlist->domains);
    }
    VIR_FREE(domlist);
}

static virshDomainListPtr
virshDomainListCollect(vshControl *ctl, unsigned int flags)
{
    virshDomainListPtr list = vshMalloc(ctl, sizeof(*list));
    size_t i;
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
    virshControlPtr priv = ctl->privData;

    /* try the list with flags support (0.9.13 and later) */
    if ((ret = virConnectListAllDomains(priv->conn, &list->domains,
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
        if ((ret = virConnectListAllDomains(priv->conn, &list->domains,
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
    if (!VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE)) {
        if ((nids = virConnectNumOfDomains(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to list active domains"));
            goto cleanup;
        }

        if (nids) {
            ids = vshMalloc(ctl, sizeof(int) * nids);

            if ((nids = virConnectListDomains(priv->conn, ids, nids)) < 0) {
                vshError(ctl, "%s", _("Failed to list active domains"));
                goto cleanup;
            }
        }
    }

    if (!VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) ||
        VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE)) {
        if ((nnames = virConnectNumOfDefinedDomains(priv->conn)) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive domains"));
            goto cleanup;
        }

        if (nnames) {
            names = vshMalloc(ctl, sizeof(char *) * nnames);

            if ((nnames = virConnectListDefinedDomains(priv->conn, names,
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
        if (!(dom = virDomainLookupByID(priv->conn, ids[i])))
            continue;
        list->domains[list->ndomains++] = dom;
    }

    /* get inactive domains */
    for (i = 0; i < nnames; i++) {
        if (!(dom = virDomainLookupByName(priv->conn, names[i])))
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
        if (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT)) {
            if ((persistent = virDomainIsPersistent(dom)) < 0) {
                vshError(ctl, "%s", _("Failed to get domain persistence info"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT) && persistent) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) && !persistent)))
                goto remove_entry;
        }

        /* domain state filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE)) {
            if (virDomainGetState(dom, &state, NULL, 0) < 0) {
                vshError(ctl, "%s", _("Failed to get domain state"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
                   state == VIR_DOMAIN_RUNNING) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
                   state == VIR_DOMAIN_PAUSED) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
                   state == VIR_DOMAIN_SHUTOFF) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
                   (state != VIR_DOMAIN_RUNNING &&
                    state != VIR_DOMAIN_PAUSED &&
                    state != VIR_DOMAIN_SHUTOFF))))
                goto remove_entry;
        }

        /* autostart filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART)) {
            if (virDomainGetAutostart(dom, &autostart) < 0) {
                vshError(ctl, "%s", _("Failed to get domain autostart state"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) && autostart) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART) && !autostart)))
                goto remove_entry;
        }

        /* managed save filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE)) {
            if ((mansave = virDomainHasManagedSaveImage(dom, 0)) < 0) {
                vshError(ctl, "%s",
                         _("Failed to check for managed save image"));
                goto cleanup;
            }

            if (!((VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) && mansave) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) && !mansave)))
                goto remove_entry;
        }

        /* snapshot filter */
        if (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)) {
            if ((nsnap = virDomainSnapshotNum(dom, 0)) < 0) {
                vshError(ctl, "%s", _("Failed to get snapshot count"));
                goto cleanup;
            }
            if (!((VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) && nsnap > 0) ||
                  (VSH_MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) && nsnap == 0)))
                goto remove_entry;
        }

        /* the domain matched all filters, it may stay */
        continue;

 remove_entry:
        /* the domain has to be removed as it failed one of the filters */
        virshDomainFree(list->domains[i]);
        list->domains[i] = NULL;
        deleted++;
    }

 finished:
    /* sort the list */
    if (list->domains && list->ndomains)
        qsort(list->domains, list->ndomains, sizeof(*list->domains),
              virshDomainSorter);

    /* truncate the list if filter simulation deleted entries */
    if (deleted)
        VIR_SHRINK_N(list->domains, list->ndomains, deleted);

    success = true;

 cleanup:
    for (i = 0; nnames != -1 && i < nnames; i++)
        VIR_FREE(names[i]);

    if (!success) {
        virshDomainListFree(list);
        list = NULL;
    }

    VIR_FREE(names);
    VIR_FREE(ids);
    return list;
}

static const vshCmdOptDef opts_list[] = {
    {.name = "inactive",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive domains")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("list inactive & active domains")
    },
    {.name = "transient",
     .type = VSH_OT_BOOL,
     .help = N_("list transient domains")
    },
    {.name = "persistent",
     .type = VSH_OT_BOOL,
     .help = N_("list persistent domains")
    },
    {.name = "with-snapshot",
     .type = VSH_OT_BOOL,
     .help = N_("list domains with existing snapshot")
    },
    {.name = "without-snapshot",
     .type = VSH_OT_BOOL,
     .help = N_("list domains without a snapshot")
    },
    {.name = "state-running",
     .type = VSH_OT_BOOL,
     .help = N_("list domains in running state")
    },
    {.name = "state-paused",
     .type = VSH_OT_BOOL,
     .help = N_("list domains in paused state")
    },
    {.name = "state-shutoff",
     .type = VSH_OT_BOOL,
     .help = N_("list domains in shutoff state")
    },
    {.name = "state-other",
     .type = VSH_OT_BOOL,
     .help = N_("list domains in other states")
    },
    {.name = "autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list domains with autostart enabled")
    },
    {.name = "no-autostart",
     .type = VSH_OT_BOOL,
     .help = N_("list domains with autostart disabled")
    },
    {.name = "with-managed-save",
     .type = VSH_OT_BOOL,
     .help = N_("list domains with managed save state")
    },
    {.name = "without-managed-save",
     .type = VSH_OT_BOOL,
     .help = N_("list domains without managed save")
    },
    {.name = "uuid",
     .type = VSH_OT_BOOL,
     .help = N_("list uuid's only")
    },
    {.name = "name",
     .type = VSH_OT_BOOL,
     .help = N_("list domain names only")
    },
    {.name = "table",
     .type = VSH_OT_BOOL,
     .help = N_("list table (default)")
    },
    {.name = "managed-save",
     .type = VSH_OT_BOOL,
     .help = N_("mark inactive domains with managed save state")
    },
    {.name = "title",
     .type = VSH_OT_BOOL,
     .help = N_("show domain title")
    },
    {.name = NULL}
};

#define FILTER(NAME, FLAG)              \
    if (vshCommandOptBool(cmd, NAME))   \
        flags |= (FLAG)
static bool
cmdList(vshControl *ctl, const vshCmd *cmd)
{
    bool managed = vshCommandOptBool(cmd, "managed-save");
    bool optTitle = vshCommandOptBool(cmd, "title");
    bool optTable = vshCommandOptBool(cmd, "table");
    bool optUUID = vshCommandOptBool(cmd, "uuid");
    bool optName = vshCommandOptBool(cmd, "name");
    size_t i;
    char *title;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int state;
    bool ret = false;
    virshDomainListPtr list = NULL;
    virDomainPtr dom;
    char id_buf[INT_BUFSIZE_BOUND(unsigned int)];
    unsigned int id;
    unsigned int flags = VIR_CONNECT_LIST_DOMAINS_ACTIVE;

    /* construct filter flags */
    if (vshCommandOptBool(cmd, "inactive") ||
        vshCommandOptBool(cmd, "state-shutoff"))
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

    VSH_EXCLUSIVE_OPTIONS("table", "name");
    VSH_EXCLUSIVE_OPTIONS("table", "uuid");

    if (!optUUID && !optName)
        optTable = true;

    if (!(list = virshDomainListCollect(ctl, flags)))
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

        if (optTable) {
            state = virshDomainState(ctl, dom, NULL);

            /* Domain could've been removed in the meantime */
            if (state < 0)
                continue;

            if (managed && state == VIR_DOMAIN_SHUTOFF &&
                virDomainHasManagedSaveImage(dom, 0) > 0)
                state = -2;

            if (optTitle) {
                if (!(title = virshGetDomainDescription(ctl, dom, true, 0)))
                    goto cleanup;

                vshPrint(ctl, " %-5s %-30s %-10s %-20s\n", id_buf,
                         virDomainGetName(dom),
                         state == -2 ? _("saved")
                         : virshDomainStateToString(state),
                         title);

                VIR_FREE(title);
            } else {
                vshPrint(ctl, " %-5s %-30s %s\n", id_buf,
                         virDomainGetName(dom),
                         state == -2 ? _("saved")
                         : virshDomainStateToString(state));
            }
        } else if (optUUID && optName) {
            if (virDomainGetUUIDString(dom, uuid) < 0) {
                vshError(ctl, "%s", _("Failed to get domain's UUID"));
                goto cleanup;
            }
            vshPrint(ctl, "%-36s %-30s\n", uuid, virDomainGetName(dom));
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
    virshDomainListFree(list);
    return ret;
}
#undef FILTER

/*
 * "domstats" command
 */
static const vshCmdInfo info_domstats[] = {
    {.name = "help",
     .data = N_("get statistics about one or multiple domains")
    },
    {.name = "desc",
     .data = N_("Gets statistics about one or more (or all) domains")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_domstats[] = {
    {.name = "state",
     .type = VSH_OT_BOOL,
     .help = N_("report domain state"),
    },
    {.name = "cpu-total",
     .type = VSH_OT_BOOL,
     .help = N_("report domain physical cpu usage"),
    },
    {.name = "balloon",
     .type = VSH_OT_BOOL,
     .help = N_("report domain balloon statistics"),
    },
    {.name = "vcpu",
     .type = VSH_OT_BOOL,
     .help = N_("report domain virtual cpu information"),
    },
    {.name = "interface",
     .type = VSH_OT_BOOL,
     .help = N_("report domain network interface information"),
    },
    {.name = "block",
     .type = VSH_OT_BOOL,
     .help = N_("report domain block device statistics"),
    },
    {.name = "perf",
     .type = VSH_OT_BOOL,
     .help = N_("report domain perf event statistics"),
    },
    {.name = "list-active",
     .type = VSH_OT_BOOL,
     .help = N_("list only active domains"),
    },
    {.name = "list-inactive",
     .type = VSH_OT_BOOL,
     .help = N_("list only inactive domains"),
    },
    {.name = "list-persistent",
     .type = VSH_OT_BOOL,
     .help = N_("list only persistent domains"),
    },
    {.name = "list-transient",
     .type = VSH_OT_BOOL,
     .help = N_("list only transient domains"),
    },
    {.name = "list-running",
     .type = VSH_OT_BOOL,
     .help = N_("list only running domains"),
    },
    {.name = "list-paused",
     .type = VSH_OT_BOOL,
     .help = N_("list only paused domains"),
    },
    {.name = "list-shutoff",
     .type = VSH_OT_BOOL,
     .help = N_("list only shutoff domains"),
    },
    {.name = "list-other",
     .type = VSH_OT_BOOL,
     .help = N_("list only domains in other states"),
    },
    {.name = "raw",
     .type = VSH_OT_BOOL,
     .help = N_("do not pretty-print the fields"),
    },
    {.name = "enforce",
     .type = VSH_OT_BOOL,
     .help = N_("enforce requested stats parameters"),
    },
    {.name = "backing",
     .type = VSH_OT_BOOL,
     .help = N_("add backing chain information to block stats"),
    },
    {.name = "domain",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_NONE,
     .help = N_("list of domains to get stats for"),
    },
    {.name = NULL}
};


static bool
virshDomainStatsPrintRecord(vshControl *ctl ATTRIBUTE_UNUSED,
                            virDomainStatsRecordPtr record,
                            bool raw ATTRIBUTE_UNUSED)
{
    char *param;
    size_t i;

    vshPrint(ctl, "Domain: '%s'\n", virDomainGetName(record->dom));

    /* XXX: Implement pretty-printing */

    for (i = 0; i < record->nparams; i++) {
        if (!(param = vshGetTypedParamValue(ctl, record->params + i)))
            return false;

        vshPrint(ctl, "  %s=%s\n", record->params[i].field, param);

        VIR_FREE(param);
    }

    return true;
}

static bool
cmdDomstats(vshControl *ctl, const vshCmd *cmd)
{
    unsigned int stats = 0;
    virDomainPtr *domlist = NULL;
    virDomainPtr dom;
    size_t ndoms = 0;
    virDomainStatsRecordPtr *records = NULL;
    virDomainStatsRecordPtr *next;
    bool raw = vshCommandOptBool(cmd, "raw");
    int flags = 0;
    const vshCmdOpt *opt = NULL;
    bool ret = false;
    virshControlPtr priv = ctl->privData;

    if (vshCommandOptBool(cmd, "state"))
        stats |= VIR_DOMAIN_STATS_STATE;

    if (vshCommandOptBool(cmd, "cpu-total"))
        stats |= VIR_DOMAIN_STATS_CPU_TOTAL;

    if (vshCommandOptBool(cmd, "balloon"))
        stats |= VIR_DOMAIN_STATS_BALLOON;

    if (vshCommandOptBool(cmd, "vcpu"))
        stats |= VIR_DOMAIN_STATS_VCPU;

    if (vshCommandOptBool(cmd, "interface"))
        stats |= VIR_DOMAIN_STATS_INTERFACE;

    if (vshCommandOptBool(cmd, "block"))
        stats |= VIR_DOMAIN_STATS_BLOCK;

    if (vshCommandOptBool(cmd, "perf"))
        stats |= VIR_DOMAIN_STATS_PERF;

    if (vshCommandOptBool(cmd, "list-active"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_ACTIVE;

    if (vshCommandOptBool(cmd, "list-inactive"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_INACTIVE;

    if (vshCommandOptBool(cmd, "list-persistent"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_PERSISTENT;

    if (vshCommandOptBool(cmd, "list-transient"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_TRANSIENT;

    if (vshCommandOptBool(cmd, "list-running"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_RUNNING;

    if (vshCommandOptBool(cmd, "list-paused"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_PAUSED;

    if (vshCommandOptBool(cmd, "list-shutoff"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_SHUTOFF;

    if (vshCommandOptBool(cmd, "list-other"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_OTHER;

    if (vshCommandOptBool(cmd, "enforce"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_ENFORCE_STATS;

    if (vshCommandOptBool(cmd, "backing"))
        flags |= VIR_CONNECT_GET_ALL_DOMAINS_STATS_BACKING;

    if (vshCommandOptBool(cmd, "domain")) {
        if (VIR_ALLOC_N(domlist, 1) < 0)
            goto cleanup;
        ndoms = 1;

        while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
            if (!(dom = virshLookupDomainBy(ctl, opt->data,
                                            VIRSH_BYID |
                                            VIRSH_BYUUID | VIRSH_BYNAME)))
                goto cleanup;

            if (VIR_INSERT_ELEMENT(domlist, ndoms - 1, ndoms, dom) < 0)
                goto cleanup;
        }

        if (virDomainListGetStats(domlist,
                                  stats,
                                  &records,
                                  flags) < 0)
            goto cleanup;
    } else {
       if ((virConnectGetAllDomainStats(priv->conn,
                                        stats,
                                        &records,
                                        flags)) < 0)
           goto cleanup;
    }

    next = records;
    while (*next) {
        if (!virshDomainStatsPrintRecord(ctl, *next, raw))
            goto cleanup;

        if (*(++next))
            vshPrint(ctl, "\n");
    }

    ret = true;
 cleanup:
    virDomainStatsRecordListFree(records);
    virObjectListFree(domlist);

    return ret;
}

/* "domifaddr" command
 */
static const vshCmdInfo info_domifaddr[] = {
    {"help", N_("Get network interfaces' addresses for a running domain")},
    {"desc", N_("Get network interfaces' addresses for a running domain")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domifaddr[] = {
    VIRSH_COMMON_OPT_DOMAIN_FULL,
    {.name = "interface",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .help = N_("network interface name")},
    {.name = "full",
     .type = VSH_OT_BOOL,
     .flags = VSH_OFLAG_NONE,
     .help = N_("display full fields")},
    {.name = "source",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_NONE,
     .help = N_("address source: 'lease' or 'agent'")},
    {.name = NULL}
};

static bool
cmdDomIfAddr(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *ifacestr = NULL;
    virDomainInterfacePtr *ifaces = NULL;
    size_t i, j;
    int ifaces_count = 0;
    bool ret = false;
    bool full = vshCommandOptBool(cmd, "full");
    const char *sourcestr = NULL;
    int source = VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptStringReq(ctl, cmd, "interface", &ifacestr) < 0)
        goto cleanup;
    if (vshCommandOptStringReq(ctl, cmd, "source", &sourcestr) < 0)
        goto cleanup;

    if (sourcestr) {
        if (STREQ(sourcestr, "lease")) {
            source = VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE;
        } else if (STREQ(sourcestr, "agent")) {
            source = VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT;
        } else {
            vshError(ctl, _("Unknown data source '%s'"), sourcestr);
            goto cleanup;
        }
    }

    if ((ifaces_count = virDomainInterfaceAddresses(dom, &ifaces, source, 0)) < 0) {
        vshError(ctl, _("Failed to query for interfaces addresses"));
        goto cleanup;
    }

    vshPrintExtra(ctl, " %-10s %-20s %-8s     %s\n%s%s\n", _("Name"),
                  _("MAC address"), _("Protocol"), _("Address"),
                  _("-------------------------------------------------"),
                  _("------------------------------"));

    for (i = 0; i < ifaces_count; i++) {
        virDomainInterfacePtr iface = ifaces[i];
        char *ip_addr_str = NULL;
        const char *type = NULL;

        if (ifacestr && STRNEQ(ifacestr, iface->name))
            continue;

        /* When the interface has no IP address */
        if (!iface->naddrs) {
            vshPrint(ctl, " %-10s %-17s    %-12s %s\n",
                     iface->name,
                     iface->hwaddr ? iface->hwaddr : "N/A", "N/A", "N/A");
            continue;
        }

        for (j = 0; j < iface->naddrs; j++) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;

            switch (iface->addrs[j].type) {
            case VIR_IP_ADDR_TYPE_IPV4:
                type = "ipv4";
                break;
            case VIR_IP_ADDR_TYPE_IPV6:
                type = "ipv6";
                break;
            }

            virBufferAsprintf(&buf, "%-12s %s/%d",
                              type, iface->addrs[j].addr,
                              iface->addrs[j].prefix);

            if (virBufferError(&buf)) {
                virBufferFreeAndReset(&buf);
                virReportOOMError();
                goto cleanup;
            }

            ip_addr_str = virBufferContentAndReset(&buf);

            if (!ip_addr_str)
                ip_addr_str = vshStrdup(ctl, "");

            /* Don't repeat interface name */
            if (full || !j)
                vshPrint(ctl, " %-10s %-17s    %s\n",
                         iface->name,
                         iface->hwaddr ? iface->hwaddr : "", ip_addr_str);
            else
                vshPrint(ctl, " %-10s %-17s    %s\n",
                         "-", "-", ip_addr_str);

            virBufferFreeAndReset(&buf);
            VIR_FREE(ip_addr_str);
        }
    }

    ret = true;

 cleanup:
    if (ifaces && ifaces_count > 0) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces[i]);
    }
    VIR_FREE(ifaces);

    virshDomainFree(dom);
    return ret;
}

const vshCmdDef domMonitoringCmds[] = {
    {.name = "domblkerror",
     .handler = cmdDomBlkError,
     .opts = opts_domblkerror,
     .info = info_domblkerror,
     .flags = 0
    },
    {.name = "domblkinfo",
     .handler = cmdDomblkinfo,
     .opts = opts_domblkinfo,
     .info = info_domblkinfo,
     .flags = 0
    },
    {.name = "domblklist",
     .handler = cmdDomblklist,
     .opts = opts_domblklist,
     .info = info_domblklist,
     .flags = 0
    },
    {.name = "domblkstat",
     .handler = cmdDomblkstat,
     .opts = opts_domblkstat,
     .info = info_domblkstat,
     .flags = 0
    },
    {.name = "domcontrol",
     .handler = cmdDomControl,
     .opts = opts_domcontrol,
     .info = info_domcontrol,
     .flags = 0
    },
    {.name = "domif-getlink",
     .handler = cmdDomIfGetLink,
     .opts = opts_domif_getlink,
     .info = info_domif_getlink,
     .flags = 0
    },
    {.name = "domifaddr",
     .handler = cmdDomIfAddr,
     .opts = opts_domifaddr,
     .info = info_domifaddr,
     .flags = 0
    },
    {.name = "domiflist",
     .handler = cmdDomiflist,
     .opts = opts_domiflist,
     .info = info_domiflist,
     .flags = 0
    },
    {.name = "domifstat",
     .handler = cmdDomIfstat,
     .opts = opts_domifstat,
     .info = info_domifstat,
     .flags = 0
    },
    {.name = "dominfo",
     .handler = cmdDominfo,
     .opts = opts_dominfo,
     .info = info_dominfo,
     .flags = 0
    },
    {.name = "dommemstat",
     .handler = cmdDomMemStat,
     .opts = opts_dommemstat,
     .info = info_dommemstat,
     .flags = 0
    },
    {.name = "domstate",
     .handler = cmdDomstate,
     .opts = opts_domstate,
     .info = info_domstate,
     .flags = 0
    },
    {.name = "domstats",
     .handler = cmdDomstats,
     .opts = opts_domstats,
     .info = info_domstats,
     .flags = 0
    },
    {.name = "domtime",
     .handler = cmdDomTime,
     .opts = opts_domtime,
     .info = info_domtime,
     .flags = 0
    },
    {.name = "list",
     .handler = cmdList,
     .opts = opts_list,
     .info = info_list,
     .flags = 0
    },
    {.name = NULL}
};
