/*
 * nwfilter_nftables_driver.c: driver for nftables on tap devices
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

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "internal.h"

#include "virbuffer.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "nwfilter_conf.h"
#include "nwfilter_nftables_driver.h"
#include "nwfilter_tech_driver.h"
#include "virfile.h"
#include "configmake.h"
#include "virstring.h"
#include "virfirewall.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

/* define nftable root tables */
#define NF_ETHERNET_TABLE "libvirt_nwfilter_ethernet"
#define NF_INET_TABLE     "libvirt_nwfilter_inet"

#define NF_COMMENT \
    "{ comment \"Managed by libvirt for network filters: " \
    "https://libvirt.org/firewall.html#the-network-filter-driver\"; }"

/* nftables counter can be enabled for firewalls transparency */
static bool counters_enabled;

/* nftables tracing can be enabled for firewall debugging,
* to find out where packets are flowing towards */
static bool trace_enabled;

/* define chains */
#define IN_CHAIN          "postrouting"
#define OUT_CHAIN         "prerouting"

/* Interface matches depend on interface index, in nftables you can supply
 * an interface name as argument which will be turned into the interface index
 * for matching purposes. oif / iif will throw an nft error if the specified
 * interface doesn't exist */
#define IN_IFMATCH        "oif"
#define OUT_IFMATCH       "iif"
/* depend on the ifname for a match during moments where the
 * interface already has dissapeared (dropAllRules) */
#define IN_IFNAMEMATCH    "oifname"
#define OUT_IFNAMEMATCH   "iifname"

#define DEFAULT_POLICY    "accept"

#define TRACE_SETTING    "meta nftrace set 1;"

#define CHAINSETTINGS     "{ }"

#define VMAP_IN           "vmap-oif"
#define VMAP_OUT          "vmap-iif"
#define VMAPSETTINGS      "{ type iface_index: verdict; }"

#define SAME_IP_SET_NAME  "same-ip-set"

#define ROOT_CHAINSETTINGS(chain, defaultPolicy) \
    "{ type filter hook "chain" priority %d;" \
    " policy "defaultPolicy"; %s }"

VIR_LOG_INIT("nwfilter.nwfilter_nftables_driver");

/* A lookup table for translating ethernet protocol IDs to human readable
 * strings. None of the human readable strings must be found as a prefix
 * in another entry here (example 'ab' would be found in 'abc') to allow
 * for prefix matching.
 */
static const struct virNWFilterUShortMap l3_protocols[] = {
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_IPV4, ETHERTYPE_IP,     "ipv4"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_IPV6, ETHERTYPE_IPV6,   "ipv6"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_ARP,  ETHERTYPE_ARP,    "arp"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_RARP, ETHERTYPE_REVARP, "rarp"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_VLAN, ETHERTYPE_VLAN,   "vlan"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_STP,  0,                "stp"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_MAC,  0,                "mac"),
    virNWFilterUShortMapEntryIdx(VIR_NWFILTER_PROTO_IDX_LAST, 0,                NULL),
};

/*
 * Given a filtername determine the protocol it is used for evaluating
 * We do prefix-matching to determine the protocol.
 */
static enum virNWFilterProtoIdx
nftablesGetProtoIdxByFiltername(const char *filtername)
{
    enum virNWFilterProtoIdx idx;

    for (idx = 0; idx < VIR_NWFILTER_PROTO_IDX_LAST; idx++) {
        if (STRPREFIX(filtername, l3_protocols[idx].val))
            return idx;
    }

    return -1;
}

/*
 * nftablesCreateSameIPSet creates libvirts same-ip-set,
 * this nft set is used in nftablesHandleGarp
 * in order to see if 'arp saddr ip == arp daddr ip'
 *
 * In nftables 'nft' we can't match 2 fields to eachother.
 * In order to support GARP matching, we define a 'same-ip-set'
 * which will be used with ip masking to see if
 * ip[0] == ip[0] && ip[1] == ip[1] && ip[2] == ip[2] && ip[3] == ip[3]
 */
static void nftablesCreateSameIPSet(virFirewall *fw,
                                    virFirewallLayer layer,
                                    const char *tableName)
{
    virFirewallCmd *fwrule = NULL;
    size_t i, j;
    virFirewallAddCmd(fw, layer, "add", "set", "bridge", tableName,
                      SAME_IP_SET_NAME, "{ type ipv4_addr . ipv4_addr; }", NULL);

    fwrule = virFirewallAddCmd(fw, layer, "add", "element", "bridge",
                               tableName, SAME_IP_SET_NAME, "{", NULL);

    for (i = 1; i <= 4; i++) {
        for (j = 0; j < 256; j++) {
            virFirewallCmdAddArgFormat(fw, fwrule, "%zu.%zu.%zu.%zu",
                                       i == 1 ? j : 0, i == 2 ? j : 0,
                                       i == 3 ? j : 0, i == 4 ? j : 0);
            virFirewallCmdAddArg(fw, fwrule, ".");
            virFirewallCmdAddArgFormat(fw, fwrule, "%zu.%zu.%zu.%zu",
                                       i == 1 ? j : 0, i == 2 ? j : 0,
                                       i == 3 ? j : 0, i == 4 ? j : 0);
            virFirewallCmdAddArg(fw, fwrule, ",");
        }
    }

    virFirewallCmdAddArg(fw, fwrule, "}");
}

static void nftablesCreateTable(virFirewall *fw,
                                virFirewallLayer layer,
                                const char *tableName)
{
    virFirewallCmd *fwrule = NULL;
    const char *traceSetting = trace_enabled ? TRACE_SETTING : "";
    int tablePriority = STREQ(tableName, NF_ETHERNET_TABLE) ? 0 : 1;

    /* define table */
    virFirewallAddCmd(fw, layer,
                      "add", "table", "bridge",
                      tableName, NF_COMMENT, NULL);

    if (STREQ(tableName, NF_ETHERNET_TABLE))
        nftablesCreateSameIPSet(fw, layer, tableName);

    /* create vmap for iface matches */
    virFirewallAddCmd(fw, layer, "add", "map", "bridge", tableName, VMAP_IN,
                      VMAPSETTINGS, NULL);
    virFirewallAddCmd(fw, layer, "add", "map", "bridge", tableName, VMAP_OUT,
                      VMAPSETTINGS, NULL);

    /* define default chains */
    fwrule = virFirewallAddCmd(fw, layer, "add", "chain", "bridge",
                               tableName, IN_CHAIN, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule,
                               ROOT_CHAINSETTINGS(IN_CHAIN, DEFAULT_POLICY),
                               tablePriority, traceSetting);
    fwrule = virFirewallAddCmd(fw, layer, "add", "chain", "bridge",
                               tableName, OUT_CHAIN, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule,
                               ROOT_CHAINSETTINGS(OUT_CHAIN, DEFAULT_POLICY),
                               tablePriority, traceSetting);

    /* add the one jump rule based on the vmap */
    fwrule = virFirewallAddCmd(fw, layer, "add", "rule", "bridge", tableName,
                               IN_CHAIN, IN_IFMATCH, "vmap", NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "@%s", VMAP_IN);
    fwrule = virFirewallAddCmd(fw, layer, "add", "rule", "bridge", tableName,
                               OUT_CHAIN, OUT_IFMATCH, "vmap", NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "@%s", VMAP_OUT);
}

static int
nftablesHandleCreateRootTables(virFirewall *fw,
                               virFirewallLayer layer,
                               const char *const *lines,
                               void *opaque G_GNUC_UNUSED)
{
    bool ethernetTableDefined = false;
    bool inetTableDefined = false;
    size_t i;

    /* parse nft tables list output to see if tables exist */
    for (i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];
        if ((line = STRSKIP(line, "table bridge ")) == NULL) {
            continue;
        }

        VIR_DEBUG("Considering table for comparison '%s'", lines[i]);

        /* if chain matches basechain */
        if (STRPREFIX(line, NF_ETHERNET_TABLE)) {
            ethernetTableDefined = true;
        } else if (STRPREFIX(line, NF_INET_TABLE)) {
            inetTableDefined = true;
        }
    }

    /* if the ethernet table doesn't exist,
     * we create it including the default chains*/
    if (!ethernetTableDefined)
        nftablesCreateTable(fw, layer, NF_ETHERNET_TABLE);
    /* if the inet table doesn't exist,
     * we create it including the default chains */
    if (!inetTableDefined)
        nftablesCreateTable(fw, layer, NF_INET_TABLE);

    return 0;
}

static void nftablesAddCmdAction(virFirewall *fw,
                                 virFirewallCmd *fwrule,
                                 virNWFilterRuleActionType action)
{
    switch (action) {
    case VIR_NWFILTER_RULE_ACTION_ACCEPT:
        virFirewallCmdAddArg(fw, fwrule, "accept");
        break;
    case VIR_NWFILTER_RULE_ACTION_DROP:
        virFirewallCmdAddArg(fw, fwrule, "drop");
        break;
    case VIR_NWFILTER_RULE_ACTION_REJECT:
        virFirewallCmdAddArg(fw, fwrule, "drop");
        break;
    case VIR_NWFILTER_RULE_ACTION_RETURN:
        virFirewallCmdAddArg(fw, fwrule, "return");
        break;
    case VIR_NWFILTER_RULE_ACTION_CONTINUE:
        virFirewallCmdAddArg(fw, fwrule, "continue");
        break;
    case VIR_NWFILTER_RULE_ACTION_LAST:
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected action %1$d"), action);
    }
}

static const char *nftablesGetProtocolType(int protocol)
{
    switch (protocol) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        return "tcp";
    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        return "udp";
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        return "udplite";
    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        return "esp";
    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        return "ah";
    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        return "sctp";
    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
        return "icmp";
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        return "icmpv6";
    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        return "igmp";
    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        return "all";
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected protocol %1$d"),
                       protocol);
        return "";
    }
}

static const char *
nftablesGetIpTypeByDataType(nwItemDesc *item)
{
    return (item->datatype == DATATYPE_IPV6ADDR) ? "ip6" : "ip";
}

static int
nftablesHandleIPHdr(virFirewall *fw,
                    virFirewallCmd *fwrule,
                    virNWFilterVarCombIter *vars,
                    ipHdrDataDef *ipHdr,
                    bool reverseRule)
{
    char ipaddr[INET6_ADDRSTRLEN];
    char ipaddralt[INET6_ADDRSTRLEN];
    char number[VIR_INT64_STR_BUFLEN];
    const char *ip = NULL;
    const char *saddr = reverseRule ? "daddr" : "saddr";
    const char *daddr = reverseRule ? "saddr" : "daddr";

    if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPAddr)) {
        ip = nftablesGetIpTypeByDataType(&ipHdr->dataSrcIPAddr);
        virFirewallCmdAddArgList(fw, fwrule, ip, saddr, NULL);

        if (virNWFilterPrintDataType(vars,
                                     ipaddr, sizeof(ipaddr),
                                     &ipHdr->dataSrcIPAddr) < 0)
            return -1;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataSrcIPAddr))
            virFirewallCmdAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPMask)) {
            if (virNWFilterPrintDataType(vars,
                                         number, sizeof(number),
                                         &ipHdr->dataSrcIPMask) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s/%s", ipaddr, number);
        } else {
            virFirewallCmdAddArg(fw, fwrule, ipaddr);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPFrom)) {
        ip = nftablesGetIpTypeByDataType(&ipHdr->dataSrcIPFrom);
        virFirewallCmdAddArgList(fw, fwrule, ip, saddr, NULL);

        if (virNWFilterPrintDataType(vars,
                                     ipaddr, sizeof(ipaddr),
                                     &ipHdr->dataSrcIPFrom) < 0)
            return -1;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataSrcIPFrom))
            virFirewallCmdAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPTo)) {

            if (virNWFilterPrintDataType(vars,
                                         ipaddralt, sizeof(ipaddralt),
                                         &ipHdr->dataSrcIPTo) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s-%s", ipaddr, ipaddralt);
        } else {
            virFirewallCmdAddArg(fw, fwrule, ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPAddr)) {
        ip = nftablesGetIpTypeByDataType(&ipHdr->dataDstIPAddr);
        virFirewallCmdAddArgList(fw, fwrule, ip, daddr, NULL);

        if (virNWFilterPrintDataType(vars,
                                     ipaddr, sizeof(ipaddr),
                                     &ipHdr->dataDstIPAddr) < 0)
           return -1;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDstIPAddr))
            virFirewallCmdAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPMask)) {
            if (virNWFilterPrintDataType(vars,
                                         number, sizeof(number),
                                         &ipHdr->dataDstIPMask) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s/%s", ipaddr, number);
        } else {
            virFirewallCmdAddArg(fw, fwrule, ipaddr);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPFrom)) {
        ip = nftablesGetIpTypeByDataType(&ipHdr->dataDstIPFrom);
        virFirewallCmdAddArgList(fw, fwrule, ip, daddr, NULL);

        if (virNWFilterPrintDataType(vars,
                                     ipaddr, sizeof(ipaddr),
                                     &ipHdr->dataDstIPFrom) < 0)
            return -1;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDstIPFrom))
            virFirewallCmdAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPTo)) {
            if (virNWFilterPrintDataType(vars,
                                         ipaddralt, sizeof(ipaddralt),
                                         &ipHdr->dataDstIPTo) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s-%s", ipaddr, ipaddralt);
        } else {
            virFirewallCmdAddArg(fw, fwrule, ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDSCP)) {
        if (!ip)
            ip = nftablesGetIpTypeByDataType(&ipHdr->dataDSCP);

        if (virNWFilterPrintDataType(vars,
                                     number, sizeof(number),
                                     &ipHdr->dataDSCP) < 0)
           return -1;

        virFirewallCmdAddArgList(fw, fwrule, ip, "dscp", NULL);
        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDSCP))
            virFirewallCmdAddArg(fw, fwrule, "!");
        virFirewallCmdAddArgList(fw, fwrule, number, NULL);
    }

    return 0;
}

static int
nftablesHandleEthHdr(virFirewall *fw,
                     virFirewallCmd *fwrule,
                     virNWFilterVarCombIter *vars,
                     ethHdrDataDef *ethHdr,
                     bool reverseRule)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char macmask[VIR_MAC_STRING_BUFLEN];
    const char *saddr = reverseRule ? "daddr" : "saddr";
    const char *daddr = reverseRule ? "saddr" : "daddr";

    if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACAddr)) {
        const char *comparison = NULL;
        if (virNWFilterPrintDataType(vars,
                                     macaddr, sizeof(macaddr),
                                     &ethHdr->dataSrcMACAddr) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", saddr, NULL);
        comparison = ENTRY_WANT_NEG_SIGN(&ethHdr->dataSrcMACAddr) ?
                                    "!=" : "==";

        if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACMask)) {
            if (virNWFilterPrintDataType(vars,
                                         macmask, sizeof(macmask),
                                         &ethHdr->dataSrcMACMask) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "& %s %s %s",
                                       macmask, comparison, macaddr);
        } else {
            virFirewallCmdAddArgList(fw, fwrule, comparison, macaddr, NULL);
        }
    }

    if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACAddr)) {
        const char *comparison = NULL;
        if (virNWFilterPrintDataType(vars,
                                     macaddr, sizeof(macaddr),
                                     &ethHdr->dataDstMACAddr) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", daddr, NULL);
        comparison = ENTRY_WANT_NEG_SIGN(&ethHdr->dataDstMACAddr) ?
                                    "!=" : "==";

        if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACMask)) {
            if (virNWFilterPrintDataType(vars,
                                         macmask, sizeof(macmask),
                                         &ethHdr->dataDstMACMask) < 0)
                return -1;

            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "& %s %s %s",
                                       macmask, comparison, macaddr);
        } else {
            virFirewallCmdAddArgList(fw, fwrule, comparison, macaddr, NULL);
        }
    }

    return 0;
}

static int
insertRuleArg2Param(virFirewall *fw,
                    virFirewallCmd *fwrule,
                    virNWFilterVarCombIter *vars,
                    nwItemDesc *itemLow,
                    nwItemDesc *itemHigh,
                    const char *argument1,
                    const char *argument2,
                    const char *seperator)
{
    char field[VIR_INT64_STR_BUFLEN];
    char fieldalt[VIR_INT64_STR_BUFLEN];

    if (HAS_ENTRY_ITEM(itemLow)) {
        if (virNWFilterPrintDataType(vars,
                                     field, sizeof(field),
                                     itemLow) < 0)
            return -1;
        virFirewallCmdAddArg(fw, fwrule, argument1);
        virFirewallCmdAddArg(fw, fwrule, argument2);
        if (ENTRY_WANT_NEG_SIGN(itemLow))
            virFirewallCmdAddArg(fw, fwrule, "!=");
        if (HAS_ENTRY_ITEM(itemHigh)) {
            if (virNWFilterPrintDataType(vars,
                                         fieldalt, sizeof(fieldalt),
                                         itemHigh) < 0)
                return -1;
            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s%s%s", field, seperator, fieldalt);
        } else  {
            virFirewallCmdAddArg(fw, fwrule, field);
        }
    }

    return 0;
}

static int
nftablesHandlePortData(virFirewall *fw,
                       virFirewallCmd *fwrule,
                       virNWFilterVarCombIter *vars,
                       const char *protocol,
                       portDataDef *portData,
                       bool reverseRule)
{
    if (insertRuleArg2Param(fw, fwrule, vars,
                            &portData->dataDstPortStart,
                            &portData->dataDstPortEnd, protocol,
                            reverseRule ? "sport" : "dport", "-") < 0)
        return -1;
    if (insertRuleArg2Param(fw, fwrule, vars,
                            &portData->dataSrcPortStart,
                            &portData->dataSrcPortEnd, protocol,
                            reverseRule ? "dport" : "sport", "-") < 0)
        return -1;

    return 0;
}

static int
nftablesHandleMacAddr(virFirewall *fw,
                      virFirewallCmd *fwrule,
                      virNWFilterVarCombIter *vars,
                      nwItemDesc *macaddr,
                      const char *argument1,
                      const char *argument2,
                      const char *argument3)
{
    char macstr[VIR_MAC_STRING_BUFLEN];

    if (HAS_ENTRY_ITEM(macaddr)) {
        if (virNWFilterPrintDataType(vars,
                                     macstr, sizeof(macstr),
                                     macaddr) < 0)
            return -1;

        virFirewallCmdAddArg(fw, fwrule, argument1);
        virFirewallCmdAddArg(fw, fwrule, argument2);
        if (argument3 != NULL)
            virFirewallCmdAddArg(fw, fwrule, argument3);

        if (ENTRY_WANT_NEG_SIGN(macaddr))
            virFirewallCmdAddArg(fw, fwrule, "!=");
        virFirewallCmdAddArg(fw, fwrule, macstr);
    }

    return 0;
}

static int
nftablesHandleSrcMacAddr(virFirewall *fw,
                         virFirewallCmd *fwrule,
                         virNWFilterVarCombIter *vars,
                         nwItemDesc *srcMacAddr)
{
    return nftablesHandleMacAddr(fw, fwrule, vars, srcMacAddr,
                                 "ether", "saddr", NULL);
}


static void
nftablesHandleGarpMask(virFirewall *fw,
                       virFirewallCmd *fwrule,
                       const char *mask,
                       const char *inOperator)
{
    virFirewallCmdAddArgList(fw, fwrule,
                             "arp", "saddr", "ip", "&", mask, ".",
                             "arp", "daddr", "ip", "&", mask, inOperator,
                             NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "@%s", SAME_IP_SET_NAME);
}

static void
nftablesHandleGarp(virFirewall *fw,
                   virFirewallCmd *fwrule,
                   nwItemDesc *garp)
{
    const char *inOperator = ENTRY_WANT_NEG_SIGN(garp) ? "!=" : "==";

    if (!HAS_ENTRY_ITEM(garp) || !garp->u.boolean)
        return;

    /* nftables 'nft' command can't handle garp nor field to field comparison like:
     * - arp saddr ip == arp daddr ip
     * we'll have to seperately compare ip[0..4] to the precreated same-ip-set
     * to see if the IP matches
     * in order to not list all possible ipv4 ips in the same-ip-set, we'll mask
     * with either 255.0.0.0 0.255.0.0 0.0.255.0 or 0.0.0.255
     * this ensures that we "only" have 1024 entries in our same-ip-set
     *
     * This will result in the following firewall rule:
     * arp saddr ip & 255.0.0.0 . arp daddr ip & 255.0.0.0 @same-ip-set
     * arp saddr ip & 0.255.0.0 . arp daddr ip & 0.255.0.0 @same-ip-set
     * arp saddr ip & 0.0.255.0 . arp daddr ip & 0.0.255.0 @same-ip-set
     * arp saddr ip & 0.0.0.255 . arp daddr ip & 0.0.0.255 @same-ip-set
     * counter accept
     */
    nftablesHandleGarpMask(fw, fwrule, "255.0.0.0", inOperator);
    nftablesHandleGarpMask(fw, fwrule, "0.255.0.0", inOperator);
    nftablesHandleGarpMask(fw, fwrule, "0.0.255.0", inOperator);
    nftablesHandleGarpMask(fw, fwrule, "0.0.0.255", inOperator);
}

static void
printStateMatchFlags(int32_t flags, char **bufptr)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virNWFilterPrintStateMatchFlags(&buf, "", flags, false);

    /* str to lower needed as nft doesn't accept upper case states */
    g_string_ascii_down(buf.str);

    *bufptr = virBufferContentAndReset(&buf);
}

static bool
nftablesRuleNeedsConntrack(virNWFilterRuleDef *rule)
{
    /* ip only */
    if (virNWFilterRuleIsProtocolEthernet(rule)) {
        return false;
    }

    /* Skip conntrack if statematch=false flag has been set */
    if (rule->flags & RULE_FLAG_NO_STATEMATCH) {
        return false;
    }

    /* If no state flags are set and rule->action is not accept,
     * we should skip conntrack */
    if (!(rule->flags & IPTABLES_STATE_FLAGS) &&
        rule->action != VIR_NWFILTER_RULE_ACTION_ACCEPT) {
        return false;
    }

    return true;
}

static bool
nftablesRuleNeedsConnLimit(ipHdrDataDef *ipHdr,
                           bool directionIn)
{
    return HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove) && !directionIn;
}

static char *
nftablesPrintTCPFlags(uint8_t flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *flagsstr = NULL;

    if (flags == 0) {
        virBufferAddLit(&buf, "0");
    } else if (flags == 0x3f) {
        virBufferAddLit(&buf, "*");
    } else {
        flagsstr = virNWFilterPrintTCPFlags(flags);
        virBufferAdd(&buf, flagsstr, -1);
        g_string_ascii_down(buf.str);
    }

    return virBufferContentAndReset(&buf);
}

/*
 * nftablesHandleInetRule:
 * @fw: the firewall ruleset to add to
 * @fwrule: the firewall command to add arguments to
 * @vars : A map containing the variables to resolve
 * @rule: The rule of the filter to convert
 * @directionIn: direction of the rule, true for in false for out
 *               directionIn is needed for additional conntrack logic
 * @reverseRule: Whether to reverse src and dst attributes
 *               ethernet reverse flag is set conntrack requires a reverse
 *               rule on the opposite chain
 *
 * Set arguments on fwrule based on given struct *rule
 *
 */
static int
nftablesHandleInetRule(virFirewall *fw,
                        virFirewallCmd *fwrule,
                        virNWFilterVarCombIter *vars,
                        virNWFilterRuleDef *rule,
                        bool directionIn,
                        bool reverseRule)
{
    char number[VIR_INT64_STR_BUFLEN];
    bool hasICMPType = false;
    bool skipDirection = false;
    g_autofree char *matchState = NULL;
    ipHdrDataDef *ipHdr = NULL;
    const char *protocol = nftablesGetProtocolType(rule->prtclType);

    virFirewallCmdAddArgList(fw, fwrule, "ether", "type", NULL);
    if (virNWFilterRuleIsProtocolIPv6(rule) &&
        !virNWFilterRuleIsProtocolIPv4(rule)) {
        virFirewallCmdAddArg(fw, fwrule, "ip6");
    } else if (virNWFilterRuleIsProtocolIPv4(rule) &&
               !virNWFilterRuleIsProtocolIPv6(rule)) {
        virFirewallCmdAddArg(fw, fwrule, "ip");
    }

    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "tcp", NULL);
        ipHdr = &rule->p.tcpHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                     &rule->p.tcpHdrFilter.dataSrcMACAddr) < 0)
            return -1;
        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPFlags)) {
            g_autofree char *mask = NULL;
            g_autofree char *flags = NULL;

            /* flags & syn == syn */
            virFirewallCmdAddArgList(fw, fwrule, "tcp", "flags", "&", NULL);

            if (!(mask = nftablesPrintTCPFlags(
                          rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.mask)))
                return -1;
            virFirewallCmdAddArgList(fw, fwrule, mask, ENTRY_WANT_NEG_SIGN(
                                            &rule->p.tcpHdrFilter.dataTCPFlags)
                                            ? "!=" : "==", NULL);

            if (!(flags = nftablesPrintTCPFlags(
                           rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.flags)))
                return -1;
            virFirewallCmdAddArgList(fw, fwrule, "{", flags, "}", NULL);
        }

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPOption)) {
            if (virNWFilterPrintDataType(vars, number, sizeof(number),
                                         &rule->p.tcpHdrFilter.dataTCPOption) < 0)
                return -1;

            virFirewallCmdAddArgList(fw, fwrule, "tcp", "option", NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPOption))
                virFirewallCmdAddArg(fw, fwrule, "!");
            virFirewallCmdAddArg(fw, fwrule, number);
        }

        if (nftablesHandlePortData(fw, fwrule, vars, protocol,
            &rule->p.tcpHdrFilter.portData, reverseRule) < 0)
            return -1;

        break;
    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "udp", NULL);
        ipHdr = &rule->p.udpHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                     &rule->p.udpHdrFilter.dataSrcMACAddr) < 0)
            return -1;
        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
        if (nftablesHandlePortData(fw, fwrule, vars, protocol,
            &rule->p.udpHdrFilter.portData, reverseRule) < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "udplite", NULL);
        ipHdr = &rule->p.udpliteHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                     &rule->p.udpliteHdrFilter.dataSrcMACAddr) < 0)
            return -1;
        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
    break;
    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "esp", NULL);
        ipHdr = &rule->p.espHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.espHdrFilter.dataSrcMACAddr) < 0)
            return -1;
        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "ah", NULL);
        ipHdr = &rule->p.ahHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.ahHdrFilter.dataSrcMACAddr) < 0)
            return -1;
        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "sctp", NULL);
        ipHdr = &rule->p.sctpHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.sctpHdrFilter.dataSrcMACAddr) < 0)
            return -1;

        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;

        if (nftablesHandlePortData(fw, fwrule, vars, protocol,
            &rule->p.sctpHdrFilter.portData, reverseRule) < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMPV6) {
            virFirewallCmdAddArgList(fw, fwrule, "ip6", "nexthdr", NULL);
        } else {
            virFirewallCmdAddArgList(fw, fwrule, "ip", "protocol", NULL);
        }
        virFirewallCmdAddArg(fw, fwrule, protocol);

        ipHdr = &rule->p.icmpHdrFilter.ipHdr;
        hasICMPType = true;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.icmpHdrFilter.dataSrcMACAddr) < 0)
            return -1;

        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;

        if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPType)) {
            virFirewallCmdAddArgList(fw, fwrule, protocol, "type", NULL);

            if (virNWFilterPrintDataType(vars,
                                         number, sizeof(number),
                                         &rule->p.icmpHdrFilter.dataICMPType) < 0)
                return -1;

            if (ENTRY_WANT_NEG_SIGN(&rule->p.icmpHdrFilter.dataICMPType))
                virFirewallCmdAddArg(fw, fwrule, "!=");

            virFirewallCmdAddArg(fw, fwrule, number);

            if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPCode)) {
                virFirewallCmdAddArgList(fw, fwrule, protocol, "code", NULL);

                if (virNWFilterPrintDataType(vars,
                                             number, sizeof(number),
                                             &rule->p.icmpHdrFilter.dataICMPCode) < 0)
                    return -1;

                if (ENTRY_WANT_NEG_SIGN(&rule->p.icmpHdrFilter.dataICMPCode))
                    virFirewallCmdAddArg(fw, fwrule, "!=");

                virFirewallCmdAddArg(fw, fwrule, number);
            }
        }
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        virFirewallCmdAddArgList(fw, fwrule, "meta", "l4proto", "igmp", NULL);
        ipHdr = &rule->p.igmpHdrFilter.ipHdr;

        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.igmpHdrFilter.dataSrcMACAddr) < 0)
            return -1;

        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        ipHdr = &rule->p.allHdrFilter.ipHdr;
        if (nftablesHandleSrcMacAddr(fw, fwrule, vars,
                                    &rule->p.allHdrFilter.dataSrcMACAddr) < 0)
            return -1;

        if (nftablesHandleIPHdr(fw, fwrule, vars, ipHdr, reverseRule) < 0)
            return -1;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected protocol %1$d"),
                       rule->prtclType);
        return -1;
    }

    /* no support for ipset */
    if (HAS_ENTRY_ITEM(&ipHdr->dataIPSet) &&
        HAS_ENTRY_ITEM(&ipHdr->dataIPSetFlags)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Rule contains unsupported ipset flags"));
    }

    /* apply conn limit only to outgoing connections */
    if (nftablesRuleNeedsConnLimit(ipHdr, directionIn)) {
        if (virNWFilterPrintDataType(vars,
                                     number, sizeof(number),
                                     &ipHdr->dataConnlimitAbove) < 0)
           return -1;

        /* place connlimit after potential state logic
           since this is the most useful order */
        virFirewallCmdAddArgList(fw, fwrule, "ct", "count", "over", NULL);
        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataConnlimitAbove))
            virFirewallCmdAddArg(fw, fwrule, "!=");
        virFirewallCmdAddArgList(fw, fwrule, number, NULL);
    }

    if (nftablesRuleNeedsConntrack(rule)) {
        /* we skip direction when ct count is set or type is icmp */
        skipDirection = nftablesRuleNeedsConnLimit(ipHdr, directionIn) ||
                            hasICMPType;

        /* no direction */
        if (!skipDirection)
            /* reverse rules are replies,
             * otherwise it is the originating direction */
            virFirewallCmdAddArgList(fw, fwrule, "ct", "direction",
                                     (reverseRule ? "reply" : "original"),
                                     NULL);

        if (rule->flags & IPTABLES_STATE_FLAGS &&
            !(rule->flags & RULE_FLAG_STATE_NONE)) {
            printStateMatchFlags(rule->flags, &matchState);
        } else {
            /* static state match is needed because when no state flags
             * have been set but statematch is enabled we need a default */
            /* reverse rules are established connections */
            matchState = g_strdup(reverseRule ?
                                  "established" :
                                  "new,established");
        }
        virFirewallCmdAddArgList(fw, fwrule, "ct", "state", matchState, NULL);
    }

    return 0;
}

static int
insertRuleArgParam(virFirewall *fw,
                   virFirewallCmd *fwrule,
                   virNWFilterVarCombIter *vars,
                   nwItemDesc *item,
                   const char *argument1,
                   const char *argument2)
{
    char field[VIR_INT64_STR_BUFLEN];

    if (HAS_ENTRY_ITEM(item)) {
        if (virNWFilterPrintDataType(vars,
                                     field, sizeof(field),
                                     item) < 0)
            return -1;
        virFirewallCmdAddArg(fw, fwrule, argument1);
        virFirewallCmdAddArg(fw, fwrule, argument2);
        if (ENTRY_WANT_NEG_SIGN(item))
            virFirewallCmdAddArg(fw, fwrule, "!=");

        virFirewallCmdAddArg(fw, fwrule, field);
    }

    return 0;
}

static int insertRuleArgParamHex(virFirewall *fw,
                                 virFirewallCmd *fwrule,
                                 virNWFilterVarCombIter *vars,
                                 nwItemDesc *item,
                                 const char *argument1,
                                 const char *argument2)
{
    char field[VIR_INT64_STR_BUFLEN];

    if (HAS_ENTRY_ITEM(item)) {
        if (virNWFilterPrintDataTypeAsHex(vars,
                                     field, sizeof(field),
                                     item) < 0)
            return -1;
        virFirewallCmdAddArg(fw, fwrule, argument1);
        if (argument2 != NULL)
           virFirewallCmdAddArg(fw, fwrule, argument2);
        if (ENTRY_WANT_NEG_SIGN(item))
            virFirewallCmdAddArg(fw, fwrule, "!=");

        virFirewallCmdAddArg(fw, fwrule, field);
    }

    return 0;
}

static int insertRuleArgParamHexRange(virFirewall *fw,
                                      virFirewallCmd *fwrule,
                                      virNWFilterVarCombIter *vars,
                                      nwItemDesc *itemLow,
                                      nwItemDesc *itemHigh,
                                      const char *argument)
{
    char fieldLow[VIR_INT64_STR_BUFLEN];
    char fieldHigh[VIR_INT64_STR_BUFLEN];

    if (!HAS_ENTRY_ITEM(itemLow))
        return 0;

    if (virNWFilterPrintDataTypeAsHex(vars, fieldLow, sizeof(fieldLow),
                                      itemLow) < 0)
        return -1;
    virFirewallCmdAddArg(fw, fwrule, argument);

    virFirewallCmdAddArg(fw, fwrule, ENTRY_WANT_NEG_SIGN(itemLow) ? "==" : "!=");

    if (HAS_ENTRY_ITEM(itemHigh)) {
        if (virNWFilterPrintDataTypeAsHex(vars, fieldHigh, sizeof(fieldHigh),
                                          itemHigh) < 0)
            return -1;
        virFirewallCmdAddArgFormat(fw, fwrule, "%s-%s", fieldLow, fieldHigh);
    } else {
        virFirewallCmdAddArg(fw, fwrule, fieldLow);
    }

    return 0;
}

static int insertRulePayloadHexIPv4(virFirewall *fw,
                                    virFirewallCmd *fwrule,
                                    virNWFilterVarCombIter *vars,
                                    nwItemDesc *itemIPAddr,
                                    nwItemDesc *itemIPMask,
                                    const char *payloadLocFormat)
{
    unsigned char buf[4];
    char ip[INET_ADDRSTRLEN];
    char maskstr[INET_ADDRSTRLEN];
    g_autofree char *hexstr = NULL;
    virSocketAddr addr;
    unsigned int mask = 32;

    if (!HAS_ENTRY_ITEM(itemIPAddr))
        return 0;

    /* parse mask to mask len */
    if (HAS_ENTRY_ITEM(itemIPMask)) {
        if (virNWFilterPrintDataType(vars, maskstr,
                                     sizeof(maskstr), itemIPMask) < 0)
            return -1;

        if (virStrToLong_ui(maskstr, NULL, 10, &mask) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot convert ipv4 mask to int '%1$s'"), maskstr);
            return -1;
        }
    }

    /* parse or retrieve the ip str */
    if (virNWFilterPrintDataType(vars, ip, sizeof(ip), itemIPAddr) < 0)
        return -1;

    /* convert ip into a virSockAddr */
    if (virSocketAddrParseIPv4(&addr, ip) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse ipv4 address '%1$s' in"), ip);
        return -1;
    }

    if (virSocketAddrMaskByPrefix(&addr, mask, &addr) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failure to mask address %1$s & %2$d"), ip, mask);
        return -1;
    }

    /* convert to byte array */
    if (virSocketAddrBytes(&addr, buf, sizeof(buf)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot convert ipv4 address to byte array '%1$s'"), ip);
        return -1;
    }

    hexstr = g_strdup_printf("0x%02x%02x%02x%02x",
                             buf[0], buf[1], buf[2], buf[3]);

    virFirewallCmdAddArgFormat(fw, fwrule, payloadLocFormat, mask);

    if (ENTRY_WANT_NEG_SIGN(itemIPAddr))
        virFirewallCmdAddArg(fw, fwrule, "!=");

    virFirewallCmdAddArg(fw, fwrule, hexstr);

    return 0;
}

static int insertRuleArgParamHexMac(virFirewall *fw,
                                   virFirewallCmd *fwrule,
                                   virNWFilterVarCombIter *vars,
                                   nwItemDesc *item)
{
    unsigned char buf[VIR_MAC_BUFLEN];
    char mac[VIR_MAC_STRING_BUFLEN];
    g_autofree char *hexstr = NULL;
    virMacAddr addr;

    /* parse or retrieve the mac str */
    if (virNWFilterPrintDataType(vars, mac, sizeof(mac), item) < 0)
        return -1;

    /* convert mac into a virMacAddr */
    if (virMacAddrParse(mac, &addr) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Cannot parse MAC address '%1$s'"), mac);
        return -1;
    }

    virMacAddrGetRaw(&addr, buf);
    hexstr = g_strdup_printf("0x%02x%02x%02x%02x%02x%02x",
                                 buf[0], buf[1], buf[2],
                                 buf[3], buf[4], buf[5]);

    virFirewallCmdAddArg(fw, fwrule, hexstr);

    return 0;
}

static int insertRulePayloadHexMac(virFirewall *fw,
                                   virFirewallCmd *fwrule,
                                   virNWFilterVarCombIter *vars,
                                   nwItemDesc *item,
                                   const char *payloadLoc)
{
    if (!HAS_ENTRY_ITEM(item))
        return 0;

    virFirewallCmdAddArg(fw, fwrule, payloadLoc);
    if (ENTRY_WANT_NEG_SIGN(item))
        virFirewallCmdAddArg(fw, fwrule, "!=");

    return insertRuleArgParamHexMac(fw, fwrule, vars, item);
}

static int insertRulePayloadHexMacMask(virFirewall *fw,
                                       virFirewallCmd *fwrule,
                                       virNWFilterVarCombIter *vars,
                                       nwItemDesc *mac,
                                       nwItemDesc *mask,
                                       const char *payloadLoc)
{
    if (!HAS_ENTRY_ITEM(mac))
        return 0;

    virFirewallCmdAddArg(fw, fwrule, payloadLoc);

    if (HAS_ENTRY_ITEM(mask)) {
        virFirewallCmdAddArg(fw, fwrule, "&");

        if (insertRuleArgParamHexMac(fw, fwrule, vars, mac) < 0)
            return -1;
    }

    if (ENTRY_WANT_NEG_SIGN(mac))
        virFirewallCmdAddArg(fw, fwrule, "!=");

    return insertRuleArgParamHexMac(fw, fwrule, vars, mac);
}

/*
 * nftablesHandleEthernetRule:
 * @fw: the firewall ruleset to add to
 * @vars : A map containing the variables to resolve
 * @rule: The rule of the filter to convert
 * @reverseRule : Whether to reverse src and dst attributes
 *                ethernet reverse flag is set when direction='inout' is set
 *
 * Set arguments on fwrule based on given struct *rule
 *
 */
static int
nftablesHandleEthernetRule(virFirewall *fw,
                           virFirewallCmd *fwrule,
                           virNWFilterVarCombIter *vars,
                           virNWFilterRuleDef *rule,
                           bool reverseRule)
{
    char number[VIR_INT64_STR_BUFLEN];
    char ipaddr[INET_ADDRSTRLEN];
    char ipmask[INET_ADDRSTRLEN];
    char ipv6addr[INET6_ADDRSTRLEN];
    bool hasMask = false;
    const char *saddr = reverseRule ? "daddr" : "saddr";
    const char *daddr = reverseRule ? "saddr" : "daddr";

    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ethHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.ethHdrFilter.dataProtocolID,
                                  "ether", "type") < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", NULL);
        if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataProtocolID))
            virFirewallCmdAddArg(fw, fwrule, "!=");
        virFirewallCmdAddArg(fw, fwrule, "ip");

        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ipHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr)) {
            if (virNWFilterPrintDataType(vars,
                                         ipaddr, sizeof(ipaddr),
                                         &rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr) < 0)
                return -1;

            virFirewallCmdAddArgList(fw, fwrule, "ip", saddr, NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             number, sizeof(number),
                                             &rule->p.ipHdrFilter.ipHdr.dataSrcIPMask) < 0)
                    return -1;
                virFirewallCmdAddArgFormat(fw, fwrule,
                                           "%s/%s", ipaddr, number);
            } else {
                virFirewallCmdAddArg(fw, fwrule, ipaddr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr)) {
            if (virNWFilterPrintDataType(vars,
                                         ipaddr, sizeof(ipaddr),
                                         &rule->p.ipHdrFilter.ipHdr.dataDstIPAddr) < 0)
                return -1;

            virFirewallCmdAddArgList(fw, fwrule, "ip", daddr, NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             number, sizeof(number),
                                             &rule->p.ipHdrFilter.ipHdr.dataDstIPMask) < 0)
                    return -1;
                virFirewallCmdAddArgFormat(fw, fwrule,
                                           "%s/%s", ipaddr, number);
            } else {
                virFirewallCmdAddArg(fw, fwrule, ipaddr);
            }
        }

        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.ipHdrFilter.ipHdr.dataProtocolID,
                               "ip", "protocol") < 0)
            return -1;
        if (insertRuleArg2Param(fw, fwrule, vars,
                                &rule->p.ipHdrFilter.portData.dataSrcPortStart,
                                &rule->p.ipHdrFilter.portData.dataSrcPortEnd,
                                "th", reverseRule ? "dport" : "sport", "-") < 0)
            return -1;
        if (insertRuleArg2Param(fw, fwrule, vars,
                                &rule->p.ipHdrFilter.portData.dataDstPortStart,
                                &rule->p.ipHdrFilter.portData.dataDstPortEnd,
                                "th", reverseRule ? "sport" : "dport", "-") < 0)
            return -1;
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.ipHdrFilter.ipHdr.dataDSCP,
                                  "ip", "dscp") < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.arpHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", NULL);
        virFirewallCmdAddArgFormat(fw, fwrule, "0x%x",
                                   l3_protocols[VIR_NWFILTER_PROTO_IDX_ARP].attr);

        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.arpHdrFilter.dataHWType,
                               "arp", "htype") < 0)
            return -1;
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataProtocolType,
                                  "arp", "ptype") < 0)
            return -1;
        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.arpHdrFilter.dataOpcode,
                               "arp", "operation") < 0)
            return -1;

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPAddr)) {
            if (virNWFilterPrintDataType(vars,
                                         ipaddr, sizeof(ipaddr),
                                         &rule->p.arpHdrFilter.dataARPSrcIPAddr) < 0)
                return -1;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             ipmask, sizeof(ipmask),
                                             &rule->p.arpHdrFilter.dataARPSrcIPMask) < 0)
                    return -1;
                hasMask = true;
            }

            virFirewallCmdAddArgList(fw, fwrule, "arp", saddr, "ip", NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");
            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s/%s", ipaddr, hasMask ? ipmask : "32");
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPAddr)) {
            if (virNWFilterPrintDataType(vars,
                                         ipaddr, sizeof(ipaddr),
                                         &rule->p.arpHdrFilter.dataARPDstIPAddr) < 0)
                return -1;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             ipmask, sizeof(ipmask),
                                             &rule->p.arpHdrFilter.dataARPDstIPMask) < 0)
                    return -1;
                hasMask = true;
            }

            virFirewallCmdAddArgList(fw, fwrule, "arp", daddr, "ip", NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");
            virFirewallCmdAddArgFormat(fw, fwrule,
                                       "%s/%s", ipaddr, hasMask ? ipmask : "32");
        }

        if (nftablesHandleMacAddr(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataARPSrcMACAddr,
                                  "arp", saddr, "ether") < 0)
            return -1;
        if (nftablesHandleMacAddr(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataARPDstMACAddr,
                                  "arp", daddr, "ether") < 0)
            return -1;

        nftablesHandleGarp(fw, fwrule, &rule->p.arpHdrFilter.dataGratuitousARP);
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_RARP:
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.arpHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", NULL);
        virFirewallCmdAddArgFormat(fw, fwrule, "0x%x",
                                   l3_protocols[VIR_NWFILTER_PROTO_IDX_RARP].attr);

        /* @nh (network header), N (bits offset), N (bits length) */
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataHWType,
                                  "@nh,0,16", NULL) < 0)
            return -1;
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataProtocolType,
                                  "@nh,40,16", NULL) < 0)
            return -1;
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.arpHdrFilter.dataOpcode,
                                  "@nh,48,16", NULL) < 0)
            return -1;
        if (insertRulePayloadHexIPv4(fw, fwrule, vars,
                                     &rule->p.arpHdrFilter.dataARPSrcIPAddr,
                                     &rule->p.arpHdrFilter.dataARPSrcIPMask,
                                     "@nh,112,%d") < 0)
            return -1;
        if (insertRulePayloadHexIPv4(fw, fwrule, vars,
                                     &rule->p.arpHdrFilter.dataARPDstIPAddr,
                                     &rule->p.arpHdrFilter.dataARPDstIPMask,
                                     "@nh,192,%d") < 0)
            return -1;
        if (insertRulePayloadHexMac(fw, fwrule, vars,
                                    &rule->p.arpHdrFilter.dataARPSrcMACAddr,
                                    "@nh,64,48") < 0)
            return -1;
        if (insertRulePayloadHexMac(fw, fwrule, vars,
                                    &rule->p.arpHdrFilter.dataARPDstMACAddr,
                                    "@nh,144,48") < 0)
            return -1;

        nftablesHandleGarp(fw, fwrule, &rule->p.arpHdrFilter.dataGratuitousARP);
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ipv6HdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", "ip6", NULL);

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr)) {
            if (virNWFilterPrintDataType(vars,
                                         ipv6addr, sizeof(ipv6addr),
                                         &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr) < 0)
                return -1;

            virFirewallCmdAddArgList(fw, fwrule, "ip6", saddr, NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             number, sizeof(number),
                                             &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask) < 0)
                    return -1;
                virFirewallCmdAddArgFormat(fw, fwrule,
                                           "%s/%s", ipv6addr, number);
            } else {
                virFirewallCmdAddArg(fw, fwrule, ipv6addr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr)) {

            if (virNWFilterPrintDataType(vars,
                                         ipv6addr, sizeof(ipv6addr),
                                         &rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr) < 0)
                return -1;

            virFirewallCmdAddArgList(fw, fwrule, "ip6", daddr, NULL);
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr))
                virFirewallCmdAddArg(fw, fwrule, "!=");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask)) {
                if (virNWFilterPrintDataType(vars,
                                             number, sizeof(number),
                                             &rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask) < 0)
                    return -1;
                virFirewallCmdAddArgFormat(fw, fwrule,
                                           "%s/%s", ipv6addr, number);
            } else {
                virFirewallCmdAddArg(fw, fwrule, ipv6addr);
            }
        }

        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.ipv6HdrFilter.ipHdr.dataProtocolID,
                               "ip6", "nexthdr") < 0)
            return -1;
        if (insertRuleArg2Param(fw, fwrule, vars,
                                &rule->p.ipv6HdrFilter.portData.dataSrcPortStart,
                                &rule->p.ipv6HdrFilter.portData.dataSrcPortEnd,
                                "th", reverseRule ? "dport" : "sport", "-") < 0)
            return -1;
        if (insertRuleArg2Param(fw, fwrule, vars,
                                &rule->p.ipv6HdrFilter.portData.dataDstPortStart,
                                &rule->p.ipv6HdrFilter.portData.dataDstPortEnd,
                                "th", reverseRule ? "sport" : "dport", "-") < 0)
            return -1;
        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPTypeStart)  ||
            HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPCodeStart)) {

            if (insertRuleArgParam(fw, fwrule, vars,
                                   &rule->p.ipv6HdrFilter.dataICMPTypeStart,
                                   "icmpv6", "type") < 0)
                return -1;
            if (insertRuleArgParam(fw, fwrule, vars,
                                   &rule->p.ipv6HdrFilter.dataICMPCodeStart,
                                   "icmpv6", "code") < 0)
                return -1;
        }
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.vlanHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", "0x8100", NULL);

        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.vlanHdrFilter.dataVlanID,
                               "vlan", "id") < 0)
            return -1;
        if (insertRuleArgParam(fw, fwrule, vars,
                               &rule->p.vlanHdrFilter.dataVlanEncap,
                               "vlan", "type") < 0)
            return -1;
        break;
    case VIR_NWFILTER_RULE_PROTOCOL_STP:
        if (reverseRule &&
            HAS_ENTRY_ITEM(&rule->p.stpHdrFilter.ethHdr.dataSrcMACAddr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("STP filtering in %1$s direction with source MAC address set is not supported"),
                           virNWFilterRuleDirectionTypeToString(
                               VIR_NWFILTER_RULE_DIRECTION_INOUT));
            return -1;
        }
        if (nftablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.stpHdrFilter.ethHdr, reverseRule) < 0)
            return -1;

        virFirewallCmdAddArgList(fw, fwrule, "ether", "daddr",
                                 NWFILTER_MAC_BGA, NULL);

        /* @nh (network header), N (bits offset), N (bits length) */

        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.stpHdrFilter.dataType,
                                  "@nh,48,8", NULL) < 0)
            return -1;
        if (insertRuleArgParamHex(fw, fwrule, vars,
                                  &rule->p.stpHdrFilter.dataFlags,
                                  "@nh,56,8", NULL) < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataRootPri,
                                       &rule->p.stpHdrFilter.dataRootPriHi,
                                       "@nh,64,16") < 0)
            return -1;
        if (insertRulePayloadHexMacMask(fw, fwrule, vars,
                                        &rule->p.stpHdrFilter.dataRootAddr,
                                        &rule->p.stpHdrFilter.dataRootAddrMask,
                                        "@nh,80,48") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataRootCost,
                                       &rule->p.stpHdrFilter.dataRootCostHi,
                                       "@nh,128,32") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataSndrPrio,
                                       &rule->p.stpHdrFilter.dataSndrPrioHi,
                                       "@nh,160,16") < 0)
            return -1;
        if (insertRulePayloadHexMacMask(fw, fwrule, vars,
                                        &rule->p.stpHdrFilter.dataSndrAddr,
                                        &rule->p.stpHdrFilter.dataSndrAddrMask,
                                        "@nh,176,48") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataPort,
                                       &rule->p.stpHdrFilter.dataPortHi,
                                       "@nh,224,16") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataAge,
                                       &rule->p.stpHdrFilter.dataAgeHi,
                                       "@nh,240,16") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataMaxAge,
                                       &rule->p.stpHdrFilter.dataMaxAgeHi,
                                       "@nh,256,16") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataHelloTime,
                                       &rule->p.stpHdrFilter.dataHelloTimeHi,
                                       "@nh,272,16") < 0)
            return -1;
        if (insertRuleArgParamHexRange(fw, fwrule, vars,
                                       &rule->p.stpHdrFilter.dataFwdDelay,
                                       &rule->p.stpHdrFilter.dataFwdDelayHi,
                                       "@nh,288,16") < 0)
            return -1;

        break;
    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected rule protocol '%1$d', priority '%2$d'"),
                       rule->prtclType,
                       rule->priority);
        return -1;
    }

    return 0;
}

/*
 * nftablesGetNFTable:
 *
 * @rule: The rule of the filter
 *
 * We have a seperate table, due to eb/iptables compatibilty
 * Ideally we allow users to have only 1 table in which all rules are placed
 * We'll need to turn that into a nwfilter feature
 */
static const char *nftablesGetNFTable(virNWFilterRuleDef *rule)
{
    return virNWFilterRuleIsProtocolEthernet(rule) ?
        NF_ETHERNET_TABLE :
        NF_INET_TABLE;
}

static void
nftablesAddCmdUserComment(virFirewall *fw,
                            virFirewallCmd *fwrule,
                            virNWFilterRuleDef *rule)
{
    g_autofree char *comment = NULL;
    comment = virStringReplace(
                    rule->p.allHdrFilter.ipHdr.dataComment.u.string,
                    "\"", "'");

    virFirewallCmdAddArg(fw, fwrule, "comment");
    virFirewallCmdAddArgFormat(fw, fwrule, "\"usercomment=%s\"", comment);
}

/*
 * nftablesCreateRuleInstance:
 * @fw: the firewall ruleset instance
 * @layer: the firewall layer
 * @chainPrefix: The suffix to put on the end of the name of the chain
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @res : The data structure to store the result(s) into
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, -1 otherwise
 */
static int
nftablesCreateRuleInstance(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *chainPrefix,
                           virNWFilterRuleDef *rule,
                           const char *ifname,
                           virNWFilterVarCombIter *vars,
                           bool directionIn,
                           bool reverseRule)
{
    int ret = -1;
    char chain[MAX_NF_CHAINNAME_LENGTH];
    virFirewallCmd *fwrule = NULL;
    const char *root = virNWFilterChainSuffixTypeToString(
                                     VIR_NWFILTER_CHAINSUFFIX_ROOT);
    const char *nftablesRootTable = nftablesGetNFTable(rule);

    /* apply root rules directly on the root chain, for example:
     * vnet1-in vnet1-out */
    /* for compatability with the ebiptables driver, we don't create subchains for inet rules
     * ebtables (ethernet) received subchains, but iptables (inet) has all rules placed in the root chain */
    if (STREQ(chainPrefix, root) || !virNWFilterRuleIsProtocolEthernet(rule)) {
        g_snprintf(chain, sizeof(chain), "n-%s-%s", ifname,
                   directionIn ? "in" : "out");
    } else {
        g_snprintf(chain, sizeof(chain), "n-%s-%s-%s", ifname, chainPrefix,
                   directionIn ? "in" : "out");
    }

    fwrule = virFirewallAddCmd(fw, layer,
                               "add", "rule", "bridge",
                               nftablesRootTable, chain, NULL);

    if (virNWFilterRuleIsProtocolEthernet(rule)) {
        if (nftablesHandleEthernetRule(fw, fwrule, vars, rule, reverseRule) < 0)
            goto cleanup;
    } else {
        if (nftablesHandleInetRule(fw, fwrule, vars, rule,
                                   directionIn, reverseRule) < 0)
            goto cleanup;
    }

    if (counters_enabled)
        virFirewallCmdAddArg(fw, fwrule, "counter");

    /* specify the action for this rule */
    nftablesAddCmdAction(fw, fwrule, rule->action);


    /* ethernet rules don't have the allHdrFilter */
    if (HAS_ENTRY_ITEM(&rule->p.allHdrFilter.ipHdr.dataComment) &&
        !virNWFilterRuleIsProtocolEthernet(rule)) {
        nftablesAddCmdUserComment(fw, fwrule, rule);
    }

    ret = 0;

 cleanup:
    if (ret == -1)
        virFirewallRemoveCmd(fw, fwrule);

    return ret;
}

static int
nftablesRuleInstCommand(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *ifname,
                        virNWFilterRuleInst *rule)
{
    int ret = -1;
    virNWFilterVarCombIter *vciter;
    virNWFilterVarCombIter *tmp;
    virNWFilterRuleDirectionType direction = rule->def->tt;

    /* rule->vars holds all the variables names that this rule will access.
     * iterate over all combinations of the variables' values and instantiate
     * the filtering rule with each combination.
     */
    tmp = vciter = virNWFilterVarCombIterCreate(rule->vars,
                                                rule->def->varAccess,
                                                rule->def->nVarAccess);
    if (!vciter)
        return -1;

    do {
        bool reverseRule = false;

        VIR_DEBUG("rule[chain='%s', dir='%d', prio='%d', action='%d', chainPrio='%d']",
              rule->chainSuffix,
              direction,
              rule->priority,
              rule->def->action,
              rule->chainPriority);

        if (direction == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            /* for direction inout we run the create instance twice,
             * with directionIn set to true and false */

            /* in */
            if (nftablesCreateRuleInstance(fw, layer, rule->chainSuffix,
                                           rule->def, ifname, tmp,
                                           true, reverseRule) < 0)
                goto cleanup;

            /* for ethernet rules, to comply to what ebiptables did,
             * we set reverseRule to true on direction inout */
            reverseRule = virNWFilterRuleIsProtocolEthernet(rule->def);

            /* out */
            if (nftablesCreateRuleInstance(fw, layer, rule->chainSuffix,
                                           rule->def, ifname, tmp,
                                           false, reverseRule) < 0)
                goto cleanup;
        } else {
            bool directionIn = direction == VIR_NWFILTER_RULE_DIRECTION_IN;
            /* otherwise we provide directionIn */
            if (nftablesCreateRuleInstance(fw, layer, rule->chainSuffix,
                                       rule->def, ifname, tmp,
                                       directionIn, reverseRule) < 0)
                goto cleanup;

            /* rules that do conntrack matching and have action accept need a
             * reverse rule on the other chain to accept the reply direction
             * so if we accept outbound we need an accept on the inbound for
             * established connections */
            if (nftablesRuleNeedsConntrack(rule->def) &&
                rule->def->action == VIR_NWFILTER_RULE_ACTION_ACCEPT) {
                reverseRule = true;
                if (nftablesCreateRuleInstance(fw, layer, rule->chainSuffix,
                                               rule->def, ifname, tmp,
                                               !directionIn, reverseRule) < 0)
                    goto cleanup;
            }
        }

        tmp = virNWFilterVarCombIterNext(tmp);
    } while (tmp != NULL);

    ret = 0;
 cleanup:
    virNWFilterVarCombIterFree(vciter);

    return ret;
}

/*
 * nftablesCreateSubChain:
 * @fw: the firewall ruleset instance
 * @layer: the firewall layer
 * @ifname : The name of the interface to apply the chain to
 * @chainPrefix: The prefix to put on the beginning of the name of the chain
 * @protoidx: Protocol id for conditional jump
 * @rootChain: The chain to define the jump on
 * @chainPostfix: The postfix to put at the end of the name of the chain
 *
 * Creates the user defined chain, chain='mac', with chainPostfix set to 'in'
 * on vnet1 for example leads to:
 *  - vnet1-mac-in
 *
 * Rules get defined on the corresponding chain based on the chosen direction,
 * either in or out or both (in and out) when direction has been set to 'inout'
 */
static void
nftablesCreateSubChain(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *nftablesTableName,
                       const char *chainPrefix,
                       enum virNWFilterProtoIdx protoidx,
                       const char *rootChain,
                       const char *chainPostfix)
{
    char chain[MAX_NF_CHAINNAME_LENGTH];
    virFirewallCmd *fwrule = NULL;
    g_snprintf(chain, sizeof(chain), "%s-%s", chainPrefix, chainPostfix);

    VIR_DEBUG("Defining chain '%s'", chain);

    virFirewallAddCmd(fw, layer, "add", "chain", "bridge",
                      nftablesTableName, chain, CHAINSETTINGS, NULL);

    /* add VM interface jump */
    fwrule = virFirewallAddCmd(fw, layer, "add", "rule", "bridge",
                      nftablesTableName, rootChain, NULL);
    if (protoidx != -1 && l3_protocols[protoidx].attr) {
        virFirewallCmdAddArgList(fw, fwrule, "ether", "type", NULL);
        virFirewallCmdAddArgFormat(fw, fwrule,
                                   "0x%04x", l3_protocols[protoidx].attr);
    } else if (protoidx == VIR_NWFILTER_PROTO_IDX_STP) {
        virFirewallCmdAddArgList(fw, fwrule, "ether", "daddr",
                                 NWFILTER_MAC_BGA, NULL);
    }

    virFirewallCmdAddArgList(fw, fwrule, "jump", chain, NULL);
}

static void
nftablesCreateRootChainJump(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *ifname,
                       const char *ifMatch,
                       const char *topChain,
                       const char *rootChain,
                       bool addTmpJump)
{
    virFirewallCmd *fwrule = NULL;

    /* add a tmp jump to avoid a firewall hole between
     * updating vmap */
    if (addTmpJump) {
        /* tmp iif oif jump */
        virFirewallAddCmd(fw, layer, "add", "rule", "bridge", NF_INET_TABLE,
                          topChain, ifMatch, ifname, "jump", rootChain, NULL);
        virFirewallAddCmd(fw, layer, "add", "rule", "bridge", NF_ETHERNET_TABLE,
                          topChain, ifMatch, ifname, "jump", rootChain, NULL);
    }

    /* remove VM interface jump */
    fwrule = virFirewallAddCmdFull(fw, layer, true, NULL, NULL, "delete",
                                   "element", "bridge", NF_INET_TABLE, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "vmap-%s", ifMatch);
    virFirewallCmdAddArgList(fw, fwrule, "{", ifname, "}", NULL);
    /* add VM interface jump */
    fwrule = virFirewallAddCmd(fw, layer, "add", "element", "bridge",
                               NF_INET_TABLE, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "vmap-%s", ifMatch);
    virFirewallCmdAddArgList(fw, fwrule, "{", ifname, ":", "jump",
                             rootChain, "}", NULL);

    /* remove VM interface jump */
    fwrule = virFirewallAddCmdFull(fw, layer, true, NULL, NULL, "delete",
                                   "element", "bridge",
                                   NF_ETHERNET_TABLE, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "vmap-%s", ifMatch);
    virFirewallCmdAddArgList(fw, fwrule, "{", ifname, "}", NULL);
    /* add VM interface jump */
    fwrule = virFirewallAddCmd(fw, layer, "add", "element", "bridge",
                               NF_ETHERNET_TABLE, NULL);
    virFirewallCmdAddArgFormat(fw, fwrule, "vmap-%s", ifMatch);
    virFirewallCmdAddArgList(fw, fwrule, "{", ifname, ":", "jump", rootChain,
                             "}", NULL);
}

/*
 * nftablesCreateRootChain:
 * @fw: the firewall ruleset instance
 * @layer: the firewall layer
 * @ifname : The name of the interface to apply the chain to
 * @ifMatch : The matcher to use for this root chain, iif/oif
 * @chainPrefix: The prefix to put on the beginning of the name of the chain
 * @protoidx: Protocol id for conditional jump
 * @topChain: The chain to define the jump on
 * @rootChain: The root chain for the interface to create
 *
 * Creates the interface root chain, chainPostfix set to 'in'
 * on vnet1 for example, leads to:
 *  - vnet1-in
 *
 * These root chains are the chains where all the subchains jumps get added to
 * vnet1-in -> jump vnet-mac-in; ether type ip jump vnet-ip-in;
 */
static void
nftablesCreateRootChain(virFirewall *fw,
                       virFirewallLayer layer,
                       const char *rootChain)
{
    VIR_DEBUG("Defining root chain '%s'", rootChain);

    virFirewallAddCmd(fw, layer, "add", "chain", "bridge",
                      NF_ETHERNET_TABLE, rootChain, CHAINSETTINGS, NULL);

    virFirewallAddCmd(fw, layer, "add", "chain", "bridge",
                      NF_INET_TABLE, rootChain, CHAINSETTINGS, NULL);
}

typedef struct _nftablesSubChain nftablesSubChain;
struct _nftablesSubChain {
    /* we use the lowest rule priority in a chain to compare root rule inserts
     * see nftablesHandleCreateChains for the explanation */
    virNWFilterRulePriority lowestRulePriority;
    virNWFilterChainPriority priority;
    enum virNWFilterProtoIdx protoidx;
    char prefix[MAX_NF_CHAINNAME_LENGTH];
    const char *suffix;
    /* to prevent creation of empty chains,
     * we track wether or not there are in/out | inout directions */
    bool ethernetOutChain;
    bool ethernetInChain;
};

static int nftablesChainCreateSort(const void *a, const void *b,
                                   void *opaque G_GNUC_UNUSED)
{
    const nftablesSubChain *insta = *(const nftablesSubChain **)a;
    const nftablesSubChain *instb = *(const nftablesSubChain **)b;
    const char *root = virNWFilterChainSuffixTypeToString(
                                     VIR_NWFILTER_CHAINSUFFIX_ROOT);
    bool root_a = STREQ(insta->suffix, root);
    bool root_b = STREQ(instb->suffix, root);

    /* ensure root chain commands appear before all others since
       we will need them to create the child chains */
    if (root_a) {
        if (!root_b)
            return -1; /* a before b */
    } else if (root_b) {
        return 1; /* b before a */
    }

    /* priorities are limited to range [-1000, 1000] */
    return insta->priority - instb->priority;
}

static void
updateChainFlags(nftablesSubChain *chain, virNWFilterRuleDef *rule)
{
    if (!virNWFilterRuleIsProtocolEthernet(rule)) {
        return;
    }

    chain->ethernetInChain  |= rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN ||
                               rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT;
    chain->ethernetOutChain |= rule->tt == VIR_NWFILTER_RULE_DIRECTION_OUT ||
                               rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT;
}

static void
nftablesGetSubChains(nftablesSubChain ***chains,
                     size_t *nchains,
                     virNWFilterRuleInst **rules,
                     size_t nrules,
                     const char *ifname)
{
    size_t i, j;

    for (i = 0; i < nrules; i++) {
        g_autofree nftablesSubChain *chain = NULL;
        nftablesSubChain **chainst = *chains;

        for (j = 0; j < *nchains; j++) {
            if (STRNEQ(rules[i]->chainSuffix, chainst[j]->suffix))
                continue;

            VIR_DEBUG("Chain already registered '%s'", chainst[j]->suffix);
            updateChainFlags(chainst[j], rules[i]->def);
            goto next_rule;
        }

        /* filter out the root chain */
        if (STREQ(rules[i]->chainSuffix,
            virNWFilterChainSuffixTypeToString(VIR_NWFILTER_CHAINSUFFIX_ROOT)))
            continue;

        /* register the chain for creation */
        chain = g_new0(nftablesSubChain, 1);

        updateChainFlags(chain, rules[i]->def);
        chain->priority = rules[i]->chainPriority;
        chain->lowestRulePriority = rules[i]->priority;
        chain->suffix = rules[i]->chainSuffix;
        g_snprintf(chain->prefix, sizeof(chain->prefix),
                   "n-%s-%s", ifname, chain->suffix);

        VIR_APPEND_ELEMENT(*chains, *nchains, chain);

 next_rule:
        continue;
    }
}

static int
nftablesHandleCreateChains(virFirewall *fw,
                           virFirewallLayer layer,
                           const char *const *lines G_GNUC_UNUSED,
                           void *opaque)
{
    size_t i, j, nchains = 0;
    size_t lastProcessedRootRuleIndex = 0;
    size_t lastCreatedRootRuleIndex = 0;
    bool hasCreatedRootRules = false;
    int ret = -1;
    virNWFilterChainCreateCallbackData *cbdata = opaque;
    nftablesSubChain **chains = NULL;
    char rootChainIn[MAX_NF_CHAINNAME_LENGTH];
    char rootChainOut[MAX_NF_CHAINNAME_LENGTH];
    const char *rootChainName = virNWFilterChainSuffixTypeToString(
                                 VIR_NWFILTER_CHAINSUFFIX_ROOT);
    g_snprintf(rootChainIn, sizeof(rootChainIn), "n-%s-in", cbdata->ifname);
    g_snprintf(rootChainOut, sizeof(rootChainOut), "n-%s-out", cbdata->ifname);

    nftablesGetSubChains(&chains,
                         &nchains,
                         cbdata->rules,
                         cbdata->nrules,
                         cbdata->ifname);

    /* sort chains on their chain priority */
    g_qsort_with_data(chains, nchains, sizeof(chains[0]),
                      nftablesChainCreateSort, NULL);

    /* first we create the root interface in-out chains */
    nftablesCreateRootChain(fw, layer, rootChainIn);
    nftablesCreateRootChain(fw, layer, rootChainOut);

    /*
     * Filtering rules on the root chain must be interleaved with subchain
     * definitions and jumps based on priority. This is required to stay
     * compatible with behavior from the ebiptables driver, where root rules
     * may need to appear before or after chain jumps depending on priority.
     *
     * Historical note:
     *   - In the ebiptables driver, iptables/ip6tables had no subchains;
     *     all inet rules lived directly on the root chain.
     *     In order to not cause sorting differences and differences on how
     *     traffic is filtered, the same logic is applied in the nftables driver.
     *     Meaning inet rules in subchains end up in the root e.g. vnet0-in
     *     or vnet0-out.
     *
     * Only the root chain needs this handling. All other chains are already
     * sorted correctly. Chains cannot be created lazily during rule
     * processing, as chains themselves have priorities.
     *
     * Therefor we apply the following logic:
     *   - Create the root chain first
     *   - Process root rules and subchains in priority order
     *   - Root rules are inserted according to rule priority
     *   - Subchains are created (with their jump) when their priority requires it
     *
     * Table specific behavior (ethernetRootRuleSorting/inetRootRuleSorting):
     *   - enet: rule->priority vs chain->priority
     *   - inet: rule->priority placed on root chain, e.g. vnet0-in or vnet-out
     */

    /* create chain if it doesn't exist */
    /* define undefined sub chains */
    for (i = 0; i < nchains; i++) {
        enum virNWFilterProtoIdx protoidx;

        /* root chain firewall rules, if there are root chain firewall rules
         * with a lower priority than this chains lowest rule priority */
        for (j = lastProcessedRootRuleIndex; j < cbdata->nrules; j++) {
            /* as root rules are inserted before all other rules,
             * we stop walking the rules list when we've hit a no root rule*/
            if (STRNEQ(cbdata->rules[j]->chainSuffix, rootChainName)) {
                break;
            }

            if (chains[i]->priority <= cbdata->rules[j]->priority)
                break;

            /* we only create subchains for ethernet rules */
            if (!virNWFilterRuleIsProtocolEthernet(cbdata->rules[j]->def))
                continue;

            if (nftablesRuleInstCommand(fw, layer,
                                        cbdata->ifname,
                                        cbdata->rules[j]) < 0)
                goto cleanup;

            hasCreatedRootRules = true;
            lastProcessedRootRuleIndex = j + 1;
            lastCreatedRootRuleIndex = j;
        }

        protoidx = nftablesGetProtoIdxByFiltername(chains[i]->suffix);
        if (chains[i]->ethernetInChain)
            nftablesCreateSubChain(fw, layer, NF_ETHERNET_TABLE,
                                   chains[i]->prefix, protoidx,
                                   rootChainIn, "in");
        if (chains[i]->ethernetOutChain)
            nftablesCreateSubChain(fw, layer, NF_ETHERNET_TABLE,
                                   chains[i]->prefix, protoidx,
                                   rootChainOut, "out");
    }

    /* process the firewall rules and chains */
    for (i = 0; i < cbdata->nrules; i++) {
        /* ethernet root chain rules till lastCreatedRootRuleIndex have been created */
        if (hasCreatedRootRules &&
            lastCreatedRootRuleIndex >= i &&
            STREQ(cbdata->rules[i]->chainSuffix, rootChainName) &&
            virNWFilterRuleIsProtocolEthernet(cbdata->rules[i]->def)) {
            continue;
        }

        if (nftablesRuleInstCommand(fw, layer,
                                    cbdata->ifname, cbdata->rules[i]) < 0)
            goto cleanup;
    }

    /* creation of temp jumps is done as libvirt doesn't execute
     * atomic nft changes (yet) */
    nftablesCreateRootChainJump(fw, layer, cbdata->ifname, IN_IFMATCH,
                                IN_CHAIN, rootChainIn, true);
    nftablesCreateRootChainJump(fw, layer, cbdata->ifname, OUT_IFMATCH,
                                OUT_CHAIN, rootChainOut, true);

    ret = 0;

 cleanup:
    for (i = 0; i < nchains; i++)
        g_free(chains[i]);
    g_free(chains);

    return ret;
}

/**
 * nftablesCreateRootTables
 *
 * @fw: the firewall instance
 *
 * Run nft list tables and parse if the table already exist
 * skips creation of base table if possible
 * see handler in nftablesHandleCreateRootTables
 */
static void nftablesCreateRootTables(virFirewall *fw)
{
    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleCreateRootTables,
                          NULL,
                          "list", "tables", NULL);
}

/**
 * nftablesEnsureRootTablesExist
 *
 * Run nftablesCreateRootTables in a seperate transaction,
 * Follow up commands like:
 * - "nft list -a" commands in nftablesRemoveAllInterfaceChains
 * - "add chain" commands in nftablesApplyBasicRules
 * Can then run and be assured that the tables should exist.
 */
static int nftablesEnsureRootTablesExist(void)
{
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    virFirewallStartTransaction(fw, 0);

    /* remove interface chains and rules */
    nftablesCreateRootTables(fw);

    return virFirewallApply(fw);
}

/**
 * nftablesCreateChains
 *
 * @fw: the firewleset instance
 * @cbdata: callback data struct which holds variables that
 *          the call back handler needs in order to create
 *          the base table and the dependant rules
 *
 * Run nft list table libvirt-nwfilter and parse if the chains already exist
 * skips creation of chains if possible
 * see handler in nftablesHandleCreateChains
 */
static void nftablesCreateChains(virFirewall *fw,
                                 virNWFilterChainCreateCallbackData *cbdata)
{
    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleCreateChains,
                          (void *)cbdata,
                          "list", "chains", NULL);
}

static const char *breakStrAt(const char *str, char untilc)
{
    const char *untilPtr = strchr(str, untilc);
    if (untilPtr) {
        *(char *)untilPtr = '\0';
    }

    return str;
}

static int
nftablesHandleRenameChains(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *const *lines,
                        void *opaque)
{
    size_t i = 0;
    const char *ifname = opaque;
    const char *tableName = NULL;
    const char *chain = NULL;
    const char *newName = NULL;
    char chainCompare[MAX_NF_CHAINNAME_LENGTH];
    g_snprintf(chainCompare, sizeof(chainCompare), "n-%s-", ifname);

    /* parse nft tables list output to see if chains exist */
    for (i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];

        /* first we'll have to parse the table name */
        if (tableName == NULL && STRPREFIX(line, "table bridge ")) {
            line = STRSKIP(line, "table bridge ");
            /* parse table that we want to clean */
            tableName = breakStrAt(line, ' ');
            continue;
        }

        virSkipSpaces(&line);

        if ((line = STRSKIP(line, "chain ")) == NULL) {
            continue;
        }
        chain = breakStrAt(line, ' ');

        if (STRPREFIX(chain, chainCompare) && STRPREFIX(chain, "n-")) {
            /* new name is name without n- at the prefix */
            newName = chain + strlen("n-");
            VIR_DEBUG("Scheduling chain rename '%s'->'%s' on table '%s'",
                      chain, newName, tableName);
            /* delete the chain */
            virFirewallAddCmd(fw, layer,
                          "rename", "chain", "bridge",
                          tableName, chain, newName, NULL);
        }
    }

    return 0;
}

static void
nftablesRemoveVmapElementList(virFirewall *fw,
                              virFirewallLayer layer,
                              const char *line,
                              const char *tableName,
                              const char *vmapName,
                              const char *chainCompare)
{
    const char *vmapKey = NULL;
    if (STRPREFIX(line, "elements = {"))
        line = STRSKIP(line, "elements = {");

    /* skip spaces up to vmap key */
    virSkipSpaces(&line);

    /* walk the elements */
    while (line && STRNEQ(line, "}") && STRNEQ(line, ",")) {
        g_autofree char *vmap = g_strdup(line);
        vmapKey = breakStrAt(vmap, ' ');

        /* skip past this vmap key */
        line = STRSKIP(line, vmapKey);

        /* skip " : jump" or ":jump" */
        virSkipSpaces(&line);
        if ((line = STRSKIP(line, ":")) == NULL)
            break;
        virSkipSpaces(&line);
        if ((line = STRSKIP(line, "jump")) == NULL)
            break;
        virSkipSpaces(&line);

        if (STRPREFIX(line, chainCompare)) {
            VIR_DEBUG("Scheduling vmap element '%s' on '%s' for deletion",
                      vmapKey, vmapName);
            virFirewallAddCmd(fw, layer,
                              "delete", "element", "bridge", tableName,
                              vmapName, "{", vmapKey, "}", NULL);
        }

        if (strchr(line, ',') != NULL)
            line = strchr(line, ',');
        if (strchr(line, ' ') != NULL)
            line = strchr(line, ' ');

        /* skip spaces up to next vmap key */
        virSkipSpaces(&line);
    }
}

static int
nftablesHandleRemoveAll(virFirewall *fw,
                        virFirewallLayer layer,
                        const char *const *lines,
                        void *opaque)
{
    size_t i = 0;
    const char *ifname = opaque;
    const char *tableName = NULL;
    const char *chain = NULL;
    const char *vmapName = NULL;
    bool vmapParsing = false;
    char chainCompare[MAX_NF_CHAINNAME_LENGTH];
    char fwCompare[MAX_NF_CHAINNAME_LENGTH];
    char tmpFwCompare[MAX_NF_CHAINNAME_LENGTH];
    g_snprintf(chainCompare, sizeof(chainCompare), "%s-", ifname);
    g_snprintf(fwCompare, sizeof(fwCompare), "\"%s\" jump %s-", ifname, ifname);
    /* match possible tmp jump on tmp name "\"vnet0\"" jump n-vnet0-" */
    g_snprintf(tmpFwCompare, sizeof(tmpFwCompare), "\"%s\" jump n-%s-", ifname,
               ifname);

    /* parse nft tables list output to see if chains exist */
    for (i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];

        /* first we'll have to parse the table name */
        if (tableName == NULL && STRPREFIX(line, "table bridge ")) {
            line = STRSKIP(line, "table bridge ");
            /* parse table that we want to clean */
            tableName = breakStrAt(line, ' ');
            continue;
        }

        virSkipSpaces(&line);

        /* delete tmp jumps */
        if (strstr(line, fwCompare) != NULL ||
            strstr(line, tmpFwCompare) != NULL) {
            line = strchr(line, '#');
            if ((line = STRSKIP(line, "# handle ")) == NULL)
                continue;

            /* delete tmp jump */
            virFirewallAddCmd(fw, layer,
                              "delete", "rule", "bridge", tableName, chain,
                              "handle", line, NULL);

            continue;
        }

        /* parse current vmap name*/
        if (STRPREFIX(line, "map ") &&
            (line = STRSKIP(line, "map ")) != NULL) {
            vmapName = breakStrAt(line, ' ');
            continue;
        }

        /* if we come acros map elements, we enable element list parsing */
        if (STRPREFIX(line, "elements = {"))
            vmapParsing = true;

        /* remove old map elements, if they exist */
        /* we are in process of parsing a vmap elements list */
        if (vmapParsing) {
            /* reached end of list */
            if (strstr(line, "}") != NULL)
                vmapParsing = false;

            nftablesRemoveVmapElementList(fw, layer, line, tableName,
                                          vmapName, chainCompare);

            continue;
        }

        if ((line = STRSKIP(line, "chain ")) == NULL) {
            continue;
        }
        chain = breakStrAt(line, ' ');

        if (STRPREFIX(chain, chainCompare)) {
            VIR_DEBUG("Scheduling chain '%s' on table '%s' for deletion",
                      chain, tableName);
            /* delete the chain */
            virFirewallAddCmd(fw, layer,
                          "delete", "chain", "bridge",
                          tableName, chain, NULL);
        }
    }

    return 0;
}

static void
nftablesRemoveAllInterfaceChains(virFirewall *fw, const char *ifname)
{
    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleRemoveAll,
                          (void *)ifname,
                          "-a", "list", "table", "bridge",
                          NF_ETHERNET_TABLE, NULL);

    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleRemoveAll,
                          (void *)ifname,
                          "-a", "list", "table", "bridge",
                          NF_INET_TABLE, NULL);
}

static void
nftablesRenameAllInterfaceChains(virFirewall *fw, const char *ifname)
{
    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleRenameChains,
                          (void *)ifname,
                          "-a", "list", "table", "bridge",
                          NF_ETHERNET_TABLE, NULL);

    virFirewallAddCmdFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                          false, nftablesHandleRenameChains,
                          (void *)ifname,
                          "-a", "list", "table", "bridge",
                          NF_INET_TABLE, NULL);
}

static int
nftablesApplyNewRules(const char *ifname,
                  virNWFilterRuleInst **rules,
                  size_t nrules)
{
    size_t i;
    g_autoptr(GHashTable) chains_in_set  = virHashNew(NULL);
    g_autoptr(GHashTable) chains_out_set = virHashNew(NULL);
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    virNWFilterChainCreateCallbackData chainCallbackData = {ifname, nrules, rules};

    /* nwfilter_nftables applies new rules first, then remove old rules
     * in order to do this we:
     * - place the new chains under a name prefixed with "n-"
     * - create tmp jump that catches vmap switch moment,
     *   traffic will temporarily not be matched as an entry from the vmap will
     *   be deleted and then recreated as you can't atomic update vmaps via a
     *   single command
     * - in the tearOldRules function, we also remove the tmp interface jump to
     *   the new chains
     * - in tearOldRules we remove the old chains
     * - in tearOldRules we rename the "n-" chains by removing "n-" from the
     *   chain name
     *
     * This allows us in a rollback scenario to simply remove the new chains
     * and jumps
     */
    char tmpIfname[VIR_INT64_STR_BUFLEN];
    g_snprintf(tmpIfname, sizeof(tmpIfname), "n-%s", ifname);

    /* walk the list of rules and increase the priority
     * of rules in case the chain priority is of higher value;
     * this preserves the order of the rules and ensures that
     * the chain will be created before the chain's rules
     * are created; don't adjust rules in the root chain
     * example: a rule of priority -510 will be adjusted to
     * priority -500 and the chain with priority -500 will
     * then be created before it.
     */
    for (i = 0; i < nrules; i++) {
        if (rules[i]->chainPriority > rules[i]->priority &&
            !strstr("root", rules[i]->chainSuffix)) {

             rules[i]->priority = rules[i]->chainPriority;
        }
    }

    /* sort rules */
    if (nrules) {
        g_qsort_with_data(rules, nrules, sizeof(rules[0]),
                          virNWFilterRuleInstSortPtr, NULL);
    }

    virFirewallStartTransaction(fw, 0);

    /* create root tables if they don't exist already */
    nftablesCreateRootTables(fw);
    /* create user chains and rules */
    nftablesCreateChains(fw, &chainCallbackData);

    /* rollback commands, if necessary */
    virFirewallStartRollback(fw, 0);
    nftablesRemoveAllInterfaceChains(fw, tmpIfname);

    /* process rules and apply them */
    return virFirewallApply(fw);
}

static int
nftablesTeardownNewRules(const char *ifname)
{
    char matchIfname[VIR_INT64_STR_BUFLEN];
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);

    g_snprintf(matchIfname, sizeof(matchIfname), "n-%s", ifname);

    virFirewallStartTransaction(fw, 0);

    /* remove tmp interface chains and rules */
    nftablesRemoveAllInterfaceChains(fw, matchIfname);

    return virFirewallApply(fw);
}

static int
nftablesTeardownOldRules(const char *ifname)
{
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    virFirewallStartTransaction(fw, 0);

    /* remove old interface chains and rules */
    nftablesRemoveAllInterfaceChains(fw, ifname);

    /* rename new temp interface chains and rules */
    nftablesRenameAllInterfaceChains(fw, ifname);

    return virFirewallApply(fw);
}

/**
 * nftablesAllTeardown:
 * @ifname : the name of the interface to which the rules apply
 *
 * Unconditionally remove all possible user defined tables and rules
 * that were created for the given interface (ifname).
 *
 * Returns 0 on success, -1 on OOM
 */
static int
nftablesAllTeardown(const char *ifname)
{
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    virFirewallStartTransaction(fw, 0);

    /* remove interface chains and rules */
    nftablesRemoveAllInterfaceChains(fw, ifname);

    return virFirewallApply(fw);
}

/**
 * nftablesCanApplyBasicRules
 *
 * Determine whether this driver can apply the basic rules, meaning
 * run nftablesApplyBasicRules and nftablesApplyDHCPOnlyRules.
 * In case of this driver we need the nft tool available.
 */
static bool nftablesCanApplyBasicRules(void)
{
    return true;
}

/**
 * nftablesApplyBasicRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 * @macaddr: MAC address the VM is using in packets sent through the
 *    interface
 *
 * Returns 0 on success, -1 on failure with the rules removed
 *
 * Apply basic filtering rules on the given interface
 * - filtering for MAC address spoofing
 * - allowing IPv4 & ARP traffic
 */
static int
nftablesApplyBasicRules(const char *ifname,
                        const virMacAddr *macaddr)
{
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);
    char macaddr_str[VIR_MAC_STRING_BUFLEN];
    char rootChainIn[MAX_NF_CHAINNAME_LENGTH];
    char rootChainOut[MAX_NF_CHAINNAME_LENGTH];

    virMacAddrFormat(macaddr, macaddr_str);

    if (nftablesEnsureRootTablesExist() < 0)
        return -1;

    if (nftablesAllTeardown(ifname) < 0)
        return -1;

    virFirewallStartTransaction(fw, 0);

    /* create root chain */
    g_snprintf(rootChainIn, sizeof(rootChainIn), "%s-in", ifname);
    g_snprintf(rootChainOut, sizeof(rootChainOut), "%s-out", ifname);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainIn);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainOut);


    /* apply rules to root chain */
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "ether", "saddr",
                      "!=", macaddr_str, "drop", NULL);
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "ether", "type", "ip",
                      "accept", NULL);
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "ether", "type", "arp",
                      "accept", NULL);
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "accept", NULL);

    nftablesCreateRootChainJump(fw, VIR_FIREWALL_LAYER_ETHERNET, ifname,
                                IN_IFMATCH, IN_CHAIN, rootChainIn, false);
    nftablesCreateRootChainJump(fw, VIR_FIREWALL_LAYER_ETHERNET, ifname,
                                OUT_IFMATCH, OUT_CHAIN, rootChainOut, false);

    if (virFirewallApply(fw) < 0) {
        nftablesAllTeardown(ifname);
        return -1;
    }

    return 0;
}

/**
 * nftablesApplyDHCPOnlyRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 * @macaddr: MAC address the VM is using in packets sent through the
 *    interface
 * @dhcpsrvrs: The DHCP server(s) from which the VM may receive traffic
 *    from; may be NULL
 * @leaveTemporary: Whether to leave the table names with their temporary
 *    names (true) or also perform the renaming to their final names as
 *    part of this call (false)
 *
 * Returns 0 on success, -1 on failure with the rules removed
 *
 * Apply filtering rules so that the VM can only send and receive
 * DHCP traffic and nothing else.
 */
static int
nftablesApplyDHCPOnlyRules(const char *ifname,
                           const virMacAddr *macaddr,
                           virNWFilterVarValue *dhcpsrvrs,
                           bool leaveTemporary G_GNUC_UNUSED)
{
    char rootChainIn [MAX_NF_CHAINNAME_LENGTH],
         rootChainOut[MAX_NF_CHAINNAME_LENGTH];
    char macaddr_str[VIR_MAC_STRING_BUFLEN];
    unsigned int idx = 0;
    unsigned int num_dhcpsrvrs;
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);

    virMacAddrFormat(macaddr, macaddr_str);

    if (nftablesEnsureRootTablesExist() < 0)
        return -1;

    if (nftablesAllTeardown(ifname) < 0)
        return -1;

    virFirewallStartTransaction(fw, 0);

    /* create root chain */
    g_snprintf(rootChainIn, sizeof(rootChainIn), "%s-in", ifname);
    g_snprintf(rootChainOut, sizeof(rootChainOut), "%s-out", ifname);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainIn);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainOut);

    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                  NF_ETHERNET_TABLE, rootChainOut, "ether", "saddr",
                  macaddr_str, "ether", "type", "ip",
                  "udp", "sport", "68", "udp", "dport", "67", "accept", NULL);

    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "drop", NULL);

    num_dhcpsrvrs = (dhcpsrvrs != NULL)
                    ? virNWFilterVarValueGetCardinality(dhcpsrvrs)
                    : 0;

    while (true) {
        const char *dhcpserver = NULL;
        int ctr;

        if (idx < num_dhcpsrvrs)
            dhcpserver = virNWFilterVarValueGetNthValue(dhcpsrvrs, idx);

        /*
         * create two rules allowing response to MAC address of VM
         * or to broadcast MAC address
         */
        for (ctr = 0; ctr < 2; ctr++) {
            if (dhcpserver)
                virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                  "add", "rule", "bridge",
                                  NF_ETHERNET_TABLE, rootChainIn, "ether",
                                  "daddr",
                                  (ctr == 0) ? macaddr_str : "ff:ff:ff:ff:ff:ff",
                                  "ether", "type", "ip",
                                  "ip", "saddr", dhcpserver,
                                  "udp", "sport", "67",
                                  "udp", "dport", "68", "accept", NULL);
            else
                virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                  "add", "rule", "bridge",
                                  NF_ETHERNET_TABLE, rootChainIn, "ether",
                                  "daddr",
                                  (ctr == 0) ? macaddr_str : "ff:ff:ff:ff:ff:ff",
                                  "ether", "type", "ip",
                                  "udp", "sport", "67",
                                  "udp", "dport", "68", "accept", NULL);
        }

        idx++;

        if (idx >= num_dhcpsrvrs)
            break;
    }

    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainIn, "drop", NULL);

    nftablesCreateRootChainJump(fw, VIR_FIREWALL_LAYER_ETHERNET, ifname,
                                IN_IFMATCH, IN_CHAIN, rootChainIn, false);
    nftablesCreateRootChainJump(fw, VIR_FIREWALL_LAYER_ETHERNET, ifname,
                                OUT_IFMATCH, OUT_CHAIN, rootChainOut, false);

    if (virFirewallApply(fw) < 0) {
        nftablesAllTeardown(ifname);
        return -1;
    }

    return 0;
}

static int
nftablesRemoveBasicRules(const char *ifname)
{
    return nftablesAllTeardown(ifname);
}

/**
 * nftablesApplyDropAllRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 *
 * Returns 0 on success, -1 on failure with the rules removed
 *
 * Apply filtering rules so that the VM cannot receive or send traffic.
 */
static int
nftablesDropAllRules(const char *ifname)
{
    char rootChainIn [MAX_NF_CHAINNAME_LENGTH],
         rootChainOut[MAX_NF_CHAINNAME_LENGTH];
    g_autoptr(virFirewall) fw = virFirewallNew(VIR_FIREWALL_BACKEND_NFTABLES);

    if (nftablesEnsureRootTablesExist() < 0)
        return -1;
    if (nftablesAllTeardown(ifname) < 0)
        return -1;

    virFirewallStartTransaction(fw, 0);

    /* create root chain */
    g_snprintf(rootChainIn, sizeof(rootChainIn), "%s-in", ifname);
    g_snprintf(rootChainOut, sizeof(rootChainOut), "%s-out", ifname);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainIn);
    nftablesCreateRootChain(fw, VIR_FIREWALL_LAYER_ETHERNET, rootChainOut);

    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainOut, "drop", NULL);
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, rootChainIn, "drop", NULL);

    /* tmp iif oif jump */
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, IN_CHAIN, IN_IFNAMEMATCH, ifname,
                      "jump", rootChainIn, NULL);
    virFirewallAddCmd(fw, VIR_FIREWALL_LAYER_ETHERNET, "add", "rule", "bridge",
                      NF_ETHERNET_TABLE, OUT_CHAIN, OUT_IFNAMEMATCH, ifname,
                      "jump", rootChainOut, NULL);

    if (virFirewallApply(fw) < 0) {
        nftablesAllTeardown(ifname);
        return -1;
    }

    return 0;
}

static int
nftablesDriverInit(bool privileged, virNWFilterDriverConfig *config G_GNUC_UNUSED)
{
    if (!privileged)
        return 0;

    trace_enabled = config->firewallTracing;
    counters_enabled = config->ruleCounters;

    nftables_driver.flags = TECHDRV_FLAG_INITIALIZED;

    return 0;
}

static void
nftablesDriverShutdown(void)
{
    nftables_driver.flags = 0;
}

virNWFilterTechDriver nftables_driver = {
    .name               = NFTABLES_DRIVER_ID,
    .flags              = 0,

    .init               = nftablesDriverInit,
    .shutdown           = nftablesDriverShutdown,

    .applyNewRules      = nftablesApplyNewRules,
    .tearNewRules       = nftablesTeardownNewRules,
    .tearOldRules       = nftablesTeardownOldRules,
    .allTeardown        = nftablesAllTeardown,

    .canApplyBasicRules = nftablesCanApplyBasicRules,
    .applyBasicRules    = nftablesApplyBasicRules,
    .applyDHCPOnlyRules = nftablesApplyDHCPOnlyRules,
    .applyDropAllRules  = nftablesDropAllRules,
    .removeBasicRules   = nftablesRemoveBasicRules,
};
