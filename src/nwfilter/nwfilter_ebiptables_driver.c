/*
 * nwfilter_ebiptables_driver.c: driver for ebtables/iptables on tap devices
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
 * Copyright (C) 2010-2012 IBM Corp.
 * Copyright (C) 2010-2012 Stefan Berger
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

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/utsname.h>

#include "internal.h"

#include "virbuffer.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "domain_conf.h"
#include "nwfilter_conf.h"
#include "nwfilter_driver.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "virfile.h"
#include "vircommand.h"
#include "configmake.h"
#include "intprops.h"
#include "virstring.h"
#include "virfirewall.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_ebiptables_driver");

#define EBTABLES_CHAIN_INCOMING "PREROUTING"
#define EBTABLES_CHAIN_OUTGOING "POSTROUTING"

#define CHAINPREFIX_HOST_IN       'I'
#define CHAINPREFIX_HOST_OUT      'O'
#define CHAINPREFIX_HOST_IN_TEMP  'J'
#define CHAINPREFIX_HOST_OUT_TEMP 'P'


#define PROC_BRIDGE_NF_CALL_IPTABLES \
        "/proc/sys/net/bridge/bridge-nf-call-iptables"
#define PROC_BRIDGE_NF_CALL_IP6TABLES \
        "/proc/sys/net/bridge/bridge-nf-call-ip6tables"

#define BRIDGE_NF_CALL_ALERT_INTERVAL  10 /* seconds */

/*
 * --ctdir original vs. --ctdir reply's meaning was inverted in netfilter
 * at some point (Linux 2.6.39)
 */
enum ctdirStatus {
    CTDIR_STATUS_UNKNOWN    = 0,
    CTDIR_STATUS_CORRECTED  = 1,
    CTDIR_STATUS_OLD        = 2,
};
static enum ctdirStatus iptables_ctdir_corrected;

#define PRINT_ROOT_CHAIN(buf, prefix, ifname) \
    snprintf(buf, sizeof(buf), "libvirt-%c-%s", prefix, ifname)
#define PRINT_CHAIN(buf, prefix, ifname, suffix) \
    snprintf(buf, sizeof(buf), "%c-%s-%s", prefix, ifname, suffix)

#define VIRT_IN_CHAIN      "libvirt-in"
#define VIRT_OUT_CHAIN     "libvirt-out"
#define VIRT_IN_POST_CHAIN "libvirt-in-post"
#define HOST_IN_CHAIN      "libvirt-host-in"

#define PRINT_IPT_ROOT_CHAIN(buf, prefix, ifname) \
    snprintf(buf, sizeof(buf), "%c%c-%s", prefix[0], prefix[1], ifname)

static bool newMatchState;

#define MATCH_PHYSDEV_IN_FW   "-m", "physdev", "--physdev-in"
#define MATCH_PHYSDEV_OUT_FW  "-m", "physdev", "--physdev-is-bridged", "--physdev-out"
#define MATCH_PHYSDEV_OUT_OLD_FW  "-m", "physdev", "--physdev-out"

static int ebtablesRemoveBasicRules(const char *ifname);
static int ebiptablesDriverInit(bool privileged);
static void ebiptablesDriverShutdown(void);
static int ebtablesCleanAll(const char *ifname);
static int ebiptablesAllTeardown(const char *ifname);

struct ushort_map {
    unsigned short attr;
    const char *val;
};


enum l3_proto_idx {
    L3_PROTO_IPV4_IDX = 0,
    L3_PROTO_IPV6_IDX,
    L3_PROTO_ARP_IDX,
    L3_PROTO_RARP_IDX,
    L2_PROTO_MAC_IDX,
    L2_PROTO_VLAN_IDX,
    L2_PROTO_STP_IDX,
    L3_PROTO_LAST_IDX
};

#define USHORTMAP_ENTRY_IDX(IDX, ATT, VAL) [IDX] = { .attr = ATT, .val = VAL }

/* A lookup table for translating ethernet protocol IDs to human readable
 * strings. None of the human readable strings must be found as a prefix
 * in another entry here (example 'ab' would be found in 'abc') to allow
 * for prefix matching.
 */
static const struct ushort_map l3_protocols[] = {
    USHORTMAP_ENTRY_IDX(L3_PROTO_IPV4_IDX, ETHERTYPE_IP,     "ipv4"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_IPV6_IDX, ETHERTYPE_IPV6,   "ipv6"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_ARP_IDX,  ETHERTYPE_ARP,    "arp"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_RARP_IDX, ETHERTYPE_REVARP, "rarp"),
    USHORTMAP_ENTRY_IDX(L2_PROTO_VLAN_IDX, ETHERTYPE_VLAN,   "vlan"),
    USHORTMAP_ENTRY_IDX(L2_PROTO_STP_IDX,  0,                "stp"),
    USHORTMAP_ENTRY_IDX(L2_PROTO_MAC_IDX,  0,                "mac"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_LAST_IDX, 0,                NULL),
};


static char chainprefixes_host[3] = {
    CHAINPREFIX_HOST_IN,
    CHAINPREFIX_HOST_OUT,
    0
};

static char chainprefixes_host_temp[3] = {
    CHAINPREFIX_HOST_IN_TEMP,
    CHAINPREFIX_HOST_OUT_TEMP,
    0
};

static int
printVar(virNWFilterVarCombIterPtr vars,
         char *buf, int bufsize,
         nwItemDescPtr item,
         bool *done)
{
    *done = false;

    if ((item->flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
        const char *val;

        val = virNWFilterVarCombIterGetVarValue(vars, item->varAccess);
        if (!val) {
            /* error has been reported */
            return -1;
        }

        if (virStrcpy(buf, val, bufsize) < 0) {
            const char *varName;

            varName = virNWFilterVarAccessGetVarName(item->varAccess);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Buffer too small to print variable "
                             "'%s' into"), varName);
            return -1;
        }

        *done = true;
    }
    return 0;
}


static int
_printDataType(virNWFilterVarCombIterPtr vars,
               char *buf, int bufsize,
               nwItemDescPtr item,
               bool asHex, bool directionIn)
{
    bool done;
    char *data;
    uint8_t ctr;
    virBuffer vb = VIR_BUFFER_INITIALIZER;
    char *flags;

    if (printVar(vars, buf, bufsize, item, &done) < 0)
        return -1;

    if (done)
        return 0;

    switch (item->datatype) {
    case DATATYPE_IPADDR:
        data = virSocketAddrFormat(&item->u.ipaddr);
        if (!data)
            return -1;
        if (snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("buffer too small for IP address"));
            VIR_FREE(data);
            return -1;
        }
        VIR_FREE(data);
    break;

    case DATATYPE_IPV6ADDR:
        data = virSocketAddrFormat(&item->u.ipaddr);
        if (!data)
            return -1;

        if (snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("buffer too small for IPv6 address"));
            VIR_FREE(data);
            return -1;
        }
        VIR_FREE(data);
    break;

    case DATATYPE_MACADDR:
    case DATATYPE_MACMASK:
        if (bufsize < VIR_MAC_STRING_BUFLEN) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for MAC address"));
            return -1;
        }

        virMacAddrFormat(&item->u.macaddr, buf);
    break;

    case DATATYPE_IPV6MASK:
    case DATATYPE_IPMASK:
        if (snprintf(buf, bufsize, "%d",
                     item->u.u8) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint8 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT32:
    case DATATYPE_UINT32_HEX:
        if (snprintf(buf, bufsize, asHex ? "0x%x" : "%u",
                     item->u.u32) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint32 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT16:
    case DATATYPE_UINT16_HEX:
        if (snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                     item->u.u16) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint16 type"));
            return -1;
        }
    break;

    case DATATYPE_UINT8:
    case DATATYPE_UINT8_HEX:
        if (snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                     item->u.u8) >= bufsize) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for uint8 type"));
            return -1;
        }
    break;

    case DATATYPE_IPSETNAME:
        if (virStrcpy(buf, item->u.ipset.setname, bufsize) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer to small for ipset name"));
            return -1;
        }
    break;

    case DATATYPE_IPSETFLAGS:
        for (ctr = 0; ctr < item->u.ipset.numFlags; ctr++) {
            if (ctr != 0)
                virBufferAddLit(&vb, ",");
            if ((item->u.ipset.flags & (1 << ctr))) {
                if (directionIn)
                    virBufferAddLit(&vb, "dst");
                else
                    virBufferAddLit(&vb, "src");
            } else {
                if (directionIn)
                    virBufferAddLit(&vb, "src");
                else
                    virBufferAddLit(&vb, "dst");
            }
        }

        if (virBufferCheckError(&vb) < 0)
            return -1;

        flags = virBufferContentAndReset(&vb);

        if (virStrcpy(buf, flags, bufsize) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for IPSETFLAGS type"));
            VIR_FREE(flags);
            return -1;
        }
        VIR_FREE(flags);
    break;

    case DATATYPE_STRING:
    case DATATYPE_STRINGCOPY:
    case DATATYPE_BOOLEAN:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot print data type %x"), item->datatype);
        return -1;
    case DATATYPE_LAST:
    default:
        virReportEnumRangeError(virNWFilterAttrDataType, item->datatype);
        return -1;
    }

    return 0;
}


static int
printDataType(virNWFilterVarCombIterPtr vars,
              char *buf, int bufsize,
              nwItemDescPtr item)
{
    return _printDataType(vars, buf, bufsize, item, 0, 0);
}

static int
printDataTypeDirection(virNWFilterVarCombIterPtr vars,
                       char *buf, int bufsize,
                       nwItemDescPtr item, bool directionIn)
{
    return _printDataType(vars, buf, bufsize, item, 0, directionIn);
}

static int
printDataTypeAsHex(virNWFilterVarCombIterPtr vars,
                   char *buf, int bufsize,
                   nwItemDescPtr item)
{
    return _printDataType(vars, buf, bufsize, item, 1, 0);
}


static int
ebtablesHandleEthHdr(virFirewallPtr fw,
                     virFirewallRulePtr fwrule,
                     virNWFilterVarCombIterPtr vars,
                     ethHdrDataDefPtr ethHdr,
                     bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    char macmask[VIR_MAC_STRING_BUFLEN];
    int ret = -1;

    if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataSrcMACAddr) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  reverse ? "-d" : "-s",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(&ethHdr->dataSrcMACAddr))
            virFirewallRuleAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACMask)) {
            if (printDataType(vars,
                              macmask, sizeof(macmask),
                              &ethHdr->dataSrcMACMask) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", macaddr, macmask);
        } else {
            virFirewallRuleAddArg(fw, fwrule, macaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataDstMACAddr) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  reverse ? "-s" : "-d",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(&ethHdr->dataDstMACAddr))
            virFirewallRuleAddArg(fw, fwrule, "!");

        if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACMask)) {
            if (printDataType(vars,
                              macmask, sizeof(macmask),
                              &ethHdr->dataDstMACMask) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", macaddr, macmask);
        } else {
            virFirewallRuleAddArg(fw, fwrule, macaddr);
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


/************************ iptables support ************************/


static void
iptablesCreateBaseChainsFW(virFirewallPtr fw,
                           virFirewallLayer layer)
{
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-N", VIRT_IN_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-N", VIRT_OUT_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-N", VIRT_IN_POST_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-N", HOST_IN_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", "FORWARD", "-j", VIRT_IN_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", "FORWARD", "-j", VIRT_OUT_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", "FORWARD", "-j", VIRT_IN_POST_CHAIN, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", "INPUT", "-j", HOST_IN_CHAIN, NULL);
    virFirewallAddRule(fw, layer,
                       "-I", "FORWARD", "1", "-j", VIRT_IN_CHAIN, NULL);
    virFirewallAddRule(fw, layer,
                       "-I", "FORWARD", "2", "-j", VIRT_OUT_CHAIN, NULL);
    virFirewallAddRule(fw, layer,
                       "-I", "FORWARD", "3", "-j", VIRT_IN_POST_CHAIN, NULL);
    virFirewallAddRule(fw, layer,
                       "-I", "INPUT", "1", "-j", HOST_IN_CHAIN, NULL);
}


static void
iptablesCreateTmpRootChainFW(virFirewallPtr fw,
                             virFirewallLayer layer,
                             char prefix,
                             bool incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
       prefix,
       incoming ? CHAINPREFIX_HOST_IN_TEMP
                : CHAINPREFIX_HOST_OUT_TEMP
    };

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRule(fw, layer,
                       "-N", chain, NULL);
}


static void
iptablesCreateTmpRootChainsFW(virFirewallPtr fw,
                              virFirewallLayer layer,
                              const char *ifname)
{
    iptablesCreateTmpRootChainFW(fw, layer, 'F', false, ifname);
    iptablesCreateTmpRootChainFW(fw, layer, 'F', true, ifname);
    iptablesCreateTmpRootChainFW(fw, layer, 'H', true, ifname);
}


static void
_iptablesRemoveRootChainFW(virFirewallPtr fw,
                           virFirewallLayer layer,
                           char prefix,
                           bool incoming, const char *ifname,
                           int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
    };

    if (isTempChain)
        chainPrefix[1] = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix[1] = incoming ? CHAINPREFIX_HOST_IN
                                  : CHAINPREFIX_HOST_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-F", chain, NULL);
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-X", chain, NULL);
}


static void
iptablesRemoveRootChainFW(virFirewallPtr fw,
                          virFirewallLayer layer,
                          char prefix,
                          bool incoming,
                          const char *ifname)
{
    _iptablesRemoveRootChainFW(fw, layer, prefix, incoming, ifname, false);
}


static void
iptablesRemoveTmpRootChainFW(virFirewallPtr fw,
                             virFirewallLayer layer,
                             char prefix,
                             bool incoming,
                             const char *ifname)
{
    _iptablesRemoveRootChainFW(fw, layer, prefix,
                               incoming, ifname, 1);
}


static void
iptablesRemoveTmpRootChainsFW(virFirewallPtr fw,
                              virFirewallLayer layer,
                              const char *ifname)
{
    iptablesRemoveTmpRootChainFW(fw, layer, 'F', false, ifname);
    iptablesRemoveTmpRootChainFW(fw, layer, 'F', true, ifname);
    iptablesRemoveTmpRootChainFW(fw, layer, 'H', true, ifname);
}


static void
iptablesRemoveRootChainsFW(virFirewallPtr fw,
                           virFirewallLayer layer,
                           const char *ifname)
{
    iptablesRemoveRootChainFW(fw, layer, 'F', false, ifname);
    iptablesRemoveRootChainFW(fw, layer, 'F', true, ifname);
    iptablesRemoveRootChainFW(fw, layer, 'H', true, ifname);
}


static void
iptablesLinkTmpRootChainFW(virFirewallPtr fw,
                           virFirewallLayer layer,
                           const char *basechain,
                           char prefix,
                           bool incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
        incoming ? CHAINPREFIX_HOST_IN_TEMP
                 : CHAINPREFIX_HOST_OUT_TEMP
    };

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    if (incoming)
        virFirewallAddRule(fw, layer,
                           "-A", basechain,
                           MATCH_PHYSDEV_IN_FW,
                           ifname,
                           "-g", chain, NULL);
    else
        virFirewallAddRule(fw, layer,
                           "-A", basechain,
                           MATCH_PHYSDEV_OUT_FW,
                           ifname,
                           "-g", chain, NULL);
}


static void
iptablesLinkTmpRootChainsFW(virFirewallPtr fw,
                            virFirewallLayer layer,
                            const char *ifname)
{
    iptablesLinkTmpRootChainFW(fw, layer, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesLinkTmpRootChainFW(fw, layer, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesLinkTmpRootChainFW(fw, layer, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesSetupVirtInPostFW(virFirewallPtr fw G_GNUC_UNUSED,
                          virFirewallLayer layer G_GNUC_UNUSED,
                          const char *ifname G_GNUC_UNUSED)
{
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", VIRT_IN_POST_CHAIN,
                           MATCH_PHYSDEV_IN_FW,
                           ifname, "-j", "ACCEPT", NULL);
    virFirewallAddRule(fw, layer,
                       "-A", VIRT_IN_POST_CHAIN,
                       MATCH_PHYSDEV_IN_FW,
                       ifname, "-j", "ACCEPT", NULL);
}


static void
iptablesClearVirtInPostFW(virFirewallPtr fw,
                          virFirewallLayer layer,
                          const char *ifname)
{
    virFirewallAddRuleFull(fw, layer,
                           true, NULL, NULL,
                           "-D", VIRT_IN_POST_CHAIN,
                           MATCH_PHYSDEV_IN_FW,
                           ifname, "-j", "ACCEPT", NULL);
}


static void
_iptablesUnlinkRootChainFW(virFirewallPtr fw,
                           virFirewallLayer layer,
                           const char *basechain,
                           char prefix,
                           bool incoming, const char *ifname,
                           int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
    };
    if (isTempChain)
        chainPrefix[1] = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix[1] = incoming ? CHAINPREFIX_HOST_IN
                                  : CHAINPREFIX_HOST_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    if (incoming)
        virFirewallAddRuleFull(fw, layer,
                               true, NULL, NULL,
                               "-D", basechain,
                               MATCH_PHYSDEV_IN_FW, ifname,
                               "-g", chain,
                               NULL);
    else
        virFirewallAddRuleFull(fw, layer,
                               true, NULL, NULL,
                               "-D", basechain,
                               MATCH_PHYSDEV_OUT_FW, ifname,
                               "-g", chain,
                               NULL);

    /*
     * Previous versions of libvirt may have created a rule
     * with the --physdev-is-bridged missing. Remove this one
     * as well.
     */
    if (!incoming)
        virFirewallAddRuleFull(fw, layer,
                               true, NULL, NULL,
                               "-D", basechain,
                               MATCH_PHYSDEV_OUT_OLD_FW, ifname,
                               "-g", chain,
                               NULL);
}


static void
iptablesUnlinkRootChainFW(virFirewallPtr fw,
                          virFirewallLayer layer,
                          const char *basechain,
                          char prefix,
                          bool incoming, const char *ifname)
{
    _iptablesUnlinkRootChainFW(fw, layer,
                               basechain, prefix, incoming, ifname, false);
}


static void
iptablesUnlinkTmpRootChainFW(virFirewallPtr fw,
                             virFirewallLayer layer,
                             const char *basechain,
                             char prefix,
                             bool incoming, const char *ifname)
{
    _iptablesUnlinkRootChainFW(fw, layer,
                               basechain, prefix, incoming, ifname, 1);
}


static void
iptablesUnlinkRootChainsFW(virFirewallPtr fw,
                           virFirewallLayer layer,
                           const char *ifname)
{
    iptablesUnlinkRootChainFW(fw, layer, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesUnlinkRootChainFW(fw, layer, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesUnlinkRootChainFW(fw, layer, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesUnlinkTmpRootChainsFW(virFirewallPtr fw,
                              virFirewallLayer layer,
                              const char *ifname)
{
    iptablesUnlinkTmpRootChainFW(fw, layer, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesUnlinkTmpRootChainFW(fw, layer, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesUnlinkTmpRootChainFW(fw, layer, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesRenameTmpRootChainFW(virFirewallPtr fw,
                             virFirewallLayer layer,
                             char prefix,
                             bool incoming,
                             const char *ifname)
{
    char tmpchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char tmpChainPrefix[2] = {
        prefix,
        incoming ? CHAINPREFIX_HOST_IN_TEMP
                 : CHAINPREFIX_HOST_OUT_TEMP
    };
    char chainPrefix[2] = {
        prefix,
        incoming ? CHAINPREFIX_HOST_IN
                 : CHAINPREFIX_HOST_OUT
    };

    PRINT_IPT_ROOT_CHAIN(tmpchain, tmpChainPrefix, ifname);
    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRule(fw, layer,
                       "-E", tmpchain, chain, NULL);
}


static void
iptablesRenameTmpRootChainsFW(virFirewallPtr fw,
                              virFirewallLayer layer,
                              const char *ifname)
{
    iptablesRenameTmpRootChainFW(fw, layer, 'F', false, ifname);
    iptablesRenameTmpRootChainFW(fw, layer, 'F', true, ifname);
    iptablesRenameTmpRootChainFW(fw, layer, 'H', true, ifname);
}


static int
iptablesHandleSrcMacAddr(virFirewallPtr fw,
                         virFirewallRulePtr fwrule,
                         virNWFilterVarCombIterPtr vars,
                         nwItemDescPtr srcMacAddr,
                         bool directionIn,
                         bool *srcmacskipped)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    int ret = -1;

    *srcmacskipped = false;

    if (HAS_ENTRY_ITEM(srcMacAddr)) {
        if (directionIn) {
            *srcmacskipped = true;
            return 0;
        }

        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          srcMacAddr) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "mac",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(srcMacAddr))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArgList(fw, fwrule,
                                  "--mac-source",
                                  macaddr,
                                  NULL);
    }

    ret = 0;
 cleanup:
    return ret;
}


static int
iptablesHandleIPHdr(virFirewallPtr fw,
                    virFirewallRulePtr fwrule,
                    virNWFilterVarCombIterPtr vars,
                    ipHdrDataDefPtr ipHdr,
                    bool directionIn,
                    bool *skipRule, bool *skipMatch)
{
    char ipaddr[INET6_ADDRSTRLEN],
         ipaddralt[INET6_ADDRSTRLEN],
         number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))];
    const char *src = "--source";
    const char *dst = "--destination";
    const char *srcrange = "--src-range";
    const char *dstrange = "--dst-range";
    int ret = -1;

    if (directionIn) {
        src = "--destination";
        dst = "--source";
        srcrange = "--dst-range";
        dstrange = "--src-range";
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPAddr)) {
        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPAddr) < 0)
            goto cleanup;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataSrcIPAddr))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, src);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPMask)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataSrcIPMask) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", ipaddr, number);
        } else {
            virFirewallRuleAddArg(fw, fwrule, ipaddr);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPFrom)) {
        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPFrom) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "iprange",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataSrcIPFrom))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, srcrange);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPTo)) {

            if (printDataType(vars,
                              ipaddralt, sizeof(ipaddralt),
                              &ipHdr->dataSrcIPTo) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s-%s", ipaddr, ipaddralt);
        } else {
            virFirewallRuleAddArg(fw, fwrule, ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPAddr)) {
        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPAddr) < 0)
           goto cleanup;

        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDstIPAddr))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, dst);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPMask)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataDstIPMask) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", ipaddr, number);
        } else {
            virFirewallRuleAddArg(fw, fwrule, ipaddr);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPFrom)) {
        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPFrom) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "iprange",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDstIPFrom))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, dstrange);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPTo)) {
            if (printDataType(vars,
                              ipaddralt, sizeof(ipaddralt),
                              &ipHdr->dataDstIPTo) < 0)
                goto cleanup;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s-%s", ipaddr, ipaddralt);
        } else {
            virFirewallRuleAddArg(fw, fwrule, ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDSCP)) {
        if (printDataType(vars,
                          number, sizeof(number),
                          &ipHdr->dataDSCP) < 0)
           goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "dscp",
                                  NULL);
        if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataDSCP))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArgList(fw, fwrule,
                                  "--dscp", number,
                                  NULL);
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove)) {
        if (directionIn) {
            /* only support for limit in outgoing dir. */
            *skipRule = true;
        } else {
            *skipMatch = true;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


static int
iptablesHandleIPHdrAfterStateMatch(virFirewallPtr fw,
                                   virFirewallRulePtr fwrule,
                                   virNWFilterVarCombIterPtr vars,
                                   ipHdrDataDefPtr ipHdr,
                                   bool directionIn)
{
    char number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))];
    char str[MAX_IPSET_NAME_LENGTH];
    int ret = -1;

    if (HAS_ENTRY_ITEM(&ipHdr->dataIPSet) &&
        HAS_ENTRY_ITEM(&ipHdr->dataIPSetFlags)) {

        if (printDataType(vars,
                          str, sizeof(str),
                          &ipHdr->dataIPSet) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "set",
                                  "--match-set", str,
                                  NULL);

        if (printDataTypeDirection(vars,
                                   str, sizeof(str),
                                   &ipHdr->dataIPSetFlags, directionIn) < 0)
            goto cleanup;

        virFirewallRuleAddArg(fw, fwrule, str);
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove)) {
        if (!directionIn) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataConnlimitAbove) < 0)
               goto cleanup;

            /* place connlimit after potential -m state --state ...
               since this is the most useful order */
            virFirewallRuleAddArgList(fw, fwrule,
                                      "-m", "connlimit",
                                      NULL);
            if (ENTRY_WANT_NEG_SIGN(&ipHdr->dataConnlimitAbove))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArgList(fw, fwrule,
                                      "--connlimit-above", number,
                                      NULL);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataComment)) {
        /* keep comments behind everything else -- they are packet eval.
           no-ops */
        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "comment",
                                  "--comment", ipHdr->dataComment.u.string,
                                  NULL);
    }

    ret = 0;
 cleanup:
    return ret;
}


static int
iptablesHandlePortData(virFirewallPtr fw,
                       virFirewallRulePtr fwrule,
                       virNWFilterVarCombIterPtr vars,
                       portDataDefPtr portData,
                       bool directionIn)
{
    char portstr[20];
    char portstralt[20];
    const char *sport = "--sport";
    const char *dport = "--dport";
    if (directionIn) {
        sport = "--dport";
        dport = "--sport";
    }

    if (HAS_ENTRY_ITEM(&portData->dataSrcPortStart)) {
        if (printDataType(vars,
                          portstr, sizeof(portstr),
                          &portData->dataSrcPortStart) < 0)
            goto err_exit;

        if (ENTRY_WANT_NEG_SIGN(&portData->dataSrcPortStart))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, sport);

        if (HAS_ENTRY_ITEM(&portData->dataSrcPortEnd)) {
            if (printDataType(vars,
                              portstralt, sizeof(portstralt),
                              &portData->dataSrcPortEnd) < 0)
                goto err_exit;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s:%s", portstr, portstralt);
        } else {
            virFirewallRuleAddArg(fw, fwrule, portstr);
        }
    }

    if (HAS_ENTRY_ITEM(&portData->dataDstPortStart)) {
        if (printDataType(vars,
                          portstr, sizeof(portstr),
                          &portData->dataDstPortStart) < 0)
            goto err_exit;

        if (ENTRY_WANT_NEG_SIGN(&portData->dataDstPortStart))
            virFirewallRuleAddArg(fw, fwrule, "!");
        virFirewallRuleAddArg(fw, fwrule, dport);

        if (HAS_ENTRY_ITEM(&portData->dataDstPortEnd)) {
            if (printDataType(vars,
                              portstralt, sizeof(portstralt),
                              &portData->dataDstPortEnd) < 0)
                goto err_exit;

            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s:%s", portstr, portstralt);
        } else {
            virFirewallRuleAddArg(fw, fwrule, portstr);
        }
    }

    return 0;

 err_exit:
    return -1;
}


static void
iptablesEnforceDirection(virFirewallPtr fw,
                         virFirewallRulePtr fwrule,
                         bool directionIn,
                         virNWFilterRuleDefPtr rule)
{
    switch (iptables_ctdir_corrected) {
    case CTDIR_STATUS_UNKNOWN:
        /* could not be determined or s.th. is seriously wrong */
        return;
    case CTDIR_STATUS_CORRECTED:
        directionIn = !directionIn;
        break;
    case CTDIR_STATUS_OLD:
        break;
    }

    if (rule->tt != VIR_NWFILTER_RULE_DIRECTION_INOUT)
        virFirewallRuleAddArgList(fw, fwrule,
                                  "-m", "conntrack",
                                  "--ctdir",
                                  (directionIn ?
                                   "Original" :
                                   "Reply"),
                                  NULL);
}


/*
 * _iptablesCreateRuleInstance:
 * @fw: the firewall ruleset instance
 * @layer: the firewall layer
 * @chainPrefix : The prefix to put in front of the name of the chain
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @match : optional string for state match
 * @accept_target : where to jump to on accepted traffic, i.e., "RETURN"
 *    "ACCEPT"
 * @maySkipICMP : whether this rule may under certain circumstances skip
 *           the ICMP rule from being created
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, != 0 otherwise.
 */
static int
_iptablesCreateRuleInstance(virFirewallPtr fw,
                            virFirewallLayer layer,
                            bool directionIn,
                            const char *chainPrefix,
                            virNWFilterRuleDefPtr rule,
                            const char *ifname,
                            virNWFilterVarCombIterPtr vars,
                            const char *match, bool defMatch,
                            const char *accept_target,
                            bool maySkipICMP)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))];
    char numberalt[MAX(INT_BUFSIZE_BOUND(uint32_t),
                       INT_BUFSIZE_BOUND(int))];
    const char *target;
    bool srcMacSkipped = false;
    bool skipRule = false;
    bool skipMatch = false;
    bool hasICMPType = false;
    virFirewallRulePtr fwrule;
    size_t fwruleargs;
    int ret = -1;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "tcp",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.tcpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.tcpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPFlags)) {
            char *flags;
            if (ENTRY_WANT_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPFlags))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, "--tcp-flags");

            if (!(flags = virNWFilterPrintTCPFlags(rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.mask)))
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, flags);
            VIR_FREE(flags);
            if (!(flags = virNWFilterPrintTCPFlags(rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.flags)))
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, flags);
            VIR_FREE(flags);
        }

        if (iptablesHandlePortData(fw, fwrule,
                                   vars,
                                   &rule->p.tcpHdrFilter.portData,
                                   directionIn) < 0)
            goto cleanup;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPOption)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.tcpHdrFilter.dataTCPOption) < 0)
                goto cleanup;

            if (ENTRY_WANT_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPOption))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArgList(fw, fwrule,
                                      "--tcp-option", number, NULL);
        }

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "udp",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.udpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.udpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

        if (iptablesHandlePortData(fw, fwrule,
                                   vars,
                                   &rule->p.udpHdrFilter.portData,
                                   directionIn) < 0)
            goto cleanup;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "udplite",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.udpliteHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.udpliteHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "esp",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.espHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.espHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "ah",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.ahHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.ahHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "sctp",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.sctpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.sctpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

        if (iptablesHandlePortData(fw, fwrule,
                                   vars,
                                   &rule->p.sctpHdrFilter.portData,
                                   directionIn) < 0)
            goto cleanup;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    NULL);

        if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMP)
            virFirewallRuleAddArgList(fw, fwrule,
                                      "-p", "icmp", NULL);
        else
            virFirewallRuleAddArgList(fw, fwrule,
                                      "-p", "icmpv6", NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.icmpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.icmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

        if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPType)) {
            const char *parm;

            hasICMPType = true;

            if (maySkipICMP) {
                virFirewallRemoveRule(fw, fwrule);
                ret = 0;
                goto cleanup;
            }

            if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMP)
                parm = "--icmp-type";
            else
                parm = "--icmpv6-type";

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.icmpHdrFilter.dataICMPType) < 0)
                goto cleanup;

            if (ENTRY_WANT_NEG_SIGN(&rule->p.icmpHdrFilter.dataICMPType))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, parm);

            if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPCode)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.icmpHdrFilter.dataICMPCode) < 0)
                    goto cleanup;

                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s/%s", number, numberalt);
            } else {
                virFirewallRuleAddArg(fw, fwrule, number);
            }
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "igmp",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.igmpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.igmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        fwrule = virFirewallAddRule(fw, layer,
                                    "-A", chain,
                                    "-p", "all",
                                    NULL);

        fwruleargs = virFirewallRuleGetArgCount(fwrule);

        if (iptablesHandleSrcMacAddr(fw, fwrule,
                                     vars,
                                     &rule->p.allHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto cleanup;

        if (iptablesHandleIPHdr(fw, fwrule,
                                vars,
                                &rule->p.allHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch) < 0)
            goto cleanup;

    break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected protocol %d"),
                       rule->prtclType);
        goto cleanup;
    }

    if ((srcMacSkipped &&
         fwruleargs == virFirewallRuleGetArgCount(fwrule)) ||
        skipRule) {
        virFirewallRemoveRule(fw, fwrule);
        return 0;
    }

    if (rule->action == VIR_NWFILTER_RULE_ACTION_ACCEPT) {
        target = accept_target;
    } else {
        target = virNWFilterJumpTargetTypeToString(rule->action);
        skipMatch = defMatch;
    }

    if (match && !skipMatch) {
        if (newMatchState)
            virFirewallRuleAddArgList(fw, fwrule,
                                      "-m", "conntrack",
                                      "--ctstate", match,
                                      NULL);
        else
            virFirewallRuleAddArgList(fw, fwrule,
                                      "-m", "state",
                                      "--state", match,
                                      NULL);
    }

    if (defMatch && match != NULL && !skipMatch && !hasICMPType)
        iptablesEnforceDirection(fw, fwrule,
                                 directionIn,
                                 rule);

    if (iptablesHandleIPHdrAfterStateMatch(fw, fwrule,
                                           vars,
                                           &rule->p.allHdrFilter.ipHdr,
                                           directionIn) < 0)
        goto cleanup;

    virFirewallRuleAddArgList(fw, fwrule,
                              "-j", target, NULL);

    ret = 0;
 cleanup:
    return ret;
}


static int
printStateMatchFlags(int32_t flags, char **bufptr)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNWFilterPrintStateMatchFlags(&buf,
                                    "",
                                    flags,
                                    false);
    if (virBufferCheckError(&buf) < 0)
        return -1;
    *bufptr = virBufferContentAndReset(&buf);
    return 0;
}

static int
iptablesCreateRuleInstanceStateCtrl(virFirewallPtr fw,
                                    virFirewallLayer layer,
                                    virNWFilterRuleDefPtr rule,
                                    const char *ifname,
                                    virNWFilterVarCombIterPtr vars)
{
    int rc = 0;
    bool directionIn = false;
    char chainPrefix[2];
    bool maySkipICMP, inout = false;
    char *matchState = NULL;
    bool create;

    if ((rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN) ||
        (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT)) {
        directionIn = true;
        inout = (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT);
    }

    chainPrefix[0] = 'F';

    maySkipICMP = directionIn || inout;

    create = true;
    matchState = NULL;

    if (directionIn && !inout) {
        if ((rule->flags & IPTABLES_STATE_FLAGS))
            create = false;
    }

    if (create && (rule->flags & IPTABLES_STATE_FLAGS)) {
        if (printStateMatchFlags(rule->flags, &matchState) < 0)
            return -1;
    }

    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    if (create) {
        rc = _iptablesCreateRuleInstance(fw,
                                         layer,
                                         directionIn,
                                         chainPrefix,
                                         rule,
                                         ifname,
                                         vars,
                                         matchState, false,
                                         "RETURN",
                                         maySkipICMP);

        VIR_FREE(matchState);
        if (rc < 0)
            return rc;
    }

    maySkipICMP = !directionIn || inout;
    create = true;

    if (!directionIn) {
        if ((rule->flags & IPTABLES_STATE_FLAGS))
            create = false;
    }

    if (create && (rule->flags & IPTABLES_STATE_FLAGS)) {
        if (printStateMatchFlags(rule->flags, &matchState) < 0)
            return -1;
    }

    chainPrefix[1] = CHAINPREFIX_HOST_OUT_TEMP;
    if (create) {
        rc = _iptablesCreateRuleInstance(fw,
                                         layer,
                                         !directionIn,
                                         chainPrefix,
                                         rule,
                                         ifname,
                                         vars,
                                         matchState, false,
                                         "ACCEPT",
                                         maySkipICMP);

        VIR_FREE(matchState);

        if (rc < 0)
            return rc;
    }

    maySkipICMP = directionIn;

    create = true;

    if (directionIn && !inout) {
        if ((rule->flags & IPTABLES_STATE_FLAGS))
            create = false;
    } else {
        if ((rule->flags & IPTABLES_STATE_FLAGS)) {
            if (printStateMatchFlags(rule->flags, &matchState) < 0)
                return -1;
        }
    }

    if (create) {
        chainPrefix[0] = 'H';
        chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
        rc = _iptablesCreateRuleInstance(fw,
                                         layer,
                                         directionIn,
                                         chainPrefix,
                                         rule,
                                         ifname,
                                         vars,
                                         matchState, false,
                                         "RETURN",
                                         maySkipICMP);
        VIR_FREE(matchState);
    }

    return rc;
}


static int
iptablesCreateRuleInstance(virFirewallPtr fw,
                           virFirewallLayer layer,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterVarCombIterPtr vars)
{
    int rc;
    bool directionIn = false;
    char chainPrefix[2];
    bool needState = true;
    bool maySkipICMP, inout = false;
    const char *matchState;

    if (!(rule->flags & RULE_FLAG_NO_STATEMATCH) &&
         (rule->flags & IPTABLES_STATE_FLAGS)) {
        return iptablesCreateRuleInstanceStateCtrl(fw,
                                                   layer,
                                                   rule,
                                                   ifname,
                                                   vars);
    }

    if ((rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN) ||
        (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT)) {
        directionIn = true;
        inout = (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT);
        if (inout)
            needState = false;
    }

    if ((rule->flags & RULE_FLAG_NO_STATEMATCH))
        needState = false;

    chainPrefix[0] = 'F';

    maySkipICMP = directionIn || inout;

    if (needState)
        matchState = directionIn ? "ESTABLISHED" : "NEW,ESTABLISHED";
    else
        matchState = NULL;

    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    rc = _iptablesCreateRuleInstance(fw,
                                     layer,
                                     directionIn,
                                     chainPrefix,
                                     rule,
                                     ifname,
                                     vars,
                                     matchState, true,
                                     "RETURN",
                                     maySkipICMP);
    if (rc < 0)
        return rc;


    maySkipICMP = !directionIn || inout;
    if (needState)
        matchState = directionIn ?  "NEW,ESTABLISHED" : "ESTABLISHED";
    else
        matchState = NULL;

    chainPrefix[1] = CHAINPREFIX_HOST_OUT_TEMP;
    rc = _iptablesCreateRuleInstance(fw,
                                     layer,
                                     !directionIn,
                                     chainPrefix,
                                     rule,
                                     ifname,
                                     vars,
                                     matchState, true,
                                     "ACCEPT",
                                     maySkipICMP);
    if (rc < 0)
        return rc;

    maySkipICMP = directionIn;
    if (needState)
        matchState = directionIn ? "ESTABLISHED" : "NEW,ESTABLISHED";
    else
        matchState = NULL;

    chainPrefix[0] = 'H';
    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    rc = _iptablesCreateRuleInstance(fw,
                                     layer,
                                     directionIn,
                                     chainPrefix,
                                     rule,
                                     ifname,
                                     vars,
                                     matchState, true,
                                     "RETURN",
                                     maySkipICMP);

    return rc;
}




/*
 * ebtablesCreateRuleInstance:
 * @fw: the firewall ruleset to add to
 * @chainPrefix : The prefix to put in front of the name of the chain
 * @chainSuffix: The suffix to put on the end of the name of the chain
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @reverse : Whether to reverse src and dst attributes
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, != 0 otherwise.
 */
static int
ebtablesCreateRuleInstance(virFirewallPtr fw,
                           char chainPrefix,
                           const char *chainSuffix,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterVarCombIterPtr vars,
                           bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN],
         ipaddr[INET_ADDRSTRLEN],
         ipmask[INET_ADDRSTRLEN],
         ipv6addr[INET6_ADDRSTRLEN],
         number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))],
         numberalt[MAX(INT_BUFSIZE_BOUND(uint32_t),
                       INT_BUFSIZE_BOUND(int))],
         field[MAX(VIR_MAC_STRING_BUFLEN, INET6_ADDRSTRLEN)],
         fieldalt[MAX(VIR_MAC_STRING_BUFLEN, INET6_ADDRSTRLEN)];
    char chain[MAX_CHAINNAME_LENGTH];
    const char *target;
    bool hasMask = false;
    virFirewallRulePtr fwrule;
    int ret = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (STREQ(chainSuffix,
              virNWFilterChainSuffixTypeToString(
                  VIR_NWFILTER_CHAINSUFFIX_ROOT)))
        PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    else
        PRINT_CHAIN(chain, chainPrefix, ifname,
                    chainSuffix);

#define INST_ITEM(STRUCT, ITEM, CLI) \
        if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM)) { \
            if (printDataType(vars, \
                              field, sizeof(field), \
                              &rule->p.STRUCT.ITEM) < 0) \
                goto cleanup; \
            virFirewallRuleAddArg(fw, fwrule, CLI); \
            if (ENTRY_WANT_NEG_SIGN(&rule->p.STRUCT.ITEM)) \
                virFirewallRuleAddArg(fw, fwrule, "!"); \
            virFirewallRuleAddArg(fw, fwrule, field); \
        }

#define INST_ITEM_2PARMS(STRUCT, ITEM, ITEM_HI, CLI, SEP) \
        if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM)) { \
            if (printDataType(vars, \
                              field, sizeof(field), \
                              &rule->p.STRUCT.ITEM) < 0) \
                goto cleanup; \
            virFirewallRuleAddArg(fw, fwrule, CLI); \
            if (ENTRY_WANT_NEG_SIGN(&rule->p.STRUCT.ITEM)) \
                virFirewallRuleAddArg(fw, fwrule, "!"); \
            if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM_HI)) { \
                if (printDataType(vars, \
                                  fieldalt, sizeof(fieldalt), \
                                  &rule->p.STRUCT.ITEM_HI) < 0) \
                    goto cleanup; \
                virFirewallRuleAddArgFormat(fw, fwrule, \
                                            "%s%s%s", field, SEP, fieldalt); \
            } else  { \
                virFirewallRuleAddArg(fw, fwrule, field); \
            } \
        }
#define INST_ITEM_RANGE(S, I, I_HI, C) \
    INST_ITEM_2PARMS(S, I, I_HI, C, ":")
#define INST_ITEM_MASK(S, I, MASK, C) \
    INST_ITEM_2PARMS(S, I, MASK, C, "/")

    switch ((int)rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat",
                                    "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ethHdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        if (HAS_ENTRY_ITEM(&rule->p.ethHdrFilter.dataProtocolID)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ethHdrFilter.dataProtocolID) < 0)
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, "-p");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ethHdrFilter.dataProtocolID))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.vlanHdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-p", "0x8100", NULL);

        INST_ITEM(vlanHdrFilter, dataVlanID, "--vlan-id")
        INST_ITEM(vlanHdrFilter, dataVlanEncap, "--vlan-encap")
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_STP:
        /* cannot handle inout direction with srcmask set in reverse dir.
           since this clashes with -d below... */
        if (reverse &&
            HAS_ENTRY_ITEM(&rule->p.stpHdrFilter.ethHdr.dataSrcMACAddr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("STP filtering in %s direction with "
                             "source MAC address set is not supported"),
                           virNWFilterRuleDirectionTypeToString(
                               VIR_NWFILTER_RULE_DIRECTION_INOUT));
            return -1;
        }

        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.stpHdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-d",  NWFILTER_MAC_BGA, NULL);

        INST_ITEM(stpHdrFilter, dataType, "--stp-type")
        INST_ITEM(stpHdrFilter, dataFlags, "--stp-flags")
        INST_ITEM_RANGE(stpHdrFilter, dataRootPri, dataRootPriHi,
                        "--stp-root-pri");
        INST_ITEM_MASK(stpHdrFilter, dataRootAddr, dataRootAddrMask,
                       "--stp-root-addr");
        INST_ITEM_RANGE(stpHdrFilter, dataRootCost, dataRootCostHi,
                        "--stp-root-cost");
        INST_ITEM_RANGE(stpHdrFilter, dataSndrPrio, dataSndrPrioHi,
                        "--stp-sender-prio");
        INST_ITEM_MASK(stpHdrFilter, dataSndrAddr, dataSndrAddrMask,
                       "--stp-sender-addr");
        INST_ITEM_RANGE(stpHdrFilter, dataPort, dataPortHi, "--stp-port");
        INST_ITEM_RANGE(stpHdrFilter, dataAge, dataAgeHi, "--stp-msg-age");
        INST_ITEM_RANGE(stpHdrFilter, dataMaxAge, dataMaxAgeHi,
                        "--stp-max-age");
        INST_ITEM_RANGE(stpHdrFilter, dataHelloTime, dataHelloTimeHi,
                        "--stp-hello-time");
        INST_ITEM_RANGE(stpHdrFilter, dataFwdDelay, dataFwdDelayHi,
                        "--stp-forward-delay");
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
    case VIR_NWFILTER_RULE_PROTOCOL_RARP:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.arpHdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        virFirewallRuleAddArg(fw, fwrule, "-p");
        virFirewallRuleAddArgFormat(fw, fwrule, "0x%x",
                                    (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ARP)
                                    ? l3_protocols[L3_PROTO_ARP_IDX].attr
                                    : l3_protocols[L3_PROTO_RARP_IDX].attr);

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataHWType)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.arpHdrFilter.dataHWType) < 0)
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, "--arp-htype");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataHWType))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataOpcode)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.arpHdrFilter.dataOpcode) < 0)
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, "--arp-opcode");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataOpcode))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataProtocolType)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.arpHdrFilter.dataProtocolType) < 0)
                goto cleanup;
            virFirewallRuleAddArg(fw, fwrule, "--arp-ptype");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataProtocolType))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPSrcIPAddr) < 0)
                goto cleanup;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPMask)) {
                if (printDataType(vars,
                                  ipmask, sizeof(ipmask),
                                  &rule->p.arpHdrFilter.dataARPSrcIPMask) < 0)
                    goto cleanup;
                hasMask = true;
            }

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--arp-ip-dst" : "--arp-ip-src");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", ipaddr, hasMask ? ipmask : "32");
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPDstIPAddr) < 0)
                goto cleanup;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPMask)) {
                if (printDataType(vars,
                                  ipmask, sizeof(ipmask),
                                  &rule->p.arpHdrFilter.dataARPDstIPMask) < 0)
                    goto cleanup;
                hasMask = true;
            }

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--arp-ip-src" : "--arp-ip-dst");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArgFormat(fw, fwrule,
                                        "%s/%s", ipaddr, hasMask ? ipmask : "32");
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPSrcMACAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--arp-mac-dst" : "--arp-mac-src");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcMACAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, macaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPDstMACAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--arp-mac-src" : "--arp-mac-dst");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstMACAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, macaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataGratuitousARP) &&
            rule->p.arpHdrFilter.dataGratuitousARP.u.boolean) {
            if (ENTRY_WANT_NEG_SIGN(&rule->p.arpHdrFilter.dataGratuitousARP))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, "--arp-gratuitous");
        }
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ipHdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-p", "ipv4", NULL);

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip-destination" : "--ip-source");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataSrcIPMask) < 0)
                    goto cleanup;
                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s/%s", ipaddr, number);
            } else {
                virFirewallRuleAddArg(fw, fwrule, ipaddr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataDstIPAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip-source" : "--ip-destination");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataDstIPMask) < 0)
                    goto cleanup;
                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s/%s", ipaddr, number);
            } else {
                virFirewallRuleAddArg(fw, fwrule, ipaddr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.ipHdr.dataProtocolID) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule, "--ip-protocol");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataProtocolID))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortStart)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataSrcPortStart) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip-destination-port" : "--ip-source-port");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataSrcPortStart))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipHdrFilter.portData.dataSrcPortEnd) < 0)
                    goto cleanup;

                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s:%s", number, numberalt);
            } else {
                virFirewallRuleAddArg(fw, fwrule, number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortStart)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataDstPortStart) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip-source-port" : "--ip-destination-port");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataDstPortStart))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipHdrFilter.portData.dataDstPortEnd) < 0)
                    goto cleanup;

                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s:%s", number, numberalt);
            } else {
                virFirewallRuleAddArg(fw, fwrule, number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDSCP)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ipHdrFilter.ipHdr.dataDSCP) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule, "--ip-tos");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDSCP))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);

        if (ebtablesHandleEthHdr(fw, fwrule,
                                 vars,
                                 &rule->p.ipv6HdrFilter.ethHdr,
                                 reverse) < 0)
            goto cleanup;

        virFirewallRuleAddArgList(fw, fwrule,
                                  "-p", "ipv6", NULL);

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip6-destination" : "--ip6-source");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask) < 0)
                    goto cleanup;
                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s/%s", ipv6addr, number);
            } else {
                virFirewallRuleAddArg(fw, fwrule, ipv6addr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip6-source" : "--ip6-destination");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask) < 0)
                    goto cleanup;
                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s/%s", ipv6addr, number);
            } else {
                virFirewallRuleAddArg(fw, fwrule, ipv6addr);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.ipHdr.dataProtocolID) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule, "--ip6-protocol");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID))
                virFirewallRuleAddArg(fw, fwrule, "!");
            virFirewallRuleAddArg(fw, fwrule, number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataSrcPortStart) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip6-destination-port" : "--ip6-source-port");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipv6HdrFilter.portData.dataSrcPortEnd) < 0)
                    goto cleanup;

                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s:%s", number, numberalt);
            } else {
                virFirewallRuleAddArg(fw, fwrule, number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataDstPortStart) < 0)
                goto cleanup;

            virFirewallRuleAddArg(fw, fwrule,
                                  reverse ? "--ip6-source-port" : "--ip6-destination-port");
            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataDstPortStart))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipv6HdrFilter.portData.dataDstPortEnd) < 0)
                    goto cleanup;

                virFirewallRuleAddArgFormat(fw, fwrule,
                                            "%s:%s", number, numberalt);
            } else {
                virFirewallRuleAddArg(fw, fwrule, number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPTypeStart)  ||
            HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPTypeEnd) ||
            HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPCodeStart) ||
            HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPCodeEnd)) {
            bool lo = false;
            char *r;

            virFirewallRuleAddArg(fw, fwrule,
                                  "--ip6-icmp-type");

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPTypeStart)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.dataICMPTypeStart) < 0)
                    goto cleanup;
                lo = true;
            } else {
                ignore_value(virStrcpyStatic(number, "0"));
            }

            virBufferStrcat(&buf, number, ":", NULL);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPTypeEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipv6HdrFilter.dataICMPTypeEnd) < 0)
                    goto cleanup;
            } else {
                if (lo)
                    ignore_value(virStrcpyStatic(numberalt, number));
                else
                    ignore_value(virStrcpyStatic(numberalt, "255"));
            }

            virBufferStrcat(&buf, numberalt, "/", NULL);

            lo = false;

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPCodeStart)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.dataICMPCodeStart) < 0)
                    goto cleanup;
                lo = true;
            } else {
                ignore_value(virStrcpyStatic(number, "0"));
            }

            virBufferStrcat(&buf, number, ":", NULL);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.dataICMPCodeEnd)) {
                if (printDataType(vars,
                                  numberalt, sizeof(numberalt),
                                  &rule->p.ipv6HdrFilter.dataICMPCodeEnd) < 0)
                    goto cleanup;
            } else {
                if (lo)
                    ignore_value(virStrcpyStatic(numberalt, number));
                else
                    ignore_value(virStrcpyStatic(numberalt, "255"));
            }

            virBufferStrcat(&buf, numberalt, NULL);

            if (ENTRY_WANT_NEG_SIGN(&rule->p.ipv6HdrFilter.dataICMPTypeStart))
                virFirewallRuleAddArg(fw, fwrule, "!");

            if (virBufferCheckError(&buf) < 0)
                 goto cleanup;

            r = virBufferContentAndReset(&buf);

            virFirewallRuleAddArg(fw, fwrule, r);

            VIR_FREE(r);
        }
        break;

    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
        fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                    "-t", "nat", "-A", chain, NULL);
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected rule protocol %d"),
                       rule->prtclType);
        return -1;
    }

    switch (rule->action) {
    case VIR_NWFILTER_RULE_ACTION_REJECT:
        /* REJECT not supported */
        target = virNWFilterJumpTargetTypeToString(
                                     VIR_NWFILTER_RULE_ACTION_DROP);
        break;
    default:
        target = virNWFilterJumpTargetTypeToString(rule->action);
    }

    virFirewallRuleAddArgList(fw, fwrule,
                              "-j", target, NULL);

#undef INST_ITEM_RANGE
#undef INST_ITEM_MASK
#undef INST_ITEM_2PARMS
#undef INST_ITEM

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&buf);

    return ret;
}


/*
 * ebiptablesCreateRuleInstance:
 * @chainPriority : The priority of the chain
 * @chainSuffix: The suffix to put on the end of the name of the chain
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
ebiptablesCreateRuleInstance(virFirewallPtr fw,
                             const char *chainSuffix,
                             virNWFilterRuleDefPtr rule,
                             const char *ifname,
                             virNWFilterVarCombIterPtr vars)
{
    int ret = -1;

    if (virNWFilterRuleIsProtocolEthernet(rule)) {
        if (rule->tt == VIR_NWFILTER_RULE_DIRECTION_OUT ||
            rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            if (ebtablesCreateRuleInstance(fw,
                                           CHAINPREFIX_HOST_IN_TEMP,
                                           chainSuffix,
                                           rule,
                                           ifname,
                                           vars,
                                           rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) < 0)
                goto cleanup;
        }

        if (rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN ||
            rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            if (ebtablesCreateRuleInstance(fw,
                                           CHAINPREFIX_HOST_OUT_TEMP,
                                           chainSuffix,
                                           rule,
                                           ifname,
                                           vars,
                                           false) < 0)
                goto cleanup;
        }
    } else {
        virFirewallLayer layer;
        if (virNWFilterRuleIsProtocolIPv6(rule)) {
            layer = VIR_FIREWALL_LAYER_IPV6;
        } else if (virNWFilterRuleIsProtocolIPv4(rule)) {
            layer = VIR_FIREWALL_LAYER_IPV4;
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           "%s", _("unexpected protocol type"));
            goto cleanup;
        }

        if (iptablesCreateRuleInstance(fw,
                                       layer,
                                       rule,
                                       ifname,
                                       vars) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


static void
ebtablesCreateTmpRootChainFW(virFirewallPtr fw,
                             int incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-N", chain, NULL);
}


static void
ebtablesLinkTmpRootChainFW(virFirewallPtr fw,
                           int incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A",
                       incoming ? EBTABLES_CHAIN_INCOMING : EBTABLES_CHAIN_OUTGOING,
                       incoming ? "-i" : "-o",
                       ifname, "-j", chain, NULL);
}


static void
_ebtablesRemoveRootChainFW(virFirewallPtr fw,
                           bool incoming, const char *ifname,
                           int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix;
    if (isTempChain)
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                               : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN
                               : CHAINPREFIX_HOST_OUT;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                           true, NULL, NULL,
                           "-t", "nat", "-F", chain, NULL);
    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                           true, NULL, NULL,
                           "-t", "nat", "-X", chain, NULL);
}


static void
ebtablesRemoveRootChainFW(virFirewallPtr fw,
                          bool incoming, const char *ifname)
{
    _ebtablesRemoveRootChainFW(fw, incoming, ifname, false);
}


static void
ebtablesRemoveTmpRootChainFW(virFirewallPtr fw,
                             bool incoming, const char *ifname)
{
    _ebtablesRemoveRootChainFW(fw, incoming, ifname, 1);
}


static void
_ebtablesUnlinkRootChainFW(virFirewallPtr fw,
                           bool incoming, const char *ifname,
                           int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix;

    if (isTempChain) {
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                               : CHAINPREFIX_HOST_OUT_TEMP;
    } else {
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN
                               : CHAINPREFIX_HOST_OUT;
    }

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                           true, NULL, NULL,
                           "-t", "nat", "-D",
                           incoming ? EBTABLES_CHAIN_INCOMING : EBTABLES_CHAIN_OUTGOING,
                           incoming ? "-i" : "-o",
                           ifname, "-j", chain, NULL);
}


static void
ebtablesUnlinkRootChainFW(virFirewallPtr fw,
                          bool incoming, const char *ifname)
{
    _ebtablesUnlinkRootChainFW(fw, incoming, ifname, false);
}


static void
ebtablesUnlinkTmpRootChainFW(virFirewallPtr fw,
                             int incoming, const char *ifname)
{
    _ebtablesUnlinkRootChainFW(fw, incoming, ifname, 1);
}

static void
ebtablesCreateTmpSubChainFW(virFirewallPtr fw,
                            bool incoming,
                            const char *ifname,
                            enum l3_proto_idx protoidx,
                            const char *filtername)
{
    char rootchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;
    virFirewallRulePtr fwrule;

    PRINT_ROOT_CHAIN(rootchain, chainPrefix, ifname);
    PRINT_CHAIN(chain, chainPrefix, ifname,
                (filtername) ? filtername : l3_protocols[protoidx].val);

    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                           true, NULL, NULL,
                           "-t", "nat", "-F", chain, NULL);
    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                           true, NULL, NULL,
                           "-t", "nat", "-X", chain, NULL);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-N", chain, NULL);

    fwrule = virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                "-t", "nat", "-A", rootchain, NULL);

    switch ((int)protoidx) {
    case L2_PROTO_MAC_IDX:
        break;
    case L2_PROTO_STP_IDX:
        virFirewallRuleAddArgList(fw, fwrule,
                                  "-d", NWFILTER_MAC_BGA, NULL);
        break;
    default:
        virFirewallRuleAddArg(fw, fwrule, "-p");
        virFirewallRuleAddArgFormat(fw, fwrule,
                                    "0x%04x",
                                    l3_protocols[protoidx].attr);
        break;
    }

    virFirewallRuleAddArgList(fw, fwrule,
                              "-j", chain, NULL);
}


static int
ebtablesRemoveSubChainsQuery(virFirewallPtr fw,
                             virFirewallLayer layer,
                             const char *const *lines,
                             void *opaque)
{
    size_t i, j;
    const char *chainprefixes = opaque;

    for (i = 0; lines[i] != NULL; i++) {
        VIR_DEBUG("Considering '%s'", lines[i]);
        char *tmp = strstr(lines[i], "-j ");
        if (!tmp)
            continue;
        tmp = tmp + 3;
        for (j = 0; chainprefixes[j]; j++) {
            if (tmp[0] == chainprefixes[j] &&
                tmp[1] == '-') {
                VIR_DEBUG("Processing chain '%s'", tmp);
                virFirewallAddRuleFull(fw, layer,
                                       false, ebtablesRemoveSubChainsQuery,
                                       (void *)chainprefixes,
                                        "-t", "nat", "-L", tmp, NULL);
                virFirewallAddRuleFull(fw, layer,
                                       true, NULL, NULL,
                                       "-t", "nat", "-F", tmp, NULL);
                virFirewallAddRuleFull(fw, layer,
                                       true, NULL, NULL,
                                       "-t", "nat", "-X", tmp, NULL);
            }
        }
    }

    return 0;
}


static void
_ebtablesRemoveSubChainsFW(virFirewallPtr fw,
                           const char *ifname,
                           const char *chainprefixes)
{
    char rootchain[MAX_CHAINNAME_LENGTH];
    size_t i;

    for (i = 0; chainprefixes[i] != 0; i++) {
        PRINT_ROOT_CHAIN(rootchain, chainprefixes[i], ifname);
        virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                               false, ebtablesRemoveSubChainsQuery,
                               (void *)chainprefixes,
                               "-t", "nat", "-L", rootchain, NULL);
    }
}

static void
ebtablesRemoveSubChainsFW(virFirewallPtr fw,
                          const char *ifname)
{
    _ebtablesRemoveSubChainsFW(fw, ifname, chainprefixes_host);
}


static void
ebtablesRemoveTmpSubChainsFW(virFirewallPtr fw,
                             const char *ifname)
{
    _ebtablesRemoveSubChainsFW(fw, ifname, chainprefixes_host_temp);
}

static void
ebtablesRenameTmpSubChainFW(virFirewallPtr fw,
                            int incoming,
                            const char *ifname,
                            const char *protocol)
{
    char tmpchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char tmpChainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                     : CHAINPREFIX_HOST_OUT_TEMP;
    char chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN
                                  : CHAINPREFIX_HOST_OUT;

    if (protocol) {
        PRINT_CHAIN(tmpchain, tmpChainPrefix, ifname, protocol);
        PRINT_CHAIN(chain, chainPrefix, ifname, protocol);
    } else {
        PRINT_ROOT_CHAIN(tmpchain, tmpChainPrefix, ifname);
        PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    }

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-E", tmpchain, chain, NULL);
}

static void
ebtablesRenameTmpRootChainFW(virFirewallPtr fw,
                             bool incoming,
                             const char *ifname)
{
    ebtablesRenameTmpSubChainFW(fw, incoming, ifname, NULL);
}


static int
ebtablesRenameTmpSubAndRootChainsQuery(virFirewallPtr fw,
                                       virFirewallLayer layer,
                                       const char *const *lines,
                                       void *opaque G_GNUC_UNUSED)
{
    size_t i;
    char newchain[MAX_CHAINNAME_LENGTH];

    for (i = 0; lines[i] != NULL; i++) {
        VIR_DEBUG("Considering '%s'", lines[i]);
        char *tmp = strstr(lines[i], "-j ");
        if (!tmp)
            continue;
        tmp = tmp + 3;
        if (tmp[0] != CHAINPREFIX_HOST_IN_TEMP &&
            tmp[0] != CHAINPREFIX_HOST_OUT_TEMP)
            continue;
        if (tmp[1] != '-')
            continue;

        ignore_value(virStrcpyStatic(newchain, tmp));
        if (newchain[0] == CHAINPREFIX_HOST_IN_TEMP)
            newchain[0] = CHAINPREFIX_HOST_IN;
        else
            newchain[0] = CHAINPREFIX_HOST_OUT;
        VIR_DEBUG("Renaming chain '%s' to '%s'", tmp, newchain);
        virFirewallAddRuleFull(fw, layer,
                               false, ebtablesRenameTmpSubAndRootChainsQuery,
                               NULL,
                               "-t", "nat", "-L", tmp, NULL);
        virFirewallAddRuleFull(fw, layer,
                               true, NULL, NULL,
                               "-t", "nat", "-F", newchain, NULL);
        virFirewallAddRuleFull(fw, layer,
                               true, NULL, NULL,
                               "-t", "nat", "-X", newchain, NULL);
        virFirewallAddRule(fw, layer,
                           "-t", "nat", "-E", tmp, newchain, NULL);
    }

    return 0;
}


static void
ebtablesRenameTmpSubAndRootChainsFW(virFirewallPtr fw,
                                    const char *ifname)
{
    char rootchain[MAX_CHAINNAME_LENGTH];
    size_t i;
    char chains[3] = {
        CHAINPREFIX_HOST_IN_TEMP,
        CHAINPREFIX_HOST_OUT_TEMP,
        0
    };
    for (i = 0; chains[i] != 0; i++) {
        PRINT_ROOT_CHAIN(rootchain, chains[i], ifname);
        virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_ETHERNET,
                               false, ebtablesRenameTmpSubAndRootChainsQuery,
                               NULL,
                               "-t", "nat", "-L", rootchain, NULL);
    }

    ebtablesRenameTmpRootChainFW(fw, true, ifname);
    ebtablesRenameTmpRootChainFW(fw, false, ifname);
}


/**
 * ebiptablesCanApplyBasicRules
 *
 * Determine whether this driver can apply the basic rules, meaning
 * run ebtablesApplyBasicRules and ebtablesApplyDHCPOnlyRules.
 * In case of this driver we need the ebtables tool available.
 */
static int
ebiptablesCanApplyBasicRules(void)
{
    return true;
}

/**
 * ebtablesApplyBasicRules
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
ebtablesApplyBasicRules(const char *ifname,
                        const virMacAddr *macaddr)
{
    virFirewallPtr fw = virFirewallNew();
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = CHAINPREFIX_HOST_IN_TEMP;
    char macaddr_str[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(macaddr, macaddr_str);

    if (ebiptablesAllTeardown(ifname) < 0)
        goto error;

    virFirewallStartTransaction(fw, 0);

    ebtablesCreateTmpRootChainFW(fw, true, ifname);

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain,
                       "-s", "!", macaddr_str,
                       "-j", "DROP", NULL);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain,
                       "-p", "IPv4",
                       "-j", "ACCEPT", NULL);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain,
                       "-p", "ARP",
                       "-j", "ACCEPT", NULL);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain,
                       "-j", "DROP", NULL);

    ebtablesLinkTmpRootChainFW(fw, true, ifname);
    ebtablesRenameTmpRootChainFW(fw, true, ifname);

    if (virFirewallApply(fw) < 0)
        goto tear_down_tmpebchains;

    virFirewallFree(fw);
    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);
 error:
    virFirewallFree(fw);
    return -1;
}


/**
 * ebtablesApplyDHCPOnlyRules
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
ebtablesApplyDHCPOnlyRules(const char *ifname,
                           const virMacAddr *macaddr,
                           virNWFilterVarValuePtr dhcpsrvrs,
                           bool leaveTemporary)
{
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];
    char macaddr_str[VIR_MAC_STRING_BUFLEN];
    unsigned int idx = 0;
    unsigned int num_dhcpsrvrs;
    virFirewallPtr fw = virFirewallNew();

    virMacAddrFormat(macaddr, macaddr_str);

    if (ebiptablesAllTeardown(ifname) < 0)
        goto error;

    virFirewallStartTransaction(fw, 0);

    ebtablesCreateTmpRootChainFW(fw, true, ifname);
    ebtablesCreateTmpRootChainFW(fw, false, ifname);

    PRINT_ROOT_CHAIN(chain_in, CHAINPREFIX_HOST_IN_TEMP, ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain_in,
                       "-s", macaddr_str,
                       "-p", "ipv4", "--ip-protocol", "udp",
                       "--ip-sport", "68", "--ip-dport", "67",
                       "-j", "ACCEPT", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain_in,
                       "-j", "DROP", NULL);

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
                virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                   "-t", "nat", "-A", chain_out,
                                   "-d", (ctr == 0) ? macaddr_str : "ff:ff:ff:ff:ff:ff",
                                   "-p", "ipv4", "--ip-protocol", "udp",
                                   "--ip-src", dhcpserver,
                                   "--ip-sport", "67", "--ip-dport", "68",
                                   "-j", "ACCEPT", NULL);
            else
                virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                                   "-t", "nat", "-A", chain_out,
                                   "-d", (ctr == 0) ? macaddr_str : "ff:ff:ff:ff:ff:ff",
                                   "-p", "ipv4", "--ip-protocol", "udp",
                                   "--ip-sport", "67", "--ip-dport", "68",
                                   "-j", "ACCEPT", NULL);
        }

        idx++;

        if (idx >= num_dhcpsrvrs)
            break;
    }

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain_out,
                       "-j", "DROP", NULL);

    ebtablesLinkTmpRootChainFW(fw, true, ifname);
    ebtablesLinkTmpRootChainFW(fw, false, ifname);

    if (!leaveTemporary) {
        ebtablesRenameTmpRootChainFW(fw, true, ifname);
        ebtablesRenameTmpRootChainFW(fw, false, ifname);
    }

    if (virFirewallApply(fw) < 0)
        goto tear_down_tmpebchains;

    virFirewallFree(fw);

    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);
 error:
    virFirewallFree(fw);
    return -1;
}


/**
 * ebtablesApplyDropAllRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 *
 * Returns 0 on success, -1 on failure with the rules removed
 *
 * Apply filtering rules so that the VM cannot receive or send traffic.
 */
static int
ebtablesApplyDropAllRules(const char *ifname)
{
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];
    virFirewallPtr fw = virFirewallNew();

    if (ebiptablesAllTeardown(ifname) < 0)
        goto error;

    virFirewallStartTransaction(fw, 0);

    ebtablesCreateTmpRootChainFW(fw, true, ifname);
    ebtablesCreateTmpRootChainFW(fw, false, ifname);

    PRINT_ROOT_CHAIN(chain_in, CHAINPREFIX_HOST_IN_TEMP, ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain_in,
                       "-j", "DROP", NULL);

    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-t", "nat", "-A", chain_out,
                       "-j", "DROP", NULL);

    ebtablesLinkTmpRootChainFW(fw, true, ifname);
    ebtablesLinkTmpRootChainFW(fw, false, ifname);
    ebtablesRenameTmpRootChainFW(fw, true, ifname);
    ebtablesRenameTmpRootChainFW(fw, false, ifname);

    if (virFirewallApply(fw) < 0)
        goto tear_down_tmpebchains;

    virFirewallFree(fw);
    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);
 error:
    virFirewallFree(fw);
    return -1;
}


static int
ebtablesRemoveBasicRules(const char *ifname)
{
    return ebtablesCleanAll(ifname);
}


static int
ebtablesCleanAll(const char *ifname)
{
    virFirewallPtr fw = virFirewallNew();
    int ret = -1;

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    ebtablesUnlinkRootChainFW(fw, true, ifname);
    ebtablesUnlinkRootChainFW(fw, false, ifname);
    ebtablesRemoveSubChainsFW(fw, ifname);
    ebtablesRemoveRootChainFW(fw, true, ifname);
    ebtablesRemoveRootChainFW(fw, false, ifname);

    ebtablesUnlinkTmpRootChainFW(fw, true, ifname);
    ebtablesUnlinkTmpRootChainFW(fw, false, ifname);
    ebtablesRemoveTmpSubChainsFW(fw, ifname);
    ebtablesRemoveTmpRootChainFW(fw, true, ifname);
    ebtablesRemoveTmpRootChainFW(fw, false, ifname);

    ret = virFirewallApply(fw);
    virFirewallFree(fw);
    return ret;
}


static int
virNWFilterRuleInstSort(const void *a, const void *b)
{
    const virNWFilterRuleInst *insta = a;
    const virNWFilterRuleInst *instb = b;
    const char *root = virNWFilterChainSuffixTypeToString(
                                     VIR_NWFILTER_CHAINSUFFIX_ROOT);
    bool root_a = STREQ(insta->chainSuffix, root);
    bool root_b = STREQ(instb->chainSuffix, root);

    /* ensure root chain commands appear before all others since
       we will need them to create the child chains */
    if (root_a) {
        if (root_b)
            goto normal;
        return -1; /* a before b */
    }
    if (root_b)
        return 1; /* b before a */
 normal:
    /* priorities are limited to range [-1000, 1000] */
    return insta->priority - instb->priority;
}


static int
virNWFilterRuleInstSortPtr(const void *a, const void *b)
{
    virNWFilterRuleInst * const *insta = a;
    virNWFilterRuleInst * const *instb = b;
    return virNWFilterRuleInstSort(*insta, *instb);
}


static int
ebiptablesFilterOrderSort(const virHashKeyValuePair *a,
                          const virHashKeyValuePair *b)
{
    /* elements' values has been limited to range [-1000, 1000] */
    return *(virNWFilterChainPriority *)a->value -
           *(virNWFilterChainPriority *)b->value;
}


static void
iptablesCheckBridgeNFCallEnabled(bool isIPv6)
{
    static time_t lastReport, lastReportIPv6;
    const char *pathname = NULL;
    char buffer[1];
    time_t now = time(NULL);

    if (isIPv6 &&
        (now - lastReportIPv6) > BRIDGE_NF_CALL_ALERT_INTERVAL) {
        pathname = PROC_BRIDGE_NF_CALL_IP6TABLES;
    } else if (now - lastReport > BRIDGE_NF_CALL_ALERT_INTERVAL) {
        pathname = PROC_BRIDGE_NF_CALL_IPTABLES;
    }

    if (pathname) {
        int fd = open(pathname, O_RDONLY);
        if (fd >= 0) {
            if (read(fd, buffer, 1) == 1) {
                if (buffer[0] == '0') {
                    char msg[256];
                    snprintf(msg, sizeof(msg),
                             _("To enable ip%stables filtering for the VM do "
                              "'echo 1 > %s'"),
                             isIPv6 ? "6" : "",
                             pathname);
                    VIR_WARN("%s", msg);
                    if (isIPv6)
                        lastReportIPv6 = now;
                    else
                        lastReport = now;
                }
            }
            VIR_FORCE_CLOSE(fd);
        }
    }
}

/*
 * Given a filtername determine the protocol it is used for evaluating
 * We do prefix-matching to determine the protocol.
 */
static enum l3_proto_idx
ebtablesGetProtoIdxByFiltername(const char *filtername)
{
    enum l3_proto_idx idx;

    for (idx = 0; idx < L3_PROTO_LAST_IDX; idx++) {
        if (STRPREFIX(filtername, l3_protocols[idx].val))
            return idx;
    }

    return -1;
}


static int
iptablesRuleInstCommand(virFirewallPtr fw,
                        const char *ifname,
                        virNWFilterRuleInstPtr rule)
{
    virNWFilterVarCombIterPtr vciter, tmp;
    int ret = -1;

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
        if (ebiptablesCreateRuleInstance(fw,
                                         rule->chainSuffix,
                                         rule->def,
                                         ifname,
                                         tmp) < 0)
            goto cleanup;
        tmp = virNWFilterVarCombIterNext(tmp);
    } while (tmp != NULL);

    ret = 0;
 cleanup:
    virNWFilterVarCombIterFree(vciter);
    return ret;
}


static int
ebtablesRuleInstCommand(virFirewallPtr fw,
                        const char *ifname,
                        virNWFilterRuleInstPtr rule)
{
    virNWFilterVarCombIterPtr vciter, tmp;
    int ret = -1;

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
        if (ebiptablesCreateRuleInstance(fw,
                                         rule->chainSuffix,
                                         rule->def,
                                         ifname,
                                         tmp) < 0)
            goto cleanup;
        tmp = virNWFilterVarCombIterNext(tmp);
    } while (tmp != NULL);

    ret = 0;
 cleanup:
    virNWFilterVarCombIterFree(vciter);
    return ret;
}

struct ebtablesSubChainInst {
    virNWFilterChainPriority priority;
    bool incoming;
    enum l3_proto_idx protoidx;
    const char *filtername;
};


static int
ebtablesSubChainInstSort(const void *a, const void *b)
{
    const struct ebtablesSubChainInst **insta = (const struct ebtablesSubChainInst **)a;
    const struct ebtablesSubChainInst **instb = (const struct ebtablesSubChainInst **)b;

    /* priorities are limited to range [-1000, 1000] */
    return (*insta)->priority - (*instb)->priority;
}


static int
ebtablesGetSubChainInsts(virHashTablePtr chains,
                         bool incoming,
                         struct ebtablesSubChainInst ***insts,
                         size_t *ninsts)
{
    virHashKeyValuePairPtr filter_names;
    size_t i;
    int ret = -1;

    filter_names = virHashGetItems(chains,
                                   ebiptablesFilterOrderSort);
    if (filter_names == NULL)
        return -1;

    for (i = 0; filter_names[i].key; i++) {
        struct ebtablesSubChainInst *inst;
        enum l3_proto_idx idx = ebtablesGetProtoIdxByFiltername(
                                  filter_names[i].key);

        if ((int)idx < 0)
            continue;

        if (VIR_ALLOC(inst) < 0)
            goto cleanup;
        inst->priority = *(const virNWFilterChainPriority *)filter_names[i].value;
        inst->incoming = incoming;
        inst->protoidx = idx;
        inst->filtername = filter_names[i].key;

        if (VIR_APPEND_ELEMENT(*insts, *ninsts, inst) < 0) {
            VIR_FREE(inst);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(filter_names);
    if (ret < 0) {
        for (i = 0; i < *ninsts; i++)
            VIR_FREE(*insts[i]);
        VIR_FREE(*insts);
        *ninsts = 0;
    }
    return ret;

}

static int
ebiptablesApplyNewRules(const char *ifname,
                        virNWFilterRuleInstPtr *rules,
                        size_t nrules)
{
    size_t i, j;
    virFirewallPtr fw = virFirewallNew();
    virHashTablePtr chains_in_set  = virHashCreate(10, NULL);
    virHashTablePtr chains_out_set = virHashCreate(10, NULL);
    bool haveEbtables = false;
    bool haveIptables = false;
    bool haveIp6tables = false;
    char *errmsg = NULL;
    struct ebtablesSubChainInst **subchains = NULL;
    size_t nsubchains = 0;
    int ret = -1;

    if (!chains_in_set || !chains_out_set)
        goto cleanup;

    if (nrules)
        qsort(rules, nrules, sizeof(rules[0]),
              virNWFilterRuleInstSortPtr);

    /* cleanup whatever may exist */
    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    ebtablesUnlinkTmpRootChainFW(fw, true, ifname);
    ebtablesUnlinkTmpRootChainFW(fw, false, ifname);
    ebtablesRemoveTmpSubChainsFW(fw, ifname);
    ebtablesRemoveTmpRootChainFW(fw, true, ifname);
    ebtablesRemoveTmpRootChainFW(fw, false, ifname);

    virFirewallStartTransaction(fw, 0);

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

    for (i = 0; i < nrules; i++) {
        if (virNWFilterRuleIsProtocolEthernet(rules[i]->def)) {
            haveEbtables = true;
        } else {
            if (virNWFilterRuleIsProtocolIPv4(rules[i]->def))
                haveIptables = true;
            else if (virNWFilterRuleIsProtocolIPv6(rules[i]->def))
                haveIp6tables = true;
        }
    }
    /* process ebtables commands; interleave commands from filters with
       commands for creating and connecting ebtables chains */
    if (haveEbtables) {

        /* scan the rules to see which chains need to be created */
        for (i = 0; i < nrules; i++) {
            if (virNWFilterRuleIsProtocolEthernet(rules[i]->def)) {
                const char *name = rules[i]->chainSuffix;
                if (rules[i]->def->tt == VIR_NWFILTER_RULE_DIRECTION_OUT ||
                    rules[i]->def->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
                    if (virHashUpdateEntry(chains_in_set, name,
                                           &rules[i]->chainPriority) < 0)
                        goto cleanup;
                }
                if (rules[i]->def->tt == VIR_NWFILTER_RULE_DIRECTION_IN ||
                    rules[i]->def->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
                    if (virHashUpdateEntry(chains_out_set, name,
                                           &rules[i]->chainPriority) < 0)
                        goto cleanup;
                }
            }
        }

        /* create needed chains */
        if (virHashSize(chains_in_set) > 0) {
            ebtablesCreateTmpRootChainFW(fw, true, ifname);
            if (ebtablesGetSubChainInsts(chains_in_set,
                                         true,
                                         &subchains,
                                         &nsubchains) < 0)
                goto cleanup;
        }
        if (virHashSize(chains_out_set) > 0) {
            ebtablesCreateTmpRootChainFW(fw, false, ifname);
            if (ebtablesGetSubChainInsts(chains_out_set,
                                         false,
                                         &subchains,
                                         &nsubchains) < 0)
                goto cleanup;
        }

        if (nsubchains > 0)
            qsort(subchains, nsubchains, sizeof(subchains[0]),
                  ebtablesSubChainInstSort);

        for (i = 0, j = 0; i < nrules; i++) {
            if (virNWFilterRuleIsProtocolEthernet(rules[i]->def)) {
                while (j < nsubchains &&
                       subchains[j]->priority <= rules[i]->priority) {
                    ebtablesCreateTmpSubChainFW(fw,
                                                subchains[j]->incoming,
                                                ifname,
                                                subchains[j]->protoidx,
                                                subchains[j]->filtername);
                    j++;
                }
                if (ebtablesRuleInstCommand(fw,
                                            ifname,
                                            rules[i]) < 0)
                    goto cleanup;
            }
        }
        while (j < nsubchains) {
            ebtablesCreateTmpSubChainFW(fw,
                                        subchains[j]->incoming,
                                        ifname,
                                        subchains[j]->protoidx,
                                        subchains[j]->filtername);
            j++;
        }
    }

    if (haveIptables) {
        iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
        iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

        iptablesCreateBaseChainsFW(fw, VIR_FIREWALL_LAYER_IPV4);
        iptablesCreateTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

        iptablesLinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
        iptablesSetupVirtInPostFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

        for (i = 0; i < nrules; i++) {
            if (virNWFilterRuleIsProtocolIPv4(rules[i]->def)) {
                if (iptablesRuleInstCommand(fw,
                                            ifname,
                                            rules[i]) < 0)
                    goto cleanup;
            }
        }

        iptablesCheckBridgeNFCallEnabled(false);
    }

    if (haveIp6tables) {
        iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
        iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

        iptablesCreateBaseChainsFW(fw, VIR_FIREWALL_LAYER_IPV6);
        iptablesCreateTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

        iptablesLinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
        iptablesSetupVirtInPostFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

        for (i = 0; i < nrules; i++) {
            if (virNWFilterRuleIsProtocolIPv6(rules[i]->def)) {
                if (iptablesRuleInstCommand(fw,
                                            ifname,
                                            rules[i]) < 0)
                    goto cleanup;
            }
        }

        iptablesCheckBridgeNFCallEnabled(true);
    }

    if (virHashSize(chains_in_set) != 0)
        ebtablesLinkTmpRootChainFW(fw, true, ifname);
    if (virHashSize(chains_out_set) != 0)
        ebtablesLinkTmpRootChainFW(fw, false, ifname);

    virFirewallStartRollback(fw, 0);
    ebtablesUnlinkTmpRootChainFW(fw, true, ifname);
    ebtablesUnlinkTmpRootChainFW(fw, false, ifname);
    if (haveIp6tables) {
        iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
        iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    }

    if (haveIptables) {
        iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
        iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    }

    ebtablesRemoveTmpSubChainsFW(fw, ifname);
    ebtablesRemoveTmpRootChainFW(fw, true, ifname);
    ebtablesRemoveTmpRootChainFW(fw, false, ifname);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    for (i = 0; i < nsubchains; i++)
        VIR_FREE(subchains[i]);
    VIR_FREE(subchains);
    virFirewallFree(fw);
    virHashFree(chains_in_set);
    virHashFree(chains_out_set);

    VIR_FREE(errmsg);
    return ret;
}


static void
ebiptablesTearNewRulesFW(virFirewallPtr fw, const char *ifname)
{
    iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

    iptablesUnlinkTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    iptablesRemoveTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

    ebtablesUnlinkTmpRootChainFW(fw, true, ifname);
    ebtablesUnlinkTmpRootChainFW(fw, false, ifname);
    ebtablesRemoveTmpSubChainsFW(fw, ifname);
    ebtablesRemoveTmpRootChainFW(fw, true, ifname);
    ebtablesRemoveTmpRootChainFW(fw, false, ifname);
}


static int
ebiptablesTearNewRules(const char *ifname)
{
    virFirewallPtr fw = virFirewallNew();
    int ret = -1;

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    ebiptablesTearNewRulesFW(fw, ifname);

    ret = virFirewallApply(fw);
    virFirewallFree(fw);
    return ret;
}

static int
ebiptablesTearOldRules(const char *ifname)
{
    virFirewallPtr fw = virFirewallNew();
    int ret = -1;

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    iptablesUnlinkRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    iptablesRemoveRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    iptablesRenameTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

    iptablesUnlinkRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    iptablesRemoveRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    iptablesRenameTmpRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

    ebtablesUnlinkRootChainFW(fw, true, ifname);
    ebtablesUnlinkRootChainFW(fw, false, ifname);
    ebtablesRemoveSubChainsFW(fw, ifname);
    ebtablesRemoveRootChainFW(fw, true, ifname);
    ebtablesRemoveRootChainFW(fw, false, ifname);
    ebtablesRenameTmpSubAndRootChainsFW(fw, ifname);

    ret = virFirewallApply(fw);
    virFirewallFree(fw);
    return ret;
}


/**
 * ebiptablesAllTeardown:
 * @ifname : the name of the interface to which the rules apply
 *
 * Unconditionally remove all possible user defined tables and rules
 * that were created for the given interface (ifname).
 *
 * Returns 0 on success, -1 on OOM
 */
static int
ebiptablesAllTeardown(const char *ifname)
{
    virFirewallPtr fw = virFirewallNew();
    int ret = -1;

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);

    ebiptablesTearNewRulesFW(fw, ifname);

    iptablesUnlinkRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    iptablesClearVirtInPostFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);
    iptablesRemoveRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV4, ifname);

    iptablesUnlinkRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    iptablesClearVirtInPostFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);
    iptablesRemoveRootChainsFW(fw, VIR_FIREWALL_LAYER_IPV6, ifname);

    ebtablesUnlinkRootChainFW(fw, true, ifname);
    ebtablesUnlinkRootChainFW(fw, false, ifname);

    ebtablesRemoveSubChainsFW(fw, ifname);

    ebtablesRemoveRootChainFW(fw, true, ifname);
    ebtablesRemoveRootChainFW(fw, false, ifname);

    ret = virFirewallApply(fw);
    virFirewallFree(fw);
    return ret;
}


virNWFilterTechDriver ebiptables_driver = {
    .name = EBIPTABLES_DRIVER_ID,
    .flags = 0,

    .init     = ebiptablesDriverInit,
    .shutdown = ebiptablesDriverShutdown,

    .applyNewRules       = ebiptablesApplyNewRules,
    .tearNewRules        = ebiptablesTearNewRules,
    .tearOldRules        = ebiptablesTearOldRules,
    .allTeardown         = ebiptablesAllTeardown,

    .canApplyBasicRules  = ebiptablesCanApplyBasicRules,
    .applyBasicRules     = ebtablesApplyBasicRules,
    .applyDHCPOnlyRules  = ebtablesApplyDHCPOnlyRules,
    .applyDropAllRules   = ebtablesApplyDropAllRules,
    .removeBasicRules    = ebtablesRemoveBasicRules,
};

static void
ebiptablesDriverProbeCtdir(void)
{
    struct utsname utsname;
    unsigned long thisversion;

    iptables_ctdir_corrected = CTDIR_STATUS_UNKNOWN;

    if (uname(&utsname) < 0) {
        VIR_ERROR(_("Call to utsname failed: %d"), errno);
        return;
    }

    /* following Linux lxr, the logic was inverted in 2.6.39 */
    if (virParseVersionString(utsname.release, &thisversion, true) < 0) {
        VIR_ERROR(_("Could not determine kernel version from string %s"),
                  utsname.release);
        return;
    }

    if (thisversion >= 2 * 1000000 + 6 * 1000 + 39)
        iptables_ctdir_corrected = CTDIR_STATUS_CORRECTED;
    else
        iptables_ctdir_corrected = CTDIR_STATUS_OLD;
}


static int
ebiptablesDriverProbeStateMatchQuery(virFirewallPtr fw G_GNUC_UNUSED,
                                     virFirewallLayer layer G_GNUC_UNUSED,
                                     const char *const *lines,
                                     void *opaque)
{
    unsigned long *version = opaque;
    char *tmp;

    if (!lines || !lines[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No output from iptables --version"));
        return -1;
    }

    /*
     * we expect output in the format
     * 'iptables v1.4.16'
     */
    if (!(tmp = strchr(lines[0], 'v')) ||
        virParseVersionString(tmp + 1, version, true) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse version string '%s'"),
                       lines[0]);
        return -1;
    }

    return 0;
}


static int
ebiptablesDriverProbeStateMatch(void)
{
    unsigned long version;
    virFirewallPtr fw = virFirewallNew();
    int ret = -1;

    virFirewallStartTransaction(fw, 0);
    virFirewallAddRuleFull(fw, VIR_FIREWALL_LAYER_IPV4,
                           false, ebiptablesDriverProbeStateMatchQuery, &version,
                           "--version", NULL);

    if (virFirewallApply(fw) < 0)
        goto cleanup;

    /*
     * since version 1.4.16 '-m state --state ...' will be converted to
     * '-m conntrack --ctstate ...'
     */
    if (version >= 1 * 1000000 + 4 * 1000 + 16)
        newMatchState = true;

    ret = 0;
 cleanup:
    virFirewallFree(fw);
    return ret;
}

static int
ebiptablesDriverInit(bool privileged)
{
    if (!privileged)
        return 0;

    ebiptablesDriverProbeCtdir();
    if (ebiptablesDriverProbeStateMatch() < 0)
        return -1;

    ebiptables_driver.flags = TECHDRV_FLAG_INITIALIZED;

    return 0;
}


static void
ebiptablesDriverShutdown(void)
{
    ebiptables_driver.flags = 0;
}
