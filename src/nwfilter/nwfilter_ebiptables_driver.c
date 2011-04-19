/*
 * nwfilter_ebiptables_driver.c: driver for ebtables/iptables on tap devices
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corp.
 * Copyright (C) 2010 Stefan Berger
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "internal.h"

#include "buf.h"
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "domain_conf.h"
#include "nwfilter_conf.h"
#include "nwfilter_gentech_driver.h"
#include "nwfilter_ebiptables_driver.h"
#include "files.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER


#define EBTABLES_DEFAULT_TABLE  "nat"
#define EBTABLES_CHAIN_INCOMING "PREROUTING"
#define EBTABLES_CHAIN_OUTGOING "POSTROUTING"

#define CHAINPREFIX_HOST_IN       'I'
#define CHAINPREFIX_HOST_OUT      'O'
#define CHAINPREFIX_HOST_IN_TEMP  'J'
#define CHAINPREFIX_HOST_OUT_TEMP 'P'

/* This file generates a temporary shell script.  Since ebiptables is
   Linux-specific, we can be reasonably certain that /bin/sh is more
   or less POSIX-compliant, so we can use $() and $(()).  However, we
   cannot assume that /bin/sh is bash, so stick to POSIX syntax.  */

#define CMD_SEPARATOR "\n"
#define CMD_DEF_PRE  "cmd='"
#define CMD_DEF_POST "'"
#define CMD_DEF(X) CMD_DEF_PRE X CMD_DEF_POST
#define CMD_EXEC   "eval res=\\$\\(\"${cmd}\"\\)" CMD_SEPARATOR
#define CMD_STOPONERR(X) \
    X ? "if [ $? -ne 0 ]; then" \
        "  echo \"Failure to execute command '${cmd}'.\";" \
        "  exit 1;" \
        "fi" CMD_SEPARATOR \
      : ""


#define PROC_BRIDGE_NF_CALL_IPTABLES \
        "/proc/sys/net/bridge/bridge-nf-call-iptables"
#define PROC_BRIDGE_NF_CALL_IP6TABLES \
        "/proc/sys/net/bridge/bridge-nf-call-ip6tables"

#define BRIDGE_NF_CALL_ALERT_INTERVAL  10 /* seconds */

static char *ebtables_cmd_path;
static char *iptables_cmd_path;
static char *ip6tables_cmd_path;
static char *grep_cmd_path;
static char *gawk_cmd_path;


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

#define PHYSDEV_IN  "--physdev-in"
#define PHYSDEV_OUT "--physdev-out"

static const char *m_state_out_str   = "-m state --state NEW,ESTABLISHED";
static const char *m_state_in_str    = "-m state --state ESTABLISHED";
static const char *m_physdev_in_str  = "-m physdev " PHYSDEV_IN;
static const char *m_physdev_out_str = "-m physdev " PHYSDEV_OUT;

#define MATCH_STATE_OUT    m_state_out_str
#define MATCH_STATE_IN     m_state_in_str
#define MATCH_PHYSDEV_IN   m_physdev_in_str
#define MATCH_PHYSDEV_OUT  m_physdev_out_str

#define COMMENT_VARNAME "comment"

static int ebtablesRemoveBasicRules(const char *ifname);
static int ebiptablesDriverInit(bool privileged);
static void ebiptablesDriverShutdown(void);
static int ebtablesCleanAll(const char *ifname);
static int ebiptablesAllTeardown(const char *ifname);

static virMutex execCLIMutex;

struct ushort_map {
    unsigned short attr;
    const char *val;
};


enum l3_proto_idx {
    L3_PROTO_IPV4_IDX = 0,
    L3_PROTO_IPV6_IDX,
    L3_PROTO_ARP_IDX,
    L3_PROTO_RARP_IDX,
    L3_PROTO_LAST_IDX
};

#define USHORTMAP_ENTRY_IDX(IDX, ATT, VAL) [IDX] = { .attr = ATT, .val = VAL }

static const struct ushort_map l3_protocols[] = {
    USHORTMAP_ENTRY_IDX(L3_PROTO_IPV4_IDX, ETHERTYPE_IP    , "ipv4"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_IPV6_IDX, ETHERTYPE_IPV6  , "ipv6"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_ARP_IDX , ETHERTYPE_ARP   , "arp"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_RARP_IDX, ETHERTYPE_REVARP, "rarp"),
    USHORTMAP_ENTRY_IDX(L3_PROTO_LAST_IDX, 0               , NULL),
};


static int
printVar(virNWFilterHashTablePtr vars,
         char *buf, int bufsize,
         nwItemDescPtr item,
         int *done)
{
    *done = 0;

    if ((item->flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
        char *val = (char *)virHashLookup(vars->hashTable, item->var);
        if (!val) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot find value for '%s'"),
                                   item->var);
            return 1;
        }

        if (!virStrcpy(buf, val, bufsize)) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Buffer to small to print MAC address "
                                   "'%s' into"),
                                   item->var);
            return 1;
        }

        *done = 1;
    }
    return 0;
}


static int
_printDataType(virNWFilterHashTablePtr vars,
               char *buf, int bufsize,
               nwItemDescPtr item,
               bool asHex)
{
    int done;
    char *data;

    if (printVar(vars, buf, bufsize, item, &done))
        return 1;

    if (done)
        return 0;

    switch (item->datatype) {
    case DATATYPE_IPADDR:
        data = virSocketFormatAddr(&item->u.ipaddr);
        if (!data)
            return 1;
        if (snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("buffer too small for IP address"));
            VIR_FREE(data);
            return 1;
        }
        VIR_FREE(data);
    break;

    case DATATYPE_IPV6ADDR:
        data = virSocketFormatAddr(&item->u.ipaddr);
        if (!data)
            return 1;

        if (snprintf(buf, bufsize, "%s", data) >= bufsize) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("buffer too small for IPv6 address"));
            VIR_FREE(data);
            return 1;
        }
        VIR_FREE(data);
    break;

    case DATATYPE_MACADDR:
    case DATATYPE_MACMASK:
        if (bufsize < VIR_MAC_STRING_BUFLEN) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Buffer too small for MAC address"));
            return 1;
        }

        virFormatMacAddr(item->u.macaddr.addr, buf);
    break;

    case DATATYPE_IPV6MASK:
    case DATATYPE_IPMASK:
        if (snprintf(buf, bufsize, "%d",
                     item->u.u8) >= bufsize) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Buffer too small for uint8 type"));
            return 1;
        }
    break;

    case DATATYPE_UINT16:
    case DATATYPE_UINT16_HEX:
        if (snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                     item->u.u16) >= bufsize) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Buffer too small for uint16 type"));
            return 1;
        }
    break;

    case DATATYPE_UINT8:
    case DATATYPE_UINT8_HEX:
        if (snprintf(buf, bufsize, asHex ? "0x%x" : "%d",
                     item->u.u8) >= bufsize) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Buffer too small for uint8 type"));
            return 1;
        }
    break;

    default:
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unhandled datatype %x"), item->datatype);
        return 1;
    break;
    }

    return 0;
}


static int
printDataType(virNWFilterHashTablePtr vars,
              char *buf, int bufsize,
              nwItemDescPtr item)
{
    return _printDataType(vars, buf, bufsize, item, 0);
}


static int
printDataTypeAsHex(virNWFilterHashTablePtr vars,
                   char *buf, int bufsize,
                   nwItemDescPtr item)
{
    return _printDataType(vars, buf, bufsize, item, 1);
}


static void
printCommentVar(virBufferPtr dest, const char *buf)
{
    size_t i, len = strlen(buf);

    virBufferAddLit(dest, COMMENT_VARNAME "='");

    if (len > IPTABLES_MAX_COMMENT_LENGTH)
        len = IPTABLES_MAX_COMMENT_LENGTH;

    for (i = 0; i < len; i++) {
        if (buf[i] == '\'')
            virBufferAddLit(dest, "'\\''");
        else
            virBufferAddChar(dest, buf[i]);
    }
    virBufferAddLit(dest,"'" CMD_SEPARATOR);
}


static void
ebiptablesRuleInstFree(ebiptablesRuleInstPtr inst)
{
    if (!inst)
        return;

    VIR_FREE(inst->commandTemplate);
    VIR_FREE(inst);
}


static int
ebiptablesAddRuleInst(virNWFilterRuleInstPtr res,
                      char *commandTemplate,
                      enum virNWFilterChainSuffixType neededChain,
                      char chainprefix,
                      unsigned int priority,
                      enum RuleType ruleType)
{
    ebiptablesRuleInstPtr inst;

    if (VIR_ALLOC(inst) < 0) {
        virReportOOMError();
        return 1;
    }

    inst->commandTemplate = commandTemplate;
    inst->neededProtocolChain = neededChain;
    inst->chainprefix = chainprefix;
    inst->priority = priority;
    inst->ruleType = ruleType;

    return virNWFilterRuleInstAddData(res, inst);
}


static int
ebtablesHandleEthHdr(virBufferPtr buf,
                     virNWFilterHashTablePtr vars,
                     ethHdrDataDefPtr ethHdr,
                     bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataSrcMACAddr))
            goto err_exit;

        virBufferVSprintf(buf,
                      " %s %s %s",
                      reverse ? "-d" : "-s",
                      ENTRY_GET_NEG_SIGN(&ethHdr->dataSrcMACAddr),
                      macaddr);

        if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACMask)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &ethHdr->dataSrcMACMask))
                goto err_exit;

            virBufferVSprintf(buf,
                              "/%s",
                              macaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataDstMACAddr))
            goto err_exit;

        virBufferVSprintf(buf,
                      " %s %s %s",
                      reverse ? "-s" : "-d",
                      ENTRY_GET_NEG_SIGN(&ethHdr->dataDstMACAddr),
                      macaddr);

        if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACMask)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &ethHdr->dataDstMACMask))
                goto err_exit;

            virBufferVSprintf(buf,
                              "/%s",
                              macaddr);
        }
    }

    return 0;

 err_exit:
    virBufferFreeAndReset(buf);

    return 1;
}


/************************ iptables support ************************/

static int iptablesLinkIPTablesBaseChain(const char *iptables_cmd,
                                         virBufferPtr buf,
                                         const char *udchain,
                                         const char *syschain,
                                         unsigned int pos,
                                         int stopOnError)
{
    virBufferVSprintf(buf,
                      "res=$(%s -L %s -n --line-number | "
                          "%s \" %s \")\n"
                      "if [ $? -ne 0 ]; then\n"
                      "  %s -I %s %d -j %s\n"
                      "else\n"
                      "  r=$(echo $res | %s '{print $1}')\n"
                      "  if [ \"${r}\" != \"%d\" ]; then\n"
                      "    " CMD_DEF("%s -I %s %d -j %s") CMD_SEPARATOR
                      "    " CMD_EXEC
                      "    %s"
                      "    r=$(( $r + 1 ))\n"
                      "    " CMD_DEF("%s -D %s ${r}") CMD_SEPARATOR
                      "    " CMD_EXEC
                      "    %s"
                      "  fi\n"
                      "fi\n",

                      iptables_cmd, syschain,
                      grep_cmd_path, udchain,

                      iptables_cmd, syschain, pos, udchain,
                      gawk_cmd_path,

                      pos,

                      iptables_cmd, syschain, pos, udchain,
                      CMD_STOPONERR(stopOnError),

                      iptables_cmd, syschain,
                      CMD_STOPONERR(stopOnError));
    return 0;
}


static int iptablesCreateBaseChains(const char *iptables_cmd,
                                    virBufferPtr buf)
{
    virBufferVSprintf(buf,"%s -N " VIRT_IN_CHAIN      CMD_SEPARATOR
                          "%s -N " VIRT_OUT_CHAIN     CMD_SEPARATOR
                          "%s -N " VIRT_IN_POST_CHAIN CMD_SEPARATOR
                          "%s -N " HOST_IN_CHAIN      CMD_SEPARATOR,
                          iptables_cmd,
                          iptables_cmd,
                          iptables_cmd,
                          iptables_cmd);
    iptablesLinkIPTablesBaseChain(iptables_cmd, buf,
                                  VIRT_IN_CHAIN     , "FORWARD", 1, 1);
    iptablesLinkIPTablesBaseChain(iptables_cmd, buf,
                                  VIRT_OUT_CHAIN    , "FORWARD", 2, 1);
    iptablesLinkIPTablesBaseChain(iptables_cmd, buf,
                                  VIRT_IN_POST_CHAIN, "FORWARD", 3, 1);
    iptablesLinkIPTablesBaseChain(iptables_cmd, buf,
                                  HOST_IN_CHAIN     , "INPUT"  , 1, 1);

    return 0;
}


static int
iptablesCreateTmpRootChain(const char *iptables_cmd,
                           virBufferPtr buf,
                           char prefix,
                           int incoming, const char *ifname,
                           int stopOnError)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
       prefix,
       (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                  : CHAINPREFIX_HOST_OUT_TEMP
    };

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      CMD_DEF("%s -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      iptables_cmd,
                      chain,
                      CMD_STOPONERR(stopOnError));

    return 0;
}


static int
iptablesCreateTmpRootChains(const char *iptables_cmd,
                            virBufferPtr buf,
                            const char *ifname)
{
    iptablesCreateTmpRootChain(iptables_cmd, buf, 'F', 0, ifname, 1);
    iptablesCreateTmpRootChain(iptables_cmd, buf, 'F', 1, ifname, 1);
    iptablesCreateTmpRootChain(iptables_cmd, buf, 'H', 1, ifname, 1);
    return 0;
}


static int
_iptablesRemoveRootChain(const char *iptables_cmd,
                         virBufferPtr buf,
                         char prefix,
                         int incoming, const char *ifname,
                         int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
    };

    if (isTempChain)
        chainPrefix[1] = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                    : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix[1] = (incoming) ? CHAINPREFIX_HOST_IN
                                    : CHAINPREFIX_HOST_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      "%s -F %s" CMD_SEPARATOR
                      "%s -X %s" CMD_SEPARATOR,
                      iptables_cmd, chain,
                      iptables_cmd, chain);

    return 0;
}


static int
iptablesRemoveRootChain(const char *iptables_cmd,
                        virBufferPtr buf,
                        char prefix,
                        int incoming,
                        const char *ifname)
{
    return _iptablesRemoveRootChain(iptables_cmd,
                                    buf, prefix, incoming, ifname, 0);
}


static int
iptablesRemoveTmpRootChain(const char *iptables_cmd,
                           virBufferPtr buf,
                           char prefix,
                           int incoming,
                           const char *ifname)
{
    return _iptablesRemoveRootChain(iptables_cmd, buf, prefix,
                                    incoming, ifname, 1);
}


static int
iptablesRemoveTmpRootChains(const char *iptables_cmd,
                            virBufferPtr buf,
                            const char *ifname)
{
    iptablesRemoveTmpRootChain(iptables_cmd, buf, 'F', 0, ifname);
    iptablesRemoveTmpRootChain(iptables_cmd, buf, 'F', 1, ifname);
    iptablesRemoveTmpRootChain(iptables_cmd, buf, 'H', 1, ifname);
    return 0;
}


static int
iptablesRemoveRootChains(const char *iptables_cmd,
                         virBufferPtr buf,
                         const char *ifname)
{
    iptablesRemoveRootChain(iptables_cmd, buf, 'F', 0, ifname);
    iptablesRemoveRootChain(iptables_cmd, buf, 'F', 1, ifname);
    iptablesRemoveRootChain(iptables_cmd, buf, 'H', 1, ifname);
    return 0;
}


static int
iptablesLinkTmpRootChain(const char *iptables_cmd,
                         virBufferPtr buf,
                         const char *basechain,
                         char prefix,
                         int incoming, const char *ifname,
                         int stopOnError)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
        (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                   : CHAINPREFIX_HOST_OUT_TEMP
    };
    const char *match = (incoming) ? MATCH_PHYSDEV_IN
                                   : MATCH_PHYSDEV_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      CMD_DEF("%s -A %s "
                              "%s %s -g %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      iptables_cmd,
                      basechain,
                      match, ifname, chain,

                      CMD_STOPONERR(stopOnError));

    return 0;
}


static int
iptablesLinkTmpRootChains(const char *cmd,
                          virBufferPtr buf,
                          const char *ifname)
{
    iptablesLinkTmpRootChain(cmd, buf, VIRT_OUT_CHAIN, 'F', 0, ifname, 1);
    iptablesLinkTmpRootChain(cmd, buf, VIRT_IN_CHAIN , 'F', 1, ifname, 1);
    iptablesLinkTmpRootChain(cmd, buf, HOST_IN_CHAIN , 'H', 1, ifname, 1);

    return 0;
}


static int
iptablesSetupVirtInPost(const char *iptables_cmd,
                        virBufferPtr buf,
                        const char *ifname)
{
    const char *match = MATCH_PHYSDEV_IN;
    virBufferVSprintf(buf,
                      "res=$(%s -n -L " VIRT_IN_POST_CHAIN
                      " | grep \"\\%s %s\")\n"
                      "if [ \"${res}\" = \"\" ]; then "
                        CMD_DEF("%s"
                        " -A " VIRT_IN_POST_CHAIN
                        " %s %s -j ACCEPT") CMD_SEPARATOR
                        CMD_EXEC
                        "%s"
                      "fi\n",
                      iptables_cmd,
                      PHYSDEV_IN, ifname,
                      iptables_cmd,
                      match, ifname,
                      CMD_STOPONERR(1));
    return 0;
}


static int
iptablesClearVirtInPost(const char *iptables_cmd,
                        virBufferPtr buf,
                        const char *ifname)
{
    const char *match = MATCH_PHYSDEV_IN;
    virBufferVSprintf(buf,
                      "%s -D " VIRT_IN_POST_CHAIN
                      " %s %s -j ACCEPT" CMD_SEPARATOR,
                      iptables_cmd,
                      match, ifname);
    return 0;
}

static int
_iptablesUnlinkRootChain(const char *iptables_cmd,
                         virBufferPtr buf,
                         const char *basechain,
                         char prefix,
                         int incoming, const char *ifname,
                         int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix[2] = {
        prefix,
    };
    if (isTempChain)
        chainPrefix[1] = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                    : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix[1] = (incoming) ? CHAINPREFIX_HOST_IN
                                    : CHAINPREFIX_HOST_OUT;
    const char *match = (incoming) ? MATCH_PHYSDEV_IN
                                   : MATCH_PHYSDEV_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      "%s -D %s "
                      "%s %s -g %s" CMD_SEPARATOR,
                      iptables_cmd,
                      basechain,
                      match, ifname, chain);

    return 0;
}


static int
iptablesUnlinkRootChain(const char *iptables_cmd,
                        virBufferPtr buf,
                        const char *basechain,
                        char prefix,
                        int incoming, const char *ifname)
{
    return _iptablesUnlinkRootChain(iptables_cmd, buf,
                                    basechain, prefix, incoming, ifname, 0);
}


static int
iptablesUnlinkTmpRootChain(const char *iptables_cmd,
                           virBufferPtr buf,
                           const char *basechain,
                           char prefix,
                           int incoming, const char *ifname)
{
    return _iptablesUnlinkRootChain(iptables_cmd, buf,
                                    basechain, prefix, incoming, ifname, 1);
}


static int
iptablesUnlinkRootChains(const char *cmd,
                         virBufferPtr buf,
                         const char *ifname)
{
    iptablesUnlinkRootChain(cmd, buf, VIRT_OUT_CHAIN, 'F', 0, ifname);
    iptablesUnlinkRootChain(cmd, buf, VIRT_IN_CHAIN , 'F', 1, ifname);
    iptablesUnlinkRootChain(cmd, buf, HOST_IN_CHAIN , 'H', 1, ifname);

    return 0;
}


static int
iptablesUnlinkTmpRootChains(const char *cmd,
                            virBufferPtr buf,
                            const char *ifname)
{
    iptablesUnlinkTmpRootChain(cmd, buf, VIRT_OUT_CHAIN, 'F', 0, ifname);
    iptablesUnlinkTmpRootChain(cmd, buf, VIRT_IN_CHAIN , 'F', 1, ifname);
    iptablesUnlinkTmpRootChain(cmd, buf, HOST_IN_CHAIN , 'H', 1, ifname);
    return 0;
}


static int
iptablesRenameTmpRootChain(const char *iptables_cmd,
                           virBufferPtr buf,
                           char prefix,
                           int incoming,
                           const char *ifname)
{
    char tmpchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char tmpChainPrefix[2] = {
        prefix,
        (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                   : CHAINPREFIX_HOST_OUT_TEMP
    };
    char chainPrefix[2] = {
        prefix,
        (incoming) ? CHAINPREFIX_HOST_IN
                   : CHAINPREFIX_HOST_OUT
    };

    PRINT_IPT_ROOT_CHAIN(tmpchain, tmpChainPrefix, ifname);
    PRINT_IPT_ROOT_CHAIN(   chain,    chainPrefix, ifname);

    virBufferVSprintf(buf,
                      "%s -E %s %s" CMD_SEPARATOR,
                      iptables_cmd,
                      tmpchain,
                      chain);
    return 0;
}


static int
iptablesRenameTmpRootChains(const char *iptables_cmd,
                            virBufferPtr buf,
                            const char *ifname)
{
    iptablesRenameTmpRootChain(iptables_cmd, buf, 'F', 0, ifname);
    iptablesRenameTmpRootChain(iptables_cmd, buf, 'F', 1, ifname);
    iptablesRenameTmpRootChain(iptables_cmd, buf, 'H', 1, ifname);
    return 0;
}


static void
iptablesInstCommand(virBufferPtr buf,
                    const char *templ, char cmd, int pos,
                    int stopOnError)
{
    char position[10] = { 0 };
    if (pos >= 0)
        snprintf(position, sizeof(position), "%d", pos);
    virBufferVSprintf(buf, templ, cmd, position);
    virBufferVSprintf(buf, CMD_SEPARATOR "%s",
                      CMD_STOPONERR(stopOnError));
}


static int
iptablesHandleSrcMacAddr(virBufferPtr buf,
                         virNWFilterHashTablePtr vars,
                         nwItemDescPtr srcMacAddr,
                         int directionIn,
                         bool *srcmacskipped)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];
    *srcmacskipped = false;

    if (HAS_ENTRY_ITEM(srcMacAddr)) {
        if (directionIn) {
            *srcmacskipped = true;
            return 0;
        }

        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          srcMacAddr))
            goto err_exit;

        virBufferVSprintf(buf,
                          " -m mac %s --mac-source %s",
                          ENTRY_GET_NEG_SIGN(srcMacAddr),
                          macaddr);
    }

    return 0;

err_exit:
    virBufferFreeAndReset(buf);

    return 1;
}


static int
iptablesHandleIpHdr(virBufferPtr buf,
                    virBufferPtr afterStateMatch,
                    virNWFilterHashTablePtr vars,
                    ipHdrDataDefPtr ipHdr,
                    int directionIn,
                    bool *skipRule, bool *skipMatch,
                    virBufferPtr prefix)
{
    char ipaddr[INET6_ADDRSTRLEN],
         number[20];
    const char *src = "--source";
    const char *dst = "--destination";
    const char *srcrange = "--src-range";
    const char *dstrange = "--dst-range";
    if (directionIn) {
        src = "--destination";
        dst = "--source";
        srcrange = "--dst-range";
        dstrange = "--src-range";
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPAddr)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPAddr))
            goto err_exit;

        virBufferVSprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataSrcIPAddr),
                          src,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPMask)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataSrcIPMask))
                goto err_exit;

            virBufferVSprintf(buf,
                              "/%s",
                              number);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPFrom)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPFrom))
            goto err_exit;

        virBufferVSprintf(buf,
                          " -m iprange %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataSrcIPFrom),
                          srcrange,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPTo)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &ipHdr->dataSrcIPTo))
                goto err_exit;

            virBufferVSprintf(buf,
                              "-%s",
                              ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPAddr)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPAddr))
           goto err_exit;

        virBufferVSprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataDstIPAddr),
                          dst,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPMask)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataDstIPMask))
                goto err_exit;

            virBufferVSprintf(buf,
                              "/%s",
                              number);

        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPFrom)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPFrom))
            goto err_exit;

        virBufferVSprintf(buf,
                          " -m iprange %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataDstIPFrom),
                          dstrange,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPTo)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &ipHdr->dataDstIPTo))
                goto err_exit;

            virBufferVSprintf(buf,
                              "-%s",
                              ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDSCP)) {

        if (printDataType(vars,
                          number, sizeof(number),
                          &ipHdr->dataDSCP))
           goto err_exit;

        virBufferVSprintf(buf,
                          " -m dscp %s --dscp %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataDSCP),
                          number);
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataConnlimitAbove)) {
        if (directionIn) {
            /* only support for limit in outgoing dir. */
            *skipRule = true;
        } else {
            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataConnlimitAbove))
               goto err_exit;

            /* place connlimit after potential -m state --state ...
               since this is the most useful order */
            virBufferVSprintf(afterStateMatch,
                              " -m connlimit %s --connlimit-above %s",
                              ENTRY_GET_NEG_SIGN(&ipHdr->dataConnlimitAbove),
                              number);
            *skipMatch = true;
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataComment)) {
        printCommentVar(prefix, ipHdr->dataComment.u.string);

        /* keep comments behind everything else -- they are packet eval.
           no-ops */
        virBufferAddLit(afterStateMatch,
                        " -m comment --comment \"$" COMMENT_VARNAME "\"");
    }

    return 0;

err_exit:
    virBufferFreeAndReset(buf);
    virBufferFreeAndReset(afterStateMatch);

    return 1;
}


static int
iptablesHandlePortData(virBufferPtr buf,
                       virNWFilterHashTablePtr vars,
                       portDataDefPtr portData,
                       int directionIn)
{
    char portstr[20];
    const char *sport = "--sport";
    const char *dport = "--dport";
    if (directionIn) {
        sport = "--dport";
        dport = "--sport";
    }

    if (HAS_ENTRY_ITEM(&portData->dataSrcPortStart)) {
        if (printDataType(vars,
                          portstr, sizeof(portstr),
                          &portData->dataSrcPortStart))
            goto err_exit;

        virBufferVSprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&portData->dataSrcPortStart),
                          sport,
                          portstr);

        if (HAS_ENTRY_ITEM(&portData->dataSrcPortEnd)) {
            if (printDataType(vars,
                              portstr, sizeof(portstr),
                              &portData->dataSrcPortEnd))
                goto err_exit;

             virBufferVSprintf(buf,
                               ":%s",
                               portstr);
        }
    }

    if (HAS_ENTRY_ITEM(&portData->dataDstPortStart)) {
        if (printDataType(vars,
                          portstr, sizeof(portstr),
                          &portData->dataDstPortStart))
            goto err_exit;

        virBufferVSprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&portData->dataDstPortStart),
                          dport,
                          portstr);

        if (HAS_ENTRY_ITEM(&portData->dataDstPortEnd)) {
            if (printDataType(vars,
                              portstr, sizeof(portstr),
                              &portData->dataDstPortEnd))
                goto err_exit;

             virBufferVSprintf(buf,
                               ":%s",
                               portstr);
        }
    }

    return 0;

err_exit:
    return 1;
}


static void
iptablesEnforceDirection(int directionIn,
                         virNWFilterRuleDefPtr rule,
                         virBufferPtr buf)
{
    if (rule->tt != VIR_NWFILTER_RULE_DIRECTION_INOUT)
        virBufferVSprintf(buf, " -m conntrack --ctdir %s",
                          (directionIn) ? "Original"
                                        : "Reply");
}


/*
 * _iptablesCreateRuleInstance:
 * @chainPrefix : The prefix to put in front of the name of the chain
 * @nwfilter : The filter
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @res : The data structure to store the result(s) into
 * @match : optional string for state match
 * @accept_target : where to jump to on accepted traffic, i.e., "RETURN"
 *    "ACCEPT"
 * @isIPv6 : Whether this is an IPv6 rule
 * @maySkipICMP : whether this rule may under certain circumstances skip
 *           the ICMP rule from being created
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, != 0 otherwise with the error message stored in the
 * virConnect object.
 */
static int
_iptablesCreateRuleInstance(int directionIn,
                            const char *chainPrefix,
                            virNWFilterDefPtr nwfilter,
                            virNWFilterRuleDefPtr rule,
                            const char *ifname,
                            virNWFilterHashTablePtr vars,
                            virNWFilterRuleInstPtr res,
                            const char *match, bool defMatch,
                            const char *accept_target,
                            bool isIPv6,
                            bool maySkipICMP)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char number[20];
    virBuffer prefix = VIR_BUFFER_INITIALIZER;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virBuffer afterStateMatch = VIR_BUFFER_INITIALIZER;
    virBufferPtr final = NULL;
    const char *target;
    const char *iptables_cmd = (isIPv6) ? ip6tables_cmd_path
                                        : iptables_cmd_path;
    unsigned int bufUsed;
    bool srcMacSkipped = false;
    bool skipRule = false;
    bool skipMatch = false;
    bool hasICMPType = false;

    if (!iptables_cmd) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot create rule since %s tool is "
                                 "missing."),
                               isIPv6 ? "ip6tables" : "iptables");
        goto err_exit;
    }

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p tcp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.tcpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.tcpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPFlags)) {
            virBufferVSprintf(&buf, " %s --tcp-flags ",
                      ENTRY_GET_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPFlags));
            virNWFilterPrintTCPFlags(&buf,
                      rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.mask,
                      ' ',
                      rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.flags);
        }

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.tcpHdrFilter.portData,
                                   directionIn))
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPOption)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.tcpHdrFilter.dataTCPOption))
                goto err_exit;

            virBufferVSprintf(&buf,
                              " %s --tcp-option %s",
                              ENTRY_GET_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPOption),
                              number);
        }

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p udp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.udpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.udpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.udpHdrFilter.portData,
                                   directionIn))
            goto err_exit;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p udplite");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.udpliteHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.udpliteHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p esp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.espHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.espHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p ah");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.ahHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.ahHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p sctp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.sctpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.sctpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.sctpHdrFilter.portData,
                                   directionIn))
            goto err_exit;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMP)
            virBufferAddLit(&buf, " -p icmp");
        else
            virBufferAddLit(&buf, " -p icmpv6");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.icmpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.icmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPType)) {
            const char *parm;

            hasICMPType = true;

            if (maySkipICMP)
                goto exit_no_error;

            if (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ICMP)
                parm = "--icmp-type";
            else
                parm = "--icmpv6-type";

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.icmpHdrFilter.dataICMPType))
                goto err_exit;

            virBufferVSprintf(&buf,
                      " %s %s %s",
                      ENTRY_GET_NEG_SIGN(&rule->p.icmpHdrFilter.dataICMPType),
                      parm,
                      number);

            if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPCode)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.icmpHdrFilter.dataICMPCode))
                    goto err_exit;

                 virBufferVSprintf(&buf,
                                   "/%s",
                                   number);
            }
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p igmp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.igmpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.igmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -%%c %s %%s",
                          iptables_cmd,
                          chain);

        virBufferAddLit(&buf, " -p all");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.allHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped))
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.allHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix))
            goto err_exit;

    break;

    default:
        return -1;
    }

    if ((srcMacSkipped && bufUsed == virBufferUse(&buf)) ||
         skipRule) {
        virBufferFreeAndReset(&buf);
        virBufferFreeAndReset(&prefix);
        return 0;
    }

    if (rule->action == VIR_NWFILTER_RULE_ACTION_ACCEPT)
        target = accept_target;
    else {
        target = virNWFilterJumpTargetTypeToString(rule->action);
        skipMatch = defMatch;
    }

    if (match && !skipMatch)
        virBufferVSprintf(&buf, " %s", match);

    if (defMatch && match != NULL && !skipMatch && !hasICMPType)
        iptablesEnforceDirection(directionIn,
                                 rule,
                                 &buf);

    if (virBufferError(&afterStateMatch)) {
        virBufferFreeAndReset(&buf);
        virBufferFreeAndReset(&prefix);
        virBufferFreeAndReset(&afterStateMatch);
        virReportOOMError();
        return -1;
    }

    if (virBufferUse(&afterStateMatch)) {
        char *s = virBufferContentAndReset(&afterStateMatch);

        virBufferAdd(&buf, s, -1);

        VIR_FREE(s);
    }

    virBufferVSprintf(&buf,
                      " -j %s" CMD_DEF_POST CMD_SEPARATOR
                      CMD_EXEC,
                      target);

    if (virBufferError(&buf) || virBufferError(&prefix)) {
        virBufferFreeAndReset(&buf);
        virBufferFreeAndReset(&prefix);
        virReportOOMError();
        return -1;
    }

    if (virBufferUse(&prefix)) {
        char *s = virBufferContentAndReset(&buf);

        virBufferAdd(&prefix, s, -1);

        VIR_FREE(s);

        final = &prefix;

        if (virBufferError(&prefix)) {
            virBufferFreeAndReset(&prefix);
            virReportOOMError();
            return -1;
        }
    } else
        final = &buf;


    return ebiptablesAddRuleInst(res,
                                 virBufferContentAndReset(final),
                                 nwfilter->chainsuffix,
                                 '\0',
                                 rule->priority,
                                 (isIPv6) ? RT_IP6TABLES : RT_IPTABLES);


err_exit:
    virBufferFreeAndReset(&buf);
    virBufferFreeAndReset(&prefix);
    virBufferFreeAndReset(&afterStateMatch);

    return -1;

exit_no_error:
    virBufferFreeAndReset(&buf);
    virBufferFreeAndReset(&prefix);
    virBufferFreeAndReset(&afterStateMatch);

    return 0;
}


static int
printStateMatchFlags(int32_t flags, char **bufptr)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNWFilterPrintStateMatchFlags(&buf,
                                    "-m state --state ",
                                    flags,
                                    false);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return 1;
    }
    *bufptr = virBufferContentAndReset(&buf);
    return 0;
}

static int
iptablesCreateRuleInstanceStateCtrl(virNWFilterDefPtr nwfilter,
                                    virNWFilterRuleDefPtr rule,
                                    const char *ifname,
                                    virNWFilterHashTablePtr vars,
                                    virNWFilterRuleInstPtr res,
                                    bool isIPv6)
{
    int rc;
    int directionIn = 0;
    char chainPrefix[2];
    bool maySkipICMP, inout = false;
    char *matchState = NULL;
    bool create;

    if ((rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN) ||
        (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT)) {
        directionIn = 1;
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
        if (printStateMatchFlags(rule->flags, &matchState))
            return 1;
    }

    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    if (create) {
        rc = _iptablesCreateRuleInstance(directionIn,
                                         chainPrefix,
                                         nwfilter,
                                         rule,
                                         ifname,
                                         vars,
                                         res,
                                         matchState, false,
                                         "RETURN",
                                         isIPv6,
                                         maySkipICMP);

        VIR_FREE(matchState);
        if (rc)
            return rc;
    }

    maySkipICMP = !directionIn || inout;
    create = true;

    if (!directionIn) {
        if ((rule->flags & IPTABLES_STATE_FLAGS))
            create = false;
    }

    if (create && (rule->flags & IPTABLES_STATE_FLAGS)) {
        if (printStateMatchFlags(rule->flags, &matchState))
            return 1;
    }

    chainPrefix[1] = CHAINPREFIX_HOST_OUT_TEMP;
    if (create) {
        rc = _iptablesCreateRuleInstance(!directionIn,
                                         chainPrefix,
                                         nwfilter,
                                         rule,
                                         ifname,
                                         vars,
                                         res,
                                         matchState, false,
                                         "ACCEPT",
                                         isIPv6,
                                         maySkipICMP);

        VIR_FREE(matchState);

        if (rc)
            return rc;
    }

    maySkipICMP = directionIn;

    create = true;

    if (directionIn && !inout) {
        if ((rule->flags & IPTABLES_STATE_FLAGS))
            create = false;
    } else {
        if ((rule->flags & IPTABLES_STATE_FLAGS)) {
            if (printStateMatchFlags(rule->flags, &matchState))
                return 1;
        }
    }

    if (create) {
        chainPrefix[0] = 'H';
        chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
        rc = _iptablesCreateRuleInstance(directionIn,
                                         chainPrefix,
                                         nwfilter,
                                         rule,
                                         ifname,
                                         vars,
                                         res,
                                         matchState, false,
                                         "RETURN",
                                         isIPv6,
                                         maySkipICMP);
        VIR_FREE(matchState);
    }

    return rc;
}


static int
iptablesCreateRuleInstance(virNWFilterDefPtr nwfilter,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterHashTablePtr vars,
                           virNWFilterRuleInstPtr res,
                           bool isIPv6)
{
    int rc;
    int directionIn = 0;
    char chainPrefix[2];
    int needState = 1;
    bool maySkipICMP, inout = false;
    const char *matchState;

    if (!(rule->flags & RULE_FLAG_NO_STATEMATCH) &&
         (rule->flags & IPTABLES_STATE_FLAGS)) {
        return iptablesCreateRuleInstanceStateCtrl(nwfilter,
                                                   rule,
                                                   ifname,
                                                   vars,
                                                   res,
                                                   isIPv6);
    }

    if ((rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN) ||
        (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT)) {
        directionIn = 1;
        inout = (rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT);
        if (inout)
            needState = 0;
    }

    if ((rule->flags & RULE_FLAG_NO_STATEMATCH))
        needState = 0;

    chainPrefix[0] = 'F';

    maySkipICMP = directionIn || inout;

    if (needState)
        matchState = directionIn ? MATCH_STATE_IN : MATCH_STATE_OUT;
    else
        matchState = NULL;

    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    rc = _iptablesCreateRuleInstance(directionIn,
                                     chainPrefix,
                                     nwfilter,
                                     rule,
                                     ifname,
                                     vars,
                                     res,
                                     matchState, true,
                                     "RETURN",
                                     isIPv6,
                                     maySkipICMP);
    if (rc)
        return rc;


    maySkipICMP = !directionIn || inout;
    if (needState)
        matchState = directionIn ? MATCH_STATE_OUT : MATCH_STATE_IN;
    else
        matchState = NULL;

    chainPrefix[1] = CHAINPREFIX_HOST_OUT_TEMP;
    rc = _iptablesCreateRuleInstance(!directionIn,
                                     chainPrefix,
                                     nwfilter,
                                     rule,
                                     ifname,
                                     vars,
                                     res,
                                     matchState, true,
                                     "ACCEPT",
                                     isIPv6,
                                     maySkipICMP);
    if (rc)
        return rc;

    maySkipICMP = directionIn;
    if (needState)
        matchState = directionIn ? MATCH_STATE_IN : MATCH_STATE_OUT;
    else
        matchState = NULL;

    chainPrefix[0] = 'H';
    chainPrefix[1] = CHAINPREFIX_HOST_IN_TEMP;
    rc = _iptablesCreateRuleInstance(directionIn,
                                     chainPrefix,
                                     nwfilter,
                                     rule,
                                     ifname,
                                     vars,
                                     res,
                                     matchState, true,
                                     "RETURN",
                                     isIPv6,
                                     maySkipICMP);

    return rc;
}




/*
 * ebtablesCreateRuleInstance:
 * @chainPrefix : The prefix to put in front of the name of the chain
 * @nwfilter : The filter
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @res : The data structure to store the result(s) into
 * @reverse : Whether to reverse src and dst attributes
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, != 0 otherwise with the error message stored in the
 * virConnect object.
 */
static int
ebtablesCreateRuleInstance(char chainPrefix,
                           virNWFilterDefPtr nwfilter,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterHashTablePtr vars,
                           virNWFilterRuleInstPtr res,
                           bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN],
         ipaddr[INET_ADDRSTRLEN],
         ipv6addr[INET6_ADDRSTRLEN],
         number[20];
    char chain[MAX_CHAINNAME_LENGTH];
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *target;

    if (!ebtables_cmd_path) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create rule since ebtables tool is "
                                 "missing."));
        goto err_exit;
    }

    if (nwfilter->chainsuffix == VIR_NWFILTER_CHAINSUFFIX_ROOT)
        PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    else
        PRINT_CHAIN(chain, chainPrefix, ifname,
                    virNWFilterChainSuffixTypeToString(nwfilter->chainsuffix));


    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:

        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -t %s -%%c %s %%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);


        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ethHdrFilter.ethHdr,
                                 reverse))
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.ethHdrFilter.dataProtocolID)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ethHdrFilter.dataProtocolID))
                goto err_exit;
            virBufferVSprintf(&buf,
                          " -p %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.ethHdrFilter.dataProtocolID),
                          number);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
    case VIR_NWFILTER_RULE_PROTOCOL_RARP:

        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -t %s -%%c %s %%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.arpHdrFilter.ethHdr,
                                 reverse))
            goto err_exit;

        virBufferVSprintf(&buf, " -p 0x%x",
                          (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ARP)
                           ? l3_protocols[L3_PROTO_ARP_IDX].attr
                           : l3_protocols[L3_PROTO_RARP_IDX].attr);

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataHWType)) {
             if (printDataType(vars,
                               number, sizeof(number),
                               &rule->p.arpHdrFilter.dataHWType))
                goto err_exit;
           virBufferVSprintf(&buf,
                          " --arp-htype %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataHWType),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataOpcode)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.arpHdrFilter.dataOpcode))
                goto err_exit;
            virBufferVSprintf(&buf,
                          " --arp-opcode %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataOpcode),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataProtocolType)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.arpHdrFilter.dataProtocolType))
                goto err_exit;
            virBufferVSprintf(&buf,
                          " --arp-ptype %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataProtocolType),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPSrcIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-ip-dst" : "--arp-ip-src",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcIPAddr),
                          ipaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPDstIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-ip-src" : "--arp-ip-dst",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstIPAddr),
                          ipaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPSrcMACAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-mac-dst" : "--arp-mac-src",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcMACAddr),
                          macaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPDstMACAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-mac-src" : "--arp-mac-dst",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstMACAddr),
                          macaddr);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -t %s -%%c %s %%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ipHdrFilter.ethHdr,
                                 reverse))
            goto err_exit;

        virBufferAddLit(&buf,
                        " -p ipv4");

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-destination" : "--ip-source",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr),
                          ipaddr);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataSrcIPMask))
                    goto err_exit;
                virBufferVSprintf(&buf,
                             "/%s",
                             number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataDstIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-source" : "--ip-destination",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr),
                          ipaddr);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataDstIPMask))
                    goto err_exit;
                virBufferVSprintf(&buf,
                                  "/%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.ipHdr.dataProtocolID))
                goto err_exit;

            virBufferVSprintf(&buf,
                 " --ip-protocol %s %s",
                 ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataProtocolID),
                 number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataSrcPortStart))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-destination-port" : "--ip-source-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataSrcPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.portData.dataSrcPortEnd))
                    goto err_exit;

                virBufferVSprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataDstPortStart))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-source-port" : "--ip-destination-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataDstPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                number, sizeof(number),
                                &rule->p.ipHdrFilter.portData.dataDstPortEnd))
                    goto err_exit;

                virBufferVSprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDSCP)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ipHdrFilter.ipHdr.dataDSCP))
                goto err_exit;

            virBufferVSprintf(&buf,
                       " --ip-tos %s %s",
                       ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDSCP),
                       number);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -t %s -%%c %s %%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ipv6HdrFilter.ethHdr,
                                 reverse))
            goto err_exit;

        virBufferAddLit(&buf,
                        " -p ipv6");

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-destination" : "--ip6-source",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr),
                          ipv6addr);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask))
                    goto err_exit;
                virBufferVSprintf(&buf,
                             "/%s",
                             number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-source" : "--ip6-destination",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr),
                          ipv6addr);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask))
                    goto err_exit;
                virBufferVSprintf(&buf,
                                  "/%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.ipHdr.dataProtocolID))
                goto err_exit;

            virBufferVSprintf(&buf,
                 " --ip6-protocol %s %s",
                 ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID),
                 number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataSrcPortStart))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-destination-port" : "--ip6-source-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.portData.dataSrcPortEnd))
                    goto err_exit;

                virBufferVSprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataDstPortStart))
                goto err_exit;

            virBufferVSprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-source-port" : "--ip6-destination-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataDstPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.portData.dataDstPortEnd))
                    goto err_exit;

                virBufferVSprintf(&buf,
                                  ":%s",
                                  number);
            }
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
        virBufferVSprintf(&buf,
                          CMD_DEF_PRE "%s -t %s -%%c %s %%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);
    break;

    default:
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

    virBufferVSprintf(&buf,
                      " -j %s" CMD_DEF_POST CMD_SEPARATOR
                      CMD_EXEC,
                      target);

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return -1;
    }

    return ebiptablesAddRuleInst(res,
                                 virBufferContentAndReset(&buf),
                                 nwfilter->chainsuffix,
                                 chainPrefix,
                                 rule->priority,
                                 RT_EBTABLES);

err_exit:
    virBufferFreeAndReset(&buf);

    return -1;
}


/*
 * ebiptablesCreateRuleInstance:
 * @conn : Pointer to a virConnect object
 * @nwfilter : The filter
 * @rule: The rule of the filter to convert
 * @ifname : The name of the interface to apply the rule to
 * @vars : A map containing the variables to resolve
 * @res : The data structure to store the result(s) into
 *
 * Convert a single rule into its representation for later instantiation
 *
 * Returns 0 in case of success with the result stored in the data structure
 * pointed to by res, != 0 otherwise with the error message stored in the
 * virConnect object.
 */
static int
ebiptablesCreateRuleInstance(virConnectPtr conn ATTRIBUTE_UNUSED,
                             enum virDomainNetType nettype ATTRIBUTE_UNUSED,
                             virNWFilterDefPtr nwfilter,
                             virNWFilterRuleDefPtr rule,
                             const char *ifname,
                             virNWFilterHashTablePtr vars,
                             virNWFilterRuleInstPtr res)
{
    int rc = 0;
    bool isIPv6;

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_IP:
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
    case VIR_NWFILTER_RULE_PROTOCOL_RARP:
    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:

        if (rule->tt == VIR_NWFILTER_RULE_DIRECTION_OUT ||
            rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            rc = ebtablesCreateRuleInstance(CHAINPREFIX_HOST_IN_TEMP,
                                            nwfilter,
                                            rule,
                                            ifname,
                                            vars,
                                            res,
                                            rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT);
            if (rc)
                return rc;
        }

        if (rule->tt == VIR_NWFILTER_RULE_DIRECTION_IN ||
            rule->tt == VIR_NWFILTER_RULE_DIRECTION_INOUT) {
            rc = ebtablesCreateRuleInstance(CHAINPREFIX_HOST_OUT_TEMP,
                                            nwfilter,
                                            rule,
                                            ifname,
                                            vars,
                                            res,
                                            false);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
        isIPv6 = 0;
        rc = iptablesCreateRuleInstance(nwfilter,
                                        rule,
                                        ifname,
                                        vars,
                                        res,
                                        isIPv6);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        isIPv6 = 1;
        rc = iptablesCreateRuleInstance(nwfilter,
                                        rule,
                                        ifname,
                                        vars,
                                        res,
                                        isIPv6);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_LAST:
        virNWFilterReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("illegal protocol type"));
        rc = 1;
    break;
    }

    return rc;
}


static int
ebiptablesFreeRuleInstance(void *_inst)
{
    ebiptablesRuleInstFree((ebiptablesRuleInstPtr)_inst);
    return 0;
}


static int
ebiptablesDisplayRuleInstance(virConnectPtr conn ATTRIBUTE_UNUSED,
                              void *_inst)
{
    ebiptablesRuleInstPtr inst = (ebiptablesRuleInstPtr)_inst;
    VIR_INFO("Command Template: '%s', Needed protocol: '%s'",
             inst->commandTemplate,
             virNWFilterChainSuffixTypeToString(inst->neededProtocolChain));
    return 0;
}


/**
 * ebiptablesWriteToTempFile:
 * @string : the string to write into the file
 *
 * Returns the tempory filename where the string was written into,
 * NULL in case of error with the error reported.
 *
 * Write the string into a temporary file and return the name of
 * the temporary file. The string is assumed to contain executable
 * commands. A line '#!/bin/sh' will automatically be written
 * as the first line in the file. The permissions of the file are
 * set so that the file can be run as an executable script.
 */
static char *
ebiptablesWriteToTempFile(const char *string) {
    char filename[] = "/tmp/virtdXXXXXX";
    int len;
    char *filnam;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *header;
    size_t written;

    virBufferAddLit(&buf, "#!/bin/sh\n");

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }
    header = virBufferContentAndReset(&buf);

    int fd = mkstemp(filename);

    if (fd < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("cannot create temporary file"));
        goto err_exit;
    }

    if (fchmod(fd, S_IXUSR| S_IRUSR | S_IWUSR) < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("cannot change permissions on temp. file"));
        goto err_exit;
    }

    len = strlen(header);
    written = safewrite(fd, header, len);
    if (written != len) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("cannot write string to file"));
        goto err_exit;
    }

    len = strlen(string);
    written = safewrite(fd, string, len);
    if (written != len) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("cannot write string to file"));
        goto err_exit;
    }

    filnam = strdup(filename);
    if (!filnam) {
        virReportOOMError();
        goto err_exit;
    }

    VIR_FREE(header);
    VIR_FORCE_CLOSE(fd);
    return filnam;

err_exit:
    VIR_FREE(header);
    VIR_FORCE_CLOSE(fd);
    unlink(filename);
    return NULL;
}


/**
 * ebiptablesExecCLI:
 * @buf : pointer to virBuffer containing the string with the commands to
 *        execute.
 * @status: Pointer to an integer for returning the WEXITSTATUS of the
 *        commands executed via the script the was run.
 *
 * Returns 0 in case of success, != 0 in case of an error. The returned
 * value is NOT the result of running the commands inside the shell
 * script.
 *
 * Execute a sequence of commands (held in the given buffer) as a /bin/sh
 * script and return the status of the execution.
 */
static int
ebiptablesExecCLI(virBufferPtr buf,
                  int *status)
{
    char *cmds;
    char *filename;
    int rc;
    const char *argv[] = {NULL, NULL};

    if (virBufferError(buf)) {
        virReportOOMError();
        virBufferFreeAndReset(buf);
        return 1;
    }

    *status = 0;

    cmds = virBufferContentAndReset(buf);

    VIR_DEBUG("%s", NULLSTR(cmds));

    if (!cmds)
        return 0;

    filename = ebiptablesWriteToTempFile(cmds);
    VIR_FREE(cmds);

    if (!filename)
        return 1;

    argv[0] = filename;

    virMutexLock(&execCLIMutex);

    rc = virRun(argv, status);

    virMutexUnlock(&execCLIMutex);

    if (rc == 0) {
        if (WIFEXITED(*status)) {
            *status = WEXITSTATUS(*status);
        } else {
            rc = -1;
            *status = 1;
        }
    }

    VIR_DEBUG("rc = %d, status = %d", rc, *status);

    unlink(filename);

    VIR_FREE(filename);

    return rc;
}


static int
ebtablesCreateTmpRootChain(virBufferPtr buf,
                           int incoming, const char *ifname,
                           int stopOnError)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      CMD_DEF("%s -t %s -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,
                      CMD_STOPONERR(stopOnError));

    return 0;
}


static int
ebtablesLinkTmpRootChain(virBufferPtr buf,
                         int incoming, const char *ifname,
                         int stopOnError)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;
    char iodev = (incoming) ? 'i' : 'o';

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      CMD_DEF("%s -t %s -A %s -%c %s -j %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                      (incoming) ? EBTABLES_CHAIN_INCOMING
                                 : EBTABLES_CHAIN_OUTGOING,
                      iodev, ifname, chain,

                      CMD_STOPONERR(stopOnError));

    return 0;
}


static int
_ebtablesRemoveRootChain(virBufferPtr buf,
                         int incoming, const char *ifname,
                         int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix;
    if (isTempChain)
        chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                 : CHAINPREFIX_HOST_OUT_TEMP;
    else
        chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN
                                 : CHAINPREFIX_HOST_OUT;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      "%s -t %s -F %s" CMD_SEPARATOR
                      "%s -t %s -X %s" CMD_SEPARATOR,
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);

    return 0;
}


static int
ebtablesRemoveRootChain(virBufferPtr buf,
                        int incoming, const char *ifname)
{
    return _ebtablesRemoveRootChain(buf, incoming, ifname, 0);
}


static int
ebtablesRemoveTmpRootChain(virBufferPtr buf,
                           int incoming, const char *ifname)
{
    return _ebtablesRemoveRootChain(buf, incoming, ifname, 1);
}


static int
_ebtablesUnlinkRootChain(virBufferPtr buf,
                         int incoming, const char *ifname,
                         int isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char iodev = (incoming) ? 'i' : 'o';
    char chainPrefix;

    if (isTempChain) {
        chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                 : CHAINPREFIX_HOST_OUT_TEMP;
    } else {
        chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN
                                 : CHAINPREFIX_HOST_OUT;
    }

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferVSprintf(buf,
                      "%s -t %s -D %s -%c %s -j %s" CMD_SEPARATOR,
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                      (incoming) ? EBTABLES_CHAIN_INCOMING
                                 : EBTABLES_CHAIN_OUTGOING,
                      iodev, ifname, chain);

    return 0;
}


static int
ebtablesUnlinkRootChain(virBufferPtr buf,
                        int incoming, const char *ifname)
{
    return _ebtablesUnlinkRootChain(buf, incoming, ifname, 0);
}


static int
ebtablesUnlinkTmpRootChain(virBufferPtr buf,
                           int incoming, const char *ifname)
{
    return _ebtablesUnlinkRootChain(buf, incoming, ifname, 1);
}


static int
ebtablesCreateTmpSubChain(virBufferPtr buf,
                          int incoming,
                          const char *ifname,
                          enum l3_proto_idx protoidx,
                          int stopOnError)
{
    char rootchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = (incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                  : CHAINPREFIX_HOST_OUT_TEMP;

    PRINT_ROOT_CHAIN(rootchain, chainPrefix, ifname);
    PRINT_CHAIN(chain, chainPrefix, ifname, l3_protocols[protoidx].val);

    virBufferVSprintf(buf,
                      CMD_DEF("%s -t %s -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s"
                      CMD_DEF("%s -t %s -A %s -p 0x%x -j %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,

                      CMD_STOPONERR(stopOnError),

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                      rootchain, l3_protocols[protoidx].attr, chain,

                      CMD_STOPONERR(stopOnError));

    return 0;
}


static int
_ebtablesRemoveSubChain(virBufferPtr buf,
                        int incoming,
                        const char *ifname,
                        enum l3_proto_idx protoidx,
                        int isTempChain)
{
    char rootchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix;

    if (isTempChain) {
        chainPrefix =(incoming) ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;
    } else {
        chainPrefix =(incoming) ? CHAINPREFIX_HOST_IN
                                : CHAINPREFIX_HOST_OUT;
    }

    PRINT_ROOT_CHAIN(rootchain, chainPrefix, ifname);
    PRINT_CHAIN(chain, chainPrefix, ifname, l3_protocols[protoidx].val);

    virBufferVSprintf(buf,
                      "%s -t %s -D %s -p 0x%x -j %s" CMD_SEPARATOR
                      "%s -t %s -F %s" CMD_SEPARATOR
                      "%s -t %s -X %s" CMD_SEPARATOR,
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                      rootchain, l3_protocols[protoidx].attr, chain,

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain);

    return 0;
}


static int
ebtablesRemoveSubChain(virBufferPtr buf,
                       int incoming,
                       const char *ifname,
                       enum l3_proto_idx protoidx)
{
    return _ebtablesRemoveSubChain(buf,
                                   incoming, ifname, protoidx, 0);
}


static int
ebtablesRemoveSubChains(virBufferPtr buf,
                        const char *ifname)
{
    enum l3_proto_idx i;

    for (i = 0; i < L3_PROTO_LAST_IDX; i++) {
        ebtablesRemoveSubChain(buf, 1, ifname, i);
        ebtablesRemoveSubChain(buf, 0, ifname, i);
    }

    return 0;
}


static int
ebtablesRemoveTmpSubChain(virBufferPtr buf,
                          int incoming,
                          const char *ifname,
                          enum l3_proto_idx protoidx)
{
    return _ebtablesRemoveSubChain(buf,
                                   incoming, ifname, protoidx, 1);
}


static int
ebtablesRemoveTmpSubChains(virBufferPtr buf,
                           const char *ifname)
{
    enum l3_proto_idx i;

    for (i = 0; i < L3_PROTO_LAST_IDX; i++) {
        ebtablesRemoveTmpSubChain(buf, 1, ifname, i);
        ebtablesRemoveTmpSubChain(buf, 0, ifname, i);
    }

    return 0;
}


static int
ebtablesRenameTmpSubChain(virBufferPtr buf,
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
        PRINT_CHAIN(   chain,    chainPrefix, ifname, protocol);
    } else {
        PRINT_ROOT_CHAIN(tmpchain, tmpChainPrefix, ifname);
        PRINT_ROOT_CHAIN(   chain,    chainPrefix, ifname);
    }

    virBufferVSprintf(buf,
                      "%s -t %s -E %s %s" CMD_SEPARATOR,
                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, tmpchain, chain);
    return 0;
}


static int
ebtablesRenameTmpSubChains(virBufferPtr buf,
                           const char *ifname)
{
    enum l3_proto_idx i;

    for (i = 0; i < L3_PROTO_LAST_IDX; i++) {
        ebtablesRenameTmpSubChain (buf, 1, ifname, l3_protocols[i].val);
        ebtablesRenameTmpSubChain (buf, 0, ifname, l3_protocols[i].val);
    }

    return 0;
}


static int
ebtablesRenameTmpRootChain(virBufferPtr buf,
                           int incoming,
                           const char *ifname)
{
    return ebtablesRenameTmpSubChain(buf, incoming, ifname, NULL);
}


static void
ebiptablesInstCommand(virBufferPtr buf,
                      const char *templ, char cmd, int pos,
                      int stopOnError)
{
    char position[10] = { 0 };
    if (pos >= 0)
        snprintf(position, sizeof(position), "%d", pos);
    virBufferVSprintf(buf, templ, cmd, position);
    virBufferVSprintf(buf, CMD_SEPARATOR "%s",
                      CMD_STOPONERR(stopOnError));
}


/**
 * ebiptablesCanApplyBasicRules
 *
 * Determine whether this driver can apply the basic rules, meaning
 * run ebtablesApplyBasicRules and ebtablesApplyDHCPOnlyRules.
 * In case of this driver we need the ebtables tool available.
 */
static int
ebiptablesCanApplyBasicRules(void) {
    return (ebtables_cmd_path != NULL);
}

/**
 * ebtablesApplyBasicRules
 *
 * @conn: virConnect object
 * @ifname: name of the backend-interface to which to apply the rules
 * @macaddr: MAC address the VM is using in packets sent through the
 *    interface
 *
 * Returns 0 on success, 1 on failure with the rules removed
 *
 * Apply basic filtering rules on the given interface
 * - filtering for MAC address spoofing
 * - allowing IPv4 & ARP traffic
 */
static int
ebtablesApplyBasicRules(const char *ifname,
                        const unsigned char *macaddr)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = CHAINPREFIX_HOST_IN_TEMP;
    char macaddr_str[VIR_MAC_STRING_BUFLEN];

    if (!ebtables_cmd_path) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create rules since ebtables tool is "
                                 "missing."));
        return 1;
    }

    virFormatMacAddr(macaddr, macaddr_str);

    ebiptablesAllTeardown(ifname);

    ebtablesCreateTmpRootChain(&buf, 1, ifname, 1);

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -s ! %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                      chain, macaddr_str,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -p IPv4 -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -p ARP -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain,
                      CMD_STOPONERR(1));

    ebtablesLinkTmpRootChain(&buf, 1, ifname, 1);
    ebtablesRenameTmpRootChain(&buf, 1, ifname);

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_tmpebchains;

    return 0;

tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virNWFilterReportError(VIR_ERR_BUILD_FIREWALL,
                           "%s",
                           _("Some rules could not be created."));

    return 1;
}


/**
 * ebtablesApplyDHCPOnlyRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 * @macaddr: MAC address the VM is using in packets sent through the
 *    interface
 * @dhcpserver: The DHCP server from which the VM may receive traffic
 *    from; may be NULL
 *
 * Returns 0 on success, 1 on failure with the rules removed
 *
 * Apply filtering rules so that the VM can only send and receive
 * DHCP traffic and nothing else.
 */
static int
ebtablesApplyDHCPOnlyRules(const char *ifname,
                           const unsigned char *macaddr,
                           const char *dhcpserver)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];
    char macaddr_str[VIR_MAC_STRING_BUFLEN];
    char *srcIPParam = NULL;

    if (!ebtables_cmd_path) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create rules since ebtables tool is "
                                 "missing."));
        return 1;
    }

    if (dhcpserver) {
        virBufferVSprintf(&buf, " --ip-src %s", dhcpserver);
        if (virBufferError(&buf))
            return 1;
        srcIPParam = virBufferContentAndReset(&buf);
    }

    virFormatMacAddr(macaddr, macaddr_str);

    ebiptablesAllTeardown(ifname);

    ebtablesCreateTmpRootChain(&buf, 1, ifname, 1);
    ebtablesCreateTmpRootChain(&buf, 0, ifname, 1);

    PRINT_ROOT_CHAIN(chain_in , CHAINPREFIX_HOST_IN_TEMP , ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s"
                              " -s %s -d Broadcast "
                              " -p ipv4 --ip-protocol udp"
                              " --ip-src 0.0.0.0 --ip-dst 255.255.255.255"
                              " --ip-sport 68 --ip-dport 67"
                              " -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_in,
                      macaddr_str,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_in,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s"
                              " -d %s"
                              " -p ipv4 --ip-protocol udp"
                              " %s"
                              " --ip-sport 67 --ip-dport 68"
                              " -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_out,
                      macaddr_str,
                      srcIPParam != NULL ? srcIPParam : "",
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_out,
                      CMD_STOPONERR(1));

    ebtablesLinkTmpRootChain(&buf, 1, ifname, 1);
    ebtablesLinkTmpRootChain(&buf, 0, ifname, 1);
    ebtablesRenameTmpRootChain(&buf, 1, ifname);
    ebtablesRenameTmpRootChain(&buf, 0, ifname);

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_tmpebchains;

    VIR_FREE(srcIPParam);

    return 0;

tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virNWFilterReportError(VIR_ERR_BUILD_FIREWALL,
                           "%s",
                           _("Some rules could not be created."));

    VIR_FREE(srcIPParam);

    return 1;
}


/**
 * ebtablesApplyDropAllRules
 *
 * @ifname: name of the backend-interface to which to apply the rules
 *
 * Returns 0 on success, 1 on failure with the rules removed
 *
 * Apply filtering rules so that the VM cannot receive or send traffic.
 */
static int
ebtablesApplyDropAllRules(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];

    if (!ebtables_cmd_path) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create rules since ebtables tool is "
                                 "missing."));
        return 1;
    }

    ebiptablesAllTeardown(ifname);

    ebtablesCreateTmpRootChain(&buf, 1, ifname, 1);
    ebtablesCreateTmpRootChain(&buf, 0, ifname, 1);

    PRINT_ROOT_CHAIN(chain_in , CHAINPREFIX_HOST_IN_TEMP , ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_in,
                      CMD_STOPONERR(1));

    virBufferVSprintf(&buf,
                      CMD_DEF("%s -t %s -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      ebtables_cmd_path, EBTABLES_DEFAULT_TABLE, chain_out,
                      CMD_STOPONERR(1));

    ebtablesLinkTmpRootChain(&buf, 1, ifname, 1);
    ebtablesLinkTmpRootChain(&buf, 0, ifname, 1);
    ebtablesRenameTmpRootChain(&buf, 1, ifname);
    ebtablesRenameTmpRootChain(&buf, 0, ifname);

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_tmpebchains;

    return 0;

tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virNWFilterReportError(VIR_ERR_BUILD_FIREWALL,
                           "%s",
                           _("Some rules could not be created."));

    return 1;
}


static int
ebtablesRemoveBasicRules(const char *ifname)
{
    return ebtablesCleanAll(ifname);
}


static int ebtablesCleanAll(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;

    if (!ebtables_cmd_path)
        return 0;

    ebtablesUnlinkRootChain(&buf, 1, ifname);
    ebtablesUnlinkRootChain(&buf, 0, ifname);
    ebtablesRemoveSubChains(&buf, ifname);
    ebtablesRemoveRootChain(&buf, 1, ifname);
    ebtablesRemoveRootChain(&buf, 0, ifname);

    ebtablesUnlinkTmpRootChain(&buf, 1, ifname);
    ebtablesUnlinkTmpRootChain(&buf, 0, ifname);
    ebtablesRemoveTmpSubChains(&buf, ifname);
    ebtablesRemoveTmpRootChain(&buf, 1, ifname);
    ebtablesRemoveTmpRootChain(&buf, 0, ifname);

    ebiptablesExecCLI(&buf, &cli_status);
    return 0;
}


static int
ebiptablesRuleOrderSort(const void *a, const void *b)
{
    const ebiptablesRuleInstPtr *insta = a;
    const ebiptablesRuleInstPtr *instb = b;
    return ((*insta)->priority - (*instb)->priority);
}


static void
iptablesCheckBridgeNFCallEnabled(bool isIPv6)
{
    static time_t lastReport, lastReportIPv6;
    const char *pathname = NULL;
    char buffer[1];
    time_t now = time(NULL);

    if (isIPv6 &&
        (now - lastReportIPv6) > BRIDGE_NF_CALL_ALERT_INTERVAL ) {
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
                    VIR_WARN0(msg);
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


static int
ebiptablesApplyNewRules(virConnectPtr conn ATTRIBUTE_UNUSED,
                        const char *ifname,
                        int nruleInstances,
                        void **_inst)
{
    int i;
    int cli_status;
    ebiptablesRuleInstPtr *inst = (ebiptablesRuleInstPtr *)_inst;
    int chains_in = 0, chains_out = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool haveIptables = false;
    bool haveIp6tables = false;

    if (nruleInstances > 1 && inst)
        qsort(inst, nruleInstances, sizeof(inst[0]), ebiptablesRuleOrderSort);

    for (i = 0; i < nruleInstances; i++) {
        sa_assert (inst);
        if (inst[i]->ruleType == RT_EBTABLES) {
            if (inst[i]->chainprefix == CHAINPREFIX_HOST_IN_TEMP)
                chains_in  |= (1 << inst[i]->neededProtocolChain);
            else
                chains_out |= (1 << inst[i]->neededProtocolChain);
        }
    }

    if (ebtables_cmd_path) {
        ebtablesUnlinkTmpRootChain(&buf, 1, ifname);
        ebtablesUnlinkTmpRootChain(&buf, 0, ifname);
        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, 1, ifname);
        ebtablesRemoveTmpRootChain(&buf, 0, ifname);
        ebiptablesExecCLI(&buf, &cli_status);
    }

    if (chains_in != 0)
        ebtablesCreateTmpRootChain(&buf, 1, ifname, 1);
    if (chains_out != 0)
        ebtablesCreateTmpRootChain(&buf, 0, ifname, 1);

    if (chains_in  & (1 << VIR_NWFILTER_CHAINSUFFIX_IPv4))
        ebtablesCreateTmpSubChain(&buf, 1, ifname, L3_PROTO_IPV4_IDX, 1);
    if (chains_out & (1 << VIR_NWFILTER_CHAINSUFFIX_IPv4))
        ebtablesCreateTmpSubChain(&buf, 0, ifname, L3_PROTO_IPV4_IDX, 1);

    if (chains_in  & (1 << VIR_NWFILTER_CHAINSUFFIX_IPv6))
        ebtablesCreateTmpSubChain(&buf, 1, ifname, L3_PROTO_IPV6_IDX, 1);
    if (chains_out & (1 << VIR_NWFILTER_CHAINSUFFIX_IPv6))
        ebtablesCreateTmpSubChain(&buf, 0, ifname, L3_PROTO_IPV6_IDX, 1);

    /* keep arp,rarp as last */
    if (chains_in  & (1 << VIR_NWFILTER_CHAINSUFFIX_ARP))
        ebtablesCreateTmpSubChain(&buf, 1, ifname, L3_PROTO_ARP_IDX, 1);
    if (chains_out & (1 << VIR_NWFILTER_CHAINSUFFIX_ARP))
        ebtablesCreateTmpSubChain(&buf, 0, ifname, L3_PROTO_ARP_IDX, 1);
    if (chains_in  & (1 << VIR_NWFILTER_CHAINSUFFIX_RARP))
        ebtablesCreateTmpSubChain(&buf, 1, ifname, L3_PROTO_RARP_IDX, 1);
    if (chains_out & (1 << VIR_NWFILTER_CHAINSUFFIX_RARP))
        ebtablesCreateTmpSubChain(&buf, 0, ifname, L3_PROTO_RARP_IDX, 1);

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_tmpebchains;

    for (i = 0; i < nruleInstances; i++) {
        sa_assert (inst);
        switch (inst[i]->ruleType) {
        case RT_EBTABLES:
            ebiptablesInstCommand(&buf,
                                  inst[i]->commandTemplate,
                                  'A', -1, 1);
        break;
        case RT_IPTABLES:
            haveIptables = true;
        break;
        case RT_IP6TABLES:
            haveIp6tables = true;
        break;
        }
    }

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_tmpebchains;

    if (haveIptables) {
        iptablesUnlinkTmpRootChains(iptables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(iptables_cmd_path, &buf, ifname);

        iptablesCreateBaseChains(iptables_cmd_path, &buf);

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
            goto tear_down_tmpebchains;

        iptablesCreateTmpRootChains(iptables_cmd_path, &buf, ifname);

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpiptchains;

        iptablesLinkTmpRootChains(iptables_cmd_path, &buf, ifname);
        iptablesSetupVirtInPost(iptables_cmd_path, &buf, ifname);
        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpiptchains;

        for (i = 0; i < nruleInstances; i++) {
            sa_assert (inst);
            if (inst[i]->ruleType == RT_IPTABLES)
                iptablesInstCommand(&buf,
                                    inst[i]->commandTemplate,
                                    'A', -1, 1);
        }

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpiptchains;

        iptablesCheckBridgeNFCallEnabled(false);
    }

    if (haveIp6tables) {
        iptablesUnlinkTmpRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(ip6tables_cmd_path, &buf, ifname);

        iptablesCreateBaseChains(ip6tables_cmd_path, &buf);

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
            goto tear_down_tmpiptchains;

        iptablesCreateTmpRootChains(ip6tables_cmd_path, &buf, ifname);

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpip6tchains;

        iptablesLinkTmpRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesSetupVirtInPost(ip6tables_cmd_path, &buf, ifname);
        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpip6tchains;

        for (i = 0; i < nruleInstances; i++) {
            if (inst[i]->ruleType == RT_IP6TABLES)
                iptablesInstCommand(&buf,
                                    inst[i]->commandTemplate,
                                    'A', -1, 1);
        }

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
           goto tear_down_tmpip6tchains;

        iptablesCheckBridgeNFCallEnabled(true);
    }

    if (chains_in != 0)
        ebtablesLinkTmpRootChain(&buf, 1, ifname, 1);
    if (chains_out != 0)
        ebtablesLinkTmpRootChain(&buf, 0, ifname, 1);

    if (ebiptablesExecCLI(&buf, &cli_status) || cli_status != 0)
        goto tear_down_ebsubchains_and_unlink;

    return 0;

tear_down_ebsubchains_and_unlink:
    if (ebtables_cmd_path) {
        ebtablesUnlinkTmpRootChain(&buf, 1, ifname);
        ebtablesUnlinkTmpRootChain(&buf, 0, ifname);
    }

tear_down_tmpip6tchains:
    if (haveIp6tables) {
        iptablesUnlinkTmpRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(ip6tables_cmd_path, &buf, ifname);
    }

tear_down_tmpiptchains:
    if (haveIptables) {
        iptablesUnlinkTmpRootChains(iptables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(iptables_cmd_path, &buf, ifname);
    }

tear_down_tmpebchains:
    if (ebtables_cmd_path) {
        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, 1, ifname);
        ebtablesRemoveTmpRootChain(&buf, 0, ifname);
    }

    ebiptablesExecCLI(&buf, &cli_status);

    virNWFilterReportError(VIR_ERR_BUILD_FIREWALL,
                           _("Some rules could not be created for "
                             "interface %s."),
                           ifname);

    return 1;
}


static int
ebiptablesTearNewRules(virConnectPtr conn ATTRIBUTE_UNUSED,
                       const char *ifname)
{
    int cli_status;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (iptables_cmd_path) {
        iptablesUnlinkTmpRootChains(iptables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(iptables_cmd_path, &buf, ifname);
    }

    if (ip6tables_cmd_path) {
        iptablesUnlinkTmpRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesRemoveTmpRootChains(ip6tables_cmd_path, &buf, ifname);
    }

    if (ebtables_cmd_path) {
        ebtablesUnlinkTmpRootChain(&buf, 1, ifname);
        ebtablesUnlinkTmpRootChain(&buf, 0, ifname);

        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, 1, ifname);
        ebtablesRemoveTmpRootChain(&buf, 0, ifname);
    }

    ebiptablesExecCLI(&buf, &cli_status);

    return 0;
}


static int
ebiptablesTearOldRules(virConnectPtr conn ATTRIBUTE_UNUSED,
                       const char *ifname)
{
    int cli_status;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    /* switch to new iptables user defined chains */
    if (iptables_cmd_path) {
        iptablesUnlinkRootChains(iptables_cmd_path, &buf, ifname);
        iptablesRemoveRootChains(iptables_cmd_path, &buf, ifname);

        iptablesRenameTmpRootChains(iptables_cmd_path, &buf, ifname);
        ebiptablesExecCLI(&buf, &cli_status);
    }

    if (ip6tables_cmd_path) {
        iptablesUnlinkRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesRemoveRootChains(ip6tables_cmd_path, &buf, ifname);

        iptablesRenameTmpRootChains(ip6tables_cmd_path, &buf, ifname);
        ebiptablesExecCLI(&buf, &cli_status);
    }

    if (ebtables_cmd_path) {
        ebtablesUnlinkRootChain(&buf, 1, ifname);
        ebtablesUnlinkRootChain(&buf, 0, ifname);

        ebtablesRemoveSubChains(&buf, ifname);

        ebtablesRemoveRootChain(&buf, 1, ifname);
        ebtablesRemoveRootChain(&buf, 0, ifname);

        ebtablesRenameTmpSubChains(&buf, ifname);
        ebtablesRenameTmpRootChain(&buf, 1, ifname);
        ebtablesRenameTmpRootChain(&buf, 0, ifname);

        ebiptablesExecCLI(&buf, &cli_status);
    }

    return 0;
}


/**
 * ebiptablesRemoveRules:
 * @conn : pointer to virConnect object
 * @ifname : the name of the interface to which the rules apply
 * @nRuleInstance : the number of given rules
 * @_inst : array of rule instantiation data
 *
 * Remove all rules one after the other
 *
 * Return 0 on success, 1 if execution of one or more cleanup
 * commands failed.
 */
static int
ebiptablesRemoveRules(virConnectPtr conn ATTRIBUTE_UNUSED,
                      const char *ifname ATTRIBUTE_UNUSED,
                      int nruleInstances,
                      void **_inst)
{
    int rc = 0;
    int cli_status;
    int i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    ebiptablesRuleInstPtr *inst = (ebiptablesRuleInstPtr *)_inst;

    for (i = 0; i < nruleInstances; i++)
        ebiptablesInstCommand(&buf,
                              inst[i]->commandTemplate,
                              'D', -1,
                              0);

    if (ebiptablesExecCLI(&buf, &cli_status))
        goto err_exit;

    if (cli_status) {
        virNWFilterReportError(VIR_ERR_BUILD_FIREWALL,
                               "%s",
                               _("error while executing CLI commands"));
        rc = 1;
    }

err_exit:
    return rc;
}


/**
 * ebiptablesAllTeardown:
 * @ifname : the name of the interface to which the rules apply
 *
 * Unconditionally remove all possible user defined tables and rules
 * that were created for the given interface (ifname).
 *
 * Always returns 0.
 */
static int
ebiptablesAllTeardown(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;

    if (iptables_cmd_path) {
        iptablesUnlinkRootChains(iptables_cmd_path, &buf, ifname);
        iptablesClearVirtInPost (iptables_cmd_path, &buf, ifname);
        iptablesRemoveRootChains(iptables_cmd_path, &buf, ifname);
    }

    if (ip6tables_cmd_path) {
        iptablesUnlinkRootChains(ip6tables_cmd_path, &buf, ifname);
        iptablesClearVirtInPost (ip6tables_cmd_path, &buf, ifname);
        iptablesRemoveRootChains(ip6tables_cmd_path, &buf, ifname);
    }

    if (ebtables_cmd_path) {
        ebtablesUnlinkRootChain(&buf, 1, ifname);
        ebtablesUnlinkRootChain(&buf, 0, ifname);

        ebtablesRemoveRootChain(&buf, 1, ifname);
        ebtablesRemoveRootChain(&buf, 0, ifname);

        ebtablesRemoveSubChains(&buf, ifname);
    }

    ebiptablesExecCLI(&buf, &cli_status);

    return 0;
}


virNWFilterTechDriver ebiptables_driver = {
    .name = EBIPTABLES_DRIVER_ID,
    .flags = 0,

    .init     = ebiptablesDriverInit,
    .shutdown = ebiptablesDriverShutdown,

    .createRuleInstance  = ebiptablesCreateRuleInstance,
    .applyNewRules       = ebiptablesApplyNewRules,
    .tearNewRules        = ebiptablesTearNewRules,
    .tearOldRules        = ebiptablesTearOldRules,
    .allTeardown         = ebiptablesAllTeardown,
    .removeRules         = ebiptablesRemoveRules,
    .freeRuleInstance    = ebiptablesFreeRuleInstance,
    .displayRuleInstance = ebiptablesDisplayRuleInstance,

    .canApplyBasicRules  = ebiptablesCanApplyBasicRules,
    .applyBasicRules     = ebtablesApplyBasicRules,
    .applyDHCPOnlyRules  = ebtablesApplyDHCPOnlyRules,
    .applyDropAllRules   = ebtablesApplyDropAllRules,
    .removeBasicRules    = ebtablesRemoveBasicRules,
};


static int
ebiptablesDriverInit(bool privileged)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int cli_status;

    if (!privileged)
        return 0;

    if (virMutexInit(&execCLIMutex))
        return EINVAL;

    gawk_cmd_path = virFindFileInPath("gawk");
    grep_cmd_path = virFindFileInPath("grep");

    ebtables_cmd_path = virFindFileInPath("ebtables");
    if (ebtables_cmd_path) {
        /* basic probing */
        virBufferVSprintf(&buf,
                          CMD_DEF("%s -t %s -L") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          ebtables_cmd_path, EBTABLES_DEFAULT_TABLE,
                          CMD_STOPONERR(1));

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status)
             VIR_FREE(ebtables_cmd_path);
    }

    iptables_cmd_path = virFindFileInPath("iptables");
    if (iptables_cmd_path) {
        virBufferVSprintf(&buf,
                          CMD_DEF("%s -n -L FORWARD") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          iptables_cmd_path,
                          CMD_STOPONERR(1));

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status)
             VIR_FREE(iptables_cmd_path);
    }

    ip6tables_cmd_path = virFindFileInPath("ip6tables");
    if (ip6tables_cmd_path) {
        virBufferVSprintf(&buf,
                          CMD_DEF("%s -n -L FORWARD") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          ip6tables_cmd_path,
                          CMD_STOPONERR(1));

        if (ebiptablesExecCLI(&buf, &cli_status) || cli_status)
             VIR_FREE(ip6tables_cmd_path);
    }

    /* ip(6)tables support needs gawk & grep, ebtables doesn't */
    if ((iptables_cmd_path != NULL || ip6tables_cmd_path != NULL) &&
        (!grep_cmd_path || !gawk_cmd_path)) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("essential tools to support ip(6)tables "
                                 "firewalls could not be located"));
        VIR_FREE(iptables_cmd_path);
        VIR_FREE(ip6tables_cmd_path);
    }


    if (!ebtables_cmd_path && !iptables_cmd_path && !ip6tables_cmd_path) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("firewall tools were not found or "
                                 "cannot be used"));
        ebiptablesDriverShutdown();
        return ENOTSUP;
    }

    ebiptables_driver.flags = TECHDRV_FLAG_INITIALIZED;

    return 0;
}


static void
ebiptablesDriverShutdown(void)
{
    VIR_FREE(gawk_cmd_path);
    VIR_FREE(grep_cmd_path);
    VIR_FREE(ebtables_cmd_path);
    VIR_FREE(iptables_cmd_path);
    VIR_FREE(ip6tables_cmd_path);
    ebiptables_driver.flags = 0;
}
