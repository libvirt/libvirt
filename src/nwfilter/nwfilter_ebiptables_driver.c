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
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include <string.h>
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

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("nwfilter.nwfilter_ebiptables_driver");

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
#define CMD_EXEC   "eval res=\\$\\(\"${cmd} 2>&1\"\\)" CMD_SEPARATOR
#define CMD_STOPONERR(X) \
    X ? "if [ $? -ne 0 ]; then" \
        "  echo \"Failure to execute command '${cmd}' : '${res}'.\";" \
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

/* The collect_chains() script recursively determines all names
 * of ebtables (nat) chains that are 'children' of a given 'root' chain.
 * The typical output of an ebtables call is as follows:
 *
 * #> ebtables -t nat -L libvirt-I-tck-test205002
 * Bridge table: nat
 *
 * Bridge chain: libvirt-I-tck-test205002, entries: 5, policy: ACCEPT
 * -p IPv4 -j I-tck-test205002-ipv4
 * -p ARP -j I-tck-test205002-arp
 * -p 0x8035 -j I-tck-test205002-rarp
 * -p 0x835 -j ACCEPT
 * -j DROP
 */
static const char ebtables_script_func_collect_chains[] =
    "collect_chains()\n"
    "{\n"
    "  for tmp2 in $*; do\n"
    "    for tmp in $($EBT -t nat -L $tmp2 | \\\n"
    "      sed -n \"/Bridge chain/,\\$ s/.*-j \\\\([%s]-.*\\\\)/\\\\1/p\");\n"
    "    do\n"
    "      echo $tmp\n"
    "      collect_chains $tmp\n"
    "    done\n"
    "  done\n"
    "}\n";

static const char ebiptables_script_func_rm_chains[] =
    "rm_chains()\n"
    "{\n"
    "  for tmp in $*; do $EBT -t nat -F $tmp; done\n"
    "  for tmp in $*; do $EBT -t nat -X $tmp; done\n"
    "}\n";

static const char ebiptables_script_func_rename_chains[] =
    "rename_chain()\n"
    "{\n"
    "  $EBT -t nat -F $2\n"
    "  $EBT -t nat -X $2\n"
    "  $EBT -t nat -E $1 $2\n"
    "}\n"
    "rename_chains()\n"
    "{\n"
    "  for tmp in $*; do\n"
    "    case $tmp in\n"
    "      %c*) rename_chain $tmp %c${tmp#?} ;;\n"
    "      %c*) rename_chain $tmp %c${tmp#?} ;;\n"
    "    esac\n"
    "  done\n"
    "}\n";

static const char ebiptables_script_set_ifs[] =
    "tmp='\n'\n"
    "IFS=' ''\t'$tmp\n";

#define NWFILTER_FUNC_COLLECT_CHAINS ebtables_script_func_collect_chains
#define NWFILTER_FUNC_RM_CHAINS ebiptables_script_func_rm_chains
#define NWFILTER_FUNC_RENAME_CHAINS ebiptables_script_func_rename_chains
#define NWFILTER_FUNC_SET_IFS ebiptables_script_set_ifs

#define NWFILTER_SET_EBTABLES_SHELLVAR(BUFPTR) \
    virBufferAsprintf(BUFPTR, "EBT=\"%s\"\n", ebtables_cmd_path);
#define NWFILTER_SET_IPTABLES_SHELLVAR(BUFPTR) \
    virBufferAsprintf(BUFPTR, "IPT=\"%s\"\n", iptables_cmd_path);
#define NWFILTER_SET_IP6TABLES_SHELLVAR(BUFPTR) \
    virBufferAsprintf(BUFPTR, "IPT=\"%s\"\n", ip6tables_cmd_path);

#define VIRT_IN_CHAIN      "libvirt-in"
#define VIRT_OUT_CHAIN     "libvirt-out"
#define VIRT_IN_POST_CHAIN "libvirt-in-post"
#define HOST_IN_CHAIN      "libvirt-host-in"

#define PRINT_IPT_ROOT_CHAIN(buf, prefix, ifname) \
    snprintf(buf, sizeof(buf), "%c%c-%s", prefix[0], prefix[1], ifname)

#define PHYSDEV_IN  "--physdev-in"
#define PHYSDEV_OUT "--physdev-is-bridged --physdev-out"
/*
 * Previous versions of libvirt only used --physdev-out.
 * To be able to upgrade with running VMs we need to be able to
 * remove rules generated by those older versions of libvirt.
 */
#define PHYSDEV_OUT_OLD  "--physdev-out"

static const char *m_state_out_str   = "-m state --state NEW,ESTABLISHED";
static const char *m_state_in_str    = "-m state --state ESTABLISHED";
static const char *m_state_out_str_new = "-m conntrack --ctstate NEW,ESTABLISHED";
static const char *m_state_in_str_new  = "-m conntrack --ctstate ESTABLISHED";

static const char *m_physdev_in_str  = "-m physdev " PHYSDEV_IN;
static const char *m_physdev_out_str = "-m physdev " PHYSDEV_OUT;
static const char *m_physdev_out_old_str = "-m physdev " PHYSDEV_OUT_OLD;

#define MATCH_STATE_OUT    m_state_out_str
#define MATCH_STATE_IN     m_state_in_str
#define MATCH_PHYSDEV_IN   m_physdev_in_str
#define MATCH_PHYSDEV_OUT  m_physdev_out_str
#define MATCH_PHYSDEV_OUT_OLD  m_physdev_out_old_str

#define COMMENT_VARNAME "comment"

static int ebtablesRemoveBasicRules(const char *ifname);
static int ebiptablesDriverInit(bool privileged);
static void ebiptablesDriverShutdown(void);
static void ebtablesCleanAll(const char *ifname);
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

        if (!virStrcpy(buf, val, bufsize)) {
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
        if (virStrcpy(buf, item->u.ipset.setname, bufsize) == NULL) {
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

        if (virBufferError(&vb)) {
            virReportOOMError();
            virBufferFreeAndReset(&vb);
            return -1;
        }

        flags = virBufferContentAndReset(&vb);

        if (virStrcpy(buf, flags, bufsize) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Buffer too small for IPSETFLAGS type"));
            VIR_FREE(flags);
            return -1;
        }
        VIR_FREE(flags);
    break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unhandled datatype %x"), item->datatype);
        return -1;
    break;
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
    virBufferAddLit(dest, "'" CMD_SEPARATOR);
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
                      const char *neededChain,
                      virNWFilterChainPriority chainPriority,
                      char chainprefix,
                      virNWFilterRulePriority priority,
                      enum RuleType ruleType)
{
    ebiptablesRuleInstPtr inst;

    if (VIR_ALLOC(inst) < 0)
        return -1;

    inst->commandTemplate = commandTemplate;
    inst->neededProtocolChain = neededChain;
    inst->chainPriority = chainPriority;
    inst->chainprefix = chainprefix;
    inst->priority = priority;
    inst->ruleType = ruleType;

    if (VIR_APPEND_ELEMENT(res->data, res->ndata, inst) < 0) {
        VIR_FREE(inst);
        return -1;
    }
    return 0;
}


static int
ebtablesHandleEthHdr(virBufferPtr buf,
                     virNWFilterVarCombIterPtr vars,
                     ethHdrDataDefPtr ethHdr,
                     bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataSrcMACAddr) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                      " %s %s %s",
                      reverse ? "-d" : "-s",
                      ENTRY_GET_NEG_SIGN(&ethHdr->dataSrcMACAddr),
                      macaddr);

        if (HAS_ENTRY_ITEM(&ethHdr->dataSrcMACMask)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &ethHdr->dataSrcMACMask) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "/%s",
                              macaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACAddr)) {
        if (printDataType(vars,
                          macaddr, sizeof(macaddr),
                          &ethHdr->dataDstMACAddr) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                      " %s %s %s",
                      reverse ? "-s" : "-d",
                      ENTRY_GET_NEG_SIGN(&ethHdr->dataDstMACAddr),
                      macaddr);

        if (HAS_ENTRY_ITEM(&ethHdr->dataDstMACMask)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &ethHdr->dataDstMACMask) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "/%s",
                              macaddr);
        }
    }

    return 0;

 err_exit:
    virBufferFreeAndReset(buf);

    return -1;
}


/************************ iptables support ************************/

static void
iptablesLinkIPTablesBaseChain(virBufferPtr buf,
                              const char *udchain,
                              const char *syschain,
                              unsigned int pos)
{
    virBufferAsprintf(buf,
                      "res=$($IPT -L %s -n --line-number | %s '%s')\n"
                      "if [ $? -ne 0 ]; then\n"
                      "  $IPT -I %s %d -j %s\n"
                      "else\n"
                      "  set dummy $res; r=$2\n"
                      "  if [ \"${r}\" != \"%d\" ]; then\n"
                      "    " CMD_DEF("$IPT -I %s %d -j %s") CMD_SEPARATOR
                      "    " CMD_EXEC
                      "    %s"
                      "    r=$(( $r + 1 ))\n"
                      "    " CMD_DEF("$IPT -D %s ${r}") CMD_SEPARATOR
                      "    " CMD_EXEC
                      "    %s"
                      "  fi\n"
                      "fi\n",

                      syschain, grep_cmd_path, udchain,

                      syschain, pos, udchain,

                      pos,

                      syschain, pos, udchain,
                      CMD_STOPONERR(true),

                      syschain,
                      CMD_STOPONERR(true));
}


static void
iptablesCreateBaseChains(virBufferPtr buf)
{
    virBufferAddLit(buf, "$IPT -N " VIRT_IN_CHAIN      CMD_SEPARATOR
                         "$IPT -N " VIRT_OUT_CHAIN     CMD_SEPARATOR
                         "$IPT -N " VIRT_IN_POST_CHAIN CMD_SEPARATOR
                         "$IPT -N " HOST_IN_CHAIN      CMD_SEPARATOR);
    iptablesLinkIPTablesBaseChain(buf,
                                  VIRT_IN_CHAIN,      "FORWARD", 1);
    iptablesLinkIPTablesBaseChain(buf,
                                  VIRT_OUT_CHAIN,     "FORWARD", 2);
    iptablesLinkIPTablesBaseChain(buf,
                                  VIRT_IN_POST_CHAIN, "FORWARD", 3);
    iptablesLinkIPTablesBaseChain(buf,
                                  HOST_IN_CHAIN,      "INPUT",   1);
}


static void
iptablesCreateTmpRootChain(virBufferPtr buf,
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

    virBufferAsprintf(buf,
                      CMD_DEF("$IPT -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      chain,
                      CMD_STOPONERR(true));
}


static void
iptablesCreateTmpRootChains(virBufferPtr buf,
                            const char *ifname)
{
    iptablesCreateTmpRootChain(buf, 'F', false, ifname);
    iptablesCreateTmpRootChain(buf, 'F', true, ifname);
    iptablesCreateTmpRootChain(buf, 'H', true, ifname);
}


static void
_iptablesRemoveRootChain(virBufferPtr buf,
                         char prefix,
                         bool incoming, const char *ifname,
                         bool isTempChain)
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

    virBufferAsprintf(buf,
                      "$IPT -F %s" CMD_SEPARATOR
                      "$IPT -X %s" CMD_SEPARATOR,
                      chain,
                      chain);
}


static void
iptablesRemoveRootChain(virBufferPtr buf,
                        char prefix,
                        bool incoming,
                        const char *ifname)
{
    _iptablesRemoveRootChain(buf, prefix, incoming, ifname, false);
}


static void
iptablesRemoveTmpRootChain(virBufferPtr buf,
                           char prefix,
                           bool incoming,
                           const char *ifname)
{
    _iptablesRemoveRootChain(buf, prefix,
                             incoming, ifname, true);
}


static void
iptablesRemoveTmpRootChains(virBufferPtr buf,
                            const char *ifname)
{
    iptablesRemoveTmpRootChain(buf, 'F', false, ifname);
    iptablesRemoveTmpRootChain(buf, 'F', true, ifname);
    iptablesRemoveTmpRootChain(buf, 'H', true, ifname);
}


static void
iptablesRemoveRootChains(virBufferPtr buf,
                         const char *ifname)
{
    iptablesRemoveRootChain(buf, 'F', false, ifname);
    iptablesRemoveRootChain(buf, 'F', true, ifname);
    iptablesRemoveRootChain(buf, 'H', true, ifname);
}


static void
iptablesLinkTmpRootChain(virBufferPtr buf,
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
    const char *match = incoming ? MATCH_PHYSDEV_IN
                                 : MATCH_PHYSDEV_OUT;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferAsprintf(buf,
                      CMD_DEF("$IPT -A %s "
                              "%s %s -g %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      basechain,
                      match, ifname, chain,

                      CMD_STOPONERR(true));
}


static void
iptablesLinkTmpRootChains(virBufferPtr buf,
                          const char *ifname)
{
    iptablesLinkTmpRootChain(buf, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesLinkTmpRootChain(buf, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesLinkTmpRootChain(buf, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesSetupVirtInPost(virBufferPtr buf,
                        const char *ifname)
{
    const char *match = MATCH_PHYSDEV_IN;
    virBufferAsprintf(buf,
                      "res=$($IPT -n -L " VIRT_IN_POST_CHAIN
                      " | grep \"\\%s %s\")\n"
                      "if [ \"${res}\" = \"\" ]; then "
                        CMD_DEF("$IPT"
                        " -A " VIRT_IN_POST_CHAIN
                        " %s %s -j ACCEPT") CMD_SEPARATOR
                        CMD_EXEC
                        "%s"
                      "fi\n",
                      PHYSDEV_IN, ifname,
                      match, ifname,
                      CMD_STOPONERR(true));
}


static void
iptablesClearVirtInPost(virBufferPtr buf,
                        const char *ifname)
{
    const char *match = MATCH_PHYSDEV_IN;
    virBufferAsprintf(buf,
                      "$IPT -D " VIRT_IN_POST_CHAIN
                      " %s %s -j ACCEPT" CMD_SEPARATOR,
                      match, ifname);
}

static void
_iptablesUnlinkRootChain(virBufferPtr buf,
                         const char *basechain,
                         char prefix,
                         bool incoming, const char *ifname,
                         bool isTempChain)
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
    const char *match = incoming ? MATCH_PHYSDEV_IN
                                 : MATCH_PHYSDEV_OUT;
    const char *old_match = incoming ? NULL
                                     : MATCH_PHYSDEV_OUT_OLD;

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferAsprintf(buf,
                      "$IPT -D %s "
                      "%s %s -g %s" CMD_SEPARATOR,
                      basechain,
                      match, ifname, chain);

    /*
     * Previous versions of libvirt may have created a rule
     * with the --physdev-is-bridged missing. Remove this one
     * as well.
     */
    if (old_match)
        virBufferAsprintf(buf,
                          "$IPT -D %s "
                          "%s %s -g %s" CMD_SEPARATOR,
                          basechain,
                          old_match, ifname, chain);
}


static void
iptablesUnlinkRootChain(virBufferPtr buf,
                        const char *basechain,
                        char prefix,
                        bool incoming, const char *ifname)
{
    _iptablesUnlinkRootChain(buf,
                             basechain, prefix, incoming, ifname, false);
}


static void
iptablesUnlinkTmpRootChain(virBufferPtr buf,
                           const char *basechain,
                           char prefix,
                           bool incoming, const char *ifname)
{
    _iptablesUnlinkRootChain(buf,
                             basechain, prefix, incoming, ifname, true);
}


static void
iptablesUnlinkRootChains(virBufferPtr buf,
                         const char *ifname)
{
    iptablesUnlinkRootChain(buf, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesUnlinkRootChain(buf, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesUnlinkRootChain(buf, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesUnlinkTmpRootChains(virBufferPtr buf,
                            const char *ifname)
{
    iptablesUnlinkTmpRootChain(buf, VIRT_OUT_CHAIN, 'F', false, ifname);
    iptablesUnlinkTmpRootChain(buf, VIRT_IN_CHAIN,  'F', true, ifname);
    iptablesUnlinkTmpRootChain(buf, HOST_IN_CHAIN,  'H', true, ifname);
}


static void
iptablesRenameTmpRootChain(virBufferPtr buf,
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

    virBufferAsprintf(buf,
                      "$IPT -E %s %s" CMD_SEPARATOR,
                      tmpchain,
                      chain);
}


static void
iptablesRenameTmpRootChains(virBufferPtr buf,
                            const char *ifname)
{
    iptablesRenameTmpRootChain(buf, 'F', false, ifname);
    iptablesRenameTmpRootChain(buf, 'F', true, ifname);
    iptablesRenameTmpRootChain(buf, 'H', true, ifname);
}


static void
iptablesInstCommand(virBufferPtr buf,
                    const char *templ, char cmd, int pos)
{
    char position[10] = { 0 };
    if (pos >= 0)
        snprintf(position, sizeof(position), "%d", pos);
    virBufferAsprintf(buf, templ, cmd, position);
    virBufferAsprintf(buf, CMD_SEPARATOR "%s",
                      CMD_STOPONERR(true));
}


static int
iptablesHandleSrcMacAddr(virBufferPtr buf,
                         virNWFilterVarCombIterPtr vars,
                         nwItemDescPtr srcMacAddr,
                         bool directionIn,
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
                          srcMacAddr) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " -m mac %s --mac-source %s",
                          ENTRY_GET_NEG_SIGN(srcMacAddr),
                          macaddr);
    }

    return 0;

 err_exit:
    virBufferFreeAndReset(buf);

    return -1;
}


static int
iptablesHandleIpHdr(virBufferPtr buf,
                    virBufferPtr afterStateMatch,
                    virNWFilterVarCombIterPtr vars,
                    ipHdrDataDefPtr ipHdr,
                    bool directionIn,
                    bool *skipRule, bool *skipMatch,
                    virBufferPtr prefix)
{
    char ipaddr[INET6_ADDRSTRLEN],
         number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))];
    char str[MAX_IPSET_NAME_LENGTH];
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

    if (HAS_ENTRY_ITEM(&ipHdr->dataIPSet) &&
        HAS_ENTRY_ITEM(&ipHdr->dataIPSetFlags)) {

        if (printDataType(vars,
                          str, sizeof(str),
                          &ipHdr->dataIPSet) < 0)
            goto err_exit;

        virBufferAsprintf(afterStateMatch,
                          " -m set --match-set \"%s\" ",
                          str);

        if (printDataTypeDirection(vars,
                                   str, sizeof(str),
                                   &ipHdr->dataIPSetFlags, directionIn) < 0)
            goto err_exit;

        virBufferAdd(afterStateMatch, str, -1);
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPAddr)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPAddr) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataSrcIPAddr),
                          src,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPMask)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataSrcIPMask) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "/%s",
                              number);
        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPFrom)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataSrcIPFrom) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " -m iprange %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataSrcIPFrom),
                          srcrange,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataSrcIPTo)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &ipHdr->dataSrcIPTo) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "-%s",
                              ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPAddr)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPAddr) < 0)
           goto err_exit;

        virBufferAsprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataDstIPAddr),
                          dst,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPMask)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &ipHdr->dataDstIPMask) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "/%s",
                              number);

        }
    } else if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPFrom)) {

        if (printDataType(vars,
                          ipaddr, sizeof(ipaddr),
                          &ipHdr->dataDstIPFrom) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " -m iprange %s %s %s",
                          ENTRY_GET_NEG_SIGN(&ipHdr->dataDstIPFrom),
                          dstrange,
                          ipaddr);

        if (HAS_ENTRY_ITEM(&ipHdr->dataDstIPTo)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &ipHdr->dataDstIPTo) < 0)
                goto err_exit;

            virBufferAsprintf(buf,
                              "-%s",
                              ipaddr);
        }
    }

    if (HAS_ENTRY_ITEM(&ipHdr->dataDSCP)) {

        if (printDataType(vars,
                          number, sizeof(number),
                          &ipHdr->dataDSCP) < 0)
           goto err_exit;

        virBufferAsprintf(buf,
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
                              &ipHdr->dataConnlimitAbove) < 0)
               goto err_exit;

            /* place connlimit after potential -m state --state ...
               since this is the most useful order */
            virBufferAsprintf(afterStateMatch,
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

    return -1;
}


static int
iptablesHandlePortData(virBufferPtr buf,
                       virNWFilterVarCombIterPtr vars,
                       portDataDefPtr portData,
                       bool directionIn)
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
                          &portData->dataSrcPortStart) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&portData->dataSrcPortStart),
                          sport,
                          portstr);

        if (HAS_ENTRY_ITEM(&portData->dataSrcPortEnd)) {
            if (printDataType(vars,
                              portstr, sizeof(portstr),
                              &portData->dataSrcPortEnd) < 0)
                goto err_exit;

             virBufferAsprintf(buf,
                               ":%s",
                               portstr);
        }
    }

    if (HAS_ENTRY_ITEM(&portData->dataDstPortStart)) {
        if (printDataType(vars,
                          portstr, sizeof(portstr),
                          &portData->dataDstPortStart) < 0)
            goto err_exit;

        virBufferAsprintf(buf,
                          " %s %s %s",
                          ENTRY_GET_NEG_SIGN(&portData->dataDstPortStart),
                          dport,
                          portstr);

        if (HAS_ENTRY_ITEM(&portData->dataDstPortEnd)) {
            if (printDataType(vars,
                              portstr, sizeof(portstr),
                              &portData->dataDstPortEnd) < 0)
                goto err_exit;

             virBufferAsprintf(buf,
                               ":%s",
                               portstr);
        }
    }

    return 0;

 err_exit:
    return -1;
}


static void
iptablesEnforceDirection(bool directionIn,
                         virNWFilterRuleDefPtr rule,
                         virBufferPtr buf)
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
        virBufferAsprintf(buf, " -m conntrack --ctdir %s",
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
 * pointed to by res, != 0 otherwise.
 */
static int
_iptablesCreateRuleInstance(bool directionIn,
                            const char *chainPrefix,
                            virNWFilterDefPtr nwfilter,
                            virNWFilterRuleDefPtr rule,
                            const char *ifname,
                            virNWFilterVarCombIterPtr vars,
                            virNWFilterRuleInstPtr res,
                            const char *match, bool defMatch,
                            const char *accept_target,
                            bool isIPv6,
                            bool maySkipICMP)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))];
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot create rule since %s tool is "
                         "missing."),
                       isIPv6 ? "ip6tables" : "iptables");
        goto err_exit;
    }

    PRINT_IPT_ROOT_CHAIN(chain, chainPrefix, ifname);

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p tcp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.tcpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.tcpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPFlags)) {
            virBufferAsprintf(&buf, " %s --tcp-flags ",
                      ENTRY_GET_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPFlags));
            virNWFilterPrintTCPFlags(&buf,
                      rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.mask,
                      ' ',
                      rule->p.tcpHdrFilter.dataTCPFlags.u.tcpFlags.flags);
        }

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.tcpHdrFilter.portData,
                                   directionIn) < 0)
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.tcpHdrFilter.dataTCPOption)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.tcpHdrFilter.dataTCPOption) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                              " %s --tcp-option %s",
                              ENTRY_GET_NEG_SIGN(&rule->p.tcpHdrFilter.dataTCPOption),
                              number);
        }

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p udp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.udpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.udpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.udpHdrFilter.portData,
                                   directionIn) < 0)
            goto err_exit;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p udplite");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.udpliteHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.udpliteHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p esp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.espHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.espHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p ah");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.ahHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.ahHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p sctp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.sctpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.sctpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

        if (iptablesHandlePortData(&buf,
                                   vars,
                                   &rule->p.sctpHdrFilter.portData,
                                   directionIn) < 0)
            goto err_exit;
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
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
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.icmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
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
                              &rule->p.icmpHdrFilter.dataICMPType) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                      " %s %s %s",
                      ENTRY_GET_NEG_SIGN(&rule->p.icmpHdrFilter.dataICMPType),
                      parm,
                      number);

            if (HAS_ENTRY_ITEM(&rule->p.icmpHdrFilter.dataICMPCode)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.icmpHdrFilter.dataICMPCode) < 0)
                    goto err_exit;

                 virBufferAsprintf(&buf,
                                   "/%s",
                                   number);
            }
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p igmp");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.igmpHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.igmpHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
            goto err_exit;

    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$IPT -%%c %s %%s",
                          chain);

        virBufferAddLit(&buf, " -p all");

        bufUsed = virBufferUse(&buf);

        if (iptablesHandleSrcMacAddr(&buf,
                                     vars,
                                     &rule->p.allHdrFilter.dataSrcMACAddr,
                                     directionIn,
                                     &srcMacSkipped) < 0)
            goto err_exit;

        if (iptablesHandleIpHdr(&buf,
                                &afterStateMatch,
                                vars,
                                &rule->p.allHdrFilter.ipHdr,
                                directionIn,
                                &skipRule, &skipMatch,
                                &prefix) < 0)
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
        virBufferAsprintf(&buf, " %s", match);

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

    virBufferAsprintf(&buf,
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
                                 nwfilter->chainPriority,
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
        return -1;
    }
    *bufptr = virBufferContentAndReset(&buf);
    return 0;
}

static int
iptablesCreateRuleInstanceStateCtrl(virNWFilterDefPtr nwfilter,
                                    virNWFilterRuleDefPtr rule,
                                    const char *ifname,
                                    virNWFilterVarCombIterPtr vars,
                                    virNWFilterRuleInstPtr res,
                                    bool isIPv6)
{
    int rc;
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
                           virNWFilterVarCombIterPtr vars,
                           virNWFilterRuleInstPtr res,
                           bool isIPv6)
{
    int rc;
    bool directionIn = false;
    char chainPrefix[2];
    bool needState = true;
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
    if (rc < 0)
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
    if (rc < 0)
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
 * pointed to by res, != 0 otherwise.
 */
static int
ebtablesCreateRuleInstance(char chainPrefix,
                           virNWFilterDefPtr nwfilter,
                           virNWFilterRuleDefPtr rule,
                           const char *ifname,
                           virNWFilterVarCombIterPtr vars,
                           virNWFilterRuleInstPtr res,
                           bool reverse)
{
    char macaddr[VIR_MAC_STRING_BUFLEN],
         ipaddr[INET_ADDRSTRLEN],
         ipmask[INET_ADDRSTRLEN],
         ipv6addr[INET6_ADDRSTRLEN],
         number[MAX(INT_BUFSIZE_BOUND(uint32_t),
                    INT_BUFSIZE_BOUND(int))],
         field[MAX(VIR_MAC_STRING_BUFLEN, INET6_ADDRSTRLEN)];
    char chain[MAX_CHAINNAME_LENGTH];
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *target;
    bool hasMask = false;

    if (!ebtables_cmd_path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create rule since ebtables tool is "
                         "missing."));
        goto err_exit;
    }

    if (STREQ(nwfilter->chainsuffix,
              virNWFilterChainSuffixTypeToString(
                  VIR_NWFILTER_CHAINSUFFIX_ROOT)))
        PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    else
        PRINT_CHAIN(chain, chainPrefix, ifname,
                    nwfilter->chainsuffix);


    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:

        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ethHdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        if (HAS_ENTRY_ITEM(&rule->p.ethHdrFilter.dataProtocolID)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ethHdrFilter.dataProtocolID) < 0)
                goto err_exit;
            virBufferAsprintf(&buf,
                          " -p %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.ethHdrFilter.dataProtocolID),
                          number);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:

        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);


        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.vlanHdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        virBufferAddLit(&buf,
                        " -p 0x8100");

#define INST_ITEM(STRUCT, ITEM, CLI) \
        if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM)) { \
            if (printDataType(vars, \
                              field, sizeof(field), \
                              &rule->p.STRUCT.ITEM) < 0) \
                goto err_exit; \
            virBufferAsprintf(&buf, \
                          " " CLI " %s %s", \
                          ENTRY_GET_NEG_SIGN(&rule->p.STRUCT.ITEM), \
                          field); \
        }

#define INST_ITEM_2PARMS(STRUCT, ITEM, ITEM_HI, CLI, SEP) \
        if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM)) { \
            if (printDataType(vars, \
                              field, sizeof(field), \
                              &rule->p.STRUCT.ITEM) < 0) \
                goto err_exit; \
            virBufferAsprintf(&buf, \
                          " " CLI " %s %s", \
                          ENTRY_GET_NEG_SIGN(&rule->p.STRUCT.ITEM), \
                          field); \
            if (HAS_ENTRY_ITEM(&rule->p.STRUCT.ITEM_HI)) { \
                if (printDataType(vars, \
                                  field, sizeof(field), \
                                  &rule->p.STRUCT.ITEM_HI) < 0) \
                    goto err_exit; \
                virBufferAsprintf(&buf, SEP "%s", field); \
            } \
        }
#define INST_ITEM_RANGE(S, I, I_HI, C) \
    INST_ITEM_2PARMS(S, I, I_HI, C, ":")
#define INST_ITEM_MASK(S, I, MASK, C) \
    INST_ITEM_2PARMS(S, I, MASK, C, "/")

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

        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);


        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.stpHdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        virBufferAddLit(&buf, " -d " NWFILTER_MAC_BGA);

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

        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.arpHdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        virBufferAsprintf(&buf, " -p 0x%x",
                          (rule->prtclType == VIR_NWFILTER_RULE_PROTOCOL_ARP)
                           ? l3_protocols[L3_PROTO_ARP_IDX].attr
                           : l3_protocols[L3_PROTO_RARP_IDX].attr);

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataHWType)) {
             if (printDataType(vars,
                               number, sizeof(number),
                               &rule->p.arpHdrFilter.dataHWType) < 0)
                goto err_exit;
           virBufferAsprintf(&buf,
                          " --arp-htype %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataHWType),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataOpcode)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.arpHdrFilter.dataOpcode) < 0)
                goto err_exit;
            virBufferAsprintf(&buf,
                          " --arp-opcode %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataOpcode),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataProtocolType)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.arpHdrFilter.dataProtocolType) < 0)
                goto err_exit;
            virBufferAsprintf(&buf,
                          " --arp-ptype %s %s",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataProtocolType),
                          number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPSrcIPAddr) < 0)
                goto err_exit;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcIPMask)) {
                if (printDataType(vars,
                                  ipmask, sizeof(ipmask),
                                  &rule->p.arpHdrFilter.dataARPSrcIPMask) < 0)
                    goto err_exit;
                hasMask = true;
            }

            virBufferAsprintf(&buf,
                          " %s %s %s/%s",
                          reverse ? "--arp-ip-dst" : "--arp-ip-src",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcIPAddr),
                          ipaddr,
                          hasMask ? ipmask : "32");
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.arpHdrFilter.dataARPDstIPAddr) < 0)
                goto err_exit;

            if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstIPMask)) {
                if (printDataType(vars,
                                  ipmask, sizeof(ipmask),
                                  &rule->p.arpHdrFilter.dataARPDstIPMask) < 0)
                    goto err_exit;
                hasMask = true;
            }

            virBufferAsprintf(&buf,
                          " %s %s %s/%s",
                          reverse ? "--arp-ip-src" : "--arp-ip-dst",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstIPAddr),
                          ipaddr,
                          hasMask ? ipmask : "32");
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPSrcMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPSrcMACAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-mac-dst" : "--arp-mac-src",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPSrcMACAddr),
                          macaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataARPDstMACAddr)) {
            if (printDataType(vars,
                              macaddr, sizeof(macaddr),
                              &rule->p.arpHdrFilter.dataARPDstMACAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--arp-mac-src" : "--arp-mac-dst",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataARPDstMACAddr),
                          macaddr);
        }

        if (HAS_ENTRY_ITEM(&rule->p.arpHdrFilter.dataGratuitousARP) &&
            rule->p.arpHdrFilter.dataGratuitousARP.u.boolean) {
            virBufferAsprintf(&buf,
                          " %s --arp-gratuitous",
                          ENTRY_GET_NEG_SIGN(&rule->p.arpHdrFilter.dataGratuitousARP));
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ipHdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        virBufferAddLit(&buf,
                        " -p ipv4");

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-destination" : "--ip-source",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr),
                          ipaddr);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataSrcIPMask)
                    < 0)
                    goto err_exit;
                virBufferAsprintf(&buf,
                             "/%s",
                             number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipaddr, sizeof(ipaddr),
                              &rule->p.ipHdrFilter.ipHdr.dataDstIPAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-source" : "--ip-destination",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDstIPAddr),
                          ipaddr);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.ipHdr.dataDstIPMask)
                    < 0)
                    goto err_exit;
                virBufferAsprintf(&buf,
                                  "/%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.ipHdr.dataProtocolID) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                 " --ip-protocol %s %s",
                 ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataProtocolID),
                 number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataSrcPortStart)
                < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-destination-port" : "--ip-source-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataSrcPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipHdrFilter.portData.dataSrcPortEnd)
                    < 0)
                    goto err_exit;

                virBufferAsprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipHdrFilter.portData.dataDstPortStart)
                < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip-source-port" : "--ip-destination-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.portData.dataDstPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                number, sizeof(number),
                                &rule->p.ipHdrFilter.portData.dataDstPortEnd)
                    < 0)
                    goto err_exit;

                virBufferAsprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipHdrFilter.ipHdr.dataDSCP)) {
            if (printDataTypeAsHex(vars,
                                   number, sizeof(number),
                                   &rule->p.ipHdrFilter.ipHdr.dataDSCP) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                       " --ip-tos %s %s",
                       ENTRY_GET_NEG_SIGN(&rule->p.ipHdrFilter.ipHdr.dataDSCP),
                       number);
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);

        if (ebtablesHandleEthHdr(&buf,
                                 vars,
                                 &rule->p.ipv6HdrFilter.ethHdr,
                                 reverse) < 0)
            goto err_exit;

        virBufferAddLit(&buf,
                        " -p ipv6");

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr)) {
            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-destination" : "--ip6-source",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr),
                          ipv6addr);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask)
                    < 0)
                    goto err_exit;
                virBufferAsprintf(&buf,
                             "/%s",
                             number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr)) {

            if (printDataType(vars,
                              ipv6addr, sizeof(ipv6addr),
                              &rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-source" : "--ip6-destination",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr),
                          ipv6addr);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask)
                    < 0)
                    goto err_exit;
                virBufferAsprintf(&buf,
                                  "/%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID)) {
            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.ipHdr.dataProtocolID) < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                 " --ip6-protocol %s %s",
                 ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.ipHdr.dataProtocolID),
                 number);
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataSrcPortStart)
                < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-destination-port" : "--ip6-source-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataSrcPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataSrcPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.portData.dataSrcPortEnd)
                    < 0)
                    goto err_exit;

                virBufferAsprintf(&buf,
                                  ":%s",
                                  number);
            }
        }

        if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortStart)) {

            if (printDataType(vars,
                              number, sizeof(number),
                              &rule->p.ipv6HdrFilter.portData.dataDstPortStart)
                < 0)
                goto err_exit;

            virBufferAsprintf(&buf,
                          " %s %s %s",
                          reverse ? "--ip6-source-port" : "--ip6-destination-port",
                          ENTRY_GET_NEG_SIGN(&rule->p.ipv6HdrFilter.portData.dataDstPortStart),
                          number);

            if (HAS_ENTRY_ITEM(&rule->p.ipv6HdrFilter.portData.dataDstPortEnd)) {
                if (printDataType(vars,
                                  number, sizeof(number),
                                  &rule->p.ipv6HdrFilter.portData.dataDstPortEnd)
                    < 0)
                    goto err_exit;

                virBufferAsprintf(&buf,
                                  ":%s",
                                  number);
            }
        }
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
        virBufferAsprintf(&buf,
                          CMD_DEF_PRE "$EBT -t nat -%%c %s %%s",
                          chain);
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

    virBufferAsprintf(&buf,
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
                                 nwfilter->chainPriority,
                                 chainPrefix,
                                 rule->priority,
                                 RT_EBTABLES);

 err_exit:
    virBufferFreeAndReset(&buf);

    return -1;
}


/*
 * ebiptablesCreateRuleInstance:
 * @nwfilter : The filter
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
ebiptablesCreateRuleInstance(enum virDomainNetType nettype ATTRIBUTE_UNUSED,
                             virNWFilterDefPtr nwfilter,
                             virNWFilterRuleDefPtr rule,
                             const char *ifname,
                             virNWFilterVarCombIterPtr vars,
                             virNWFilterRuleInstPtr res)
{
    int rc = 0;
    bool isIPv6;

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_IP:
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:
    case VIR_NWFILTER_RULE_PROTOCOL_STP:
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
            if (rc < 0)
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
        isIPv6 = false;
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
        isIPv6 = true;
        rc = iptablesCreateRuleInstance(nwfilter,
                                        rule,
                                        ifname,
                                        vars,
                                        res,
                                        isIPv6);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_LAST:
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("illegal protocol type"));
        rc = -1;
    break;
    }

    return rc;
}

static int
ebiptablesCreateRuleInstanceIterate(
                             enum virDomainNetType nettype ATTRIBUTE_UNUSED,
                             virNWFilterDefPtr nwfilter,
                             virNWFilterRuleDefPtr rule,
                             const char *ifname,
                             virNWFilterHashTablePtr vars,
                             virNWFilterRuleInstPtr res)
{
    int rc = 0;
    virNWFilterVarCombIterPtr vciter, tmp;

    /* rule->vars holds all the variables names that this rule will access.
     * iterate over all combinations of the variables' values and instantiate
     * the filtering rule with each combination.
     */
    tmp = vciter = virNWFilterVarCombIterCreate(vars,
                                                rule->varAccess, rule->nVarAccess);
    if (!vciter)
        return -1;

    do {
        rc = ebiptablesCreateRuleInstance(nettype,
                                          nwfilter,
                                          rule,
                                          ifname,
                                          tmp,
                                          res);
        if (rc < 0)
            break;
        tmp = virNWFilterVarCombIterNext(tmp);
    } while (tmp != NULL);

    virNWFilterVarCombIterFree(vciter);

    return rc;
}

static int
ebiptablesFreeRuleInstance(void *_inst)
{
    ebiptablesRuleInstFree((ebiptablesRuleInstPtr)_inst);
    return 0;
}


static int
ebiptablesDisplayRuleInstance(void *_inst)
{
    ebiptablesRuleInstPtr inst = (ebiptablesRuleInstPtr)_inst;
    VIR_INFO("Command Template: '%s', Needed protocol: '%s'",
             inst->commandTemplate,
             inst->neededProtocolChain);
    return 0;
}


/**
 * ebiptablesExecCLI:
 * @buf: pointer to virBuffer containing the string with the commands to
 *       execute.
 * @ignoreNonzero: true if non-zero status is not fatal
 * @outbuf: Optional pointer to a string that will hold the buffer with
 *          output of the executed command. The actual buffer holding
 *          the message will be newly allocated by this function and
 *          any passed in buffer freed first.
 *
 * Returns 0 in case of success, < 0 in case of an error. The returned
 * value is NOT the result of running the commands inside the shell
 * script.
 *
 * Execute a sequence of commands (held in the given buffer) as a /bin/sh
 * script.  Depending on ignoreNonzero, this function will fail if the
 * script has unexpected status.
 */
static int
ebiptablesExecCLI(virBufferPtr buf, bool ignoreNonzero, char **outbuf)
{
    int rc = -1;
    virCommandPtr cmd;
    int status;

    if (!virBufferError(buf) && !virBufferUse(buf))
        return 0;

    if (outbuf)
        VIR_FREE(*outbuf);

    cmd = virCommandNewArgList("/bin/sh", "-c", NULL);
    virCommandAddArgBuffer(cmd, buf);
    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);

    virMutexLock(&execCLIMutex);

    rc = virCommandRun(cmd, ignoreNonzero ? &status : NULL);

    virMutexUnlock(&execCLIMutex);

    virCommandFree(cmd);

    return rc;
}


static void
ebtablesCreateTmpRootChain(virBufferPtr buf,
                           bool incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferAsprintf(buf,
                      CMD_DEF("$EBT -t nat -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      chain,
                      CMD_STOPONERR(true));

}


static void
ebtablesLinkTmpRootChain(virBufferPtr buf,
                         bool incoming, const char *ifname)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;
    char iodev = incoming ? 'i' : 'o';

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferAsprintf(buf,
                      CMD_DEF("$EBT -t nat -A %s -%c %s -j %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",
                      incoming ? EBTABLES_CHAIN_INCOMING
                               : EBTABLES_CHAIN_OUTGOING,
                      iodev, ifname, chain,

                      CMD_STOPONERR(true));
}


static void
_ebtablesRemoveRootChain(virBufferPtr buf,
                         bool incoming, const char *ifname,
                         bool isTempChain)
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

    virBufferAsprintf(buf,
                      "$EBT -t nat -F %s" CMD_SEPARATOR
                      "$EBT -t nat -X %s" CMD_SEPARATOR,
                      chain,
                      chain);
}


static void
ebtablesRemoveRootChain(virBufferPtr buf,
                        bool incoming, const char *ifname)
{
    _ebtablesRemoveRootChain(buf, incoming, ifname, false);
}


static void
ebtablesRemoveTmpRootChain(virBufferPtr buf,
                           bool incoming, const char *ifname)
{
    _ebtablesRemoveRootChain(buf, incoming, ifname, true);
}


static void
_ebtablesUnlinkRootChain(virBufferPtr buf,
                         bool incoming, const char *ifname,
                         bool isTempChain)
{
    char chain[MAX_CHAINNAME_LENGTH];
    char iodev = incoming ? 'i' : 'o';
    char chainPrefix;

    if (isTempChain) {
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                               : CHAINPREFIX_HOST_OUT_TEMP;
    } else {
        chainPrefix = incoming ? CHAINPREFIX_HOST_IN
                               : CHAINPREFIX_HOST_OUT;
    }

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);

    virBufferAsprintf(buf,
                      "$EBT -t nat -D %s -%c %s -j %s" CMD_SEPARATOR,
                      incoming ? EBTABLES_CHAIN_INCOMING
                               : EBTABLES_CHAIN_OUTGOING,
                      iodev, ifname, chain);
}


static void
ebtablesUnlinkRootChain(virBufferPtr buf,
                        bool incoming, const char *ifname)
{
    _ebtablesUnlinkRootChain(buf, incoming, ifname, false);
}


static void
ebtablesUnlinkTmpRootChain(virBufferPtr buf,
                           bool incoming, const char *ifname)
{
    _ebtablesUnlinkRootChain(buf, incoming, ifname, true);
}


static int
ebtablesCreateTmpSubChain(ebiptablesRuleInstPtr *inst,
                          int *nRuleInstances,
                          bool incoming,
                          const char *ifname,
                          enum l3_proto_idx protoidx,
                          const char *filtername,
                          virNWFilterChainPriority priority)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    ebiptablesRuleInstPtr tmp = *inst;
    size_t count = *nRuleInstances;
    char rootchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                : CHAINPREFIX_HOST_OUT_TEMP;
    char *protostr = NULL;

    PRINT_ROOT_CHAIN(rootchain, chainPrefix, ifname);
    PRINT_CHAIN(chain, chainPrefix, ifname,
                (filtername) ? filtername : l3_protocols[protoidx].val);

    switch (protoidx) {
    case L2_PROTO_MAC_IDX:
        ignore_value(VIR_STRDUP(protostr, ""));
        break;
    case L2_PROTO_STP_IDX:
        ignore_value(VIR_STRDUP(protostr, "-d " NWFILTER_MAC_BGA " "));
        break;
    default:
        ignore_value(virAsprintf(&protostr, "-p 0x%04x ",
                     l3_protocols[protoidx].attr));
        break;
    }

    if (!protostr)
        return -1;

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -F %s") CMD_SEPARATOR
                      CMD_EXEC
                      CMD_DEF("$EBT -t nat -X %s") CMD_SEPARATOR
                      CMD_EXEC
                      CMD_DEF("$EBT -t nat -N %s") CMD_SEPARATOR
                      CMD_EXEC
                      "%s"
                      CMD_DEF("$EBT -t nat -%%c %s %%s %s-j %s")
                          CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain,
                      chain,
                      chain,

                      CMD_STOPONERR(true),

                      rootchain, protostr, chain,

                      CMD_STOPONERR(true));

    VIR_FREE(protostr);

    if (virBufferError(&buf) ||
        VIR_EXPAND_N(tmp, count, 1) < 0) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        return -1;
    }

    *nRuleInstances = count;
    *inst = tmp;

    tmp[*nRuleInstances - 1].priority = priority;
    tmp[*nRuleInstances - 1].commandTemplate =
        virBufferContentAndReset(&buf);
    tmp[*nRuleInstances - 1].neededProtocolChain =
        virNWFilterChainSuffixTypeToString(VIR_NWFILTER_CHAINSUFFIX_ROOT);

    return 0;
}

static void
_ebtablesRemoveSubChains(virBufferPtr buf,
                         const char *ifname,
                         const char *chains)
{
    char rootchain[MAX_CHAINNAME_LENGTH];
    size_t i;

    NWFILTER_SET_EBTABLES_SHELLVAR(buf);

    virBufferAsprintf(buf, NWFILTER_FUNC_COLLECT_CHAINS,
                      chains);
    virBufferAdd(buf, NWFILTER_FUNC_RM_CHAINS, -1);

    virBufferAsprintf(buf, NWFILTER_FUNC_SET_IFS);
    virBufferAddLit(buf, "chains=\"$(collect_chains");
    for (i = 0; chains[i] != 0; i++) {
        PRINT_ROOT_CHAIN(rootchain, chains[i], ifname);
        virBufferAsprintf(buf, " %s", rootchain);
    }
    virBufferAddLit(buf, ")\"\n");

    for (i = 0; chains[i] != 0; i++) {
        PRINT_ROOT_CHAIN(rootchain, chains[i], ifname);
        virBufferAsprintf(buf,
                          "$EBT -t nat -F %s\n",
                          rootchain);
    }
    virBufferAddLit(buf, "rm_chains $chains\n");
}

static void
ebtablesRemoveSubChains(virBufferPtr buf,
                        const char *ifname)
{
    char chains[3] = {
        CHAINPREFIX_HOST_IN,
        CHAINPREFIX_HOST_OUT,
        0
    };

    _ebtablesRemoveSubChains(buf, ifname, chains);
}

static void
ebtablesRemoveTmpSubChains(virBufferPtr buf,
                           const char *ifname)
{
    char chains[3] = {
        CHAINPREFIX_HOST_IN_TEMP,
        CHAINPREFIX_HOST_OUT_TEMP,
        0
    };

    _ebtablesRemoveSubChains(buf, ifname, chains);
}

static void
ebtablesRenameTmpSubChain(virBufferPtr buf,
                          bool incoming,
                          const char *ifname,
                          const char *protocol)
{
    char tmpchain[MAX_CHAINNAME_LENGTH], chain[MAX_CHAINNAME_LENGTH];
    char tmpChainPrefix = incoming ? CHAINPREFIX_HOST_IN_TEMP
                                   : CHAINPREFIX_HOST_OUT_TEMP;
    char chainPrefix = incoming ? CHAINPREFIX_HOST_IN
                                : CHAINPREFIX_HOST_OUT;

    if (protocol) {
        PRINT_CHAIN(tmpchain, tmpChainPrefix, ifname, protocol);
        PRINT_CHAIN(chain, chainPrefix, ifname, protocol);
    } else {
        PRINT_ROOT_CHAIN(tmpchain, tmpChainPrefix, ifname);
        PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    }

    virBufferAsprintf(buf,
                      "$EBT -t nat -E %s %s" CMD_SEPARATOR,
                      tmpchain, chain);
}

static void
ebtablesRenameTmpRootChain(virBufferPtr buf,
                           bool incoming,
                           const char *ifname)
{
    ebtablesRenameTmpSubChain(buf, incoming, ifname, NULL);
}

static void
ebtablesRenameTmpSubAndRootChains(virBufferPtr buf,
                                  const char *ifname)
{
    char rootchain[MAX_CHAINNAME_LENGTH];
    size_t i;
    char chains[3] = {
        CHAINPREFIX_HOST_IN_TEMP,
        CHAINPREFIX_HOST_OUT_TEMP,
        0};

    NWFILTER_SET_EBTABLES_SHELLVAR(buf);

    virBufferAsprintf(buf, NWFILTER_FUNC_COLLECT_CHAINS,
                      chains);
    virBufferAsprintf(buf, NWFILTER_FUNC_RENAME_CHAINS,
                      CHAINPREFIX_HOST_IN_TEMP,
                      CHAINPREFIX_HOST_IN,
                      CHAINPREFIX_HOST_OUT_TEMP,
                      CHAINPREFIX_HOST_OUT);

    virBufferAsprintf(buf, NWFILTER_FUNC_SET_IFS);
    virBufferAddLit(buf, "chains=\"$(collect_chains");
    for (i = 0; chains[i] != 0; i++) {
        PRINT_ROOT_CHAIN(rootchain, chains[i], ifname);
        virBufferAsprintf(buf, " %s", rootchain);
    }
    virBufferAddLit(buf, ")\"\n");

    virBufferAddLit(buf, "rename_chains $chains\n");

    ebtablesRenameTmpRootChain(buf, true, ifname);
    ebtablesRenameTmpRootChain(buf, false, ifname);
}

static void
ebiptablesInstCommand(virBufferPtr buf,
                      const char *templ, char cmd, int pos,
                      bool stopOnError)
{
    char position[10] = { 0 };
    if (pos >= 0)
        snprintf(position, sizeof(position), "%d", pos);
    virBufferAsprintf(buf, templ, cmd, position);
    virBufferAsprintf(buf, CMD_SEPARATOR "%s",
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
ebiptablesCanApplyBasicRules(void)
{
    return ebtables_cmd_path != NULL;
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
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char chain[MAX_CHAINNAME_LENGTH];
    char chainPrefix = CHAINPREFIX_HOST_IN_TEMP;
    char macaddr_str[VIR_MAC_STRING_BUFLEN];

    if (!ebtables_cmd_path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create rules since ebtables tool is "
                         "missing."));
        return -1;
    }

    virMacAddrFormat(macaddr, macaddr_str);

    ebiptablesAllTeardown(ifname);

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    ebtablesCreateTmpRootChain(&buf, true, ifname);

    PRINT_ROOT_CHAIN(chain, chainPrefix, ifname);
    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -s ! %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain, macaddr_str,
                      CMD_STOPONERR(true));

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -p IPv4 -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain,
                      CMD_STOPONERR(true));

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -p ARP -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain,
                      CMD_STOPONERR(true));

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain,
                      CMD_STOPONERR(true));

    ebtablesLinkTmpRootChain(&buf, true, ifname);
    ebtablesRenameTmpRootChain(&buf, true, ifname);

    if (ebiptablesExecCLI(&buf, false, NULL) < 0)
        goto tear_down_tmpebchains;

    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virReportError(VIR_ERR_BUILD_FIREWALL,
                   "%s",
                   _("Some rules could not be created."));

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
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];
    char macaddr_str[VIR_MAC_STRING_BUFLEN];
    unsigned int idx = 0;
    unsigned int num_dhcpsrvrs;

    if (!ebtables_cmd_path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create rules since ebtables tool is "
                         "missing."));
        return -1;
    }

    virMacAddrFormat(macaddr, macaddr_str);

    ebiptablesAllTeardown(ifname);

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    ebtablesCreateTmpRootChain(&buf, true, ifname);
    ebtablesCreateTmpRootChain(&buf, false, ifname);

    PRINT_ROOT_CHAIN(chain_in, CHAINPREFIX_HOST_IN_TEMP, ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s"
                              " -s %s"
                              " -p ipv4 --ip-protocol udp"
                              " --ip-sport 68 --ip-dport 67"
                              " -j ACCEPT") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain_in,
                      macaddr_str,
                      CMD_STOPONERR(true));

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain_in,
                      CMD_STOPONERR(true));

    num_dhcpsrvrs = (dhcpsrvrs != NULL)
                    ? virNWFilterVarValueGetCardinality(dhcpsrvrs)
                    : 0;

    while (true) {
        char *srcIPParam = NULL;
        int ctr;

        if (idx < num_dhcpsrvrs) {
            const char *dhcpserver;

            dhcpserver = virNWFilterVarValueGetNthValue(dhcpsrvrs, idx);

            if (virAsprintf(&srcIPParam, "--ip-src %s", dhcpserver) < 0)
                goto tear_down_tmpebchains;
        }

        /*
         * create two rules allowing response to MAC address of VM
         * or to broadcast MAC address
         */
        for (ctr = 0; ctr < 2; ctr++) {
            virBufferAsprintf(&buf,
                              CMD_DEF("$EBT -t nat -A %s"
                                      " -d %s"
                                      " -p ipv4 --ip-protocol udp"
                                      " %s"
                                      " --ip-sport 67 --ip-dport 68"
                                      " -j ACCEPT") CMD_SEPARATOR
                              CMD_EXEC
                              "%s",

                              chain_out,
                              (ctr == 0) ? macaddr_str : "ff:ff:ff:ff:ff:ff",
                              srcIPParam != NULL ? srcIPParam : "",
                              CMD_STOPONERR(true));
        }

        VIR_FREE(srcIPParam);

        idx++;

        if (idx >= num_dhcpsrvrs)
            break;
    }

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain_out,
                      CMD_STOPONERR(true));

    ebtablesLinkTmpRootChain(&buf, true, ifname);
    ebtablesLinkTmpRootChain(&buf, false, ifname);

    if (!leaveTemporary) {
        ebtablesRenameTmpRootChain(&buf, true, ifname);
        ebtablesRenameTmpRootChain(&buf, false, ifname);
    }

    if (ebiptablesExecCLI(&buf, false, NULL) < 0)
        goto tear_down_tmpebchains;

    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virReportError(VIR_ERR_BUILD_FIREWALL,
                   "%s",
                   _("Some rules could not be created."));

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
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char chain_in [MAX_CHAINNAME_LENGTH],
         chain_out[MAX_CHAINNAME_LENGTH];

    if (!ebtables_cmd_path) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot create rules since ebtables tool is "
                         "missing."));
        return -1;
    }

    ebiptablesAllTeardown(ifname);

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    ebtablesCreateTmpRootChain(&buf, true, ifname);
    ebtablesCreateTmpRootChain(&buf, false, ifname);

    PRINT_ROOT_CHAIN(chain_in, CHAINPREFIX_HOST_IN_TEMP, ifname);
    PRINT_ROOT_CHAIN(chain_out, CHAINPREFIX_HOST_OUT_TEMP, ifname);

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain_in,
                      CMD_STOPONERR(true));

    virBufferAsprintf(&buf,
                      CMD_DEF("$EBT -t nat -A %s -j DROP") CMD_SEPARATOR
                      CMD_EXEC
                      "%s",

                      chain_out,
                      CMD_STOPONERR(true));

    ebtablesLinkTmpRootChain(&buf, true, ifname);
    ebtablesLinkTmpRootChain(&buf, false, ifname);
    ebtablesRenameTmpRootChain(&buf, true, ifname);
    ebtablesRenameTmpRootChain(&buf, false, ifname);

    if (ebiptablesExecCLI(&buf, false, NULL) < 0)
        goto tear_down_tmpebchains;

    return 0;

 tear_down_tmpebchains:
    ebtablesCleanAll(ifname);

    virReportError(VIR_ERR_BUILD_FIREWALL,
                   "%s",
                   _("Some rules could not be created."));

    return -1;
}


static int
ebtablesRemoveBasicRules(const char *ifname)
{
    ebtablesCleanAll(ifname);
    return 0;
}


static void
ebtablesCleanAll(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!ebtables_cmd_path)
        return;

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    ebtablesUnlinkRootChain(&buf, true, ifname);
    ebtablesUnlinkRootChain(&buf, false, ifname);
    ebtablesRemoveSubChains(&buf, ifname);
    ebtablesRemoveRootChain(&buf, true, ifname);
    ebtablesRemoveRootChain(&buf, false, ifname);

    ebtablesUnlinkTmpRootChain(&buf, true, ifname);
    ebtablesUnlinkTmpRootChain(&buf, false, ifname);
    ebtablesRemoveTmpSubChains(&buf, ifname);
    ebtablesRemoveTmpRootChain(&buf, true, ifname);
    ebtablesRemoveTmpRootChain(&buf, false, ifname);

    ebiptablesExecCLI(&buf, true, NULL);
}


static int
ebiptablesRuleOrderSort(const void *a, const void *b)
{
    const ebiptablesRuleInst *insta = a;
    const ebiptablesRuleInst *instb = b;
    const char *root = virNWFilterChainSuffixTypeToString(
                                     VIR_NWFILTER_CHAINSUFFIX_ROOT);
    bool root_a = STREQ(insta->neededProtocolChain, root);
    bool root_b = STREQ(instb->neededProtocolChain, root);

    /* ensure root chain commands appear before all others since
       we will need them to create the child chains */
    if (root_a) {
        if (root_b) {
            goto normal;
        }
        return -1; /* a before b */
    }
    if (root_b) {
        return 1; /* b before a */
    }
 normal:
    /* priorities are limited to range [-1000, 1000] */
    return insta->priority - instb->priority;
}

static int
ebiptablesRuleOrderSortPtr(const void *a, const void *b)
{
    ebiptablesRuleInst * const *insta = a;
    ebiptablesRuleInst * const *instb = b;
    return ebiptablesRuleOrderSort(*insta, *instb);
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
        if (STRPREFIX(filtername, l3_protocols[idx].val)) {
            return idx;
        }
    }

    return -1;
}

static int
ebtablesCreateTmpRootAndSubChains(virBufferPtr buf,
                                  const char *ifname,
                                  virHashTablePtr chains,
                                  bool incoming,
                                  ebiptablesRuleInstPtr *inst,
                                  int *nRuleInstances)
{
    int rc = 0;
    size_t i;
    virHashKeyValuePairPtr filter_names;
    const virNWFilterChainPriority *priority;

    ebtablesCreateTmpRootChain(buf, incoming, ifname);

    filter_names = virHashGetItems(chains,
                                   ebiptablesFilterOrderSort);
    if (filter_names == NULL)
        return -1;

    for (i = 0; filter_names[i].key; i++) {
        enum l3_proto_idx idx = ebtablesGetProtoIdxByFiltername(
                                  filter_names[i].key);
        if ((int)idx < 0)
            continue;
        priority = (const virNWFilterChainPriority *)filter_names[i].value;
        rc = ebtablesCreateTmpSubChain(inst, nRuleInstances,
                                       incoming, ifname, idx,
                                       filter_names[i].key,
                                       *priority);
        if (rc < 0)
            break;
    }

    VIR_FREE(filter_names);
    return rc;
}

static int
ebiptablesApplyNewRules(const char *ifname,
                        int nruleInstances,
                        void **_inst)
{
    size_t i, j;
    ebiptablesRuleInstPtr *inst = (ebiptablesRuleInstPtr *)_inst;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virHashTablePtr chains_in_set  = virHashCreate(10, NULL);
    virHashTablePtr chains_out_set = virHashCreate(10, NULL);
    bool haveIptables = false;
    bool haveIp6tables = false;
    ebiptablesRuleInstPtr ebtChains = NULL;
    int nEbtChains = 0;
    char *errmsg = NULL;

    if (inst == NULL)
        nruleInstances = 0;

    if (!chains_in_set || !chains_out_set)
        goto exit_free_sets;

    if (nruleInstances > 1 && inst)
        qsort(inst, nruleInstances, sizeof(inst[0]),
              ebiptablesRuleOrderSortPtr);

    /* scan the rules to see which chains need to be created */
    for (i = 0; i < nruleInstances; i++) {
        sa_assert(inst);
        if (inst[i]->ruleType == RT_EBTABLES) {
            const char *name = inst[i]->neededProtocolChain;
            if (inst[i]->chainprefix == CHAINPREFIX_HOST_IN_TEMP) {
                if (virHashUpdateEntry(chains_in_set, name,
                                       &inst[i]->chainPriority) < 0)
                    goto exit_free_sets;
            } else {
                if (virHashUpdateEntry(chains_out_set, name,
                                       &inst[i]->chainPriority) < 0)
                    goto exit_free_sets;
            }
        }
    }


    /* cleanup whatever may exist */
    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesUnlinkTmpRootChain(&buf, true, ifname);
        ebtablesUnlinkTmpRootChain(&buf, false, ifname);
        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, true, ifname);
        ebtablesRemoveTmpRootChain(&buf, false, ifname);
        ebiptablesExecCLI(&buf, true, NULL);
    }

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    /* create needed chains */
    if ((virHashSize(chains_in_set) > 0 &&
         ebtablesCreateTmpRootAndSubChains(&buf, ifname, chains_in_set, true,
                                           &ebtChains, &nEbtChains) < 0) ||
        (virHashSize(chains_out_set) > 0 &&
         ebtablesCreateTmpRootAndSubChains(&buf, ifname, chains_out_set, false,
                                           &ebtChains, &nEbtChains) < 0)) {
        goto tear_down_tmpebchains;
    }

    if (nEbtChains > 0)
        qsort(&ebtChains[0], nEbtChains, sizeof(ebtChains[0]),
              ebiptablesRuleOrderSort);

    if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
        goto tear_down_tmpebchains;

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    /* walk the list of rules and increase the priority
     * of rules in case the chain priority is of higher value;
     * this preserves the order of the rules and ensures that
     * the chain will be created before the chain's rules
     * are created; don't adjust rules in the root chain
     * example: a rule of priority -510 will be adjusted to
     * priority -500 and the chain with priority -500 will
     * then be created before it.
     */
    for (i = 0; i < nruleInstances; i++) {
        if (inst[i]->chainPriority > inst[i]->priority &&
            !strstr("root", inst[i]->neededProtocolChain)) {

             inst[i]->priority = inst[i]->chainPriority;
        }
    }

    /* process ebtables commands; interleave commands from filters with
       commands for creating and connecting ebtables chains */
    j = 0;
    for (i = 0; i < nruleInstances; i++) {
        sa_assert(inst);
        switch (inst[i]->ruleType) {
        case RT_EBTABLES:
            while (j < nEbtChains &&
                   ebtChains[j].priority <= inst[i]->priority) {
                ebiptablesInstCommand(&buf,
                                      ebtChains[j++].commandTemplate,
                                      'A', -1, true);
            }
            ebiptablesInstCommand(&buf,
                                  inst[i]->commandTemplate,
                                  'A', -1, true);
        break;
        case RT_IPTABLES:
            haveIptables = true;
        break;
        case RT_IP6TABLES:
            haveIp6tables = true;
        break;
        }
    }

    while (j < nEbtChains)
        ebiptablesInstCommand(&buf,
                              ebtChains[j++].commandTemplate,
                              'A', -1, true);

    if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
        goto tear_down_tmpebchains;

    if (haveIptables) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);

        iptablesCreateBaseChains(&buf);

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
            goto tear_down_tmpebchains;

        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesCreateTmpRootChains(&buf, ifname);

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpiptchains;

        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesLinkTmpRootChains(&buf, ifname);
        iptablesSetupVirtInPost(&buf, ifname);
        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpiptchains;

        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        for (i = 0; i < nruleInstances; i++) {
            sa_assert(inst);
            if (inst[i]->ruleType == RT_IPTABLES)
                iptablesInstCommand(&buf,
                                    inst[i]->commandTemplate,
                                    'A', -1);
        }

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpiptchains;

        iptablesCheckBridgeNFCallEnabled(false);
    }

    if (haveIp6tables) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);

        iptablesCreateBaseChains(&buf);

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
            goto tear_down_tmpiptchains;

        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesCreateTmpRootChains(&buf, ifname);

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpip6tchains;

        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesLinkTmpRootChains(&buf, ifname);
        iptablesSetupVirtInPost(&buf, ifname);
        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpip6tchains;

        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        for (i = 0; i < nruleInstances; i++) {
            if (inst[i]->ruleType == RT_IP6TABLES)
                iptablesInstCommand(&buf,
                                    inst[i]->commandTemplate,
                                    'A', -1);
        }

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
           goto tear_down_tmpip6tchains;

        iptablesCheckBridgeNFCallEnabled(true);
    }

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    if (virHashSize(chains_in_set) != 0)
        ebtablesLinkTmpRootChain(&buf, true, ifname);
    if (virHashSize(chains_out_set) != 0)
        ebtablesLinkTmpRootChain(&buf, false, ifname);

    if (ebiptablesExecCLI(&buf, false, &errmsg) < 0)
        goto tear_down_ebsubchains_and_unlink;

    virHashFree(chains_in_set);
    virHashFree(chains_out_set);

    for (i = 0; i < nEbtChains; i++)
        VIR_FREE(ebtChains[i].commandTemplate);
    VIR_FREE(ebtChains);

    VIR_FREE(errmsg);

    return 0;

 tear_down_ebsubchains_and_unlink:
    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesUnlinkTmpRootChain(&buf, true, ifname);
        ebtablesUnlinkTmpRootChain(&buf, false, ifname);
    }

 tear_down_tmpip6tchains:
    if (haveIp6tables) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);
    }

 tear_down_tmpiptchains:
    if (haveIptables) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);
    }

 tear_down_tmpebchains:
    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, true, ifname);
        ebtablesRemoveTmpRootChain(&buf, false, ifname);
    }

    ebiptablesExecCLI(&buf, true, NULL);

    virReportError(VIR_ERR_BUILD_FIREWALL,
                   _("Some rules could not be created for "
                     "interface %s%s%s"),
                   ifname,
                   errmsg ? ": " : "",
                   errmsg ? errmsg : "");

 exit_free_sets:
    virHashFree(chains_in_set);
    virHashFree(chains_out_set);

    for (i = 0; i < nEbtChains; i++)
        VIR_FREE(ebtChains[i].commandTemplate);
    VIR_FREE(ebtChains);

    VIR_FREE(errmsg);

    return -1;
}


static int
ebiptablesTearNewRules(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (iptables_cmd_path) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);
    }

    if (ip6tables_cmd_path) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesUnlinkTmpRootChains(&buf, ifname);
        iptablesRemoveTmpRootChains(&buf, ifname);
    }

    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesUnlinkTmpRootChain(&buf, true, ifname);
        ebtablesUnlinkTmpRootChain(&buf, false, ifname);

        ebtablesRemoveTmpSubChains(&buf, ifname);
        ebtablesRemoveTmpRootChain(&buf, true, ifname);
        ebtablesRemoveTmpRootChain(&buf, false, ifname);
    }

    ebiptablesExecCLI(&buf, true, NULL);

    return 0;
}


static int
ebiptablesTearOldRules(const char *ifname)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    /* switch to new iptables user defined chains */
    if (iptables_cmd_path) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesUnlinkRootChains(&buf, ifname);
        iptablesRemoveRootChains(&buf, ifname);

        iptablesRenameTmpRootChains(&buf, ifname);
        ebiptablesExecCLI(&buf, true, NULL);
    }

    if (ip6tables_cmd_path) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesUnlinkRootChains(&buf, ifname);
        iptablesRemoveRootChains(&buf, ifname);

        iptablesRenameTmpRootChains(&buf, ifname);
        ebiptablesExecCLI(&buf, true, NULL);
    }

    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesUnlinkRootChain(&buf, true, ifname);
        ebtablesUnlinkRootChain(&buf, false, ifname);

        ebtablesRemoveSubChains(&buf, ifname);

        ebtablesRemoveRootChain(&buf, true, ifname);
        ebtablesRemoveRootChain(&buf, false, ifname);

        ebtablesRenameTmpSubAndRootChains(&buf, ifname);

        ebiptablesExecCLI(&buf, true, NULL);
    }

    return 0;
}


/**
 * ebiptablesRemoveRules:
 * @ifname : the name of the interface to which the rules apply
 * @nRuleInstance : the number of given rules
 * @_inst : array of rule instantiation data
 *
 * Remove all rules one after the other
 *
 * Return 0 on success, -1 if execution of one or more cleanup
 * commands failed.
 */
static int
ebiptablesRemoveRules(const char *ifname ATTRIBUTE_UNUSED,
                      int nruleInstances,
                      void **_inst)
{
    int rc = -1;
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    ebiptablesRuleInstPtr *inst = (ebiptablesRuleInstPtr *)_inst;

    NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

    for (i = 0; i < nruleInstances; i++)
        ebiptablesInstCommand(&buf,
                              inst[i]->commandTemplate,
                              'D', -1,
                              false);

    if (ebiptablesExecCLI(&buf, true, NULL) < 0)
        goto cleanup;

    rc = 0;

 cleanup:
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

    if (iptables_cmd_path) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        iptablesUnlinkRootChains(&buf, ifname);
        iptablesClearVirtInPost(&buf, ifname);
        iptablesRemoveRootChains(&buf, ifname);
    }

    if (ip6tables_cmd_path) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        iptablesUnlinkRootChains(&buf, ifname);
        iptablesClearVirtInPost(&buf, ifname);
        iptablesRemoveRootChains(&buf, ifname);
    }

    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);

        ebtablesUnlinkRootChain(&buf, true, ifname);
        ebtablesUnlinkRootChain(&buf, false, ifname);

        ebtablesRemoveSubChains(&buf, ifname);

        ebtablesRemoveRootChain(&buf, true, ifname);
        ebtablesRemoveRootChain(&buf, false, ifname);
    }
    ebiptablesExecCLI(&buf, true, NULL);

    return 0;
}


virNWFilterTechDriver ebiptables_driver = {
    .name = EBIPTABLES_DRIVER_ID,
    .flags = 0,

    .init     = ebiptablesDriverInit,
    .shutdown = ebiptablesDriverShutdown,

    .createRuleInstance  = ebiptablesCreateRuleInstanceIterate,
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

/*
 * ebiptablesDriverInitWithFirewallD
 *
 * Try to use firewall-cmd by testing it once; if it works, have ebtables
 * and ip6tables commands use firewall-cmd.
 */
static int
ebiptablesDriverInitWithFirewallD(void)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *firewall_cmd_path;
    char *output = NULL;
    int ret = -1;

    if (!virNWFilterDriverIsWatchingFirewallD())
        return -1;

    firewall_cmd_path = virFindFileInPath("firewall-cmd");

    if (firewall_cmd_path) {
        virBufferAsprintf(&buf, "FWC=%s\n", firewall_cmd_path);
        virBufferAsprintf(&buf,
                          CMD_DEF("$FWC --state") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          CMD_STOPONERR(true));

        if (ebiptablesExecCLI(&buf, false, &output) < 0) {
            VIR_INFO("firewalld support disabled for nwfilter");
        } else {
            VIR_INFO("firewalld support enabled for nwfilter");

            if (virAsprintf(&ebtables_cmd_path,
                            "%s --direct --passthrough eb",
                            firewall_cmd_path) < 0 ||
                virAsprintf(&iptables_cmd_path,
                            "%s --direct --passthrough ipv4",
                            firewall_cmd_path) < 0 ||
                virAsprintf(&ip6tables_cmd_path,
                            "%s --direct --passthrough ipv6",
                            firewall_cmd_path) < 0) {
                VIR_FREE(ebtables_cmd_path);
                VIR_FREE(iptables_cmd_path);
                VIR_FREE(ip6tables_cmd_path);
                ret = -1;
                goto err_exit;
            }
            ret = 0;
        }
    }

 err_exit:
    VIR_FREE(firewall_cmd_path);
    VIR_FREE(output);

    return ret;
}

static void
ebiptablesDriverInitCLITools(void)
{
    ebtables_cmd_path = virFindFileInPath("ebtables");
    if (!ebtables_cmd_path)
        VIR_WARN("Could not find 'ebtables' executable");

    iptables_cmd_path = virFindFileInPath("iptables");
    if (!iptables_cmd_path)
        VIR_WARN("Could not find 'iptables' executable");

    ip6tables_cmd_path = virFindFileInPath("ip6tables");
    if (!ip6tables_cmd_path)
        VIR_WARN("Could not find 'ip6tables' executable");
}

/*
 * ebiptablesDriverTestCLITools
 *
 * Test the CLI tools. If one is found not to be working, free the buffer
 * holding its path as a sign that the tool cannot be used.
 */
static int
ebiptablesDriverTestCLITools(void)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *errmsg = NULL;
    int ret = 0;

    if (ebtables_cmd_path) {
        NWFILTER_SET_EBTABLES_SHELLVAR(&buf);
        /* basic probing */
        virBufferAsprintf(&buf,
                          CMD_DEF("$EBT -t nat -L") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          CMD_STOPONERR(true));

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0) {
            VIR_FREE(ebtables_cmd_path);
            VIR_ERROR(_("Testing of ebtables command failed: %s"),
                      errmsg);
            ret = -1;
        }
    }

    if (iptables_cmd_path) {
        NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

        virBufferAsprintf(&buf,
                          CMD_DEF("$IPT -n -L FORWARD") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          CMD_STOPONERR(true));

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0) {
            VIR_FREE(iptables_cmd_path);
            VIR_ERROR(_("Testing of iptables command failed: %s"),
                      errmsg);
            ret = -1;
        }
    }

    if (ip6tables_cmd_path) {
        NWFILTER_SET_IP6TABLES_SHELLVAR(&buf);

        virBufferAsprintf(&buf,
                          CMD_DEF("$IPT -n -L FORWARD") CMD_SEPARATOR
                          CMD_EXEC
                          "%s",
                          CMD_STOPONERR(true));

        if (ebiptablesExecCLI(&buf, false, &errmsg) < 0) {
            VIR_FREE(ip6tables_cmd_path);
            VIR_ERROR(_("Testing of ip6tables command failed: %s"),
                      errmsg);
            ret = -1;
        }
    }

    VIR_FREE(errmsg);

    return ret;
}

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

static void
ebiptablesDriverProbeStateMatch(void)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *cmdout = NULL, *version;
    unsigned long thisversion;

    NWFILTER_SET_IPTABLES_SHELLVAR(&buf);

    virBufferAsprintf(&buf,
                      "$IPT --version");

    if (ebiptablesExecCLI(&buf, false, &cmdout) < 0) {
        VIR_ERROR(_("Testing of iptables command failed: %s"),
                  cmdout);
        return;
    }

    /*
     * we expect output in the format
     * iptables v1.4.16
     */
    if (!(version = strchr(cmdout, 'v')) ||
        virParseVersionString(version + 1, &thisversion, true) < 0) {
        VIR_ERROR(_("Could not determine iptables version from string %s"),
                  cmdout);
        goto cleanup;
    }

    /*
     * since version 1.4.16 '-m state --state ...' will be converted to
     * '-m conntrack --ctstate ...'
     */
    if (thisversion >= 1 * 1000000 + 4 * 1000 + 16) {
        m_state_out_str = m_state_out_str_new;
        m_state_in_str = m_state_in_str_new;
    }

 cleanup:
    VIR_FREE(cmdout);
    return;
}

static int
ebiptablesDriverInit(bool privileged)
{
    if (!privileged)
        return 0;

    if (virMutexInit(&execCLIMutex) < 0)
        return -EINVAL;

    grep_cmd_path = virFindFileInPath("grep");

    /*
     * check whether we can run with firewalld's tools --
     * if not, we just fall back to eb/iptables command
     * line tools.
     */
    if (ebiptablesDriverInitWithFirewallD() < 0)
        ebiptablesDriverInitCLITools();

    /* make sure tools are available and work */
    ebiptablesDriverTestCLITools();

    /* ip(6)tables support needs awk & grep, ebtables doesn't */
    if ((iptables_cmd_path != NULL || ip6tables_cmd_path != NULL) &&
        !grep_cmd_path) {
        VIR_ERROR(_("essential tools to support ip(6)tables "
                  "firewalls could not be located"));
        VIR_FREE(iptables_cmd_path);
        VIR_FREE(ip6tables_cmd_path);
    }

    if (!ebtables_cmd_path && !iptables_cmd_path && !ip6tables_cmd_path) {
        VIR_ERROR(_("firewall tools were not found or cannot be used"));
        ebiptablesDriverShutdown();
        return -ENOTSUP;
    }

    if (iptables_cmd_path) {
        ebiptablesDriverProbeCtdir();
        ebiptablesDriverProbeStateMatch();
    }

    ebiptables_driver.flags = TECHDRV_FLAG_INITIALIZED;

    return 0;
}


static void
ebiptablesDriverShutdown(void)
{
    VIR_FREE(grep_cmd_path);
    VIR_FREE(ebtables_cmd_path);
    VIR_FREE(iptables_cmd_path);
    VIR_FREE(ip6tables_cmd_path);
    ebiptables_driver.flags = 0;
}
