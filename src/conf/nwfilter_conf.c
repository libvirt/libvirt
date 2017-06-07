/*
 * nwfilter_conf.c: network filter XML processing
 *                  (derived from storage_conf.c)
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 *
 * Copyright (C) 2010-2011 IBM Corporation
 * Copyright (C) 2010-2011 Stefan Berger
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if HAVE_NET_ETHERNET_H
# include <net/ethernet.h>
#endif
#include <unistd.h>

#include "internal.h"

#include "viruuid.h"
#include "viralloc.h"
#include "virerror.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "nwfilter_conf.h"
#include "domain_conf.h"
#include "c-ctype.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER


VIR_ENUM_IMPL(virNWFilterRuleAction, VIR_NWFILTER_RULE_ACTION_LAST,
              "drop",
              "accept",
              "reject",
              "return",
              "continue");

VIR_ENUM_IMPL(virNWFilterJumpTarget, VIR_NWFILTER_RULE_ACTION_LAST,
              "DROP",
              "ACCEPT",
              "REJECT",
              "RETURN",
              "CONTINUE");

VIR_ENUM_IMPL(virNWFilterRuleDirection, VIR_NWFILTER_RULE_DIRECTION_LAST,
              "in",
              "out",
              "inout");

VIR_ENUM_IMPL(virNWFilterChainPolicy, VIR_NWFILTER_CHAIN_POLICY_LAST,
              "ACCEPT",
              "DROP");

VIR_ENUM_IMPL(virNWFilterEbtablesTable, VIR_NWFILTER_EBTABLES_TABLE_LAST,
              "filter",
              "nat",
              "broute");

VIR_ENUM_IMPL(virNWFilterChainSuffix, VIR_NWFILTER_CHAINSUFFIX_LAST,
              "root",
              "mac",
              "vlan",
              "stp",
              "arp",
              "rarp",
              "ipv4",
              "ipv6");

VIR_ENUM_IMPL(virNWFilterRuleProtocol, VIR_NWFILTER_RULE_PROTOCOL_LAST,
              "none",
              "mac",
              "vlan",
              "stp",
              "arp",
              "rarp",
              "ip",
              "ipv6",
              "tcp",
              "icmp",
              "igmp",
              "udp",
              "udplite",
              "esp",
              "ah",
              "sctp",
              "all",
              "tcp-ipv6",
              "icmpv6",
              "udp-ipv6",
              "udplite-ipv6",
              "esp-ipv6",
              "ah-ipv6",
              "sctp-ipv6",
              "all-ipv6");


/*
 * a map entry for a simple static int-to-string map
 */
struct int_map {
    int32_t attr;
    const char *val;
};

#define INTMAP_ENTRY(ATT, VAL) { .attr = ATT, .val = VAL }
#define INTMAP_ENTRY_LAST      { .val = NULL }

static const struct int_map chain_priorities[] = {
    INTMAP_ENTRY(NWFILTER_ROOT_FILTER_PRI, "root"),
    INTMAP_ENTRY(NWFILTER_MAC_FILTER_PRI,  "mac"),
    INTMAP_ENTRY(NWFILTER_VLAN_FILTER_PRI, "vlan"),
    INTMAP_ENTRY(NWFILTER_IPV4_FILTER_PRI, "ipv4"),
    INTMAP_ENTRY(NWFILTER_IPV6_FILTER_PRI, "ipv6"),
    INTMAP_ENTRY(NWFILTER_ARP_FILTER_PRI,  "arp"),
    INTMAP_ENTRY(NWFILTER_RARP_FILTER_PRI, "rarp"),
    INTMAP_ENTRY_LAST,
};


/*
 * only one filter update allowed
 */
static virRWLock updateLock;
static bool initialized;

void
virNWFilterReadLockFilterUpdates(void)
{
    virRWLockRead(&updateLock);
}


void
virNWFilterWriteLockFilterUpdates(void)
{
    virRWLockWrite(&updateLock);
}


void
virNWFilterUnlockFilterUpdates(void)
{
    virRWLockUnlock(&updateLock);
}


/*
 * attribute names for the rules XML
 */
static const char srcmacaddr_str[]    = "srcmacaddr";
static const char srcmacmask_str[]    = "srcmacmask";
static const char dstmacaddr_str[]    = "dstmacaddr";
static const char dstmacmask_str[]    = "dstmacmask";
static const char arpsrcmacaddr_str[] = "arpsrcmacaddr";
static const char arpdstmacaddr_str[] = "arpdstmacaddr";
static const char arpsrcipaddr_str[]  = "arpsrcipaddr";
static const char arpsrcipmask_str[]  = "arpsrcipmask";
static const char arpdstipaddr_str[]  = "arpdstipaddr";
static const char arpdstipmask_str[]  = "arpdstipmask";
static const char srcipaddr_str[]     = "srcipaddr";
static const char srcipmask_str[]     = "srcipmask";
static const char dstipaddr_str[]     = "dstipaddr";
static const char dstipmask_str[]     = "dstipmask";
static const char srcipfrom_str[]     = "srcipfrom";
static const char srcipto_str[]       = "srcipto";
static const char dstipfrom_str[]     = "dstipfrom";
static const char dstipto_str[]       = "dstipto";
static const char srcportstart_str[]  = "srcportstart";
static const char srcportend_str[]    = "srcportend";
static const char dstportstart_str[]  = "dstportstart";
static const char dstportend_str[]    = "dstportend";
static const char dscp_str[]          = "dscp";
static const char state_str[]         = "state";
static const char ipset_str[]         = "ipset";
static const char ipsetflags_str[]    = "ipsetflags";

#define SRCMACADDR    srcmacaddr_str
#define SRCMACMASK    srcmacmask_str
#define DSTMACADDR    dstmacaddr_str
#define DSTMACMASK    dstmacmask_str
#define ARPSRCMACADDR arpsrcmacaddr_str
#define ARPDSTMACADDR arpdstmacaddr_str
#define ARPSRCIPADDR  arpsrcipaddr_str
#define ARPSRCIPMASK  arpsrcipmask_str
#define ARPDSTIPADDR  arpdstipaddr_str
#define ARPDSTIPMASK  arpdstipmask_str
#define SRCIPADDR     srcipaddr_str
#define SRCIPMASK     srcipmask_str
#define DSTIPADDR     dstipaddr_str
#define DSTIPMASK     dstipmask_str
#define SRCIPFROM     srcipfrom_str
#define SRCIPTO       srcipto_str
#define DSTIPFROM     dstipfrom_str
#define DSTIPTO       dstipto_str
#define SRCPORTSTART  srcportstart_str
#define SRCPORTEND    srcportend_str
#define DSTPORTSTART  dstportstart_str
#define DSTPORTEND    dstportend_str
#define DSCP          dscp_str
#define STATE         state_str
#define IPSET         ipset_str
#define IPSETFLAGS    ipsetflags_str


/**
 * intMapGetByInt:
 * @intmap: Pointer to int-to-string map
 * @attr: The attribute to look up
 * @res: Pointer to string pointer for result
 *
 * Returns 0 if value was found with result returned, -1 otherwise.
 *
 * lookup a map entry given the integer.
 */
static int
intMapGetByInt(const struct int_map *intmap,
               int32_t attr,
               const char **res)
{
    size_t i = 0;
    bool found = false;

    while (intmap[i].val && !found) {
        if (intmap[i].attr == attr) {
            *res = intmap[i].val;
            found = true;
        }
        i++;
    }
    return (found) ? 0 : -1;
}


/**
 * intMapGetByString:
 * @intmap: Pointer to int-to-string map
 * @str: Pointer to string for which to find the entry
 * @casecmp : Whether to ignore case when doing string matching
 * @result: Pointer to int for result
 *
 * Returns 0 if entry was found, -1 otherwise.
 *
 * Do a lookup in the map trying to find an integer key using the string
 * value. Returns 0 if entry was found with result returned, -1 otherwise.
 */
static int
intMapGetByString(const struct int_map *intmap,
                  const char *str,
                  int casecmp,
                  int32_t *result)
{
    size_t i = 0;
    bool found = false;

    while (intmap[i].val && !found) {
        if ((casecmp && STRCASEEQ(intmap[i].val, str)) ||
            STREQ(intmap[i].val, str)) {
            *result = intmap[i].attr;
            found = true;
        }
        i++;
    }
    return (found) ? 0 : -1;
}


void
virNWFilterRuleDefFree(virNWFilterRuleDefPtr def)
{
    size_t i;
    if (!def)
        return;

    for (i = 0; i < def->nVarAccess; i++)
        virNWFilterVarAccessFree(def->varAccess[i]);

    for (i = 0; i < def->nstrings; i++)
        VIR_FREE(def->strings[i]);

    VIR_FREE(def->varAccess);
    VIR_FREE(def->strings);

    VIR_FREE(def);
}


static void
virNWFilterIncludeDefFree(virNWFilterIncludeDefPtr inc)
{
    if (!inc)
        return;
    virNWFilterHashTableFree(inc->params);
    VIR_FREE(inc->filterref);
    VIR_FREE(inc);
}


static void
virNWFilterEntryFree(virNWFilterEntryPtr entry)
{
    if (!entry)
        return;

    virNWFilterRuleDefFree(entry->rule);
    virNWFilterIncludeDefFree(entry->include);
    VIR_FREE(entry);
}


void
virNWFilterDefFree(virNWFilterDefPtr def)
{
    size_t i;
    if (!def)
        return;

    VIR_FREE(def->name);

    for (i = 0; i < def->nentries; i++)
        virNWFilterEntryFree(def->filterEntries[i]);

    VIR_FREE(def->filterEntries);
    VIR_FREE(def->chainsuffix);

    VIR_FREE(def);
}


static int
virNWFilterRuleDefAddVar(virNWFilterRuleDefPtr nwf,
                         nwItemDesc *item,
                         const char *var)
{
    size_t i = 0;
    virNWFilterVarAccessPtr varAccess;

    varAccess = virNWFilterVarAccessParse(var);
    if (varAccess == NULL)
        return -1;

    if (nwf->varAccess) {
        for (i = 0; i < nwf->nVarAccess; i++)
            if (virNWFilterVarAccessEqual(nwf->varAccess[i], varAccess)) {
                virNWFilterVarAccessFree(varAccess);
                item->varAccess = nwf->varAccess[i];
                return 0;
            }
    }

    if (VIR_EXPAND_N(nwf->varAccess, nwf->nVarAccess, 1) < 0) {
        virNWFilterVarAccessFree(varAccess);
        return -1;
    }

    nwf->varAccess[nwf->nVarAccess - 1] = varAccess;
    item->varAccess = varAccess;

    return 0;
}


static char *
virNWFilterRuleDefAddString(virNWFilterRuleDefPtr nwf,
                            const char *string,
                            size_t maxstrlen)
{
    char *tmp;

    if (VIR_STRNDUP(tmp, string, maxstrlen) < 0 ||
        VIR_APPEND_ELEMENT_COPY(nwf->strings, nwf->nstrings, tmp) < 0)
        VIR_FREE(tmp);

    return tmp;
}


union data {
    void *v;
    char *c;
    unsigned char *uc;
    unsigned int ui;
};

typedef bool (*valueValidator)(enum attrDatatype datatype, union data *valptr,
                               virNWFilterRuleDefPtr nwf,
                               nwItemDesc *item);
typedef bool (*valueFormatter)(virBufferPtr buf,
                               virNWFilterRuleDefPtr nwf,
                               nwItemDesc *item);

typedef struct _virXMLAttr2Struct virXMLAttr2Struct;
struct _virXMLAttr2Struct
{
    const char *name;           /* attribute name */
    enum attrDatatype datatype;
    int dataIdx;                /* offset of the hasXYZ boolean */
    valueValidator validator;   /* beyond-standard checkers */
    valueFormatter formatter;   /* beyond-standard formatter */
    size_t maxstrlen;
};


static const struct int_map macProtoMap[] = {
    INTMAP_ENTRY(ETHERTYPE_ARP,    "arp"),
    INTMAP_ENTRY(ETHERTYPE_REVARP, "rarp"),
    INTMAP_ENTRY(ETHERTYPE_IP,     "ipv4"),
    INTMAP_ENTRY(ETHERTYPE_IPV6,   "ipv6"),
    INTMAP_ENTRY(ETHERTYPE_VLAN,   "vlan"),
    INTMAP_ENTRY_LAST
};


static bool
checkMacProtocolID(enum attrDatatype datatype,
                   union data *value,
                   virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(macProtoMap, value->c, 1, &res) < 0)
            res = -1;
        datatype = DATATYPE_UINT16;
    } else if (datatype == DATATYPE_UINT16 ||
               datatype == DATATYPE_UINT16_HEX) {
        res = value->ui;
        if (res < 0x600)
            res = -1;
    }

    if (res != -1) {
        nwf->p.ethHdrFilter.dataProtocolID.u.u16 = res;
        nwf->p.ethHdrFilter.dataProtocolID.datatype = datatype;
        return true;
    }

    return false;
}


static bool
macProtocolIDFormatter(virBufferPtr buf,
                       virNWFilterRuleDefPtr nwf,
                       nwItemDesc *item ATTRIBUTE_UNUSED)
{
    const char *str = NULL;
    bool asHex = true;

    if (intMapGetByInt(macProtoMap,
                       nwf->p.ethHdrFilter.dataProtocolID.u.u16,
                       &str) == 0) {
        virBufferAdd(buf, str, -1);
    } else {
        if (nwf->p.ethHdrFilter.dataProtocolID.datatype == DATATYPE_UINT16)
            asHex = false;
        virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                          nwf->p.ethHdrFilter.dataProtocolID.u.u16);
    }
    return true;
}


static bool
checkVlanVlanID(enum attrDatatype datatype,
                union data *value,
                virNWFilterRuleDefPtr nwf,
                nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res;

    res = value->ui;
    if (res < 0 || res > 4095)
        res = -1;

    if (res != -1) {
        nwf->p.vlanHdrFilter.dataVlanID.u.u16 = res;
        nwf->p.vlanHdrFilter.dataVlanID.datatype = datatype;
        return true;
    }

    return false;
}


static bool
checkVlanProtocolID(enum attrDatatype datatype,
                    union data *value,
                    virNWFilterRuleDefPtr nwf,
                    nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(macProtoMap, value->c, 1, &res) < 0)
            res = -1;
        datatype = DATATYPE_UINT16;
    } else if (datatype == DATATYPE_UINT16 ||
               datatype == DATATYPE_UINT16_HEX) {
        res = value->ui;
        if (res < 0x3c)
            res = -1;
    }

    if (res != -1) {
        nwf->p.vlanHdrFilter.dataVlanEncap.u.u16 = res;
        nwf->p.vlanHdrFilter.dataVlanEncap.datatype = datatype;
        return true;
    }

    return false;
}


static bool
vlanProtocolIDFormatter(virBufferPtr buf,
                        virNWFilterRuleDefPtr nwf,
                        nwItemDesc *item ATTRIBUTE_UNUSED)
{
    const char *str = NULL;
    bool asHex = true;

    if (intMapGetByInt(macProtoMap,
                       nwf->p.vlanHdrFilter.dataVlanEncap.u.u16,
                       &str) == 0) {
        virBufferAdd(buf, str, -1);
    } else {
        if (nwf->p.vlanHdrFilter.dataVlanEncap.datatype == DATATYPE_UINT16)
            asHex = false;
        virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                          nwf->p.vlanHdrFilter.dataVlanEncap.u.u16);
    }
    return true;
}


/* generic function to check for a valid (ipv4,ipv6, mac) mask
 * A mask is valid of there is a sequence of 1's followed by a sequence
 * of 0s or only 1s or only 0s
 */
static bool
checkValidMask(unsigned char *data,
               int len)
{
    uint32_t idx = 0;
    uint8_t mask = 0x80;
    bool checkones = true;

    while ((idx >> 3) < len) {
        if (checkones) {
            if (!(data[idx>>3] & mask))
                checkones = false;
        } else {
            if ((data[idx>>3] & mask))
                return false;
        }

        idx++;
        mask >>= 1;
        if (!mask)
            mask = 0x80;
    }
    return true;
}


static bool
checkMACMask(enum attrDatatype datatype ATTRIBUTE_UNUSED,
             union data *macMask,
             virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
             nwItemDesc *item ATTRIBUTE_UNUSED)
{
    return checkValidMask(macMask->uc, 6);
}


/*
 * supported arp opcode -- see 'ebtables -h arp' for the naming
 */
static const struct int_map arpOpcodeMap[] = {
    INTMAP_ENTRY(1, "Request"),
    INTMAP_ENTRY(2, "Reply"),
    INTMAP_ENTRY(3, "Request_Reverse"),
    INTMAP_ENTRY(4, "Reply_Reverse"),
    INTMAP_ENTRY(5, "DRARP_Request"),
    INTMAP_ENTRY(6, "DRARP_Reply"),
    INTMAP_ENTRY(7, "DRARP_Error"),
    INTMAP_ENTRY(8, "InARP_Request"),
    INTMAP_ENTRY(9, "ARP_NAK"),
    INTMAP_ENTRY_LAST
};


static bool
arpOpcodeValidator(enum attrDatatype datatype,
                   union data *value,
                   virNWFilterRuleDefPtr nwf,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(arpOpcodeMap, value->c, 1, &res) < 0)
            res = -1;
        datatype = DATATYPE_UINT16;
    } else if (datatype == DATATYPE_UINT16 ||
               datatype == DATATYPE_UINT16_HEX) {
        res = (uint32_t)value->ui;
    }

    if (res != -1) {
        nwf->p.arpHdrFilter.dataOpcode.u.u16 = res;
        nwf->p.arpHdrFilter.dataOpcode.datatype = datatype;
        return true;
    }
    return false;
}


static bool
arpOpcodeFormatter(virBufferPtr buf,
                   virNWFilterRuleDefPtr nwf,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    const char *str = NULL;

    if (intMapGetByInt(arpOpcodeMap,
                       nwf->p.arpHdrFilter.dataOpcode.u.u16,
                       &str) == 0) {
        virBufferAdd(buf, str, -1);
    } else {
        virBufferAsprintf(buf, "%d", nwf->p.arpHdrFilter.dataOpcode.u.u16);
    }
    return true;
}


static const struct int_map ipProtoMap[] = {
    INTMAP_ENTRY(IPPROTO_TCP, "tcp"),
    INTMAP_ENTRY(IPPROTO_UDP, "udp"),
#ifdef IPPROTO_UDPLITE
    INTMAP_ENTRY(IPPROTO_UDPLITE, "udplite"),
#endif
    INTMAP_ENTRY(IPPROTO_ESP, "esp"),
    INTMAP_ENTRY(IPPROTO_AH,  "ah"),
    INTMAP_ENTRY(IPPROTO_ICMP, "icmp"),
    INTMAP_ENTRY(IPPROTO_IGMP, "igmp"),
#ifdef IPPROTO_SCTP
    INTMAP_ENTRY(IPPROTO_SCTP, "sctp"),
#endif
    INTMAP_ENTRY(IPPROTO_ICMPV6, "icmpv6"),
    INTMAP_ENTRY_LAST
};


static bool
checkIPProtocolID(enum attrDatatype datatype,
                  union data *value,
                  virNWFilterRuleDefPtr nwf,
                  nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(ipProtoMap, value->c, 1, &res) < 0)
            res = -1;
        datatype = DATATYPE_UINT8_HEX;
    } else if (datatype == DATATYPE_UINT8 ||
               datatype == DATATYPE_UINT8_HEX) {
        res = (uint32_t)value->ui;
    }

    if (res != -1) {
        nwf->p.ipHdrFilter.ipHdr.dataProtocolID.u.u8 = res;
        nwf->p.ipHdrFilter.ipHdr.dataProtocolID.datatype = datatype;
        return true;
    }
    return false;
}


static bool
formatIPProtocolID(virBufferPtr buf,
                   virNWFilterRuleDefPtr nwf,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    const char *str = NULL;
    bool asHex = true;

    if (intMapGetByInt(ipProtoMap,
                       nwf->p.ipHdrFilter.ipHdr.dataProtocolID.u.u8,
                       &str) == 0) {
        virBufferAdd(buf, str, -1);
    } else {
        if (nwf->p.ipHdrFilter.ipHdr.dataProtocolID.datatype == DATATYPE_UINT8)
            asHex = false;
        virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                          nwf->p.ipHdrFilter.ipHdr.dataProtocolID.u.u8);
    }
    return true;
}


static bool
dscpValidator(enum attrDatatype datatype,
              union data *val,
              virNWFilterRuleDefPtr nwf,
              nwItemDesc *item ATTRIBUTE_UNUSED)
{
    uint8_t dscp = val->ui;
    if (dscp > 63)
        return false;

    nwf->p.ipHdrFilter.ipHdr.dataDSCP.datatype = datatype;

    return true;
}


static const struct int_map stateMatchMap[] = {
    INTMAP_ENTRY(RULE_FLAG_STATE_NEW,           "NEW"),
    INTMAP_ENTRY(RULE_FLAG_STATE_ESTABLISHED,   "ESTABLISHED"),
    INTMAP_ENTRY(RULE_FLAG_STATE_RELATED,       "RELATED"),
    INTMAP_ENTRY(RULE_FLAG_STATE_INVALID,       "INVALID"),
    INTMAP_ENTRY(RULE_FLAG_STATE_NONE,          "NONE"),
    INTMAP_ENTRY_LAST,
};


static int
parseStringItems(const struct int_map *int_map,
                 const char *input,
                 int32_t *flags,
                 char sep)
{
    int rc = 0;
    size_t i, j;
    bool found;

    i = 0;
    while (input[i]) {
        found = false;
        while (c_isspace(input[i]) || input[i] == sep)
            i++;
        if (!input[i])
            break;
        for (j = 0; int_map[j].val; j++) {
            if (STRCASEEQLEN(&input[i], int_map[j].val,
                             strlen(int_map[j].val))) {
                *flags |= int_map[j].attr;
                i += strlen(int_map[j].val);
                found = true;
                break;
            }
        }
        if (!found) {
            rc = -1;
            break;
        }
    }
    return rc;
}


static int
printStringItems(virBufferPtr buf,
                 const struct int_map *int_map,
                 int32_t flags,
                 const char *sep)
{
    size_t i;
    unsigned int c = 0;
    int32_t mask = 0x1;

    while (mask) {
        if ((mask & flags)) {
            for (i = 0; int_map[i].val; i++) {
                if (mask == int_map[i].attr) {
                    if (c >= 1)
                        virBufferAdd(buf, sep, -1);
                    virBufferAdd(buf, int_map[i].val, -1);
                    c++;
                }
            }
            flags ^= mask;
        }
        if (!flags)
            break;
        mask <<= 1;
    }

    return 0;
}


static int
parseStateMatch(const char *statematch,
                int32_t *flags)
{
    int rc = parseStringItems(stateMatchMap, statematch, flags, ',');

    if ((*flags & RULE_FLAG_STATE_NONE))
        *flags = RULE_FLAG_STATE_NONE;

    return rc;
}


void
virNWFilterPrintStateMatchFlags(virBufferPtr buf,
                                const char *prefix,
                                int32_t flags,
                                bool disp_none)
{
    if (!disp_none && (flags & RULE_FLAG_STATE_NONE))
        return;

    virBufferAdd(buf, prefix, -1);

    printStringItems(buf, stateMatchMap, flags, ",");
}


static bool
stateValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED,
               union data *val,
               virNWFilterRuleDefPtr nwf,
               nwItemDesc *item)
{
    char *input = val->c;
    int32_t flags = 0;

    if (parseStateMatch(input, &flags) < 0)
        return false;

    item->u.u16 = flags;
    nwf->flags |= flags;

    item->datatype = DATATYPE_UINT16;

    return true;
}


static bool
stateFormatter(virBufferPtr buf,
               virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
               nwItemDesc *item)
{
    virNWFilterPrintStateMatchFlags(buf, "", item->u.u16, true);

    return true;
}


static const struct int_map tcpFlags[] = {
    INTMAP_ENTRY(0x1,  "FIN"),
    INTMAP_ENTRY(0x2,  "SYN"),
    INTMAP_ENTRY(0x4,  "RST"),
    INTMAP_ENTRY(0x8,  "PSH"),
    INTMAP_ENTRY(0x10, "ACK"),
    INTMAP_ENTRY(0x20, "URG"),
    INTMAP_ENTRY(0x3F, "ALL"),
    INTMAP_ENTRY(0x0,  "NONE"),
    INTMAP_ENTRY_LAST
};


static bool
tcpFlagsValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED,
                  union data *val,
                  virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                  nwItemDesc *item)
{
    bool rc = false;
    char *s_mask = val->c;
    char *sep = strchr(val->c, '/');
    char *s_flags;
    int32_t mask = 0, flags = 0;

    if (!sep)
        return false;

    s_flags = sep + 1;

    *sep = '\0';

    if (parseStringItems(tcpFlags, s_mask, &mask, ',') == 0 &&
        parseStringItems(tcpFlags, s_flags, &flags, ',') == 0) {
        item->u.tcpFlags.mask  = mask  & 0x3f;
        item->u.tcpFlags.flags = flags & 0x3f;
        rc = true;
    }

    *sep = '/';

    return rc;
}


static void
printTCPFlags(virBufferPtr buf,
              uint8_t flags)
{
    if (flags == 0)
        virBufferAddLit(buf, "NONE");
    else if (flags == 0x3f)
        virBufferAddLit(buf, "ALL");
    else
        printStringItems(buf, tcpFlags, flags, ",");
}


char *
virNWFilterPrintTCPFlags(uint8_t flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    printTCPFlags(&buf, flags);
    if (virBufferCheckError(&buf) < 0)
        return NULL;
    return virBufferContentAndReset(&buf);
}


static bool
tcpFlagsFormatter(virBufferPtr buf,
                  virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                  nwItemDesc *item)
{
    printTCPFlags(buf, item->u.tcpFlags.mask);
    virBufferAddLit(buf, "/");
    printTCPFlags(buf, item->u.tcpFlags.flags);

    return true;
}


static bool
ipsetValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED,
               union data *val,
               virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
               nwItemDesc *item)
{
    const char *errmsg = NULL;

    if (virStrcpy(item->u.ipset.setname, val->c,
                  sizeof(item->u.ipset.setname)) == NULL) {
        errmsg = _("ipset name is too long");
        goto arg_err_exit;
    }

    if (item->u.ipset.setname[strspn(item->u.ipset.setname,
                                     VALID_IPSETNAME)] != 0) {
        errmsg = _("ipset name contains invalid characters");
        goto arg_err_exit;
    }

    return true;

 arg_err_exit:
    virReportError(VIR_ERR_INVALID_ARG,
                   "%s", errmsg);
    return false;
}


static bool
ipsetFormatter(virBufferPtr buf,
               virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
               nwItemDesc *item)
{
    virBufferAdd(buf, item->u.ipset.setname, -1);

    return true;
}


static bool
ipsetFlagsValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED,
                    union data *val,
                    virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                    nwItemDesc *item)
{
    const char *errmsg = NULL;
    size_t idx = 0;

    item->u.ipset.numFlags = 0;
    item->u.ipset.flags = 0;

    errmsg = _("malformed ipset flags");

    while (item->u.ipset.numFlags < 6) {
        if (STRCASEEQLEN(&val->c[idx], "src", 3)) {
            item->u.ipset.flags |= (1 << item->u.ipset.numFlags);
        } else if (!STRCASEEQLEN(&val->c[idx], "dst", 3)) {
            goto arg_err_exit;
        }
        item->u.ipset.numFlags++;
        idx += 3;
        if (val->c[idx] != ',')
            break;
        idx++;
    }

    if (val->c[idx] != '\0')
        goto arg_err_exit;

    return true;

 arg_err_exit:
    virReportError(VIR_ERR_INVALID_ARG,
                   "%s", errmsg);
    return false;
}


static bool
ipsetFlagsFormatter(virBufferPtr buf,
                    virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                    nwItemDesc *item)
{
    uint8_t ctr;

    for (ctr = 0; ctr < item->u.ipset.numFlags; ctr++) {
        if (ctr != 0)
            virBufferAddLit(buf, ",");
        if ((item->u.ipset.flags & (1 << ctr)))
            virBufferAddLit(buf, "src");
        else
            virBufferAddLit(buf, "dst");
    }

    return true;
}


#define COMMON_MAC_PROPS(STRUCT) \
    {\
        .name = SRCMACADDR,\
        .datatype = DATATYPE_MACADDR,\
            .dataIdx = offsetof(virNWFilterRuleDef,\
                            p.STRUCT.ethHdr.dataSrcMACAddr),\
    },\
    {\
        .name = SRCMACMASK,\
        .datatype = DATATYPE_MACMASK,\
        .dataIdx = offsetof(virNWFilterRuleDef,\
                            p.STRUCT.ethHdr.dataSrcMACMask),\
    },\
    {\
        .name = DSTMACADDR,\
        .datatype = DATATYPE_MACADDR,\
        .dataIdx = offsetof(virNWFilterRuleDef,\
                            p.STRUCT.ethHdr.dataDstMACAddr),\
    },\
    {\
        .name = DSTMACMASK,\
        .datatype = DATATYPE_MACMASK,\
        .dataIdx = offsetof(virNWFilterRuleDef,\
                            p.STRUCT.ethHdr.dataDstMACMask),\
    }


#define COMMENT_PROP(STRUCT) \
    {\
        .name = "comment",\
        .datatype = DATATYPE_STRINGCOPY,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.dataComment),\
        .maxstrlen = MAX_COMMENT_LENGTH,\
    }

#define COMMENT_PROP_IPHDR(STRUCT) \
    COMMENT_PROP(STRUCT.ipHdr)


static const virXMLAttr2Struct macAttributes[] = {
    COMMON_MAC_PROPS(ethHdrFilter),
    {
        .name = "protocolid",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX | DATATYPE_STRING,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ethHdrFilter.dataProtocolID),
        .validator = checkMacProtocolID,
        .formatter = macProtocolIDFormatter,
    },
    COMMENT_PROP(ethHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct vlanAttributes[] = {
    COMMON_MAC_PROPS(ethHdrFilter),
    {
        .name = "vlanid",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.vlanHdrFilter.dataVlanID),
        .validator = checkVlanVlanID,
    },
    {
        .name = "encap-protocol",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX | DATATYPE_STRING,
        .dataIdx = offsetof(virNWFilterRuleDef, p.vlanHdrFilter.dataVlanEncap),
        .validator = checkVlanProtocolID,
        .formatter = vlanProtocolIDFormatter,
    },
    COMMENT_PROP(vlanHdrFilter),
    {
        .name = NULL,
    }
};

/* STP is documented by IEEE 802.1D; for a synopsis,
 * see http://www.javvin.com/protocolSTP.html */
static const virXMLAttr2Struct stpAttributes[] = {
    /* spanning tree uses a special destination MAC address */
    {
        .name = SRCMACADDR,
        .datatype = DATATYPE_MACADDR,
        .dataIdx = offsetof(virNWFilterRuleDef,
                            p.stpHdrFilter.ethHdr.dataSrcMACAddr),
    },
    {
        .name = SRCMACMASK,
        .datatype = DATATYPE_MACMASK,
        .dataIdx = offsetof(virNWFilterRuleDef,
                            p.stpHdrFilter.ethHdr.dataSrcMACMask),
    },
    {
        .name = "type",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataType),
    },
    {
        .name = "flags",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataFlags),
    },
    {
        .name = "root-priority",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootPri),
    },
    {
        .name = "root-priority-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootPriHi),
    },
    {
        .name = "root-address",
        .datatype = DATATYPE_MACADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootAddr),
    },
    {
        .name = "root-address-mask",
        .datatype = DATATYPE_MACMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootAddrMask),
    },
    {
        .name = "root-cost",
        .datatype = DATATYPE_UINT32 | DATATYPE_UINT32_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootCost),
    },
    {
        .name = "root-cost-hi",
        .datatype = DATATYPE_UINT32 | DATATYPE_UINT32_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataRootCostHi),
    },
    {
        .name = "sender-priority",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataSndrPrio),
    },
    {
        .name = "sender-priority-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataSndrPrioHi),
    },
    {
        .name = "sender-address",
        .datatype = DATATYPE_MACADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataSndrAddr),
    },
    {
        .name = "sender-address-mask",
        .datatype = DATATYPE_MACMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataSndrAddrMask),
    },
    {
        .name = "port",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataPort),
    },
    {
        .name = "port-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataPortHi),
    },
    {
        .name = "age",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataAge),
    },
    {
        .name = "age-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataAgeHi),
    },
    {
        .name = "max-age",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataMaxAge),
    },
    {
        .name = "max-age-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataMaxAgeHi),
    },
    {
        .name = "hello-time",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataHelloTime),
    },
    {
        .name = "hello-time-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataHelloTimeHi),
    },
    {
        .name = "forward-delay",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataFwdDelay),
    },
    {
        .name = "forward-delay-hi",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.stpHdrFilter.dataFwdDelayHi),
    },
    COMMENT_PROP(stpHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct arpAttributes[] = {
    COMMON_MAC_PROPS(arpHdrFilter),
    {
        .name = "hwtype",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataHWType),
    }, {
        .name = "protocoltype",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataProtocolType),
    }, {
        .name = "opcode",
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX | DATATYPE_STRING,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataOpcode),
        .validator = arpOpcodeValidator,
        .formatter = arpOpcodeFormatter,
    }, {
        .name = ARPSRCMACADDR,
        .datatype = DATATYPE_MACADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPSrcMACAddr),
    }, {
        .name = ARPDSTMACADDR,
        .datatype = DATATYPE_MACADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPDstMACAddr),
    }, {
        .name = ARPSRCIPADDR,
        .datatype = DATATYPE_IPADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPSrcIPAddr),
    }, {
        .name = ARPSRCIPMASK,
        .datatype = DATATYPE_IPMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPSrcIPMask),
    }, {
        .name = ARPDSTIPADDR,
        .datatype = DATATYPE_IPADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPDstIPAddr),
    }, {
        .name = ARPDSTIPMASK,
        .datatype = DATATYPE_IPMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPDstIPMask),
    }, {
        .name = "gratuitous",
        .datatype = DATATYPE_BOOLEAN,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataGratuitousARP),
    },
    COMMENT_PROP(arpHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct ipAttributes[] = {
    COMMON_MAC_PROPS(ipHdrFilter),
    {
        .name = SRCIPADDR,
        .datatype = DATATYPE_IPADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataSrcIPAddr),
    },
    {
        .name = SRCIPMASK,
        .datatype = DATATYPE_IPMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataSrcIPMask),
    },
    {
        .name = DSTIPADDR,
        .datatype = DATATYPE_IPADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataDstIPAddr),
    },
    {
        .name = DSTIPMASK,
        .datatype = DATATYPE_IPMASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataDstIPMask),
    },
    {
        .name = "protocol",
        .datatype = DATATYPE_STRING | DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataProtocolID),
        .validator = checkIPProtocolID,
        .formatter = formatIPProtocolID,
    },
    {
        .name = SRCPORTSTART,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.portData.dataSrcPortStart),
    },
    {
        .name = SRCPORTEND,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.portData.dataSrcPortEnd),
    },
    {
        .name = DSTPORTSTART,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.portData.dataDstPortStart),
    },
    {
        .name = DSTPORTEND,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.portData.dataDstPortEnd),
    },
    {
        .name = DSCP,
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipHdrFilter.ipHdr.dataDSCP),
        .validator = dscpValidator,
    },
    COMMENT_PROP_IPHDR(ipHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct ipv6Attributes[] = {
    COMMON_MAC_PROPS(ipv6HdrFilter),
    {
        .name = SRCIPADDR,
        .datatype = DATATYPE_IPV6ADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.ipHdr.dataSrcIPAddr),
    },
    {
        .name = SRCIPMASK,
        .datatype = DATATYPE_IPV6MASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.ipHdr.dataSrcIPMask),
    },
    {
        .name = DSTIPADDR,
        .datatype = DATATYPE_IPV6ADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.ipHdr.dataDstIPAddr),
    },
    {
        .name = DSTIPMASK,
        .datatype = DATATYPE_IPV6MASK,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.ipHdr.dataDstIPMask),
    },
    {
        .name = "protocol",
        .datatype = DATATYPE_STRING | DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.ipHdr.dataProtocolID),
        .validator = checkIPProtocolID,
        .formatter = formatIPProtocolID,
    },
    {
        .name = SRCPORTSTART,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.portData.dataSrcPortStart),
    },
    {
        .name = SRCPORTEND,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.portData.dataSrcPortEnd),
    },
    {
        .name = DSTPORTSTART,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.portData.dataDstPortStart),
    },
    {
        .name = DSTPORTEND,
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.portData.dataDstPortEnd),
    },
    {
        .name = "type",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.dataICMPTypeStart),
    },
    {
        .name = "typeend",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.dataICMPTypeEnd),
    },
    {
        .name = "code",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.dataICMPCodeStart),
    },
    {
        .name = "codeend",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.ipv6HdrFilter.dataICMPCodeEnd),
    },
    COMMENT_PROP_IPHDR(ipv6HdrFilter),
    {
        .name = NULL,
    }
};


#define COMMON_L3_MAC_PROPS(STRUCT) \
    {\
        .name = SRCMACADDR,\
        .datatype = DATATYPE_MACADDR,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.dataSrcMACAddr),\
    }

#define COMMON_IP_PROPS(STRUCT, ADDRTYPE, MASKTYPE) \
    COMMON_L3_MAC_PROPS(STRUCT),\
    {\
        .name = SRCIPADDR,\
        .datatype = ADDRTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataSrcIPAddr),\
    },\
    {\
        .name = SRCIPMASK,\
        .datatype = MASKTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataSrcIPMask),\
    },\
    {\
        .name = DSTIPADDR,\
        .datatype = ADDRTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataDstIPAddr),\
    },\
    {\
        .name = DSTIPMASK,\
        .datatype = MASKTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataDstIPMask),\
    },\
    {\
        .name = SRCIPFROM,\
        .datatype = ADDRTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataSrcIPFrom),\
    },\
    {\
        .name = SRCIPTO,\
        .datatype = ADDRTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataSrcIPTo),\
    },\
    {\
        .name = DSTIPFROM,\
        .datatype = ADDRTYPE,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataDstIPFrom),\
    },\
    {\
        .name = DSTIPTO,\
        .datatype = DATATYPE_IPADDR,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataDstIPTo),\
    },\
    {\
        .name = DSCP,\
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataDSCP),\
        .validator = dscpValidator,\
    },\
    {\
        .name = "connlimit-above",\
        .datatype = DATATYPE_UINT16,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataConnlimitAbove),\
    },\
    {\
        .name = STATE,\
        .datatype = DATATYPE_STRING,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataState),\
        .validator = stateValidator,\
        .formatter = stateFormatter,\
    },\
    {\
        .name = IPSET,\
        .datatype = DATATYPE_IPSETNAME,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataIPSet),\
        .validator = ipsetValidator,\
        .formatter = ipsetFormatter,\
    },\
    {\
        .name = IPSETFLAGS,\
        .datatype = DATATYPE_IPSETFLAGS,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ipHdr.dataIPSetFlags),\
        .validator = ipsetFlagsValidator,\
        .formatter = ipsetFlagsFormatter,\
    }

#define COMMON_PORT_PROPS(STRUCT) \
    {\
        .name = SRCPORTSTART,\
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.portData.dataSrcPortStart),\
    },\
    {\
        .name = SRCPORTEND,\
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.portData.dataSrcPortEnd),\
    },\
    {\
        .name = DSTPORTSTART,\
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.portData.dataDstPortStart),\
    },\
    {\
        .name = DSTPORTEND,\
        .datatype = DATATYPE_UINT16 | DATATYPE_UINT16_HEX,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.portData.dataDstPortEnd),\
    }

static const virXMLAttr2Struct tcpAttributes[] = {
    COMMON_IP_PROPS(tcpHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMON_PORT_PROPS(tcpHdrFilter),
    {
        .name = "option",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.tcpHdrFilter.dataTCPOption),
    },
    {
        .name = "flags",
        .datatype = DATATYPE_STRING,
        .dataIdx = offsetof(virNWFilterRuleDef, p.tcpHdrFilter.dataTCPFlags),
        .validator = tcpFlagsValidator,
        .formatter = tcpFlagsFormatter,
    },
    COMMENT_PROP_IPHDR(tcpHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct udpAttributes[] = {
    COMMON_IP_PROPS(udpHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMON_PORT_PROPS(udpHdrFilter),
    COMMENT_PROP_IPHDR(udpHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct udpliteAttributes[] = {
    COMMON_IP_PROPS(udpliteHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMENT_PROP_IPHDR(udpliteHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct espAttributes[] = {
    COMMON_IP_PROPS(espHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMENT_PROP_IPHDR(espHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct ahAttributes[] = {
    COMMON_IP_PROPS(ahHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMENT_PROP_IPHDR(ahHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct sctpAttributes[] = {
    COMMON_IP_PROPS(sctpHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMON_PORT_PROPS(sctpHdrFilter),
    COMMENT_PROP_IPHDR(sctpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct icmpAttributes[] = {
    COMMON_IP_PROPS(icmpHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    {
        .name = "type",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.icmpHdrFilter.dataICMPType),
    },
    {
        .name = "code",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.icmpHdrFilter.dataICMPCode),
    },
    COMMENT_PROP_IPHDR(icmpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct allAttributes[] = {
    COMMON_IP_PROPS(allHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMENT_PROP_IPHDR(allHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct igmpAttributes[] = {
    COMMON_IP_PROPS(igmpHdrFilter, DATATYPE_IPADDR, DATATYPE_IPMASK),
    COMMENT_PROP_IPHDR(igmpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct tcpipv6Attributes[] = {
    COMMON_IP_PROPS(tcpHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMON_PORT_PROPS(tcpHdrFilter),
    {
        .name = "option",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.tcpHdrFilter.dataTCPOption),
    },
    COMMENT_PROP_IPHDR(tcpHdrFilter),
    {
        .name = NULL,
    }
};

static const virXMLAttr2Struct udpipv6Attributes[] = {
    COMMON_IP_PROPS(udpHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMON_PORT_PROPS(udpHdrFilter),
    COMMENT_PROP_IPHDR(udpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct udpliteipv6Attributes[] = {
    COMMON_IP_PROPS(udpliteHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMENT_PROP_IPHDR(udpliteHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct espipv6Attributes[] = {
    COMMON_IP_PROPS(espHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMENT_PROP_IPHDR(espHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct ahipv6Attributes[] = {
    COMMON_IP_PROPS(ahHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMENT_PROP_IPHDR(ahHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct sctpipv6Attributes[] = {
    COMMON_IP_PROPS(sctpHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMON_PORT_PROPS(sctpHdrFilter),
    COMMENT_PROP_IPHDR(sctpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct icmpv6Attributes[] = {
    COMMON_IP_PROPS(icmpHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    {
        .name = "type",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.icmpHdrFilter.dataICMPType),
    },
    {
        .name = "code",
        .datatype = DATATYPE_UINT8 | DATATYPE_UINT8_HEX,
        .dataIdx = offsetof(virNWFilterRuleDef, p.icmpHdrFilter.dataICMPCode),
    },
    COMMENT_PROP_IPHDR(icmpHdrFilter),
    {
        .name = NULL,
    }
};


static const virXMLAttr2Struct allipv6Attributes[] = {
    COMMON_IP_PROPS(allHdrFilter, DATATYPE_IPV6ADDR, DATATYPE_IPV6MASK),
    COMMENT_PROP_IPHDR(allHdrFilter),
    {
        .name = NULL,
    }
};


typedef struct _virAttributes virAttributes;
struct _virAttributes {
    const char *id;
    const virXMLAttr2Struct *att;
    virNWFilterRuleProtocolType prtclType;
};

#define PROTOCOL_ENTRY(ID, ATT, PRTCLTYPE) \
    { .id = ID, .att = ATT, .prtclType = PRTCLTYPE }
#define PROTOCOL_ENTRY_LAST { .id = NULL }


static const virAttributes virAttr[] = {
    PROTOCOL_ENTRY("arp",     arpAttributes,     VIR_NWFILTER_RULE_PROTOCOL_ARP),
    PROTOCOL_ENTRY("rarp",    arpAttributes,     VIR_NWFILTER_RULE_PROTOCOL_RARP),
    PROTOCOL_ENTRY("mac",     macAttributes,     VIR_NWFILTER_RULE_PROTOCOL_MAC),
    PROTOCOL_ENTRY("vlan",    vlanAttributes,    VIR_NWFILTER_RULE_PROTOCOL_VLAN),
    PROTOCOL_ENTRY("stp",     stpAttributes,     VIR_NWFILTER_RULE_PROTOCOL_STP),
    PROTOCOL_ENTRY("ip",      ipAttributes,      VIR_NWFILTER_RULE_PROTOCOL_IP),
    PROTOCOL_ENTRY("ipv6",    ipv6Attributes,    VIR_NWFILTER_RULE_PROTOCOL_IPV6),
    PROTOCOL_ENTRY("tcp",     tcpAttributes,     VIR_NWFILTER_RULE_PROTOCOL_TCP),
    PROTOCOL_ENTRY("udp",     udpAttributes,     VIR_NWFILTER_RULE_PROTOCOL_UDP),
    PROTOCOL_ENTRY("udplite", udpliteAttributes, VIR_NWFILTER_RULE_PROTOCOL_UDPLITE),
    PROTOCOL_ENTRY("esp",     espAttributes,     VIR_NWFILTER_RULE_PROTOCOL_ESP),
    PROTOCOL_ENTRY("ah",      ahAttributes,      VIR_NWFILTER_RULE_PROTOCOL_AH),
    PROTOCOL_ENTRY("sctp",    sctpAttributes,    VIR_NWFILTER_RULE_PROTOCOL_SCTP),
    PROTOCOL_ENTRY("icmp",    icmpAttributes,    VIR_NWFILTER_RULE_PROTOCOL_ICMP),
    PROTOCOL_ENTRY("all",     allAttributes,     VIR_NWFILTER_RULE_PROTOCOL_ALL),
    PROTOCOL_ENTRY("igmp",    igmpAttributes,    VIR_NWFILTER_RULE_PROTOCOL_IGMP),
    PROTOCOL_ENTRY("tcp-ipv6",     tcpipv6Attributes,     VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6),
    PROTOCOL_ENTRY("udp-ipv6",     udpipv6Attributes,     VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6),
    PROTOCOL_ENTRY("udplite-ipv6", udpliteipv6Attributes, VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6),
    PROTOCOL_ENTRY("esp-ipv6",     espipv6Attributes,     VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6),
    PROTOCOL_ENTRY("ah-ipv6",      ahipv6Attributes,      VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6),
    PROTOCOL_ENTRY("sctp-ipv6",    sctpipv6Attributes,    VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6),
    PROTOCOL_ENTRY("icmpv6",       icmpv6Attributes,      VIR_NWFILTER_RULE_PROTOCOL_ICMPV6),
    PROTOCOL_ENTRY("all-ipv6",     allipv6Attributes,     VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6),
    PROTOCOL_ENTRY_LAST
};


static int
virNWFilterRuleDetailsParse(xmlNodePtr node,
                            virNWFilterRuleDefPtr nwf,
                            const virXMLAttr2Struct *att)
{
    int rc = 0, g_rc = 0;
    int idx = 0;
    char *prop;
    bool found = false;
    enum attrDatatype datatype, att_datatypes;
    virNWFilterEntryItemFlags *flags, match_flag = 0, flags_set = 0;
    nwItemDesc *item;
    int int_val;
    unsigned int uint_val;
    union data data;
    valueValidator validator;
    char *match = virXMLPropString(node, "match");
    virSocketAddr ipaddr;
    int base;

    if (match && STREQ(match, "no"))
        match_flag = NWFILTER_ENTRY_ITEM_FLAG_IS_NEG;
    VIR_FREE(match);
    match = NULL;

    while (att[idx].name != NULL) {
        prop = virXMLPropString(node, att[idx].name);

        VIR_WARNINGS_NO_CAST_ALIGN
        item = (nwItemDesc *)((char *)nwf + att[idx].dataIdx);
        VIR_WARNINGS_RESET
        flags = &item->flags;
        flags_set = match_flag;

        if (prop) {
            found = false;

            validator = NULL;

            if (STRPREFIX(prop, "$")) {
                flags_set |= NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR;
                if (virNWFilterRuleDefAddVar(nwf,
                                             item,
                                             &prop[1]) < 0)
                    rc = -1;
                found = true;
            }

            datatype = 1;

            att_datatypes = att[idx].datatype;

            while (datatype <= DATATYPE_LAST && found == 0 && rc == 0) {
                if ((att_datatypes & datatype)) {

                    att_datatypes ^= datatype;

                    validator = att[idx].validator;

                    base = 10;

                    switch (datatype) {
                        case DATATYPE_UINT8_HEX:
                            base = 16;
                            ATTRIBUTE_FALLTHROUGH;
                        case DATATYPE_UINT8:
                            if (virStrToLong_ui(prop, NULL, base, &uint_val) >= 0) {
                                if (uint_val <= 0xff) {
                                    item->u.u8 = uint_val;
                                    found = true;
                                    data.ui = uint_val;
                                } else {
                                    rc = -1;
                                }
                            } else {
                                rc = -1;
                            }
                        break;

                        case DATATYPE_UINT16_HEX:
                            base = 16;
                            ATTRIBUTE_FALLTHROUGH;
                        case DATATYPE_UINT16:
                            if (virStrToLong_ui(prop, NULL, base, &uint_val) >= 0) {
                                if (uint_val <= 0xffff) {
                                    item->u.u16 = uint_val;
                                    found = true;
                                    data.ui = uint_val;
                                } else {
                                    rc = -1;
                                }
                            } else {
                                rc = -1;
                            }
                        break;

                        case DATATYPE_UINT32_HEX:
                            base = 16;
                            ATTRIBUTE_FALLTHROUGH;
                        case DATATYPE_UINT32:
                            if (virStrToLong_ui(prop, NULL, base, &uint_val) >= 0) {
                                item->u.u32 = uint_val;
                                found = true;
                                data.ui = uint_val;
                            } else {
                                rc = -1;
                            }
                        break;

                        case DATATYPE_IPADDR:
                            if (virSocketAddrParseIPv4(&item->u.ipaddr, prop) < 0)
                                rc = -1;
                            found = true;
                        break;

                        case DATATYPE_IPMASK:
                            if (virStrToLong_ui(prop, NULL, 10, &uint_val) == 0) {
                                if (uint_val <= 32) {
                                    if (!validator)
                                        item->u.u8 = (uint8_t)uint_val;
                                    found = true;
                                    data.ui = uint_val;
                                } else {
                                    rc = -1;
                                }
                            } else {
                                if (virSocketAddrParseIPv4(&ipaddr, prop) < 0) {
                                    rc = -1;
                                } else {
                                    int_val = virSocketAddrGetNumNetmaskBits(&ipaddr);
                                    if (int_val >= 0)
                                        item->u.u8 = int_val;
                                    else
                                        rc = -1;
                                    found = true;
                                }
                            }
                        break;

                        case DATATYPE_MACADDR:
                            if (virMacAddrParse(prop,
                                                &item->u.macaddr) < 0) {
                                rc = -1;
                            }
                            found = true;
                        break;

                        case DATATYPE_MACMASK:
                            validator = checkMACMask;
                            if (virMacAddrParse(prop,
                                                &item->u.macaddr) < 0) {
                                rc = -1;
                            }
                            data.v = &item->u.macaddr;
                            found = true;
                        break;

                        case DATATYPE_IPV6ADDR:
                            if (virSocketAddrParseIPv6(&item->u.ipaddr, prop) < 0)
                                rc = -1;
                            found = true;
                        break;

                        case DATATYPE_IPV6MASK:
                            if (virStrToLong_ui(prop, NULL, 10, &uint_val) == 0) {
                                if (uint_val <= 128) {
                                    if (!validator)
                                        item->u.u8 = (uint8_t)uint_val;
                                    found = true;
                                    data.ui = uint_val;
                                } else {
                                    rc = -1;
                                }
                            } else {
                                if (virSocketAddrParseIPv6(&ipaddr, prop) < 0) {
                                    rc = -1;
                                } else {
                                    int_val = virSocketAddrGetNumNetmaskBits(&ipaddr);
                                    if (int_val >= 0)
                                        item->u.u8 = int_val;
                                    else
                                        rc = -1;
                                    found = true;
                                }
                            }
                        break;

                        case DATATYPE_STRING:
                        case DATATYPE_IPSETFLAGS:
                        case DATATYPE_IPSETNAME:
                            if (!validator) {
                                /* not supported */
                                rc = -1;
                                break;
                            }
                            data.c = prop;
                            found = true;
                        break;

                        case DATATYPE_STRINGCOPY:
                            if (!(item->u.string =
                                  virNWFilterRuleDefAddString(nwf, prop,
                                                       att[idx].maxstrlen))) {
                                rc = -1;
                                break;
                            }
                            data.c = item->u.string;
                            found = true;
                        break;

                        case DATATYPE_BOOLEAN:
                            if (STREQ(prop, "true") ||
                                STREQ(prop, "1") ||
                                STREQ(prop, "yes"))
                                item->u.boolean = true;
                            else
                                item->u.boolean = false;

                            data.ui = item->u.boolean;
                            found = true;
                        break;

                        case DATATYPE_LAST:
                        default:
                        break;
                    }
                }

                if (rc != 0 && att_datatypes != 0) {
                    rc = 0;
                    found = false;
                }

                datatype <<= 1;
            } /* while */

            if (found && rc == 0) {
                *flags = NWFILTER_ENTRY_ITEM_FLAG_EXISTS | flags_set;
                item->datatype = datatype >> 1;
                if (validator) {
                    if (!validator(datatype >> 1, &data, nwf, item)) {
                        rc = -1;
                        *flags = 0;
                    }
                }
            }

            if (!found || rc) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("%s has illegal value %s"),
                               att[idx].name, prop);
                rc = -1;
            }
            VIR_FREE(prop);
        }

        if (rc) {
            g_rc = rc;
            rc = 0;
        }

        idx++;
    }

    return g_rc;
}


static virNWFilterIncludeDefPtr
virNWFilterIncludeParse(xmlNodePtr cur)
{
    virNWFilterIncludeDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->filterref = virXMLPropString(cur, "filter");
    if (!ret->filterref) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("rule node requires action attribute"));
        goto err_exit;
    }

    ret->params = virNWFilterParseParamAttributes(cur);
    if (!ret->params)
        goto err_exit;

 cleanup:
    return ret;

 err_exit:
    virNWFilterIncludeDefFree(ret);
    ret = NULL;
    goto cleanup;
}


static void
virNWFilterRuleDefFixupIPSet(ipHdrDataDefPtr ipHdr)
{
    if (HAS_ENTRY_ITEM(&ipHdr->dataIPSet) &&
        !HAS_ENTRY_ITEM(&ipHdr->dataIPSetFlags)) {
        ipHdr->dataIPSetFlags.flags = NWFILTER_ENTRY_ITEM_FLAG_EXISTS;
        ipHdr->dataIPSetFlags.u.ipset.numFlags = 1;
        ipHdr->dataIPSetFlags.u.ipset.flags = 1;
    } else {
        ipHdr->dataIPSet.flags = 0;
        ipHdr->dataIPSetFlags.flags = 0;
    }
}


/*
 * virNWFilterRuleValidate
 *
 * Perform some basic rule validation to prevent rules from being
 * defined that cannot be instantiated.
 */
static int
virNWFilterRuleValidate(virNWFilterRuleDefPtr rule)
{
    int ret = 0;
    portDataDefPtr portData = NULL;
    nwItemDescPtr dataProtocolID = NULL;
    const char *protocol = NULL;

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        portData = &rule->p.ipHdrFilter.portData;
        protocol = "IP";
        dataProtocolID = &rule->p.ipHdrFilter.ipHdr.dataProtocolID;
        ATTRIBUTE_FALLTHROUGH;
    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        if (portData == NULL) {
            portData = &rule->p.ipv6HdrFilter.portData;
            protocol = "IPv6";
            dataProtocolID = &rule->p.ipv6HdrFilter.ipHdr.dataProtocolID;
        }
        if (HAS_ENTRY_ITEM(&portData->dataSrcPortStart) ||
            HAS_ENTRY_ITEM(&portData->dataDstPortStart) ||
            HAS_ENTRY_ITEM(&portData->dataSrcPortEnd) ||
            HAS_ENTRY_ITEM(&portData->dataDstPortEnd)) {
            if (HAS_ENTRY_ITEM(dataProtocolID)) {
                switch (dataProtocolID->u.u8) {
                case 6:   /* tcp */
                case 17:  /* udp */
                case 33:  /* dccp */
                case 132: /* sctp */
                    break;
                default:
                    ret = -1;
                }
            } else {
                ret = -1;
            }
            if (ret < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("%s rule with port specification requires "
                                 "protocol specification with protocol to be "
                                 "either one of tcp(6), udp(17), dccp(33), or "
                                 "sctp(132)"), protocol);
            }
        }
        break;
    default:
        break;
    }

    return ret;
}


static void
virNWFilterRuleDefFixup(virNWFilterRuleDefPtr rule)
{
#define COPY_NEG_SIGN(A, B) \
    (A).flags = ((A).flags & ~NWFILTER_ENTRY_ITEM_FLAG_IS_NEG) | \
                ((B).flags &  NWFILTER_ENTRY_ITEM_FLAG_IS_NEG);

    switch (rule->prtclType) {
    case VIR_NWFILTER_RULE_PROTOCOL_MAC:
        COPY_NEG_SIGN(rule->p.ethHdrFilter.ethHdr.dataSrcMACMask,
                      rule->p.ethHdrFilter.ethHdr.dataSrcMACAddr);
        COPY_NEG_SIGN(rule->p.ethHdrFilter.ethHdr.dataDstMACMask,
                      rule->p.ethHdrFilter.ethHdr.dataDstMACAddr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_VLAN:
        COPY_NEG_SIGN(rule->p.vlanHdrFilter.ethHdr.dataSrcMACMask,
                      rule->p.vlanHdrFilter.ethHdr.dataSrcMACAddr);
        COPY_NEG_SIGN(rule->p.vlanHdrFilter.ethHdr.dataDstMACMask,
                      rule->p.vlanHdrFilter.ethHdr.dataDstMACAddr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_STP:
        COPY_NEG_SIGN(rule->p.stpHdrFilter.ethHdr.dataSrcMACMask,
                      rule->p.stpHdrFilter.ethHdr.dataSrcMACAddr);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataRootPriHi,
                      rule->p.stpHdrFilter.dataRootPri);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataRootAddrMask,
                      rule->p.stpHdrFilter.dataRootAddr);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataRootCostHi,
                      rule->p.stpHdrFilter.dataRootCost);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataSndrPrioHi,
                      rule->p.stpHdrFilter.dataSndrPrio);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataSndrAddrMask,
                      rule->p.stpHdrFilter.dataSndrAddr);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataPortHi,
                      rule->p.stpHdrFilter.dataPort);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataAgeHi,
                      rule->p.stpHdrFilter.dataAge);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataMaxAgeHi,
                      rule->p.stpHdrFilter.dataMaxAge);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataHelloTimeHi,
                      rule->p.stpHdrFilter.dataHelloTime);
        COPY_NEG_SIGN(rule->p.stpHdrFilter.dataFwdDelayHi,
                      rule->p.stpHdrFilter.dataFwdDelay);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        COPY_NEG_SIGN(rule->p.ipHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.ipHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.ipHdrFilter.ipHdr.dataDstIPAddr);
        virNWFilterRuleDefFixupIPSet(&rule->p.ipHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask,
                      rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.dataICMPTypeEnd,
                      rule->p.ipv6HdrFilter.dataICMPTypeStart);
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.dataICMPCodeStart,
                      rule->p.ipv6HdrFilter.dataICMPTypeStart);
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.dataICMPCodeEnd,
                      rule->p.ipv6HdrFilter.dataICMPTypeStart);
        virNWFilterRuleDefFixupIPSet(&rule->p.ipv6HdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ARP:
    case VIR_NWFILTER_RULE_PROTOCOL_RARP:
    case VIR_NWFILTER_RULE_PROTOCOL_NONE:
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_TCP:
    case VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6:
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.tcpHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.tcpHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.tcpHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.tcpHdrFilter.ipHdr.dataDstIPFrom);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.portData.dataSrcPortEnd,
                      rule->p.tcpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.portData.dataDstPortStart,
                      rule->p.tcpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.tcpHdrFilter.portData.dataDstPortEnd,
                      rule->p.tcpHdrFilter.portData.dataSrcPortStart);
        virNWFilterRuleDefFixupIPSet(&rule->p.tcpHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDP:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6:
        COPY_NEG_SIGN(rule->p.udpHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.udpHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.udpHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.udpHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.udpHdrFilter.ipHdr.dataDstIPFrom);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.portData.dataSrcPortEnd,
                      rule->p.udpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.portData.dataDstPortStart,
                      rule->p.udpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.udpHdrFilter.portData.dataDstPortEnd,
                      rule->p.udpHdrFilter.portData.dataSrcPortStart);
        virNWFilterRuleDefFixupIPSet(&rule->p.udpHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITE:
    case VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6:
        COPY_NEG_SIGN(rule->p.udpliteHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.udpliteHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.udpliteHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.udpliteHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.udpliteHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.udpliteHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.udpliteHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.udpliteHdrFilter.ipHdr.dataDstIPFrom);
        virNWFilterRuleDefFixupIPSet(&rule->p.udpliteHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ESP:
    case VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6:
        COPY_NEG_SIGN(rule->p.espHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.espHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.espHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.espHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.espHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.espHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.espHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.espHdrFilter.ipHdr.dataDstIPFrom);
        virNWFilterRuleDefFixupIPSet(&rule->p.espHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_AH:
    case VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6:
        COPY_NEG_SIGN(rule->p.ahHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.ahHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.ahHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.ahHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.ahHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.ahHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.ahHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.ahHdrFilter.ipHdr.dataDstIPFrom);
        virNWFilterRuleDefFixupIPSet(&rule->p.ahHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_SCTP:
    case VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6:
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.sctpHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.sctpHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.sctpHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.sctpHdrFilter.ipHdr.dataDstIPFrom);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.portData.dataSrcPortEnd,
                      rule->p.sctpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.portData.dataDstPortStart,
                      rule->p.sctpHdrFilter.portData.dataSrcPortStart);
        COPY_NEG_SIGN(rule->p.sctpHdrFilter.portData.dataDstPortEnd,
                      rule->p.sctpHdrFilter.portData.dataSrcPortStart);
        virNWFilterRuleDefFixupIPSet(&rule->p.sctpHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ICMP:
    case VIR_NWFILTER_RULE_PROTOCOL_ICMPV6:
        COPY_NEG_SIGN(rule->p.icmpHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.icmpHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.icmpHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.icmpHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.icmpHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.icmpHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.icmpHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.icmpHdrFilter.ipHdr.dataDstIPFrom);
        COPY_NEG_SIGN(rule->p.icmpHdrFilter.dataICMPCode,
                      rule->p.icmpHdrFilter.dataICMPType);
        virNWFilterRuleDefFixupIPSet(&rule->p.icmpHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_ALL:
    case VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6:
        COPY_NEG_SIGN(rule->p.allHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.allHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.allHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.allHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.allHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.allHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.allHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.allHdrFilter.ipHdr.dataDstIPFrom);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IGMP:
        COPY_NEG_SIGN(rule->p.igmpHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.igmpHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.igmpHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.igmpHdrFilter.ipHdr.dataDstIPAddr);
        COPY_NEG_SIGN(rule->p.igmpHdrFilter.ipHdr.dataSrcIPTo,
                      rule->p.igmpHdrFilter.ipHdr.dataSrcIPFrom);
        COPY_NEG_SIGN(rule->p.igmpHdrFilter.ipHdr.dataDstIPTo,
                      rule->p.igmpHdrFilter.ipHdr.dataDstIPFrom);
        virNWFilterRuleDefFixupIPSet(&rule->p.igmpHdrFilter.ipHdr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_LAST:
    break;
    }
#undef COPY_NEG_SIGN
}


static virNWFilterRuleDefPtr
virNWFilterRuleParse(xmlNodePtr node)
{
    char *action;
    char *direction;
    char *prio;
    char *statematch;
    bool found;
    int found_i = 0;
    int priority;

    xmlNodePtr cur;
    virNWFilterRuleDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    action     = virXMLPropString(node, "action");
    direction  = virXMLPropString(node, "direction");
    prio       = virXMLPropString(node, "priority");
    statematch = virXMLPropString(node, "statematch");

    if (!action) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("rule node requires action attribute"));
        goto err_exit;
    }

    if ((ret->action = virNWFilterRuleActionTypeFromString(action)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s",
                       _("unknown rule action attribute value"));
        goto err_exit;
    }

    if (!direction) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("rule node requires direction attribute"));
        goto err_exit;
    }

    if ((ret->tt = virNWFilterRuleDirectionTypeFromString(direction)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s",
                       _("unknown rule direction attribute value"));
        goto err_exit;
    }

    ret->priority = MAX_RULE_PRIORITY / 2;

    if (prio) {
        if (virStrToLong_i(prio, NULL, 10, &priority) >= 0) {
            if (priority <= MAX_RULE_PRIORITY &&
                priority >= MIN_RULE_PRIORITY)
                ret->priority = priority;
        }
    }

    if (statematch &&
        (STREQ(statematch, "0") || STRCASEEQ(statematch, "false")))
        ret->flags |= RULE_FLAG_NO_STATEMATCH;

    cur = node->children;

    found = false;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            size_t i = 0;
            while (1) {
                if (found)
                    i = found_i;

                if (xmlStrEqual(cur->name, BAD_CAST virAttr[i].id)) {

                    found_i = i;
                    found = true;
                    ret->prtclType = virAttr[i].prtclType;

                    if (virNWFilterRuleDetailsParse(cur,
                                                    ret,
                                                    virAttr[i].att) < 0) {
                        goto err_exit;
                    }
                    if (virNWFilterRuleValidate(ret) < 0)
                        goto err_exit;
                    break;
                }
                if (!found) {
                    i++;
                    if (!virAttr[i].id)
                        break;
                } else {
                   break;
                }
            }
        }

        cur = cur->next;
    }

    virNWFilterRuleDefFixup(ret);

 cleanup:
    VIR_FREE(prio);
    VIR_FREE(action);
    VIR_FREE(direction);
    VIR_FREE(statematch);

    return ret;

 err_exit:
    virNWFilterRuleDefFree(ret);
    ret = NULL;
    goto cleanup;
}


static bool
virNWFilterIsValidChainName(const char *chainname)
{
    if (strlen(chainname) > MAX_CHAIN_SUFFIX_SIZE) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Name of chain is longer than "
                         "%u characters"),
                       MAX_CHAIN_SUFFIX_SIZE);
        return false;
    }

    if (chainname[strspn(chainname, VALID_CHAINNAME)] != 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Chain name contains invalid characters"));
        return false;
    }

    return true;
}


/*
 * Test whether the name of the chain is supported.
 * It current has to have a prefix of either one of the strings found in
 * virNWFilterChainSuffixTypeToString().
 */
static const char *
virNWFilterIsAllowedChain(const char *chainname)
{
    virNWFilterChainSuffixType i;
    const char *name;
    char *msg;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool printed = false;

    if (!virNWFilterIsValidChainName(chainname))
        return NULL;

    for (i = 0; i < VIR_NWFILTER_CHAINSUFFIX_LAST; i++) {
        name = virNWFilterChainSuffixTypeToString(i);
        if (i == VIR_NWFILTER_CHAINSUFFIX_ROOT) {
            /* allow 'root' as a complete name but not as a prefix */
            if (STREQ(chainname, name))
                return name;
            if (STRPREFIX(chainname, name))
                return NULL;
        }
        if (STRPREFIX(chainname, name))
            return name;
    }

    virBufferAsprintf(&buf,
                      _("Invalid chain name '%s'. Please use a chain name "
                      "called '%s' or any of the following prefixes: "),
                      chainname,
                      virNWFilterChainSuffixTypeToString(
                          VIR_NWFILTER_CHAINSUFFIX_ROOT));
    for (i = 0; i < VIR_NWFILTER_CHAINSUFFIX_LAST; i++) {
        if (i == VIR_NWFILTER_CHAINSUFFIX_ROOT)
            continue;
        if (printed)
            virBufferAddLit(&buf, ", ");
        virBufferAdd(&buf, virNWFilterChainSuffixTypeToString(i), -1);
        printed = true;
    }

    if (virBufferCheckError(&buf) < 0)
        goto err_exit;

    msg = virBufferContentAndReset(&buf);

    virReportError(VIR_ERR_INVALID_ARG, "%s", msg);
    VIR_FREE(msg);

 err_exit:
    return NULL;
}


static virNWFilterDefPtr
virNWFilterDefParseXML(xmlXPathContextPtr ctxt)
{
    virNWFilterDefPtr ret;
    xmlNodePtr curr = ctxt->node;
    char *uuid = NULL;
    char *chain = NULL;
    char *chain_pri_s = NULL;
    virNWFilterEntryPtr entry;
    int chain_priority;
    const char *name_prefix;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->name = virXPathString("string(./@name)", ctxt);
    if (!ret->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter has no name"));
        goto cleanup;
    }

    chain_pri_s = virXPathString("string(./@priority)", ctxt);
    if (chain_pri_s) {
        if (virStrToLong_i(chain_pri_s, NULL, 10, &chain_priority) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Could not parse chain priority '%s'"),
                           chain_pri_s);
            goto cleanup;
        }
        if (chain_priority < NWFILTER_MIN_FILTER_PRIORITY ||
            chain_priority > NWFILTER_MAX_FILTER_PRIORITY) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Priority '%d' is outside valid "
                             "range of [%d,%d]"),
                           chain_priority,
                           NWFILTER_MIN_FILTER_PRIORITY,
                           NWFILTER_MAX_FILTER_PRIORITY);
            goto cleanup;
        }
    }

    chain = virXPathString("string(./@chain)", ctxt);
    if (chain) {
        name_prefix = virNWFilterIsAllowedChain(chain);
        if (name_prefix == NULL)
            goto cleanup;
        ret->chainsuffix = chain;

        if (chain_pri_s) {
            ret->chainPriority = chain_priority;
        } else {
            /* assign default priority if none can be found via lookup */
            if (!name_prefix ||
                 intMapGetByString(chain_priorities, name_prefix, 0,
                                   &ret->chainPriority) < 0) {
                /* assign default chain priority */
                ret->chainPriority = (NWFILTER_MAX_FILTER_PRIORITY +
                                      NWFILTER_MIN_FILTER_PRIORITY) / 2;
            }
        }
        chain = NULL;
    } else {
        if (VIR_STRDUP(ret->chainsuffix,
                       virNWFilterChainSuffixTypeToString(VIR_NWFILTER_CHAINSUFFIX_ROOT)) < 0)
            goto cleanup;
    }

    uuid = virXPathString("string(./uuid)", ctxt);
    ret->uuid_specified = (uuid != NULL);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("unable to generate uuid"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("malformed uuid element"));
            goto cleanup;
        }
        VIR_FREE(uuid);
    }

    curr = curr->children;

    while (curr != NULL) {
        if (curr->type == XML_ELEMENT_NODE) {
            if (VIR_ALLOC(entry) < 0)
                goto cleanup;

            if (xmlStrEqual(curr->name, BAD_CAST "rule")) {
                if (!(entry->rule = virNWFilterRuleParse(curr))) {
                    virNWFilterEntryFree(entry);
                    goto cleanup;
                }
            } else if (xmlStrEqual(curr->name, BAD_CAST "filterref")) {
                if (!(entry->include = virNWFilterIncludeParse(curr))) {
                    virNWFilterEntryFree(entry);
                    goto cleanup;
                }
            }

            if (entry->rule || entry->include) {
                if (VIR_APPEND_ELEMENT_COPY(ret->filterEntries,
                                            ret->nentries, entry) < 0) {
                    virNWFilterEntryFree(entry);
                    goto cleanup;
                }
            } else {
                virNWFilterEntryFree(entry);
            }
        }
        curr = curr->next;
    }

    VIR_FREE(chain);
    VIR_FREE(chain_pri_s);

    return ret;

 cleanup:
    virNWFilterDefFree(ret);
    VIR_FREE(chain);
    VIR_FREE(uuid);
    VIR_FREE(chain_pri_s);
    return NULL;
}


virNWFilterDefPtr
virNWFilterDefParseNode(xmlDocPtr xml,
                        xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNWFilterDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "filter")) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s",
                       _("unknown root element for nw filter"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virNWFilterDefParseXML(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


static virNWFilterDefPtr
virNWFilterDefParse(const char *xmlStr,
                    const char *filename)
{
    virNWFilterDefPtr def = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(nwfilter_definition)")))) {
        def = virNWFilterDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return def;
}


virNWFilterDefPtr
virNWFilterDefParseString(const char *xmlStr)
{
    return virNWFilterDefParse(xmlStr, NULL);
}


virNWFilterDefPtr
virNWFilterDefParseFile(const char *filename)
{
    return virNWFilterDefParse(NULL, filename);
}


int
virNWFilterSaveXML(const char *configDir,
                   virNWFilterDefPtr def,
                   const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *configFile = NULL;
    int ret = -1;

    if (!(configFile = virFileBuildPath(configDir, def->name, ".xml")))
        goto cleanup;

    virUUIDFormat(def->uuid, uuidstr);
    ret = virXMLSaveFile(configFile,
                         virXMLPickShellSafeComment(def->name, uuidstr),
                         "nwfilter-edit", xml);

 cleanup:
    VIR_FREE(configFile);
    return ret;
}


int
virNWFilterSaveConfig(const char *configDir,
                      virNWFilterDefPtr def)
{
    int ret = -1;
    char *xml;

    if (!(xml = virNWFilterDefFormat(def)))
        goto cleanup;

    if (virNWFilterSaveXML(configDir, def, xml) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


int nCallbackDriver;
#define MAX_CALLBACK_DRIVER 10
static virNWFilterCallbackDriverPtr callbackDrvArray[MAX_CALLBACK_DRIVER];

void
virNWFilterRegisterCallbackDriver(virNWFilterCallbackDriverPtr cbd)
{
    if (nCallbackDriver < MAX_CALLBACK_DRIVER)
        callbackDrvArray[nCallbackDriver++] = cbd;
}


void
virNWFilterUnRegisterCallbackDriver(virNWFilterCallbackDriverPtr cbd)
{
    size_t i = 0;

    while (i < nCallbackDriver && callbackDrvArray[i] != cbd)
        i++;

    if (i < nCallbackDriver) {
        memmove(&callbackDrvArray[i], &callbackDrvArray[i+1],
                (nCallbackDriver - i - 1) * sizeof(callbackDrvArray[i]));
        callbackDrvArray[i] = 0;
        nCallbackDriver--;
    }
}


void
virNWFilterCallbackDriversLock(void)
{
    size_t i;

    for (i = 0; i < nCallbackDriver; i++)
        callbackDrvArray[i]->vmDriverLock();
}


void
virNWFilterCallbackDriversUnlock(void)
{
    size_t i;

    for (i = 0; i < nCallbackDriver; i++)
        callbackDrvArray[i]->vmDriverUnlock();
}


static virDomainObjListIterator virNWFilterDomainFWUpdateCB;
static void *virNWFilterDomainFWUpdateOpaque;

/**
 * virNWFilterInstFiltersOnAllVMs:
 * Apply all filters on all running VMs. Don't terminate in case of an
 * error. This should be called upon reloading of the driver.
 */
int
virNWFilterInstFiltersOnAllVMs(void)
{
    size_t i;
    struct domUpdateCBStruct cb = {
        .opaque = virNWFilterDomainFWUpdateOpaque,
        .step = STEP_APPLY_CURRENT,
        .skipInterfaces = NULL, /* not needed */
    };

    for (i = 0; i < nCallbackDriver; i++)
        callbackDrvArray[i]->vmFilterRebuild(virNWFilterDomainFWUpdateCB,
                                             &cb);

    return 0;
}


int
virNWFilterTriggerVMFilterRebuild(void)
{
    size_t i;
    int ret = 0;
    struct domUpdateCBStruct cb = {
        .opaque = virNWFilterDomainFWUpdateOpaque,
        .step = STEP_APPLY_NEW,
        .skipInterfaces = virHashCreate(0, NULL),
    };

    if (!cb.skipInterfaces)
        return -1;

    for (i = 0; i < nCallbackDriver; i++) {
        if (callbackDrvArray[i]->vmFilterRebuild(virNWFilterDomainFWUpdateCB,
                                                 &cb) < 0)
            ret = -1;
    }

    if (ret < 0) {
        cb.step = STEP_TEAR_NEW; /* rollback */

        for (i = 0; i < nCallbackDriver; i++)
            callbackDrvArray[i]->vmFilterRebuild(virNWFilterDomainFWUpdateCB,
                                                 &cb);
    } else {
        cb.step = STEP_TEAR_OLD; /* switch over */

        for (i = 0; i < nCallbackDriver; i++)
            callbackDrvArray[i]->vmFilterRebuild(virNWFilterDomainFWUpdateCB,
                                                 &cb);
    }

    virHashFree(cb.skipInterfaces);

    return ret;
}


int
virNWFilterDeleteDef(const char *configDir,
                     virNWFilterDefPtr def)
{
    int ret = -1;
    char *configFile = NULL;

    if (!(configFile = virFileBuildPath(configDir, def->name, ".xml")))
        goto error;

    if (unlink(configFile) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot remove config for %s"),
                       def->name);
        goto error;
    }

    ret = 0;
 error:
    VIR_FREE(configFile);
    return ret;
}


static void
virNWIPAddressFormat(virBufferPtr buf,
                     virSocketAddrPtr ipaddr)
{
    char *output = virSocketAddrFormat(ipaddr);

    if (output) {
        virBufferAdd(buf, output, -1);
        VIR_FREE(output);
    }
}


static void
virNWFilterRuleDefDetailsFormat(virBufferPtr buf,
                                const char *type,
                                const virXMLAttr2Struct *att,
                                virNWFilterRuleDefPtr def)
{
    size_t i = 0, j;
    bool typeShown = false;
    bool neverShown = true;
    bool asHex;
    enum match {
        MATCH_NONE = 0,
        MATCH_YES,
        MATCH_NO
    } matchShown = MATCH_NONE;
    nwItemDesc *item;

    while (att[i].name) {
        VIR_WARNINGS_NO_CAST_ALIGN
        item = (nwItemDesc *)((char *)def + att[i].dataIdx);
        VIR_WARNINGS_RESET
        virNWFilterEntryItemFlags flags = item->flags;
        if ((flags & NWFILTER_ENTRY_ITEM_FLAG_EXISTS)) {
            if (!typeShown) {
                virBufferAsprintf(buf, "<%s", type);
                typeShown = true;
                neverShown = false;
            }

            if ((flags & NWFILTER_ENTRY_ITEM_FLAG_IS_NEG)) {
                if (matchShown == MATCH_NONE) {
                    virBufferAddLit(buf, " match='no'");
                    matchShown = MATCH_NO;
                } else if (matchShown == MATCH_YES) {
                    virBufferAddLit(buf, "/>\n");
                    typeShown = 0;
                    matchShown = MATCH_NONE;
                    continue;
                }
            } else {
                if (matchShown == MATCH_NO) {
                    virBufferAddLit(buf, "/>\n");
                    typeShown = 0;
                    matchShown = MATCH_NONE;
                    continue;
                }
                matchShown = MATCH_YES;
            }

            virBufferAsprintf(buf, " %s='",
                              att[i].name);
            if (att[i].formatter && !(flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
               if (!att[i].formatter(buf, def, item)) {
                  virReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("formatter for %s %s reported error"),
                                 type,
                                 att[i].name);
                   goto err_exit;
               }
            } else if ((flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
                virBufferAddChar(buf, '$');
                virNWFilterVarAccessPrint(item->varAccess, buf);
            } else {
               asHex = false;

               switch (item->datatype) {

               case DATATYPE_UINT8_HEX:
                   asHex = true;
                   ATTRIBUTE_FALLTHROUGH;
               case DATATYPE_IPMASK:
               case DATATYPE_IPV6MASK:
                   /* display all masks in CIDR format */
               case DATATYPE_UINT8:
                   virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                                     item->u.u8);
               break;

               case DATATYPE_UINT16_HEX:
                   asHex = true;
                   ATTRIBUTE_FALLTHROUGH;
               case DATATYPE_UINT16:
                   virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                                     item->u.u16);
               break;

               case DATATYPE_UINT32_HEX:
                   asHex = true;
                   ATTRIBUTE_FALLTHROUGH;
               case DATATYPE_UINT32:
                   virBufferAsprintf(buf, asHex ? "0x%x" : "%u",
                                     item->u.u32);
               break;

               case DATATYPE_IPADDR:
               case DATATYPE_IPV6ADDR:
                   virNWIPAddressFormat(buf,
                                        &item->u.ipaddr);
               break;

               case DATATYPE_MACMASK:
               case DATATYPE_MACADDR:
                   for (j = 0; j < 6; j++)
                       virBufferAsprintf(buf, "%02x%s",
                                         item->u.macaddr.addr[j],
                                         (j < 5) ? ":" : "");
               break;

               case DATATYPE_STRINGCOPY:
                   virBufferEscapeString(buf, "%s", item->u.string);
               break;

               case DATATYPE_BOOLEAN:
                   if (item->u.boolean)
                       virBufferAddLit(buf, "true");
                   else
                       virBufferAddLit(buf, "false");
               break;

               case DATATYPE_STRING:
               default:
                   virBufferAsprintf(buf,
                                     "UNSUPPORTED DATATYPE 0x%02x\n",
                                     att[i].datatype);
               }
            }
            virBufferAddLit(buf, "'");
        }
        i++;
    }
    if (typeShown)
       virBufferAddLit(buf, "/>\n");

    if (neverShown)
       virBufferAsprintf(buf,
                         "<%s/>\n", type);

 err_exit:
    return;
}


static int
virNWFilterRuleDefFormat(virBufferPtr buf,
                         virNWFilterRuleDefPtr def)
{
    size_t i;
    bool subelement = false;

    virBufferAsprintf(buf, "<rule action='%s' direction='%s' priority='%d'",
                      virNWFilterRuleActionTypeToString(def->action),
                      virNWFilterRuleDirectionTypeToString(def->tt),
                      def->priority);

    if ((def->flags & RULE_FLAG_NO_STATEMATCH))
        virBufferAddLit(buf, " statematch='false'");

    virBufferAdjustIndent(buf, 2);
    i = 0;
    while (virAttr[i].id) {
        if (virAttr[i].prtclType == def->prtclType) {
            if (!subelement)
                virBufferAddLit(buf, ">\n");
            virNWFilterRuleDefDetailsFormat(buf,
                                            virAttr[i].id,
                                            virAttr[i].att,
                                            def);
            subelement = true;
            break;
        }
        i++;
    }

    virBufferAdjustIndent(buf, -2);
    if (subelement)
        virBufferAddLit(buf, "</rule>\n");
    else
        virBufferAddLit(buf, "/>\n");
    return 0;
}


static int
virNWFilterEntryFormat(virBufferPtr buf,
                       virNWFilterEntryPtr entry)
{
    if (entry->rule)
        return virNWFilterRuleDefFormat(buf, entry->rule);
    return virNWFilterFormatParamAttributes(buf, entry->include->params,
                                            entry->include->filterref);
}


char *
virNWFilterDefFormat(const virNWFilterDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char uuid[VIR_UUID_STRING_BUFLEN];
    size_t i;

    virBufferAsprintf(&buf, "<filter name='%s' chain='%s'",
                      def->name,
                      def->chainsuffix);
    if (def->chainPriority != 0)
        virBufferAsprintf(&buf, " priority='%d'",
                          def->chainPriority);
    virBufferAddLit(&buf, ">\n");
    virBufferAdjustIndent(&buf, 2);

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", uuid);

    for (i = 0; i < def->nentries; i++) {
        if (virNWFilterEntryFormat(&buf, def->filterEntries[i]) < 0)
            goto err_exit;
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</filter>\n");

    if (virBufferCheckError(&buf) < 0)
        goto err_exit;

    return virBufferContentAndReset(&buf);

 err_exit:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
virNWFilterConfLayerInit(virDomainObjListIterator domUpdateCB,
                         void *opaque)
{
    if (initialized)
        return -1;

    virNWFilterDomainFWUpdateCB = domUpdateCB;
    virNWFilterDomainFWUpdateOpaque = opaque;

    initialized = true;

    if (virRWLockInit(&updateLock) < 0)
        return -1;

    return 0;
}


void
virNWFilterConfLayerShutdown(void)
{
    if (!initialized)
        return;

    virRWLockDestroy(&updateLock);

    initialized = false;
    virNWFilterDomainFWUpdateOpaque = NULL;
    virNWFilterDomainFWUpdateCB = NULL;
}


bool
virNWFilterRuleIsProtocolIPv4(virNWFilterRuleDefPtr rule)
{
    if (rule->prtclType >= VIR_NWFILTER_RULE_PROTOCOL_TCP &&
        rule->prtclType <= VIR_NWFILTER_RULE_PROTOCOL_ALL)
        return true;
    return false;
}


bool
virNWFilterRuleIsProtocolIPv6(virNWFilterRuleDefPtr rule)
{
    if (rule->prtclType >= VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6 &&
        rule->prtclType <= VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6)
        return true;
    return false;
}


bool
virNWFilterRuleIsProtocolEthernet(virNWFilterRuleDefPtr rule)
{
    if (rule->prtclType <= VIR_NWFILTER_RULE_PROTOCOL_IPV6)
        return true;
    return false;
}
