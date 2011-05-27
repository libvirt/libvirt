/*
 * nwfilter_conf.c: network filter XML processing
 *                  (derived from storage_conf.c)
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#if HAVE_NET_ETHERNET_H
# include <net/ethernet.h>
#endif
#include <unistd.h>

#include "internal.h"

#include "uuid.h"
#include "memory.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "nwfilter_params.h"
#include "nwfilter_conf.h"
#include "domain_conf.h"
#include "c-ctype.h"
#include "files.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER


VIR_ENUM_IMPL(virNWFilterRuleAction, VIR_NWFILTER_RULE_ACTION_LAST,
              "drop",
              "accept",
              "reject");

VIR_ENUM_IMPL(virNWFilterJumpTarget, VIR_NWFILTER_RULE_ACTION_LAST,
              "DROP",
              "ACCEPT",
              "REJECT");

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
              "arp",
              "rarp",
              "ipv4",
              "ipv6");

VIR_ENUM_IMPL(virNWFilterRuleProtocol, VIR_NWFILTER_RULE_PROTOCOL_LAST,
              "none",
              "mac",
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


/*
 * only one filter update allowed
 */
static virMutex updateMutex;
static bool initialized = false;

void
virNWFilterLockFilterUpdates(void) {
    virMutexLock(&updateMutex);
}

void
virNWFilterUnlockFilterUpdates(void) {
    virMutexUnlock(&updateMutex);
}



/*
 * attribute names for the rules XML
 */
static const char srcmacaddr_str[]   = "srcmacaddr";
static const char srcmacmask_str[]   = "srcmacmask";
static const char dstmacaddr_str[]   = "dstmacaddr";
static const char dstmacmask_str[]   = "dstmacmask";
static const char arpsrcmacaddr_str[]= "arpsrcmacaddr";
static const char arpdstmacaddr_str[]= "arpdstmacaddr";
static const char arpsrcipaddr_str[] = "arpsrcipaddr";
static const char arpdstipaddr_str[] = "arpdstipaddr";
static const char srcipaddr_str[]    = "srcipaddr";
static const char srcipmask_str[]    = "srcipmask";
static const char dstipaddr_str[]    = "dstipaddr";
static const char dstipmask_str[]    = "dstipmask";
static const char srcipfrom_str[]    = "srcipfrom";
static const char srcipto_str[]      = "srcipto";
static const char dstipfrom_str[]    = "dstipfrom";
static const char dstipto_str[]      = "dstipto";
static const char srcportstart_str[] = "srcportstart";
static const char srcportend_str[]   = "srcportend";
static const char dstportstart_str[] = "dstportstart";
static const char dstportend_str[]   = "dstportend";
static const char dscp_str[]         = "dscp";
static const char state_str[]        = "state";

#define SRCMACADDR    srcmacaddr_str
#define SRCMACMASK    srcmacmask_str
#define DSTMACADDR    dstmacaddr_str
#define DSTMACMASK    dstmacmask_str
#define ARPSRCMACADDR arpsrcmacaddr_str
#define ARPDSTMACADDR arpdstmacaddr_str
#define ARPSRCIPADDR  arpsrcipaddr_str
#define ARPDSTIPADDR  arpdstipaddr_str
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


/**
 * intMapGetByInt:
 * @intmap: Pointer to int-to-string map
 * @attr: The attribute to look up
 * @res: Pointer to string pointer for result
 *
 * Returns 1 if value was found with result returned, 0 otherwise.
 *
 * lookup a map entry given the integer.
 */
static bool
intMapGetByInt(const struct int_map *intmap, int32_t attr, const char **res)
{
    int i = 0;
    bool found = 0;
    while (intmap[i].val && !found) {
        if (intmap[i].attr == attr) {
            *res = intmap[i].val;
            found = 1;
        }
        i++;
    }
    return found;
}


/**
 * intMapGetByString:
 * @intmap: Pointer to int-to-string map
 * @str: Pointer to string for which to find the entry
 * @casecmp : Whether to ignore case when doing string matching
 * @result: Pointer to int for result
 *
 * Returns 0 if no entry was found, 1 otherwise.
 *
 * Do a lookup in the map trying to find an integer key using the string
 * value. Returns 1 if entry was found with result returned, 0 otherwise.
 */
static bool
intMapGetByString(const struct int_map *intmap, const char *str, int casecmp,
                  int32_t *result)
{
    int i = 0;
    bool found = 0;
    while (intmap[i].val && !found) {
        if ( (casecmp && STRCASEEQ(intmap[i].val, str)) ||
                         STREQ    (intmap[i].val, str)    ) {
            *result = intmap[i].attr;
            found = 1;
        }
        i++;
    }
    return found;
}


void
virNWFilterRuleDefFree(virNWFilterRuleDefPtr def) {
    int i;
    if (!def)
        return;

    for (i = 0; i < def->nvars; i++)
        VIR_FREE(def->vars[i]);

    for (i = 0; i < def->nstrings; i++)
        VIR_FREE(def->strings[i]);

    VIR_FREE(def->vars);
    VIR_FREE(def->strings);

    VIR_FREE(def);
}


static void
virNWFilterIncludeDefFree(virNWFilterIncludeDefPtr inc) {
    if (!inc)
        return;
    virNWFilterHashTableFree(inc->params);
    VIR_FREE(inc->filterref);
    VIR_FREE(inc);
}


static void
virNWFilterEntryFree(virNWFilterEntryPtr entry) {
    if (!entry)
        return;

    virNWFilterRuleDefFree(entry->rule);
    virNWFilterIncludeDefFree(entry->include);
    VIR_FREE(entry);
}


void
virNWFilterDefFree(virNWFilterDefPtr def) {
    int i;
    if (!def)
        return;

    VIR_FREE(def->name);

    for (i = 0; i < def->nentries; i++)
        virNWFilterEntryFree(def->filterEntries[i]);

    VIR_FREE(def->filterEntries);

    VIR_FREE(def);
}


void
virNWFilterObjFree(virNWFilterObjPtr obj)
{
    if (!obj)
        return;

    virNWFilterDefFree(obj->def);
    virNWFilterDefFree(obj->newDef);

    VIR_FREE(obj->configFile);

    virMutexDestroy(&obj->lock);

    VIR_FREE(obj);
}


void
virNWFilterObjListFree(virNWFilterObjListPtr nwfilters)
{
    unsigned int i;
    for (i = 0 ; i < nwfilters->count ; i++)
        virNWFilterObjFree(nwfilters->objs[i]);
    VIR_FREE(nwfilters->objs);
    nwfilters->count = 0;
}


static int
virNWFilterRuleDefAddVar(virNWFilterRuleDefPtr nwf,
                         nwItemDesc *item,
                         const char *var)
{
    int i = 0;

    if (nwf->vars) {
        for (i = 0; i < nwf->nvars; i++)
            if (STREQ(nwf->vars[i], var)) {
                item->var = nwf->vars[i];
                return 0;
            }
    }

    if (VIR_REALLOC_N(nwf->vars, nwf->nvars+1) < 0) {
        virReportOOMError();
        return 1;
    }

    nwf->vars[nwf->nvars] = strdup(var);

    if (!nwf->vars[nwf->nvars]) {
        virReportOOMError();
        return 1;
    }

    item->var = nwf->vars[nwf->nvars++];

    return 0;
}


static char *
virNWFilterRuleDefAddString(virNWFilterRuleDefPtr nwf,
                            const char *string,
                            size_t maxstrlen)
{
    if (VIR_REALLOC_N(nwf->strings, nwf->nstrings+1) < 0) {
        virReportOOMError();
        return NULL;
    }

    nwf->strings[nwf->nstrings] = strndup(string, maxstrlen);

    if (!nwf->strings[nwf->nstrings]) {
        virReportOOMError();
        return NULL;
    }

    nwf->nstrings++;

    return nwf->strings[nwf->nstrings-1];
}


void
virNWFilterObjRemove(virNWFilterObjListPtr nwfilters,
                     virNWFilterObjPtr nwfilter)
{
    unsigned int i;

    virNWFilterObjUnlock(nwfilter);

    for (i = 0 ; i < nwfilters->count ; i++) {
        virNWFilterObjLock(nwfilters->objs[i]);
        if (nwfilters->objs[i] == nwfilter) {
            virNWFilterObjUnlock(nwfilters->objs[i]);
            virNWFilterObjFree(nwfilters->objs[i]);

            if (i < (nwfilters->count - 1))
                memmove(nwfilters->objs + i, nwfilters->objs + i + 1,
                        sizeof(*(nwfilters->objs)) * (nwfilters->count - (i + 1)));

            if (VIR_REALLOC_N(nwfilters->objs, nwfilters->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            nwfilters->count--;

            break;
        }
        virNWFilterObjUnlock(nwfilters->objs[i]);
    }
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
    INTMAP_ENTRY(ETHERTYPE_ARP   , "arp"),
    INTMAP_ENTRY(ETHERTYPE_REVARP, "rarp"),
    INTMAP_ENTRY(ETHERTYPE_IP    , "ipv4"),
    INTMAP_ENTRY(ETHERTYPE_IPV6  , "ipv6"),
    INTMAP_ENTRY_LAST
};


static bool
checkMacProtocolID(enum attrDatatype datatype, union data *value,
                   virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(macProtoMap, value->c, 1, &res) == 0)
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
        return 1;
    }

    return 0;
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
                       &str)) {
        virBufferAdd(buf, str, -1);
    } else {
        if (nwf->p.ethHdrFilter.dataProtocolID.datatype == DATATYPE_UINT16)
            asHex = false;
        virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                          nwf->p.ethHdrFilter.dataProtocolID.u.u16);
    }
    return 1;
}


/* generic function to check for a valid (ipv4,ipv6, mac) mask
 * A mask is valid of there is a sequence of 1's followed by a sequence
 * of 0s or only 1s or only 0s
 */
static bool
checkValidMask(unsigned char *data, int len)
{
    uint32_t idx = 0;
    uint8_t mask = 0x80;
    int checkones = 1;

    while ((idx >> 3) < len) {
        if (checkones) {
            if (!(data[idx>>3] & mask))
                checkones = 0;
        } else {
            if ((data[idx>>3] & mask))
                return 0;
        }

        idx++;
        mask >>= 1;
        if (!mask)
            mask = 0x80;
    }
    return 1;
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
        if (intMapGetByString(arpOpcodeMap, value->c, 1, &res) == 0)
            res = -1;
        datatype = DATATYPE_UINT16;
    } else if (datatype == DATATYPE_UINT16 ||
               datatype == DATATYPE_UINT16_HEX) {
        res = (uint32_t)value->ui;
    }

    if (res != -1) {
        nwf->p.arpHdrFilter.dataOpcode.u.u16 = res;
        nwf->p.arpHdrFilter.dataOpcode.datatype = datatype;
        return 1;
    }
    return 0;
}


static bool
arpOpcodeFormatter(virBufferPtr buf,
                   virNWFilterRuleDefPtr nwf,
                   nwItemDesc *item ATTRIBUTE_UNUSED)
{
    const char *str = NULL;

    if (intMapGetByInt(arpOpcodeMap,
                       nwf->p.arpHdrFilter.dataOpcode.u.u16,
                       &str)) {
        virBufferAdd(buf, str, -1);
    } else {
        virBufferAsprintf(buf, "%d", nwf->p.arpHdrFilter.dataOpcode.u.u16);
    }
    return 1;
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


static bool checkIPProtocolID(enum attrDatatype datatype,
                              union data *value,
                              virNWFilterRuleDefPtr nwf,
                              nwItemDesc *item ATTRIBUTE_UNUSED)
{
    int32_t res = -1;

    if (datatype == DATATYPE_STRING) {
        if (intMapGetByString(ipProtoMap, value->c, 1, &res) == 0)
            res = -1;
        datatype = DATATYPE_UINT8_HEX;
    } else if (datatype == DATATYPE_UINT8 ||
               datatype == DATATYPE_UINT8_HEX) {
        res = (uint32_t)value->ui;
    }

    if (res != -1) {
        nwf->p.ipHdrFilter.ipHdr.dataProtocolID.u.u8 = res;
        nwf->p.ipHdrFilter.ipHdr.dataProtocolID.datatype = datatype;
        return 1;
    }
    return 0;
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
                       &str)) {
        virBufferAdd(buf, str, -1);
    } else {
        if (nwf->p.ipHdrFilter.ipHdr.dataProtocolID.datatype == DATATYPE_UINT8)
            asHex = false;
        virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                          nwf->p.ipHdrFilter.ipHdr.dataProtocolID.u.u8);
    }
    return 1;
}


static bool
dscpValidator(enum attrDatatype datatype, union data *val,
              virNWFilterRuleDefPtr nwf,
              nwItemDesc *item ATTRIBUTE_UNUSED)
{
    uint8_t dscp = val->ui;
    if (dscp > 63)
        return 0;

    nwf->p.ipHdrFilter.ipHdr.dataDSCP.datatype = datatype;

    return 1;
}


static const struct int_map stateMatchMap[] = {
    INTMAP_ENTRY(RULE_FLAG_STATE_NEW          , "NEW"),
    INTMAP_ENTRY(RULE_FLAG_STATE_ESTABLISHED  , "ESTABLISHED"),
    INTMAP_ENTRY(RULE_FLAG_STATE_RELATED      , "RELATED"),
    INTMAP_ENTRY(RULE_FLAG_STATE_INVALID      , "INVALID"),
    INTMAP_ENTRY(RULE_FLAG_STATE_NONE         , "NONE"),
    INTMAP_ENTRY_LAST,
};


static int
parseStringItems(const struct int_map *int_map,
                 const char *input, int32_t *flags, char sep)
{
    int rc = 0;
    unsigned int i, j;
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
            rc = 1;
            break;
        }
    }
    return rc;
}


static int
printStringItems(virBufferPtr buf, const struct int_map *int_map,
                 int32_t flags, const char *sep)
{
    unsigned int i, c = 0;
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
parseStateMatch(const char *statematch, int32_t *flags)
{
    int rc = parseStringItems(stateMatchMap, statematch, flags, ',');

    if ((*flags & RULE_FLAG_STATE_NONE))
        *flags = RULE_FLAG_STATE_NONE;

    return rc;
}


void
virNWFilterPrintStateMatchFlags(virBufferPtr buf, const char *prefix,
                                int32_t flags, bool disp_none)
{
    if (!disp_none && (flags & RULE_FLAG_STATE_NONE))
        return;

    virBufferAdd(buf, prefix, -1);

    printStringItems(buf, stateMatchMap, flags, ",");
}


static bool
stateValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED, union data *val,
               virNWFilterRuleDefPtr nwf,
               nwItemDesc *item)
{
    char *input = val->c;
    int32_t flags = 0;

    if (parseStateMatch(input, &flags))
        return 0;

    item->u.u16 = flags;
    nwf->flags |= flags;

    item->datatype = DATATYPE_UINT16;

    return 1;
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
    INTMAP_ENTRY(0x1 , "FIN"),
    INTMAP_ENTRY(0x2 , "SYN"),
    INTMAP_ENTRY(0x4 , "RST"),
    INTMAP_ENTRY(0x8 , "PSH"),
    INTMAP_ENTRY(0x10, "ACK"),
    INTMAP_ENTRY(0x20, "URG"),
    INTMAP_ENTRY(0x3F, "ALL"),
    INTMAP_ENTRY(0x0 , "NONE"),
    INTMAP_ENTRY_LAST
};


static bool
tcpFlagsValidator(enum attrDatatype datatype ATTRIBUTE_UNUSED, union data *val,
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

    if (!parseStringItems(tcpFlags, s_mask , &mask , ',') &&
        !parseStringItems(tcpFlags, s_flags, &flags, ',')) {
        item->u.tcpFlags.mask  = mask  & 0x3f;
        item->u.tcpFlags.flags = flags & 0x3f;
        rc = true;
    }

    *sep = '/';

    return rc;
}


static void
printTCPFlags(virBufferPtr buf, uint8_t flags)
{
    if (flags == 0)
        virBufferAddLit(buf, "NONE");
    else if (flags == 0x3f)
        virBufferAddLit(buf, "ALL");
    else
        printStringItems(buf, tcpFlags, flags, ",");
}


void
virNWFilterPrintTCPFlags(virBufferPtr buf,
                         uint8_t mask, char sep, uint8_t flags)
{
    printTCPFlags(buf, mask);
    virBufferAddChar(buf, sep);
    printTCPFlags(buf, flags);
}


static bool
tcpFlagsFormatter(virBufferPtr buf,
                  virNWFilterRuleDefPtr nwf ATTRIBUTE_UNUSED,
                  nwItemDesc *item)
{
    virNWFilterPrintTCPFlags(buf,
                             item->u.tcpFlags.mask,
                             '/',
                             item->u.tcpFlags.flags);

    return true;
}


#define COMMON_MAC_PROPS(STRUCT) \
    {\
        .name = SRCMACADDR,\
        .datatype = DATATYPE_MACADDR,\
        .dataIdx = offsetof(virNWFilterRuleDef,p.STRUCT.ethHdr.dataSrcMACAddr),\
    },\
    {\
        .name = SRCMACMASK,\
        .datatype = DATATYPE_MACMASK,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ethHdr.dataSrcMACMask),\
    },\
    {\
        .name = DSTMACADDR,\
        .datatype = DATATYPE_MACADDR,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ethHdr.dataDstMACAddr),\
    },\
    {\
        .name = DSTMACMASK,\
        .datatype = DATATYPE_MACMASK,\
        .dataIdx = offsetof(virNWFilterRuleDef, p.STRUCT.ethHdr.dataDstMACMask),\
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
        .validator= checkMacProtocolID,
        .formatter= macProtocolIDFormatter,
    },
    COMMENT_PROP(ethHdrFilter),
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
        .validator= arpOpcodeValidator,
        .formatter= arpOpcodeFormatter,
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
        .name = ARPDSTIPADDR,
        .datatype = DATATYPE_IPADDR,
        .dataIdx = offsetof(virNWFilterRuleDef, p.arpHdrFilter.dataARPDstIPAddr),
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
        .validator= checkIPProtocolID,
        .formatter= formatIPProtocolID,
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
        .validator= checkIPProtocolID,
        .formatter= formatIPProtocolID,
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
    enum virNWFilterRuleProtocolType prtclType;
};

#define PROTOCOL_ENTRY(ID, ATT, PRTCLTYPE) \
    { .id = ID, .att = ATT, .prtclType = PRTCLTYPE }
#define PROTOCOL_ENTRY_LAST { .id = NULL }


static const virAttributes virAttr[] = {
    PROTOCOL_ENTRY("arp"    , arpAttributes    , VIR_NWFILTER_RULE_PROTOCOL_ARP),
    PROTOCOL_ENTRY("rarp"   , arpAttributes    , VIR_NWFILTER_RULE_PROTOCOL_RARP),
    PROTOCOL_ENTRY("mac"    , macAttributes    , VIR_NWFILTER_RULE_PROTOCOL_MAC),
    PROTOCOL_ENTRY("ip"     , ipAttributes     , VIR_NWFILTER_RULE_PROTOCOL_IP),
    PROTOCOL_ENTRY("ipv6"   , ipv6Attributes   , VIR_NWFILTER_RULE_PROTOCOL_IPV6),
    PROTOCOL_ENTRY("tcp"    , tcpAttributes    , VIR_NWFILTER_RULE_PROTOCOL_TCP),
    PROTOCOL_ENTRY("udp"    , udpAttributes    , VIR_NWFILTER_RULE_PROTOCOL_UDP),
    PROTOCOL_ENTRY("udplite", udpliteAttributes, VIR_NWFILTER_RULE_PROTOCOL_UDPLITE),
    PROTOCOL_ENTRY("esp"    , espAttributes    , VIR_NWFILTER_RULE_PROTOCOL_ESP),
    PROTOCOL_ENTRY("ah"     , ahAttributes     , VIR_NWFILTER_RULE_PROTOCOL_AH),
    PROTOCOL_ENTRY("sctp"   , sctpAttributes   , VIR_NWFILTER_RULE_PROTOCOL_SCTP),
    PROTOCOL_ENTRY("icmp"   , icmpAttributes   , VIR_NWFILTER_RULE_PROTOCOL_ICMP),
    PROTOCOL_ENTRY("all"    , allAttributes    , VIR_NWFILTER_RULE_PROTOCOL_ALL),
    PROTOCOL_ENTRY("igmp"   , igmpAttributes   , VIR_NWFILTER_RULE_PROTOCOL_IGMP),
    PROTOCOL_ENTRY("tcp-ipv6"    , tcpipv6Attributes    , VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6),
    PROTOCOL_ENTRY("udp-ipv6"    , udpipv6Attributes    , VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6),
    PROTOCOL_ENTRY("udplite-ipv6", udpliteipv6Attributes, VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6),
    PROTOCOL_ENTRY("esp-ipv6"    , espipv6Attributes    , VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6),
    PROTOCOL_ENTRY("ah-ipv6"     , ahipv6Attributes     , VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6),
    PROTOCOL_ENTRY("sctp-ipv6"   , sctpipv6Attributes   , VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6),
    PROTOCOL_ENTRY("icmpv6"      , icmpv6Attributes     , VIR_NWFILTER_RULE_PROTOCOL_ICMPV6),
    PROTOCOL_ENTRY("all-ipv6"    , allipv6Attributes    , VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6),
    PROTOCOL_ENTRY_LAST
};


static bool
virNWMACAddressParser(const char *input,
                      nwMACAddressPtr output)
{
    if (virParseMacAddr(input, &output->addr[0]) == 0)
        return 1;
    return 0;
}


static int
virNWFilterRuleDetailsParse(xmlNodePtr node,
                            virNWFilterRuleDefPtr nwf,
                            const virXMLAttr2Struct *att)
{
    int rc = 0, g_rc = 0;
    int idx = 0;
    char *prop;
    int found = 0;
    enum attrDatatype datatype, att_datatypes;
    enum virNWFilterEntryItemFlags *flags ,match_flag = 0, flags_set = 0;
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

        item = (nwItemDesc *)((char *)nwf + att[idx].dataIdx);
        flags = &item->flags;
        flags_set = match_flag;

        if (prop) {
            found = 0;

            validator = NULL;

            if (STRPREFIX(prop, "$")) {
                flags_set |= NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR;
                if (virNWFilterRuleDefAddVar(nwf,
                                             item,
                                             &prop[1]))
                    rc = -1;
                found = 1;
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
                        case DATATYPE_UINT8:
                            if (virStrToLong_ui(prop, NULL, base, &uint_val) >= 0) {
                                if (uint_val <= 0xff) {
                                    item->u.u8 = uint_val;
                                    found = 1;
                                    data.ui = uint_val;
                                } else
                                    rc = -1;
                            } else
                                rc = -1;
                        break;

                        case DATATYPE_UINT16_HEX:
                            base = 16;
                        case DATATYPE_UINT16:
                            if (virStrToLong_ui(prop, NULL, base, &uint_val) >= 0) {
                                if (uint_val <= 0xffff) {
                                    item->u.u16 = uint_val;
                                    found = 1;
                                    data.ui = uint_val;
                                } else
                                    rc = -1;
                            } else
                                rc = -1;
                        break;

                        case DATATYPE_IPADDR:
                            if (virSocketParseIpv4Addr(prop,
                                                       &item->u.ipaddr) < 0)
                                rc = -1;
                            found = 1;
                        break;

                        case DATATYPE_IPMASK:
                            if (virStrToLong_ui(prop, NULL, 10, &uint_val) == 0) {
                                if (uint_val <= 32) {
                                    if (!validator)
                                        item->u.u8 = (uint8_t)uint_val;
                                    found = 1;
                                    data.ui = uint_val;
                                } else
                                    rc = -1;
                            } else {
                                if (virSocketParseIpv4Addr(prop, &ipaddr) < 0) {
                                    rc = -1;
                                } else {
                                    int_val = virSocketGetNumNetmaskBits(&ipaddr);
                                    if (int_val >= 0)
                                        item->u.u8 = int_val;
                                    else
                                        rc = -1;
                                    found = 1;
                                }
                            }
                        break;

                        case DATATYPE_MACADDR:
                            if (!virNWMACAddressParser(prop,
                                                       &item->u.macaddr)) {
                                rc = -1;
                            }
                            found = 1;
                        break;

                        case DATATYPE_MACMASK:
                            validator = checkMACMask;
                            if (!virNWMACAddressParser(prop,
                                                       &item->u.macaddr)) {
                                rc = -1;
                            }
                            data.v = &item->u.macaddr;
                            found = 1;
                        break;

                        case DATATYPE_IPV6ADDR:
                            if (virSocketParseIpv6Addr(prop,
                                                       &item->u.ipaddr) < 0)
                                rc = -1;
                            found = 1;
                        break;

                        case DATATYPE_IPV6MASK:
                            if (virStrToLong_ui(prop, NULL, 10, &uint_val) == 0) {
                                if (uint_val <= 128) {
                                    if (!validator)
                                        item->u.u8 = (uint8_t)uint_val;
                                    found = 1;
                                    data.ui = uint_val;
                                } else
                                    rc = -1;
                            } else {
                                if (virSocketParseIpv6Addr(prop, &ipaddr) < 0) {
                                    rc = -1;
                                } else {
                                    int_val = virSocketGetNumNetmaskBits(&ipaddr);
                                    if (int_val >= 0)
                                        item->u.u8 = int_val;
                                    else
                                        rc = -1;
                                    found = 1;
                                }
                            }
                        break;

                        case DATATYPE_STRING:
                            if (!validator) {
                                /* not supported */
                                rc = -1;
                                break;
                            }
                            data.c = prop;
                            found = 1;
                        break;

                        case DATATYPE_STRINGCOPY:
                            if (!(item->u.string =
                                  virNWFilterRuleDefAddString(nwf, prop,
                                                       att[idx].maxstrlen))) {
                                rc = -1;
                                break;
                            }
                            data.c = item->u.string;
                            found = 1;
                        break;

                        case DATATYPE_BOOLEAN:
                            if (STREQ(prop, "true") ||
                                STREQ(prop, "1") ||
                                STREQ(prop, "yes"))
                                item->u.boolean = true;
                            else
                                item->u.boolean = false;

                            data.ui = item->u.boolean;
                            found = 1;
                        break;

                        case DATATYPE_LAST:
                        default:
                        break;
                    }
                }

                if (rc != 0 && att_datatypes != 0) {
                    rc = 0;
                    found = 0;
                }

                datatype <<= 1;
            } /* while */

            if (found == 1 && rc == 0) {
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
                virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    ret->filterref = virXMLPropString(cur, "filter");
    if (!ret->filterref) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
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

    case VIR_NWFILTER_RULE_PROTOCOL_IP:
        COPY_NEG_SIGN(rule->p.ipHdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.ipHdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.ipHdrFilter.ipHdr.dataDstIPMask,
                      rule->p.ipHdrFilter.ipHdr.dataDstIPAddr);
    break;

    case VIR_NWFILTER_RULE_PROTOCOL_IPV6:
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.ipHdr.dataSrcIPMask,
                      rule->p.ipv6HdrFilter.ipHdr.dataSrcIPAddr);
        COPY_NEG_SIGN(rule->p.ipv6HdrFilter.ipHdr.dataDstIPMask,
                      rule->p.ipv6HdrFilter.ipHdr.dataDstIPAddr);
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
    int found;
    int found_i = 0;
    unsigned int priority;

    xmlNodePtr cur;
    virNWFilterRuleDefPtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    action    = virXMLPropString(node, "action");
    direction = virXMLPropString(node, "direction");
    prio      = virXMLPropString(node, "priority");
    statematch= virXMLPropString(node, "statematch");

    if (!action) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("rule node requires action attribute"));
        goto err_exit;
    }

    if ((ret->action = virNWFilterRuleActionTypeFromString(action)) < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("unknown rule action attribute value"));
        goto err_exit;
    }

    if (!direction) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("rule node requires direction attribute"));
        goto err_exit;
    }

    if ((ret->tt = virNWFilterRuleDirectionTypeFromString(direction)) < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s",
                               _("unknown rule direction attribute value"));
        goto err_exit;
    }

    ret->priority = MAX_RULE_PRIORITY / 2;

    if (prio) {
        if (virStrToLong_ui(prio, NULL, 10, &priority) >= 0) {
            if (priority <= MAX_RULE_PRIORITY)
                ret->priority = priority;
        }
    }

    if (statematch &&
        (STREQ(statematch, "0") || STRCASEEQ(statematch, "false")))
        ret->flags |= RULE_FLAG_NO_STATEMATCH;

    cur = node->children;

    found = 0;

    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE) {
            int i = 0;
            while (1) {
                if (found)
                    i = found_i;

                if (xmlStrEqual(cur->name, BAD_CAST virAttr[i].id)) {

                    found_i = i;
                    found = 1;
                    ret->prtclType = virAttr[i].prtclType;

                    if (virNWFilterRuleDetailsParse(cur,
                                                    ret,
                                                    virAttr[i].att) < 0) {
                        /* we ignore malformed rules
                           goto err_exit;
                        */
                    }
                    break;
                }
                if (!found) {
                    i++;
                    if (!virAttr[i].id)
                        break;
                } else
                   break;
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


static virNWFilterDefPtr
virNWFilterDefParseXML(xmlXPathContextPtr ctxt) {
    virNWFilterDefPtr ret;
    xmlNodePtr curr = ctxt->node;
    char *uuid = NULL;
    char *chain = NULL;
    virNWFilterEntryPtr entry;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    ret->name = virXPathString("string(./@name)", ctxt);
    if (!ret->name) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("filter has no name"));
        goto cleanup;
    }

    ret->chainsuffix = VIR_NWFILTER_CHAINSUFFIX_ROOT;
    chain = virXPathString("string(./@chain)", ctxt);
    if (chain) {
        if ((ret->chainsuffix =
             virNWFilterChainSuffixTypeFromString(chain)) < 0) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unknown chain suffix '%s'"), chain);
            goto cleanup;
        }
    }

    uuid = virXPathString("string(./uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("unable to generate uuid"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virNWFilterReportError(VIR_ERR_XML_ERROR,
                                  "%s", _("malformed uuid element"));
            goto cleanup;
        }
        VIR_FREE(uuid);
    }

    curr = curr->children;

    while (curr != NULL) {
        if (curr->type == XML_ELEMENT_NODE) {
            if (VIR_ALLOC(entry) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            /* ignore malformed rule and include elements */
            if (xmlStrEqual(curr->name, BAD_CAST "rule"))
                entry->rule = virNWFilterRuleParse(curr);
            else if (xmlStrEqual(curr->name, BAD_CAST "filterref"))
                entry->include = virNWFilterIncludeParse(curr);

            if (entry->rule || entry->include) {
                if (VIR_REALLOC_N(ret->filterEntries, ret->nentries+1) < 0) {
                    VIR_FREE(entry);
                    virReportOOMError();
                    goto cleanup;
                }
                ret->filterEntries[ret->nentries++] = entry;
            } else
                VIR_FREE(entry);
        }
        curr = curr->next;
    }

    VIR_FREE(chain);

    return ret;

 cleanup:
    virNWFilterDefFree(ret);
    VIR_FREE(chain);
    VIR_FREE(uuid);
    return NULL;
}


virNWFilterDefPtr
virNWFilterDefParseNode(xmlDocPtr xml,
                        xmlNodePtr root) {
    xmlXPathContextPtr ctxt = NULL;
    virNWFilterDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "filter")) {
        virNWFilterReportError(VIR_ERR_XML_ERROR,
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
virNWFilterDefParse(virConnectPtr conn ATTRIBUTE_UNUSED,
                    const char *xmlStr,
                    const char *filename) {
    virNWFilterDefPtr def = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, "nwfilter.xml"))) {
        def = virNWFilterDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return def;
}


virNWFilterDefPtr
virNWFilterDefParseString(virConnectPtr conn,
                          const char *xmlStr)
{
    return virNWFilterDefParse(conn, xmlStr, NULL);
}


virNWFilterDefPtr
virNWFilterDefParseFile(virConnectPtr conn,
                        const char *filename)
{
    return virNWFilterDefParse(conn, NULL, filename);
}


virNWFilterObjPtr
virNWFilterObjFindByUUID(virNWFilterObjListPtr nwfilters,
                         const unsigned char *uuid)
{
    unsigned int i;

    for (i = 0 ; i < nwfilters->count ; i++) {
        virNWFilterObjLock(nwfilters->objs[i]);
        if (!memcmp(nwfilters->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return nwfilters->objs[i];
        virNWFilterObjUnlock(nwfilters->objs[i]);
    }

    return NULL;
}


virNWFilterObjPtr
virNWFilterObjFindByName(virNWFilterObjListPtr nwfilters, const char *name)
{
    unsigned int i;

    for (i = 0 ; i < nwfilters->count ; i++) {
        virNWFilterObjLock(nwfilters->objs[i]);
        if (STREQ(nwfilters->objs[i]->def->name, name))
            return nwfilters->objs[i];
        virNWFilterObjUnlock(nwfilters->objs[i]);
    }

    return NULL;
}


int virNWFilterSaveXML(const char *configDir,
                       virNWFilterDefPtr def,
                       const char *xml)
{
    char *configFile = NULL;
    int fd = -1, ret = -1;
    size_t towrite;
    int err;

    if ((configFile = virNWFilterConfigFile(configDir, def->name)) == NULL)
        goto cleanup;

    if ((err = virFileMakePath(configDir))) {
        virReportSystemError(err,
                             _("cannot create config directory '%s'"),
                             configDir);
        goto cleanup;
    }

    if ((fd = open(configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virReportSystemError(errno,
                             _("cannot create config file '%s'"),
                             configFile);
        goto cleanup;
    }

    virEmitXMLWarning(fd, def->name, "nwfilter-edit");

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        virReportSystemError(errno,
                             _("cannot write config file '%s'"),
                             configFile);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot save config file '%s'"),
                             configFile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(configFile);

    return ret;
}


int virNWFilterSaveConfig(const char *configDir,
                          virNWFilterDefPtr def)
{
    int ret = -1;
    char *xml;

    if (!(xml = virNWFilterDefFormat(def)))
        goto cleanup;

    if (virNWFilterSaveXML(configDir, def, xml))
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(xml);
    return ret;
}


static int
_virNWFilterDefLoopDetect(virConnectPtr conn,
                          virNWFilterObjListPtr nwfilters,
                          virNWFilterDefPtr def,
                          const char *filtername)
{
    int rc = 0;
    int i;
    virNWFilterEntryPtr entry;
    virNWFilterObjPtr obj;

    if (!def)
        return 0;

    for (i = 0; i < def->nentries; i++) {
        entry = def->filterEntries[i];
        if (entry->include) {

            if (STREQ(filtername, entry->include->filterref)) {
                rc = 1;
                break;
            }

            obj = virNWFilterObjFindByName(nwfilters,
                                           entry->include->filterref);
            if (obj) {
                rc = _virNWFilterDefLoopDetect(conn, nwfilters,
                                               obj->def, filtername);

                virNWFilterObjUnlock(obj);
                if (rc)
                   break;
            }
        }
    }

    return rc;
}


/*
 * virNWFilterDefLoopDetect:
 * @conn: pointer to virConnect object
 * @nwfilters : the nwfilters to search
 * @def : the filter definiton that may add a loop and is to be tested
 *
 * Detect a loop introduced through the filters being able to
 * reference each other.
 *
 * Returns 0 in case no loop was detected, 1 otherwise.
 */
static int
virNWFilterDefLoopDetect(virConnectPtr conn,
                         virNWFilterObjListPtr nwfilters,
                         virNWFilterDefPtr def)
{
    return _virNWFilterDefLoopDetect(conn, nwfilters, def, def->name);
}

int nCallbackDriver;
#define MAX_CALLBACK_DRIVER 10
static virNWFilterCallbackDriverPtr callbackDrvArray[MAX_CALLBACK_DRIVER];

void
virNWFilterRegisterCallbackDriver(virNWFilterCallbackDriverPtr cbd)
{
    if (nCallbackDriver < MAX_CALLBACK_DRIVER) {
        callbackDrvArray[nCallbackDriver++] = cbd;
    }
}

void
virNWFilterCallbackDriversLock(void)
{
    int i;

    for (i = 0; i < nCallbackDriver; i++)
        callbackDrvArray[i]->vmDriverLock();
}

void
virNWFilterCallbackDriversUnlock(void)
{
    int i;

    for (i = 0; i < nCallbackDriver; i++)
        callbackDrvArray[i]->vmDriverUnlock();
}


static virHashIterator virNWFilterDomainFWUpdateCB;


static int
virNWFilterTriggerVMFilterRebuild(virConnectPtr conn)
{
    int i;
    int err;
    struct domUpdateCBStruct cb = {
        .conn = conn,
        .err = 0,
        .step = STEP_APPLY_NEW,
        .skipInterfaces = virHashCreate(0, NULL),
    };

    if (!cb.skipInterfaces)
        return 1;

    for (i = 0; i < nCallbackDriver; i++) {
        callbackDrvArray[i]->vmFilterRebuild(conn,
                                             virNWFilterDomainFWUpdateCB,
                                             &cb);
    }

    err = cb.err;

    if (err) {
        cb.step = STEP_TEAR_NEW; /* rollback */
        cb.err = 0;

        for (i = 0; i < nCallbackDriver; i++)
            callbackDrvArray[i]->vmFilterRebuild(conn,
                                                 virNWFilterDomainFWUpdateCB,
                                                 &cb);
    } else {
        cb.step = STEP_TEAR_OLD; /* switch over */

        for (i = 0; i < nCallbackDriver; i++)
            callbackDrvArray[i]->vmFilterRebuild(conn,
                                                 virNWFilterDomainFWUpdateCB,
                                                 &cb);
    }

    virHashFree(cb.skipInterfaces);

    return err;
}


int
virNWFilterTestUnassignDef(virConnectPtr conn,
                           virNWFilterObjPtr nwfilter)
{
    int rc = 0;

    nwfilter->wantRemoved = 1;
    /* trigger the update on VMs referencing the filter */
    if (virNWFilterTriggerVMFilterRebuild(conn))
        rc = 1;

    nwfilter->wantRemoved = 0;

    return rc;
}


virNWFilterObjPtr
virNWFilterObjAssignDef(virConnectPtr conn,
                        virNWFilterObjListPtr nwfilters,
                        virNWFilterDefPtr def)
{
    virNWFilterObjPtr nwfilter;

    nwfilter = virNWFilterObjFindByUUID(nwfilters, def->uuid);

    if (nwfilter) {
        if (!STREQ(def->name, nwfilter->def->name)) {
            virNWFilterReportError(VIR_ERR_OPERATION_FAILED,
                                   _("filter with same UUID but different name "
                                     "('%s') already exists"),
                                   nwfilter->def->name);
            virNWFilterObjUnlock(nwfilter);
            return NULL;
        }
        virNWFilterObjUnlock(nwfilter);
    }

    if (virNWFilterDefLoopDetect(conn, nwfilters, def)) {
        virNWFilterReportError(VIR_ERR_OPERATION_FAILED,
                              "%s", _("filter would introduce a loop"));
        return NULL;
    }

    virNWFilterLockFilterUpdates();

    if ((nwfilter = virNWFilterObjFindByName(nwfilters, def->name))) {
        nwfilter->newDef = def;
        /* trigger the update on VMs referencing the filter */
        if (virNWFilterTriggerVMFilterRebuild(conn)) {
            nwfilter->newDef = NULL;
            virNWFilterUnlockFilterUpdates();
            virNWFilterObjUnlock(nwfilter);
            return NULL;
        }

        virNWFilterDefFree(nwfilter->def);
        nwfilter->def = def;
        nwfilter->newDef = NULL;
        virNWFilterUnlockFilterUpdates();
        return nwfilter;
    }

    virNWFilterUnlockFilterUpdates();

    if (VIR_ALLOC(nwfilter) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInitRecursive(&nwfilter->lock) < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot initialize mutex"));
        VIR_FREE(nwfilter);
        return NULL;
    }
    virNWFilterObjLock(nwfilter);
    nwfilter->active = 0;
    nwfilter->def = def;

    if (VIR_REALLOC_N(nwfilters->objs, nwfilters->count + 1) < 0) {
        nwfilter->def = NULL;
        virNWFilterObjUnlock(nwfilter);
        virNWFilterObjFree(nwfilter);
        virReportOOMError();
        return NULL;
    }
    nwfilters->objs[nwfilters->count++] = nwfilter;

    return nwfilter;
}


static virNWFilterObjPtr
virNWFilterObjLoad(virConnectPtr conn,
                   virNWFilterObjListPtr nwfilters,
                   const char *file,
                   const char *path)
{
    virNWFilterDefPtr def;
    virNWFilterObjPtr nwfilter;

    if (!(def = virNWFilterDefParseFile(conn, path))) {
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virNWFilterReportError(VIR_ERR_XML_ERROR,
            _("network filter config filename '%s' does not match name '%s'"),
            path, def->name);
        virNWFilterDefFree(def);
        return NULL;
    }

    if (!(nwfilter = virNWFilterObjAssignDef(conn, nwfilters, def))) {
        virNWFilterDefFree(def);
        return NULL;
    }

    VIR_FREE(nwfilter->configFile); /* for driver reload */
    nwfilter->configFile = strdup(path);
    if (nwfilter->configFile == NULL) {
        virReportOOMError();
        virNWFilterDefFree(def);
        return NULL;
    }

    return nwfilter;
}


int
virNWFilterLoadAllConfigs(virConnectPtr conn,
                          virNWFilterObjListPtr nwfilters,
                          const char *configDir)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT) {
            return 0;
        }
        virReportSystemError(errno, _("Failed to open dir '%s'"),
                             configDir);
        return -1;
    }

    while ((entry = readdir(dir))) {
        char *path;
        virNWFilterObjPtr nwfilter;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (!(path = virFileBuildPath(configDir, entry->d_name, NULL)))
            continue;

        nwfilter = virNWFilterObjLoad(conn, nwfilters, entry->d_name, path);
        if (nwfilter)
            virNWFilterObjUnlock(nwfilter);

        VIR_FREE(path);
    }

    closedir(dir);

    return 0;
}


int
virNWFilterObjSaveDef(virNWFilterDriverStatePtr driver,
                      virNWFilterObjPtr nwfilter,
                      virNWFilterDefPtr def)
{
    char *xml;
    int fd = -1, ret = -1;
    ssize_t towrite;

    if (!nwfilter->configFile) {
        int err;

        if ((err = virFileMakePath(driver->configDir))) {
            virReportSystemError(err,
                                 _("cannot create config directory %s"),
                                 driver->configDir);
            return -1;
        }

        if (!(nwfilter->configFile = virFileBuildPath(driver->configDir,
                                                      def->name, ".xml"))) {
            return -1;
        }
    }

    if (!(xml = virNWFilterDefFormat(def))) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("failed to generate XML"));
        return -1;
    }

    if ((fd = open(nwfilter->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virReportSystemError(errno,
                             _("cannot create config file %s"),
                             nwfilter->configFile);
        goto cleanup;
    }

    virEmitXMLWarning(fd, def->name, "nwfilter-edit");

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) != towrite) {
        virReportSystemError(errno,
                             _("cannot write config file %s"),
                             nwfilter->configFile);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("cannot save config file %s"),
                             nwfilter->configFile);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);

    VIR_FREE(xml);

    return ret;
}


int
virNWFilterObjDeleteDef(virNWFilterObjPtr nwfilter)
{
    if (!nwfilter->configFile) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("no config file for %s"), nwfilter->def->name);
        return -1;
    }

    if (unlink(nwfilter->configFile) < 0) {
        virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot remove config for %s"),
                               nwfilter->def->name);
        return -1;
    }

    return 0;
}


static void
virNWIPAddressFormat(virBufferPtr buf, virSocketAddrPtr ipaddr)
{
    char *output = virSocketFormatAddr(ipaddr);

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
    int i = 0, j;
    bool typeShown = 0;
    bool neverShown = 1;
    bool asHex;
    enum match {
        MATCH_NONE = 0,
        MATCH_YES,
        MATCH_NO
    } matchShown = MATCH_NONE;
    nwItemDesc *item;

    while (att[i].name) {
        item = (nwItemDesc *)((char *)def + att[i].dataIdx);
        enum virNWFilterEntryItemFlags flags = item->flags;
        if ((flags & NWFILTER_ENTRY_ITEM_FLAG_EXISTS)) {
            if (!typeShown) {
                virBufferAsprintf(buf, "    <%s", type);
                typeShown = 1;
                neverShown = 0;
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
            if (att[i].formatter) {
               if (!att[i].formatter(buf, def, item)) {
                  virNWFilterReportError(VIR_ERR_INTERNAL_ERROR,
                                         _("formatter for %s %s reported error"),
                                         type,
                                         att[i].name);
                   goto err_exit;
               }
            } else if ((flags & NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR)) {
                virBufferAsprintf(buf, "$%s", item->var);
            } else {
               asHex = false;

               switch (item->datatype) {

               case DATATYPE_UINT8_HEX:
                   asHex = true;
               case DATATYPE_IPMASK:
               case DATATYPE_IPV6MASK:
                   /* display all masks in CIDR format */
               case DATATYPE_UINT8:
                   virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                                     item->u.u8);
               break;

               case DATATYPE_UINT16_HEX:
                   asHex = true;
               case DATATYPE_UINT16:
                   virBufferAsprintf(buf, asHex ? "0x%x" : "%d",
                                     item->u.u16);
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
                   if (item->u.boolean == true)
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
                         "    <%s/>\n", type);

err_exit:
    return;
}


static char *
virNWFilterRuleDefFormat(virNWFilterRuleDefPtr def)
{
    int i;
    virBuffer buf  = VIR_BUFFER_INITIALIZER;
    virBuffer buf2 = VIR_BUFFER_INITIALIZER;
    char *data;

    virBufferAsprintf(&buf, "  <rule action='%s' direction='%s' priority='%d'",
                      virNWFilterRuleActionTypeToString(def->action),
                      virNWFilterRuleDirectionTypeToString(def->tt),
                      def->priority);

    if ((def->flags & RULE_FLAG_NO_STATEMATCH))
        virBufferAddLit(&buf, " statematch='false'");

    i = 0;
    while (virAttr[i].id) {
        if (virAttr[i].prtclType == def->prtclType) {
            virNWFilterRuleDefDetailsFormat(&buf2,
                                            virAttr[i].id,
                                            virAttr[i].att,
                                            def);
            break;
        }
        i++;
    }

    if (virBufferError(&buf2))
        goto no_memory;

    data = virBufferContentAndReset(&buf2);

    if (data) {
        virBufferAddLit(&buf, ">\n");
        virBufferAsprintf(&buf, "%s  </rule>\n", data);
        VIR_FREE(data);
    } else
        virBufferAddLit(&buf, "/>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

no_memory:
    virReportOOMError();
    virBufferFreeAndReset(&buf);
    virBufferFreeAndReset(&buf2);

    return NULL;
}


static char *
virNWFilterIncludeDefFormat(virNWFilterIncludeDefPtr inc)
{
    char *attrs;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf,"  <filterref filter='%s'",
                      inc->filterref);

    attrs = virNWFilterFormatParamAttributes(inc->params, "    ");

    if (!attrs || strlen(attrs) <= 1)
        virBufferAddLit(&buf, "/>\n");
    else
        virBufferAsprintf(&buf, ">\n%s  </filterref>\n", attrs);

    if (virBufferError(&buf)) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


static char *
virNWFilterEntryFormat(virNWFilterEntryPtr entry)
{
    if (entry->rule)
        return virNWFilterRuleDefFormat(entry->rule);
    return virNWFilterIncludeDefFormat(entry->include);
}


char *
virNWFilterDefFormat(virNWFilterDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int i;
    char *xml;

    virBufferAsprintf(&buf, "<filter name='%s' chain='%s'",
                      def->name,
                      virNWFilterChainSuffixTypeToString(def->chainsuffix));
    virBufferAddLit(&buf, ">\n");

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(&buf,"  <uuid>%s</uuid>\n", uuid);

    for (i = 0; i < def->nentries; i++) {
        xml = virNWFilterEntryFormat(def->filterEntries[i]);
        if (!xml)
            goto err_exit;
        virBufferAdd(&buf, xml, -1);
        VIR_FREE(xml);
    }

    virBufferAddLit(&buf, "</filter>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();

 err_exit:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *virNWFilterConfigFile(const char *dir,
                            const char *name)
{
    char *ret = NULL;

    if (virAsprintf(&ret, "%s/%s.xml", dir, name) < 0) {
        virReportOOMError();
        return NULL;
    }

    return ret;
}


int virNWFilterConfLayerInit(virHashIterator domUpdateCB)
{
    virNWFilterDomainFWUpdateCB = domUpdateCB;

    initialized = true;

    if (virMutexInitRecursive(&updateMutex))
        return 1;

    return 0;
}


void virNWFilterConfLayerShutdown(void)
{
    if (!initialized)
        return;

    virMutexDestroy(&updateMutex);

    initialized = false;
}


void virNWFilterObjLock(virNWFilterObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virNWFilterObjUnlock(virNWFilterObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}
