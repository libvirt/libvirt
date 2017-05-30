/*
 * nwfilter_conf.h: network filter XML processing
 *                  (derived from storage_conf.h)
 *
 * Copyright (C) 2006-2010, 2012-2014 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 *
 * Copyright (C) 2010 IBM Corporation
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
#ifndef NWFILTER_CONF_H
# define NWFILTER_CONF_H

# include "internal.h"

# include "virhash.h"
# include "virxml.h"
# include "virbuffer.h"
# include "virsocketaddr.h"
# include "virmacaddr.h"
# include "virdomainobjlist.h"

/* XXX
 * The config parser/structs should not be using platform specific
 * constants. Win32 lacks these constants, breaking the parser,
 * so temporarily define them until this can be re-written to use
 * locally defined enums for all constants
 */
# ifndef ETHERTYPE_IP
#  define ETHERTYPE_IP            0x0800
# endif
# ifndef ETHERTYPE_ARP
#  define ETHERTYPE_ARP           0x0806
# endif
# ifndef ETHERTYPE_REVARP
#  define ETHERTYPE_REVARP        0x8035
# endif
# ifndef ETHERTYPE_IPV6
#  define ETHERTYPE_IPV6          0x86dd
# endif
# ifndef ETHERTYPE_VLAN
#  define ETHERTYPE_VLAN          0x8100
# endif

/**
 * Chain suffix size is:
 * max. user define table name length -
 *   sizeof("FO-") -
 *   max. interface name size -
 *   sizeof("-") -
 *   terminating '0' =
 * 32-3-15-1-1 = 12
 */
# define MAX_CHAIN_SUFFIX_SIZE	12


typedef enum {
    NWFILTER_ENTRY_ITEM_FLAG_EXISTS   = 1 << 0,
    NWFILTER_ENTRY_ITEM_FLAG_IS_NEG   = 1 << 1,
    NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR  = 1 << 2,
} virNWFilterEntryItemFlags;


# define MAX_COMMENT_LENGTH  256
# define MAX_IPSET_NAME_LENGTH 32 /* incl. terminating '\0' */

# define HAS_ENTRY_ITEM(data) \
  (((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_EXISTS)

# define ENTRY_WANT_NEG_SIGN(data) \
  (((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_IS_NEG)

/* datatypes appearing in rule attributes */
enum attrDatatype {
    DATATYPE_UINT16           = (1 << 0),
    DATATYPE_UINT8            = (1 << 1),
    DATATYPE_UINT16_HEX       = (1 << 2),
    DATATYPE_UINT8_HEX        = (1 << 3),
    DATATYPE_MACADDR          = (1 << 4),
    DATATYPE_MACMASK          = (1 << 5),
    DATATYPE_IPADDR           = (1 << 6),
    DATATYPE_IPMASK           = (1 << 7),
    DATATYPE_STRING           = (1 << 8),
    DATATYPE_IPV6ADDR         = (1 << 9),
    DATATYPE_IPV6MASK         = (1 << 10),
    DATATYPE_STRINGCOPY       = (1 << 11),
    DATATYPE_BOOLEAN          = (1 << 12),
    DATATYPE_UINT32           = (1 << 13),
    DATATYPE_UINT32_HEX       = (1 << 14),
    DATATYPE_IPSETNAME        = (1 << 15),
    DATATYPE_IPSETFLAGS       = (1 << 16),

    DATATYPE_LAST             = (1 << 17),
};

# define NWFILTER_MAC_BGA "01:80:c2:00:00:00"


typedef struct _nwItemDesc nwItemDesc;
typedef nwItemDesc *nwItemDescPtr;
struct _nwItemDesc {
    virNWFilterEntryItemFlags flags;
    virNWFilterVarAccessPtr varAccess;
    enum attrDatatype datatype;
    union {
        virMacAddr macaddr;
        virSocketAddr ipaddr;
        bool         boolean;
        uint8_t      u8;
        uint16_t     u16;
        uint32_t     u32;
        char         protocolID[10];
        char         *string;
        struct {
            uint8_t  mask;
            uint8_t  flags;
        } tcpFlags;
        struct {
            char setname[MAX_IPSET_NAME_LENGTH];
            uint8_t numFlags;
            uint8_t flags;
        } ipset;
    } u;
};

# define VALID_IPSETNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-+ "

typedef struct _ethHdrDataDef ethHdrDataDef;
typedef ethHdrDataDef *ethHdrDataDefPtr;
struct _ethHdrDataDef {
    nwItemDesc dataSrcMACAddr;
    nwItemDesc dataSrcMACMask;
    nwItemDesc dataDstMACAddr;
    nwItemDesc dataDstMACMask;
};


typedef struct _ethHdrFilterDef  ethHdrFilterDef;
typedef ethHdrFilterDef *ethHdrFilterDefPtr;
struct _ethHdrFilterDef {
    ethHdrDataDef ethHdr;
    nwItemDesc dataProtocolID;
    nwItemDesc dataComment;
};


typedef struct _vlanHdrFilterDef  vlanHdrFilterDef;
typedef vlanHdrFilterDef *vlanHdrFilterDefPtr;
struct _vlanHdrFilterDef {
    ethHdrDataDef ethHdr;
    nwItemDesc dataVlanID;
    nwItemDesc dataVlanEncap;
    nwItemDesc dataComment;
};


typedef struct _stpHdrFilterDef  stpHdrFilterDef;
typedef stpHdrFilterDef *stpHdrFilterDefPtr;
struct _stpHdrFilterDef {
    ethHdrDataDef ethHdr;
    nwItemDesc dataType;
    nwItemDesc dataFlags;
    nwItemDesc dataRootPri;
    nwItemDesc dataRootPriHi;
    nwItemDesc dataRootAddr;
    nwItemDesc dataRootAddrMask;
    nwItemDesc dataRootCost;
    nwItemDesc dataRootCostHi;
    nwItemDesc dataSndrPrio;
    nwItemDesc dataSndrPrioHi;
    nwItemDesc dataSndrAddr;
    nwItemDesc dataSndrAddrMask;
    nwItemDesc dataPort;
    nwItemDesc dataPortHi;
    nwItemDesc dataAge;
    nwItemDesc dataAgeHi;
    nwItemDesc dataMaxAge;
    nwItemDesc dataMaxAgeHi;
    nwItemDesc dataHelloTime;
    nwItemDesc dataHelloTimeHi;
    nwItemDesc dataFwdDelay;
    nwItemDesc dataFwdDelayHi;
    nwItemDesc dataComment;
};


typedef struct _arpHdrFilterDef  arpHdrFilterDef;
typedef arpHdrFilterDef *arpHdrFilterDefPtr;
struct _arpHdrFilterDef {
    ethHdrDataDef ethHdr;
    nwItemDesc dataHWType;
    nwItemDesc dataProtocolType;
    nwItemDesc dataOpcode;
    nwItemDesc dataARPSrcMACAddr;
    nwItemDesc dataARPSrcIPAddr;
    nwItemDesc dataARPSrcIPMask;
    nwItemDesc dataARPDstMACAddr;
    nwItemDesc dataARPDstIPAddr;
    nwItemDesc dataARPDstIPMask;
    nwItemDesc dataGratuitousARP;
    nwItemDesc dataComment;
};


typedef struct _ipHdrDataDef  ipHdrDataDef;
typedef ipHdrDataDef *ipHdrDataDefPtr;
struct _ipHdrDataDef {
    nwItemDesc dataIPVersion;
    nwItemDesc dataSrcIPAddr;
    nwItemDesc dataSrcIPMask;
    nwItemDesc dataDstIPAddr;
    nwItemDesc dataDstIPMask;
    nwItemDesc dataProtocolID;
    nwItemDesc dataSrcIPFrom;
    nwItemDesc dataSrcIPTo;
    nwItemDesc dataDstIPFrom;
    nwItemDesc dataDstIPTo;
    nwItemDesc dataDSCP;
    nwItemDesc dataState;
    nwItemDesc dataConnlimitAbove;
    nwItemDesc dataComment;
    nwItemDesc dataIPSet;
    nwItemDesc dataIPSetFlags;
};


typedef struct _portDataDef portDataDef;
typedef portDataDef *portDataDefPtr;
struct _portDataDef {
    nwItemDesc dataSrcPortStart;
    nwItemDesc dataSrcPortEnd;
    nwItemDesc dataDstPortStart;
    nwItemDesc dataDstPortEnd;
};


typedef struct _ipHdrFilterDef  ipHdrFilterDef;
typedef ipHdrFilterDef *ipHdrFilterDefPtr;
struct _ipHdrFilterDef {
    ethHdrDataDef ethHdr;
    ipHdrDataDef ipHdr;
    portDataDef  portData;
};


typedef struct _ipv6HdrFilterDef  ipv6HdrFilterDef;
typedef ipv6HdrFilterDef *ipv6HdrFilterDefPtr;
struct _ipv6HdrFilterDef {
    ethHdrDataDef  ethHdr;
    ipHdrDataDef   ipHdr;
    portDataDef    portData;
    nwItemDesc     dataICMPTypeStart;
    nwItemDesc     dataICMPTypeEnd;
    nwItemDesc     dataICMPCodeStart;
    nwItemDesc     dataICMPCodeEnd;
};


typedef struct _icmpHdrFilterDef  icmpHdrFilterDef;
typedef icmpHdrFilterDef *icmpHdrFilterDefPtr;
struct _icmpHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
    nwItemDesc   dataICMPType;
    nwItemDesc   dataICMPCode;
    nwItemDesc   dataStateFlags;
};


typedef struct _allHdrFilterDef  allHdrFilterDef;
typedef allHdrFilterDef *allHdrFilterDefPtr;
struct _allHdrFilterDef {
    nwItemDesc    dataSrcMACAddr;
    ipHdrDataDef  ipHdr;
};


typedef struct _igmpHdrFilterDef  igmpHdrFilterDef;
typedef igmpHdrFilterDef *igmpHdrFilterDefPtr;
struct _igmpHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
};


typedef struct _tcpHdrFilterDef  tcpHdrFilterDef;
typedef tcpHdrFilterDef *tcpHdrFilterDefPtr;
struct _tcpHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
    portDataDef  portData;
    nwItemDesc   dataTCPOption;
    nwItemDesc   dataTCPFlags;
};


typedef struct _udpHdrFilterDef  udpHdrFilterDef;
typedef udpHdrFilterDef *udpHdrFilterDefPtr;
struct _udpHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
    portDataDef  portData;
};


typedef struct _sctpHdrFilterDef  sctpHdrFilterDef;
typedef sctpHdrFilterDef *sctpHdrFilterDefPtr;
struct _sctpHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
    portDataDef  portData;
};


typedef struct _espHdrFilterDef  espHdrFilterDef;
typedef espHdrFilterDef *espHdrFilterDefPtr;
struct _espHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
};


typedef struct _ahHdrFilterDef  ahHdrFilterDef;
typedef ahHdrFilterDef *ahHdrFilterDefPtr;
struct _ahHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
};


typedef struct _udpliteHdrFilterDef  udpliteHdrFilterDef;
typedef udpliteHdrFilterDef *udpliteHdrFilterDefPtr;
struct _udpliteHdrFilterDef {
    nwItemDesc   dataSrcMACAddr;
    ipHdrDataDef ipHdr;
};


typedef enum {
    VIR_NWFILTER_RULE_ACTION_DROP = 0,
    VIR_NWFILTER_RULE_ACTION_ACCEPT,
    VIR_NWFILTER_RULE_ACTION_REJECT,
    VIR_NWFILTER_RULE_ACTION_RETURN,
    VIR_NWFILTER_RULE_ACTION_CONTINUE,

    VIR_NWFILTER_RULE_ACTION_LAST,
} virNWFilterRuleActionType;

typedef enum {
    VIR_NWFILTER_RULE_DIRECTION_IN = 0,
    VIR_NWFILTER_RULE_DIRECTION_OUT,
    VIR_NWFILTER_RULE_DIRECTION_INOUT,

    VIR_NWFILTER_RULE_DIRECTION_LAST,
} virNWFilterRuleDirectionType ;

typedef enum {
    VIR_NWFILTER_CHAIN_POLICY_ACCEPT = 0,
    VIR_NWFILTER_CHAIN_POLICY_DROP,

    VIR_NWFILTER_CHAIN_POLICY_LAST,
} virNWFilterChainPolicyType;


/*
 * If adding protocols be sure to update the
 * virNWFilterRuleIsProtocolXXXX function impls
 */
typedef enum {
    /* Ethernet layer protocols */
    VIR_NWFILTER_RULE_PROTOCOL_NONE = 0,
    VIR_NWFILTER_RULE_PROTOCOL_MAC,
    VIR_NWFILTER_RULE_PROTOCOL_VLAN,
    VIR_NWFILTER_RULE_PROTOCOL_STP,
    VIR_NWFILTER_RULE_PROTOCOL_ARP,
    VIR_NWFILTER_RULE_PROTOCOL_RARP,
    VIR_NWFILTER_RULE_PROTOCOL_IP,
    VIR_NWFILTER_RULE_PROTOCOL_IPV6,

    /* IPv4 layer protocols */
    VIR_NWFILTER_RULE_PROTOCOL_TCP,
    VIR_NWFILTER_RULE_PROTOCOL_ICMP,
    VIR_NWFILTER_RULE_PROTOCOL_IGMP,
    VIR_NWFILTER_RULE_PROTOCOL_UDP,
    VIR_NWFILTER_RULE_PROTOCOL_UDPLITE,
    VIR_NWFILTER_RULE_PROTOCOL_ESP,
    VIR_NWFILTER_RULE_PROTOCOL_AH,
    VIR_NWFILTER_RULE_PROTOCOL_SCTP,
    VIR_NWFILTER_RULE_PROTOCOL_ALL,

    /* IPv6 layer protocols */
    VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ICMPV6,
    VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6,

    VIR_NWFILTER_RULE_PROTOCOL_LAST
} virNWFilterRuleProtocolType;

typedef enum {
    VIR_NWFILTER_EBTABLES_TABLE_FILTER = 0,
    VIR_NWFILTER_EBTABLES_TABLE_NAT,
    VIR_NWFILTER_EBTABLES_TABLE_BROUTE,

    VIR_NWFILTER_EBTABLES_TABLE_LAST,
} virNWFilterEbtablesTableType;


# define MIN_RULE_PRIORITY  -1000
# define MAX_RULE_PRIORITY  1000

# define NWFILTER_MIN_FILTER_PRIORITY -1000
# define NWFILTER_MAX_FILTER_PRIORITY MAX_RULE_PRIORITY

# define NWFILTER_ROOT_FILTER_PRI 0
# define NWFILTER_STP_FILTER_PRI  -810
# define NWFILTER_MAC_FILTER_PRI  -800
# define NWFILTER_VLAN_FILTER_PRI -750
# define NWFILTER_IPV4_FILTER_PRI -700
# define NWFILTER_IPV6_FILTER_PRI -600
# define NWFILTER_ARP_FILTER_PRI  -500
# define NWFILTER_RARP_FILTER_PRI -400

typedef enum {
    RULE_FLAG_NO_STATEMATCH      = (1 << 0),
    RULE_FLAG_STATE_NEW          = (1 << 1),
    RULE_FLAG_STATE_ESTABLISHED  = (1 << 2),
    RULE_FLAG_STATE_RELATED      = (1 << 3),
    RULE_FLAG_STATE_INVALID      = (1 << 4),
    RULE_FLAG_STATE_NONE         = (1 << 5),
} virNWFilterRuleFlags;


# define IPTABLES_STATE_FLAGS \
  (RULE_FLAG_STATE_NEW | \
   RULE_FLAG_STATE_ESTABLISHED | \
   RULE_FLAG_STATE_RELATED | \
   RULE_FLAG_STATE_INVALID | \
   RULE_FLAG_STATE_NONE)

void virNWFilterPrintStateMatchFlags(virBufferPtr buf, const char *prefix,
                                     int32_t flags, bool disp_none);

typedef int32_t virNWFilterRulePriority;

typedef struct _virNWFilterRuleDef  virNWFilterRuleDef;
typedef virNWFilterRuleDef *virNWFilterRuleDefPtr;
struct _virNWFilterRuleDef {
    virNWFilterRulePriority priority;
    virNWFilterRuleFlags flags;
    int action; /* virNWFilterRuleActionType */
    int tt; /* virNWFilterRuleDirectionType */
    virNWFilterRuleProtocolType prtclType;
    union {
        ethHdrFilterDef  ethHdrFilter;
        vlanHdrFilterDef vlanHdrFilter;
        stpHdrFilterDef stpHdrFilter;
        arpHdrFilterDef  arpHdrFilter; /* also used for rarp */
        ipHdrFilterDef   ipHdrFilter;
        ipv6HdrFilterDef ipv6HdrFilter;
        tcpHdrFilterDef  tcpHdrFilter;
        icmpHdrFilterDef icmpHdrFilter;
        udpHdrFilterDef  udpHdrFilter;
        udpliteHdrFilterDef  udpliteHdrFilter;
        espHdrFilterDef  espHdrFilter;
        ahHdrFilterDef  ahHdrFilter;
        allHdrFilterDef  allHdrFilter;
        igmpHdrFilterDef igmpHdrFilter;
        sctpHdrFilterDef sctpHdrFilter;
    } p;

    size_t nVarAccess;
    virNWFilterVarAccessPtr *varAccess;

    size_t nstrings;
    char **strings;
};


typedef struct _virNWFilterIncludeDef virNWFilterIncludeDef;
typedef virNWFilterIncludeDef *virNWFilterIncludeDefPtr;
struct _virNWFilterIncludeDef {
    char *filterref;
    virNWFilterHashTablePtr params;
};


typedef struct _virNWFilterEntry virNWFilterEntry;
typedef virNWFilterEntry *virNWFilterEntryPtr;
struct _virNWFilterEntry {
    virNWFilterRuleDef    *rule;
    virNWFilterIncludeDef *include;
};

typedef enum {
    VIR_NWFILTER_CHAINSUFFIX_ROOT = 0,
    VIR_NWFILTER_CHAINSUFFIX_MAC,
    VIR_NWFILTER_CHAINSUFFIX_VLAN,
    VIR_NWFILTER_CHAINSUFFIX_STP,
    VIR_NWFILTER_CHAINSUFFIX_ARP,
    VIR_NWFILTER_CHAINSUFFIX_RARP,
    VIR_NWFILTER_CHAINSUFFIX_IPv4,
    VIR_NWFILTER_CHAINSUFFIX_IPv6,

    VIR_NWFILTER_CHAINSUFFIX_LAST,
} virNWFilterChainSuffixType;

# define VALID_CHAINNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"

typedef int32_t virNWFilterChainPriority;

typedef struct _virNWFilterDef virNWFilterDef;
typedef virNWFilterDef *virNWFilterDefPtr;

struct _virNWFilterDef {
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    bool uuid_specified;

    char *chainsuffix;
    virNWFilterChainPriority chainPriority;

    size_t nentries;
    virNWFilterEntryPtr *filterEntries;
};


typedef enum {
    STEP_APPLY_NEW,
    STEP_TEAR_NEW,
    STEP_TEAR_OLD,
    STEP_APPLY_CURRENT,
} UpdateStep;

struct domUpdateCBStruct {
    void *opaque;
    UpdateStep step;
    virHashTablePtr skipInterfaces;
};


void
virNWFilterRuleDefFree(virNWFilterRuleDefPtr def);

void
virNWFilterDefFree(virNWFilterDefPtr def);

int
virNWFilterTriggerVMFilterRebuild(void);

int
virNWFilterDeleteDef(const char *configDir,
                     virNWFilterDefPtr def);

virNWFilterDefPtr
virNWFilterDefParseNode(xmlDocPtr xml,
                        xmlNodePtr root);

char *
virNWFilterDefFormat(const virNWFilterDef *def);

int
virNWFilterSaveConfig(const char *configDir,
                      virNWFilterDefPtr def);

virNWFilterDefPtr
virNWFilterDefParseString(const char *xml);

virNWFilterDefPtr
virNWFilterDefParseFile(const char *filename);

void
virNWFilterWriteLockFilterUpdates(void);

void
virNWFilterReadLockFilterUpdates(void);

void
virNWFilterUnlockFilterUpdates(void);

int
virNWFilterConfLayerInit(virDomainObjListIterator domUpdateCB,
                         void *opaque);

void
virNWFilterConfLayerShutdown(void);

int
virNWFilterInstFiltersOnAllVMs(void);

typedef int
(*virNWFilterRebuild)(virDomainObjListIterator domUpdateCB,
                      void *data);

typedef void
(*virNWFilterVoidCall)(void);

typedef struct _virNWFilterCallbackDriver virNWFilterCallbackDriver;
typedef virNWFilterCallbackDriver *virNWFilterCallbackDriverPtr;
struct _virNWFilterCallbackDriver {
    const char *name;

    virNWFilterRebuild vmFilterRebuild;
    virNWFilterVoidCall vmDriverLock;
    virNWFilterVoidCall vmDriverUnlock;
};

void
virNWFilterRegisterCallbackDriver(virNWFilterCallbackDriverPtr);

void
virNWFilterUnRegisterCallbackDriver(virNWFilterCallbackDriverPtr);

void
virNWFilterCallbackDriversLock(void);

void
virNWFilterCallbackDriversUnlock(void);

char *
virNWFilterPrintTCPFlags(uint8_t flags);

bool
virNWFilterRuleIsProtocolIPv4(virNWFilterRuleDefPtr rule);

bool
virNWFilterRuleIsProtocolIPv6(virNWFilterRuleDefPtr rule);

bool
virNWFilterRuleIsProtocolEthernet(virNWFilterRuleDefPtr rule);

VIR_ENUM_DECL(virNWFilterRuleAction);
VIR_ENUM_DECL(virNWFilterRuleDirection);
VIR_ENUM_DECL(virNWFilterRuleProtocol);
VIR_ENUM_DECL(virNWFilterJumpTarget);
VIR_ENUM_DECL(virNWFilterChainPolicy);
VIR_ENUM_DECL(virNWFilterEbtablesTable);
VIR_ENUM_DECL(virNWFilterChainSuffix);

#endif /* NWFILTER_CONF_H */
