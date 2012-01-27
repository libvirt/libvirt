/*
 * nwfilter_conf.h: network filter XML processing
 *                  (derived from storage_conf.h)
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef NWFILTER_CONF_H
# define NWFILTER_CONF_H

# include <stdint.h>
# include <stddef.h>

# include "internal.h"

# include "util.h"
# include "virhash.h"
# include "xml.h"
# include "buf.h"
# include "virsocketaddr.h"

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


enum virNWFilterEntryItemFlags {
    NWFILTER_ENTRY_ITEM_FLAG_EXISTS   = 1 << 0,
    NWFILTER_ENTRY_ITEM_FLAG_IS_NEG   = 1 << 1,
    NWFILTER_ENTRY_ITEM_FLAG_HAS_VAR  = 1 << 2,
};


# define MAX_COMMENT_LENGTH  256

# define HAS_ENTRY_ITEM(data) \
  (((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_EXISTS)

# define ENTRY_GET_NEG_SIGN(data) \
  ((((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_IS_NEG) ? "!" : "")

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

    DATATYPE_LAST             = (1 << 15),
};

# define NWFILTER_MAC_BGA "01:80:c2:00:00:00"


typedef struct _nwMACAddress nwMACAddress;
typedef nwMACAddress *nwMACAddressPtr;
struct _nwMACAddress {
    unsigned char addr[6];
};


typedef struct _nwItemDesc nwItemDesc;
typedef nwItemDesc *nwItemDescPtr;
struct _nwItemDesc {
    enum virNWFilterEntryItemFlags flags;
    virNWFilterVarAccessPtr varAccess;
    enum attrDatatype datatype;
    union {
        nwMACAddress macaddr;
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
    } u;
};


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
    nwItemDesc dataARPDstMACAddr;
    nwItemDesc dataARPDstIPAddr;
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


enum virNWFilterRuleActionType {
    VIR_NWFILTER_RULE_ACTION_DROP = 0,
    VIR_NWFILTER_RULE_ACTION_ACCEPT,
    VIR_NWFILTER_RULE_ACTION_REJECT,
    VIR_NWFILTER_RULE_ACTION_RETURN,
    VIR_NWFILTER_RULE_ACTION_CONTINUE,

    VIR_NWFILTER_RULE_ACTION_LAST,
};

enum virNWFilterRuleDirectionType {
    VIR_NWFILTER_RULE_DIRECTION_IN = 0,
    VIR_NWFILTER_RULE_DIRECTION_OUT,
    VIR_NWFILTER_RULE_DIRECTION_INOUT,

    VIR_NWFILTER_RULE_DIRECTION_LAST,
};

enum virNWFilterChainPolicyType {
    VIR_NWFILTER_CHAIN_POLICY_ACCEPT = 0,
    VIR_NWFILTER_CHAIN_POLICY_DROP,

    VIR_NWFILTER_CHAIN_POLICY_LAST,
};

enum virNWFilterRuleProtocolType {
    VIR_NWFILTER_RULE_PROTOCOL_NONE = 0,
    VIR_NWFILTER_RULE_PROTOCOL_MAC,
    VIR_NWFILTER_RULE_PROTOCOL_VLAN,
    VIR_NWFILTER_RULE_PROTOCOL_STP,
    VIR_NWFILTER_RULE_PROTOCOL_ARP,
    VIR_NWFILTER_RULE_PROTOCOL_RARP,
    VIR_NWFILTER_RULE_PROTOCOL_IP,
    VIR_NWFILTER_RULE_PROTOCOL_IPV6,
    VIR_NWFILTER_RULE_PROTOCOL_TCP,
    VIR_NWFILTER_RULE_PROTOCOL_ICMP,
    VIR_NWFILTER_RULE_PROTOCOL_IGMP,
    VIR_NWFILTER_RULE_PROTOCOL_UDP,
    VIR_NWFILTER_RULE_PROTOCOL_UDPLITE,
    VIR_NWFILTER_RULE_PROTOCOL_ESP,
    VIR_NWFILTER_RULE_PROTOCOL_AH,
    VIR_NWFILTER_RULE_PROTOCOL_SCTP,
    VIR_NWFILTER_RULE_PROTOCOL_ALL,
    VIR_NWFILTER_RULE_PROTOCOL_TCPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ICMPV6,
    VIR_NWFILTER_RULE_PROTOCOL_UDPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_UDPLITEoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ESPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_AHoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_SCTPoIPV6,
    VIR_NWFILTER_RULE_PROTOCOL_ALLoIPV6,

    VIR_NWFILTER_RULE_PROTOCOL_LAST
};

enum virNWFilterEbtablesTableType {
    VIR_NWFILTER_EBTABLES_TABLE_FILTER = 0,
    VIR_NWFILTER_EBTABLES_TABLE_NAT,
    VIR_NWFILTER_EBTABLES_TABLE_BROUTE,

    VIR_NWFILTER_EBTABLES_TABLE_LAST,
};


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

enum virNWFilterRuleFlags {
    RULE_FLAG_NO_STATEMATCH      = (1 << 0),
    RULE_FLAG_STATE_NEW          = (1 << 1),
    RULE_FLAG_STATE_ESTABLISHED  = (1 << 2),
    RULE_FLAG_STATE_RELATED      = (1 << 3),
    RULE_FLAG_STATE_INVALID      = (1 << 4),
    RULE_FLAG_STATE_NONE         = (1 << 5),
};


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
    enum virNWFilterRuleFlags flags;
    int action; /*enum virNWFilterRuleActionType*/
    int tt; /*enum virNWFilterRuleDirectionType*/
    enum virNWFilterRuleProtocolType prtclType;
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

    int nstrings;
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

enum virNWFilterChainSuffixType {
    VIR_NWFILTER_CHAINSUFFIX_ROOT = 0,
    VIR_NWFILTER_CHAINSUFFIX_MAC,
    VIR_NWFILTER_CHAINSUFFIX_VLAN,
    VIR_NWFILTER_CHAINSUFFIX_STP,
    VIR_NWFILTER_CHAINSUFFIX_ARP,
    VIR_NWFILTER_CHAINSUFFIX_RARP,
    VIR_NWFILTER_CHAINSUFFIX_IPv4,
    VIR_NWFILTER_CHAINSUFFIX_IPv6,

    VIR_NWFILTER_CHAINSUFFIX_LAST,
};

# define VALID_CHAINNAME \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"

typedef int32_t virNWFilterChainPriority;

typedef struct _virNWFilterDef virNWFilterDef;
typedef virNWFilterDef *virNWFilterDefPtr;

struct _virNWFilterDef {
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];

    char *chainsuffix;
    virNWFilterChainPriority chainPriority;

    int nentries;
    virNWFilterEntryPtr *filterEntries;
};


typedef struct _virNWFilterObj virNWFilterObj;
typedef virNWFilterObj *virNWFilterObjPtr;

struct _virNWFilterObj {
    virMutex lock;

    char *configFile;
    int active;
    int wantRemoved;

    virNWFilterDefPtr def;
    virNWFilterDefPtr newDef;
};


typedef struct _virNWFilterObjList virNWFilterObjList;
typedef virNWFilterObjList *virNWFilterObjListPtr;
struct _virNWFilterObjList {
    unsigned int count;
    virNWFilterObjPtr *objs;
};


typedef struct _virNWFilterDriverState virNWFilterDriverState;
typedef virNWFilterDriverState *virNWFilterDriverStatePtr;
struct _virNWFilterDriverState {
    virMutex lock;

    virNWFilterObjList nwfilters;

    char *configDir;
};


typedef struct _virNWFilterTechDriver virNWFilterTechDriver;
typedef virNWFilterTechDriver *virNWFilterTechDriverPtr;


typedef struct _virNWFilterRuleInst virNWFilterRuleInst;
typedef virNWFilterRuleInst *virNWFilterRuleInstPtr;
struct _virNWFilterRuleInst {
   int ndata;
   void **data;
   virNWFilterTechDriverPtr techdriver;
};


enum UpdateStep {
    STEP_APPLY_NEW,
    STEP_TEAR_NEW,
    STEP_TEAR_OLD,
    STEP_APPLY_CURRENT,
};

struct domUpdateCBStruct {
    virConnectPtr conn;
    enum UpdateStep step;
    int err;
    virHashTablePtr skipInterfaces;
};


typedef int (*virNWFilterTechDrvInit)(bool privileged);
typedef void (*virNWFilterTechDrvShutdown)(void);

enum virDomainNetType;

typedef int (*virNWFilterRuleCreateInstance)(enum virDomainNetType nettype,
                                             virNWFilterDefPtr filter,
                                             virNWFilterRuleDefPtr rule,
                                             const char *ifname,
                                             virNWFilterHashTablePtr vars,
                                             virNWFilterRuleInstPtr res);

typedef int (*virNWFilterRuleApplyNewRules)(const char *ifname,
                                            int nruleInstances,
                                            void **_inst);

typedef int (*virNWFilterRuleTeardownNewRules)(const char *ifname);

typedef int (*virNWFilterRuleTeardownOldRules)(const char *ifname);

typedef int (*virNWFilterRuleRemoveRules)(const char *ifname,
                                          int nruleInstances,
                                          void **_inst);

typedef int (*virNWFilterRuleAllTeardown)(const char *ifname);

typedef int (*virNWFilterRuleFreeInstanceData)(void * _inst);

typedef int (*virNWFilterRuleDisplayInstanceData)(void *_inst);

typedef int (*virNWFilterCanApplyBasicRules)(void);

typedef int (*virNWFilterApplyBasicRules)(const char *ifname,
                                          const unsigned char *macaddr);

typedef int (*virNWFilterApplyDHCPOnlyRules)(const char *ifname,
                                             const unsigned char *macaddr,
                                             const char *dhcpserver,
                                             bool leaveTemporary);

typedef int (*virNWFilterRemoveBasicRules)(const char *ifname);

typedef int (*virNWFilterDropAllRules)(const char *ifname);

enum techDrvFlags {
    TECHDRV_FLAG_INITIALIZED = (1 << 0),
};

struct _virNWFilterTechDriver {
    const char *name;
    enum techDrvFlags flags;

    virNWFilterTechDrvInit init;
    virNWFilterTechDrvShutdown shutdown;

    virNWFilterRuleCreateInstance createRuleInstance;
    virNWFilterRuleApplyNewRules applyNewRules;
    virNWFilterRuleTeardownNewRules tearNewRules;
    virNWFilterRuleTeardownOldRules tearOldRules;
    virNWFilterRuleRemoveRules removeRules;
    virNWFilterRuleAllTeardown allTeardown;
    virNWFilterRuleFreeInstanceData freeRuleInstance;
    virNWFilterRuleDisplayInstanceData displayRuleInstance;

    virNWFilterCanApplyBasicRules canApplyBasicRules;
    virNWFilterApplyBasicRules applyBasicRules;
    virNWFilterApplyDHCPOnlyRules applyDHCPOnlyRules;
    virNWFilterDropAllRules applyDropAllRules;
    virNWFilterRemoveBasicRules removeBasicRules;
};



void virNWFilterRuleDefFree(virNWFilterRuleDefPtr def);

void virNWFilterDefFree(virNWFilterDefPtr def);
void virNWFilterObjListFree(virNWFilterObjListPtr nwfilters);
void virNWFilterObjRemove(virNWFilterObjListPtr nwfilters,
                          virNWFilterObjPtr nwfilter);

void virNWFilterObjFree(virNWFilterObjPtr obj);

virNWFilterObjPtr virNWFilterObjFindByUUID(virNWFilterObjListPtr nwfilters,
                                           const unsigned char *uuid);

virNWFilterObjPtr virNWFilterObjFindByName(virNWFilterObjListPtr nwfilters,
                                           const char *name);


int virNWFilterObjSaveDef(virNWFilterDriverStatePtr driver,
                          virNWFilterObjPtr nwfilter,
                          virNWFilterDefPtr def);

int virNWFilterObjDeleteDef(virNWFilterObjPtr nwfilter);

virNWFilterObjPtr virNWFilterObjAssignDef(virConnectPtr conn,
                                          virNWFilterObjListPtr nwfilters,
                                          virNWFilterDefPtr def);

int virNWFilterTestUnassignDef(virConnectPtr conn,
                               virNWFilterObjPtr nwfilter);

virNWFilterDefPtr virNWFilterDefParseNode(xmlDocPtr xml,
                                          xmlNodePtr root);

char *virNWFilterDefFormat(virNWFilterDefPtr def);

int virNWFilterSaveXML(const char *configDir,
                       virNWFilterDefPtr def,
                       const char *xml);

int virNWFilterSaveConfig(const char *configDir,
                          virNWFilterDefPtr def);

int virNWFilterLoadAllConfigs(virConnectPtr conn,
                              virNWFilterObjListPtr nwfilters,
                              const char *configDir);

char *virNWFilterConfigFile(const char *dir,
                            const char *name);

virNWFilterDefPtr virNWFilterDefParseString(virConnectPtr conn,
                                            const char *xml);
virNWFilterDefPtr virNWFilterDefParseFile(virConnectPtr conn,
                                          const char *filename);

void virNWFilterObjLock(virNWFilterObjPtr obj);
void virNWFilterObjUnlock(virNWFilterObjPtr obj);

void virNWFilterLockFilterUpdates(void);
void virNWFilterUnlockFilterUpdates(void);

int virNWFilterConfLayerInit(virHashIterator domUpdateCB);
void virNWFilterConfLayerShutdown(void);

int virNWFilterInstFiltersOnAllVMs(virConnectPtr conn);

# define virNWFilterReportError(code, fmt...)                      \
        virReportErrorHelper(VIR_FROM_NWFILTER, code, __FILE__,    \
                             __FUNCTION__, __LINE__, fmt)


typedef int (*virNWFilterRebuild)(virConnectPtr conn,
                                  virHashIterator, void *data);
typedef void (*virNWFilterVoidCall)(void);


typedef struct _virNWFilterCallbackDriver virNWFilterCallbackDriver;
typedef virNWFilterCallbackDriver *virNWFilterCallbackDriverPtr;
struct _virNWFilterCallbackDriver {
    const char *name;

    virNWFilterRebuild vmFilterRebuild;
    virNWFilterVoidCall vmDriverLock;
    virNWFilterVoidCall vmDriverUnlock;
};

void virNWFilterRegisterCallbackDriver(virNWFilterCallbackDriverPtr);
void virNWFilterCallbackDriversLock(void);
void virNWFilterCallbackDriversUnlock(void);


void virNWFilterPrintTCPFlags(virBufferPtr buf, uint8_t mask,
                              char sep, uint8_t flags);


VIR_ENUM_DECL(virNWFilterRuleAction);
VIR_ENUM_DECL(virNWFilterRuleDirection);
VIR_ENUM_DECL(virNWFilterRuleProtocol);
VIR_ENUM_DECL(virNWFilterJumpTarget);
VIR_ENUM_DECL(virNWFilterChainPolicy);
VIR_ENUM_DECL(virNWFilterEbtablesTable);
VIR_ENUM_DECL(virNWFilterChainSuffix);

#endif /* NWFILTER_CONF_H */
