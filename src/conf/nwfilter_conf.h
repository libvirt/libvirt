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
# include "hash.h"
# include "xml.h"
# include "network.h"


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


# define HAS_ENTRY_ITEM(data) \
  (((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_EXISTS)

# define ENTRY_GET_NEG_SIGN(data) \
  ((((data)->flags) & NWFILTER_ENTRY_ITEM_FLAG_IS_NEG) ? "!" : "")

// datatypes appearing in rule attributes
enum attrDatatype {
    DATATYPE_UINT16           = (1 << 0),
    DATATYPE_UINT8            = (1 << 1),
    DATATYPE_MACADDR          = (1 << 2),
    DATATYPE_MACMASK          = (1 << 3),
    DATATYPE_IPADDR           = (1 << 4),
    DATATYPE_IPMASK           = (1 << 5),
    DATATYPE_STRING           = (1 << 6),
    DATATYPE_IPV6ADDR         = (1 << 7),
    DATATYPE_IPV6MASK         = (1 << 8),

    DATATYPE_LAST             = (1 << 9),
};


typedef struct _nwMACAddress nwMACAddress;
typedef nwMACAddress *nwMACAddressPtr;
struct _nwMACAddress {
    unsigned char addr[6];
};


typedef struct _nwIPAddress nwIPAddress;
typedef nwIPAddress *nwIPAddressPtr;
struct _nwIPAddress {
    virSocketAddr addr;
};


typedef struct _nwItemDesc nwItemDesc;
typedef nwItemDesc *nwItemDescPtr;
struct _nwItemDesc {
    enum virNWFilterEntryItemFlags flags;
    char *var;
    enum attrDatatype datatype;
    union {
        nwMACAddress macaddr;
        nwIPAddress  ipaddr;
        uint8_t      u8;
        uint16_t     u16;
        char         protocolID[10];
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
    VIR_NWFILTER_RULE_PROTOCOL_ARP,
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


# define MAX_RULE_PRIORITY  1000


typedef struct _virNWFilterRuleDef  virNWFilterRuleDef;
typedef virNWFilterRuleDef *virNWFilterRuleDefPtr;
struct _virNWFilterRuleDef {
    unsigned int priority;
    int action; /*enum virNWFilterRuleActionType*/
    int tt; /*enum virNWFilterRuleDirectionType*/
    enum virNWFilterRuleProtocolType prtclType;
    union {
        ethHdrFilterDef  ethHdrFilter;
        arpHdrFilterDef  arpHdrFilter;
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

    int nvars;
    char **vars;
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
    VIR_NWFILTER_CHAINSUFFIX_ARP,
    VIR_NWFILTER_CHAINSUFFIX_IPv4,
    VIR_NWFILTER_CHAINSUFFIX_IPv6,

    VIR_NWFILTER_CHAINSUFFIX_LAST,
};


typedef struct _virNWFilterDef virNWFilterDef;
typedef virNWFilterDef *virNWFilterDefPtr;

struct _virNWFilterDef {
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];

    int chainsuffix; /*enum virNWFilterChainSuffixType */

    int nentries;
    virNWFilterEntryPtr *filterEntries;
};


typedef struct _virNWFilterPoolObj virNWFilterPoolObj;
typedef virNWFilterPoolObj *virNWFilterPoolObjPtr;

struct _virNWFilterPoolObj {
    virMutex lock;

    char *configFile;
    int active;
    int wantRemoved;

    virNWFilterDefPtr def;
    virNWFilterDefPtr newDef;
};


typedef struct _virNWFilterPoolObjList virNWFilterPoolObjList;
typedef virNWFilterPoolObjList *virNWFilterPoolObjListPtr;
struct _virNWFilterPoolObjList {
    unsigned int count;
    virNWFilterPoolObjPtr *objs;
};


typedef struct _virNWFilterDriverState virNWFilterDriverState;
typedef virNWFilterDriverState *virNWFilterDriverStatePtr;
struct _virNWFilterDriverState {
    virMutex lock;

    virNWFilterPoolObjList pools;

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
};

struct domUpdateCBStruct {
    virConnectPtr conn;
    enum UpdateStep step;
    int err;
};


enum virDomainNetType;

typedef int (*virNWFilterRuleCreateInstance)(virConnectPtr conn,
                                             enum virDomainNetType nettype,
                                             virNWFilterDefPtr filter,
                                             virNWFilterRuleDefPtr rule,
                                             const char *ifname,
                                             virNWFilterHashTablePtr vars,
                                             virNWFilterRuleInstPtr res);

typedef int (*virNWFilterRuleApplyNewRules)(virConnectPtr conn,
                                            const char *ifname,
                                            int nruleInstances,
                                            void **_inst);

typedef int (*virNWFilterRuleTeardownNewRules)(virConnectPtr conn,
                                               const char *ifname);

typedef int (*virNWFilterRuleTeardownOldRules)(virConnectPtr conn,
                                               const char *ifname);

typedef int (*virNWFilterRuleRemoveRules)(virConnectPtr conn,
                                          const char *ifname,
                                          int nruleInstances,
                                          void **_inst);

typedef int (*virNWFilterRuleAllTeardown)(const char *ifname);

typedef int (*virNWFilterRuleFreeInstanceData)(void * _inst);

typedef int (*virNWFilterRuleDisplayInstanceData)(virConnectPtr conn,
                                                  void *_inst);


struct _virNWFilterTechDriver {
    const char *name;

    virNWFilterRuleCreateInstance createRuleInstance;
    virNWFilterRuleApplyNewRules applyNewRules;
    virNWFilterRuleTeardownNewRules tearNewRules;
    virNWFilterRuleTeardownOldRules tearOldRules;
    virNWFilterRuleRemoveRules removeRules;
    virNWFilterRuleAllTeardown allTeardown;
    virNWFilterRuleFreeInstanceData freeRuleInstance;
    virNWFilterRuleDisplayInstanceData displayRuleInstance;
};



void virNWFilterRuleDefFree(virNWFilterRuleDefPtr def);

void virNWFilterDefFree(virNWFilterDefPtr def);
void virNWFilterPoolObjListFree(virNWFilterPoolObjListPtr pools);
void virNWFilterPoolObjRemove(virNWFilterPoolObjListPtr pools,
                              virNWFilterPoolObjPtr pool);

void virNWFilterPoolObjFree(virNWFilterPoolObjPtr obj);

virNWFilterPoolObjPtr
        virNWFilterPoolObjFindByUUID(virNWFilterPoolObjListPtr pools,
                                     const unsigned char *uuid);

virNWFilterPoolObjPtr
        virNWFilterPoolObjFindByName(virNWFilterPoolObjListPtr pools,
                                     const char *name);


int virNWFilterPoolObjSaveDef(virNWFilterDriverStatePtr driver,
                              virNWFilterPoolObjPtr pool,
                              virNWFilterDefPtr def);

int virNWFilterPoolObjDeleteDef(virNWFilterPoolObjPtr pool);

virNWFilterPoolObjPtr virNWFilterPoolObjAssignDef(virConnectPtr conn,
                                                  virNWFilterPoolObjListPtr pools,
                                                  virNWFilterDefPtr def);

int virNWFilterTestUnassignDef(virConnectPtr conn,
                               virNWFilterPoolObjPtr pool);

virNWFilterDefPtr virNWFilterDefParseNode(xmlDocPtr xml,
                                          xmlNodePtr root);

char *virNWFilterDefFormat(virNWFilterDefPtr def);

int virNWFilterSaveXML(const char *configDir,
                       virNWFilterDefPtr def,
                       const char *xml);

int virNWFilterSaveConfig(const char *configDir,
                          virNWFilterDefPtr def);

int virNWFilterPoolLoadAllConfigs(virConnectPtr conn,
                                  virNWFilterPoolObjListPtr pools,
                                  const char *configDir);

char *virNWFilterConfigFile(const char *dir,
                            const char *name);

virNWFilterDefPtr virNWFilterDefParseString(virConnectPtr conn,
                                            const char *xml);
virNWFilterDefPtr virNWFilterDefParseFile(virConnectPtr conn,
                                          const char *filename);

void virNWFilterPoolObjLock(virNWFilterPoolObjPtr obj);
void virNWFilterPoolObjUnlock(virNWFilterPoolObjPtr obj);

void virNWFilterLockFilterUpdates(void);
void virNWFilterUnlockFilterUpdates(void);

int virNWFilterConfLayerInit(virHashIterator domUpdateCB);
void virNWFilterConfLayerShutdown(void);

# define virNWFilterReportError(code, fmt...)				\
        virReportErrorHelper(NULL, VIR_FROM_NWFILTER, code, __FILE__,	\
                               __FUNCTION__, __LINE__, fmt)


typedef int (*virNWFilterRebuild)(virConnectPtr conn,
                                  virHashIterator, void *data);

typedef struct _virNWFilterCallbackDriver virNWFilterCallbackDriver;
typedef virNWFilterCallbackDriver *virNWFilterCallbackDriverPtr;
struct _virNWFilterCallbackDriver {
    const char *name;

    virNWFilterRebuild vmFilterRebuild;
};

void virNWFilterRegisterCallbackDriver(virNWFilterCallbackDriverPtr);


VIR_ENUM_DECL(virNWFilterRuleAction);
VIR_ENUM_DECL(virNWFilterRuleDirection);
VIR_ENUM_DECL(virNWFilterRuleProtocol);
VIR_ENUM_DECL(virNWFilterJumpTarget);
VIR_ENUM_DECL(virNWFilterChainPolicy);
VIR_ENUM_DECL(virNWFilterEbtablesTable);
VIR_ENUM_DECL(virNWFilterChainSuffix);

#endif /* NWFILTER_CONF_H */
