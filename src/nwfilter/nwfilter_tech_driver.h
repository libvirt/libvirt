/*
 * nwfilter_tech_driver.h: network filter technology driver interface
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 */

#pragma once

#include "virnwfilterobj.h"

typedef struct _virNWFilterRuleInst virNWFilterRuleInst;
struct _virNWFilterRuleInst {
    const char *chainSuffix;
    virNWFilterChainPriority chainPriority;
    virNWFilterRuleDef *def;
    virNWFilterRulePriority priority;
    GHashTable *vars;
};


typedef struct _virNWFilterChainCreateCallbackData virNWFilterChainCreateCallbackData;
struct _virNWFilterChainCreateCallbackData {
    const char *ifname;
    int nrules;
    virNWFilterRuleInst **rules;
};

struct virNWFilterUShortMap {
    unsigned short attr;
    const char *val;
};

enum virNWFilterProtoIdx {
    VIR_NWFILTER_PROTO_IDX_IPV4 = 0,
    VIR_NWFILTER_PROTO_IDX_IPV6,
    VIR_NWFILTER_PROTO_IDX_ARP,
    VIR_NWFILTER_PROTO_IDX_RARP,
    VIR_NWFILTER_PROTO_IDX_MAC,
    VIR_NWFILTER_PROTO_IDX_VLAN,
    VIR_NWFILTER_PROTO_IDX_STP,
    VIR_NWFILTER_PROTO_IDX_LAST
};

#define virNWFilterUShortMapEntryIdx(IDX, ATT, VAL) [IDX] = { .attr = ATT, .val = VAL }

typedef int (*virNWFilterTechDrvInit)(bool privileged);
typedef void (*virNWFilterTechDrvShutdown)(void);

typedef int (*virNWFilterRuleApplyNewRules)(const char *ifname,
                                            virNWFilterRuleInst **rules,
                                            size_t nrules);

typedef int (*virNWFilterRuleTeardownNewRules)(const char *ifname);

typedef int (*virNWFilterRuleTeardownOldRules)(const char *ifname);

typedef int (*virNWFilterRuleAllTeardown)(const char *ifname);

typedef bool (*virNWFilterCanApplyBasicRules)(void);

typedef int (*virNWFilterApplyBasicRules)(const char *ifname,
                                          const virMacAddr *macaddr);

typedef int (*virNWFilterApplyDHCPOnlyRules)(const char *ifname,
                                             const virMacAddr *macaddr,
                                             virNWFilterVarValue *dhcpsrvs,
                                             bool leaveTemporary);

typedef int (*virNWFilterRemoveBasicRules)(const char *ifname);

typedef int (*virNWFilterDropAllRules)(const char *ifname);

enum techDrvFlags {
    TECHDRV_FLAG_INITIALIZED = (1 << 0),
};

typedef struct _virNWFilterTechDriver virNWFilterTechDriver;
struct _virNWFilterTechDriver {
    const char *name;
    enum techDrvFlags flags;

    virNWFilterTechDrvInit init;
    virNWFilterTechDrvShutdown shutdown;

    virNWFilterRuleApplyNewRules applyNewRules;
    virNWFilterRuleTeardownNewRules tearNewRules;
    virNWFilterRuleTeardownOldRules tearOldRules;
    virNWFilterRuleAllTeardown allTeardown;

    virNWFilterCanApplyBasicRules canApplyBasicRules;
    virNWFilterApplyBasicRules applyBasicRules;
    virNWFilterApplyDHCPOnlyRules applyDHCPOnlyRules;
    virNWFilterDropAllRules applyDropAllRules;
    virNWFilterRemoveBasicRules removeBasicRules;
};

int virNWFilterRuleInstSort(const void *a, const void *b);

int virNWFilterRuleInstSortPtr(const void *a,
                           const void *b,
                           void *opaque);
int virNWFilterPrintVar(virNWFilterVarCombIter *vars,
                        char *buf, int bufsize,
                        nwItemDesc *item,
                        bool *done);

int virNWFilterPrintDataType(virNWFilterVarCombIter *vars,
                             char *buf, int bufsize,
                             nwItemDesc *item);

int virNWFilterPrintDataTypeDirection(virNWFilterVarCombIter *vars,
                                      char *buf, int bufsize,
                                      nwItemDesc *item, bool directionIn);

int virNWFilterPrintDataTypeAsHex(virNWFilterVarCombIter *vars,
                                  char *buf, int bufsize,
                                  nwItemDesc *item);
