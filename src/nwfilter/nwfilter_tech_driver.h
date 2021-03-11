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

typedef struct _virNWFilterTechDriver virNWFilterTechDriver;


typedef struct _virNWFilterRuleInst virNWFilterRuleInst;
struct _virNWFilterRuleInst {
    const char *chainSuffix;
    virNWFilterChainPriority chainPriority;
    virNWFilterRuleDef *def;
    virNWFilterRulePriority priority;
    GHashTable *vars;
};


typedef int (*virNWFilterTechDrvInit)(bool privileged);
typedef void (*virNWFilterTechDrvShutdown)(void);

typedef int (*virNWFilterRuleApplyNewRules)(const char *ifname,
                                            virNWFilterRuleInst **rules,
                                            size_t nrules);

typedef int (*virNWFilterRuleTeardownNewRules)(const char *ifname);

typedef int (*virNWFilterRuleTeardownOldRules)(const char *ifname);

typedef int (*virNWFilterRuleAllTeardown)(const char *ifname);

typedef int (*virNWFilterCanApplyBasicRules)(void);

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
