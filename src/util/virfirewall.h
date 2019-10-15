 /*
 * virfirewall.h: integration with firewalls
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include "internal.h"

typedef struct _virFirewall virFirewall;
typedef virFirewall *virFirewallPtr;

typedef struct _virFirewallRule virFirewallRule;
typedef virFirewallRule *virFirewallRulePtr;

typedef enum {
    VIR_FIREWALL_LAYER_ETHERNET,
    VIR_FIREWALL_LAYER_IPV4,
    VIR_FIREWALL_LAYER_IPV6,

    VIR_FIREWALL_LAYER_LAST,
} virFirewallLayer;

virFirewallPtr virFirewallNew(void);

void virFirewallFree(virFirewallPtr firewall);

/**
 * virFirewallAddRule:
 * @firewall: firewall ruleset to add to
 * @layer: the firewall layer to change
 * @...: NULL terminated list of strings for the rule
 *
 * Add any type of rule to the firewall ruleset.
 *
 * Returns the new rule
 */
#define virFirewallAddRule(firewall, layer, ...) \
         virFirewallAddRuleFull(firewall, layer, false, NULL, NULL, __VA_ARGS__)

typedef int (*virFirewallQueryCallback)(virFirewallPtr firewall,
                                        virFirewallLayer layer,
                                        const char *const *lines,
                                        void *opaque);

virFirewallRulePtr virFirewallAddRuleFull(virFirewallPtr firewall,
                                          virFirewallLayer layer,
                                          bool ignoreErrors,
                                          virFirewallQueryCallback cb,
                                          void *opaque,
                                          ...)
    G_GNUC_NULL_TERMINATED;

void virFirewallRemoveRule(virFirewallPtr firewall,
                           virFirewallRulePtr rule);

void virFirewallRuleAddArg(virFirewallPtr firewall,
                           virFirewallRulePtr rule,
                           const char *arg)
    ATTRIBUTE_NONNULL(3);

void virFirewallRuleAddArgFormat(virFirewallPtr firewall,
                                 virFirewallRulePtr rule,
                                 const char *fmt, ...)
    ATTRIBUTE_NONNULL(3) G_GNUC_PRINTF(3, 4);

void virFirewallRuleAddArgSet(virFirewallPtr firewall,
                              virFirewallRulePtr rule,
                              const char *const *args)
    ATTRIBUTE_NONNULL(3);

void virFirewallRuleAddArgList(virFirewallPtr firewall,
                               virFirewallRulePtr rule,
                               ...)
    G_GNUC_NULL_TERMINATED;

size_t virFirewallRuleGetArgCount(virFirewallRulePtr rule);

typedef enum {
    /* Ignore all errors when applying rules, so no
     * rollback block will be required */
    VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS = (1 << 0),
} virFirewallTransactionFlags;

void virFirewallStartTransaction(virFirewallPtr firewall,
                                 unsigned int flags);

typedef enum {
    /* Execute previous rollback block before this
     * one, to chain cleanup */
    VIR_FIREWALL_ROLLBACK_INHERIT_PREVIOUS = (1 << 0),
} virFirewallRollbackFlags;

void virFirewallStartRollback(virFirewallPtr firewall,
                              unsigned int flags);

int virFirewallApply(virFirewallPtr firewall);

void virFirewallSetLockOverride(bool avoid);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virFirewall, virFirewallFree);
