/*
 * virebtables.c: Helper APIs for managing ebtables
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
 * Copyright (C) 2009 IBM Corp.
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

#include <config.h>

#include "internal.h"
#include "virebtables.h"
#include "virlog.h"
#include "virfirewall.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.ebtables");

struct _ebtablesContext
{
    char *chain;
};

enum {
    ADD = 0,
    REMOVE,
};

/**
 * ebtablesContextNew:
 *
 * Create a new ebtable context
 *
 * Returns a pointer to the new structure or NULL in case of error
 */
ebtablesContext *
ebtablesContextNew(const char *driver)
{
    ebtablesContext *ctx = NULL;

    ctx = g_new0(ebtablesContext, 1);

    ctx->chain = g_strdup_printf("libvirt_%s_FORWARD", driver);

    return ctx;
}

/**
 * ebtablesContextFree:
 * @ctx: pointer to the EB table context
 *
 * Free the resources associated with an EB table context
 */
void
ebtablesContextFree(ebtablesContext *ctx)
{
    if (!ctx)
        return;
    g_free(ctx->chain);
    g_free(ctx);
}


int
ebtablesAddForwardPolicyReject(ebtablesContext *ctx)
{
    g_autoptr(virFirewall) fw = virFirewallNew();

    virFirewallStartTransaction(fw, VIR_FIREWALL_TRANSACTION_IGNORE_ERRORS);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "--new-chain", ctx->chain,
                       NULL);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "--insert", "FORWARD",
                       "--jump", ctx->chain, NULL);

    virFirewallStartTransaction(fw, 0);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       "-P", ctx->chain, "DROP",
                       NULL);

    return virFirewallApply(fw);
}


/*
 * Allow all traffic destined to the bridge, with a valid network address
 */
static int
ebtablesForwardAllowIn(ebtablesContext *ctx,
                       const char *iface,
                       const char *macaddr,
                       int action)
{
    g_autoptr(virFirewall) fw = virFirewallNew();

    virFirewallStartTransaction(fw, 0);
    virFirewallAddRule(fw, VIR_FIREWALL_LAYER_ETHERNET,
                       action == ADD ? "--insert" : "--delete",
                       ctx->chain,
                       "--in-interface", iface,
                       "--source", macaddr,
                       "--jump", "ACCEPT",
                       NULL);

    return virFirewallApply(fw);
}

/**
 * ebtablesAddForwardAllowIn:
 * @ctx: pointer to the EB table context
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Add rules to the EB table context to allow the traffic on
 * @physdev device to be forwarded to interface @iface. This allows
 * the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
ebtablesAddForwardAllowIn(ebtablesContext *ctx,
                          const char *iface,
                          const virMacAddr *mac)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);
    return ebtablesForwardAllowIn(ctx, iface, macaddr, ADD);
}

/**
 * ebtablesRemoveForwardAllowIn:
 * @ctx: pointer to the EB table context
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Remove rules from the EB table context hence forbidding the traffic
 * on the @physdev device to be forwarded to interface @iface. This
 * stops the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
ebtablesRemoveForwardAllowIn(ebtablesContext *ctx,
                             const char *iface,
                             const virMacAddr *mac)
{
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(mac, macaddr);
    return ebtablesForwardAllowIn(ctx, iface, macaddr, REMOVE);
}
