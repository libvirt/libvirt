/*
 * Copyright (C) 2007-2011 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#include "internal.h"
#include "iptables.h"
#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define iptablesError(code, ...)                                        \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

enum {
    ADD = 0,
    REMOVE
};

typedef struct
{
    char  *table;
    char  *chain;
} iptRules;

struct _iptablesContext
{
    iptRules *input_filter;
    iptRules *forward_filter;
    iptRules *nat_postrouting;
    iptRules *mangle_postrouting;
};

static void
iptRulesFree(iptRules *rules)
{
    VIR_FREE(rules->table);
    VIR_FREE(rules->chain);
    VIR_FREE(rules);
}

static iptRules *
iptRulesNew(const char *table,
            const char *chain)
{
    iptRules *rules;

    if (VIR_ALLOC(rules) < 0)
        return NULL;

    if (!(rules->table = strdup(table)))
        goto error;

    if (!(rules->chain = strdup(chain)))
        goto error;

    return rules;

 error:
    iptRulesFree(rules);
    return NULL;
}

static int ATTRIBUTE_SENTINEL
iptablesAddRemoveRule(iptRules *rules, int family, int action,
                      const char *arg, ...)
{
    va_list args;
    int ret;
    virCommandPtr cmd;
    const char *s;

    cmd = virCommandNew((family == AF_INET6)
                        ? IP6TABLES_PATH : IPTABLES_PATH);

    virCommandAddArgList(cmd, "--table", rules->table,
                         action == ADD ? "--insert" : "--delete",
                         rules->chain, arg, NULL);

    va_start(args, arg);
    while ((s = va_arg(args, const char *)))
        virCommandAddArg(cmd, s);
    va_end(args);

    ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    return ret;
}

/**
 * iptablesContextNew:
 *
 * Create a new IPtable context
 *
 * Returns a pointer to the new structure or NULL in case of error
 */
iptablesContext *
iptablesContextNew(void)
{
    iptablesContext *ctx;

    if (VIR_ALLOC(ctx) < 0)
        return NULL;

    if (!(ctx->input_filter = iptRulesNew("filter", "INPUT")))
        goto error;

    if (!(ctx->forward_filter = iptRulesNew("filter", "FORWARD")))
        goto error;

    if (!(ctx->nat_postrouting = iptRulesNew("nat", "POSTROUTING")))
        goto error;

    if (!(ctx->mangle_postrouting = iptRulesNew("mangle", "POSTROUTING")))
        goto error;

    return ctx;

 error:
    iptablesContextFree(ctx);
    return NULL;
}

/**
 * iptablesContextFree:
 * @ctx: pointer to the IP table context
 *
 * Free the resources associated with an IP table context
 */
void
iptablesContextFree(iptablesContext *ctx)
{
    if (ctx->input_filter)
        iptRulesFree(ctx->input_filter);
    if (ctx->forward_filter)
        iptRulesFree(ctx->forward_filter);
    if (ctx->nat_postrouting)
        iptRulesFree(ctx->nat_postrouting);
    if (ctx->mangle_postrouting)
        iptRulesFree(ctx->mangle_postrouting);
    VIR_FREE(ctx);
}

static int
iptablesInput(iptablesContext *ctx,
              int family,
              const char *iface,
              int port,
              int action,
              int tcp)
{
    char portstr[32];

    snprintf(portstr, sizeof(portstr), "%d", port);
    portstr[sizeof(portstr) - 1] = '\0';

    return iptablesAddRemoveRule(ctx->input_filter,
                                 family,
                                 action,
                                 "--in-interface", iface,
                                 "--protocol", tcp ? "tcp" : "udp",
                                 "--destination-port", portstr,
                                 "--jump", "ACCEPT",
                                 NULL);
}

/**
 * iptablesAddTcpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to add
 *
 * Add an input to the IP table allowing access to the given @port on
 * the given @iface interface for TCP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */

int
iptablesAddTcpInput(iptablesContext *ctx,
                    int family,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, family, iface, port, ADD, 1);
}

/**
 * iptablesRemoveTcpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the TCP port to remove
 *
 * Removes an input from the IP table, hence forbidding access to the given
 * @port on the given @iface interface for TCP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */
int
iptablesRemoveTcpInput(iptablesContext *ctx,
                       int family,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, family, iface, port, REMOVE, 1);
}

/**
 * iptablesAddUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to add
 *
 * Add an input to the IP table allowing access to the given @port on
 * the given @iface interface for UDP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */

int
iptablesAddUdpInput(iptablesContext *ctx,
                    int family,
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, family, iface, port, ADD, 0);
}

/**
 * iptablesRemoveUdpInput:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to remove
 *
 * Removes an input from the IP table, hence forbidding access to the given
 * @port on the given @iface interface for UDP packets
 *
 * Returns 0 in case of success or an error code in case of error
 */
int
iptablesRemoveUdpInput(iptablesContext *ctx,
                       int family,
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, family, iface, port, REMOVE, 0);
}


static char *iptablesFormatNetwork(virSocketAddr *netaddr,
                                   unsigned int prefix)
{
    virSocketAddr network;
    char *netstr;
    char *ret;

    if (!(VIR_SOCKET_ADDR_IS_FAMILY(netaddr, AF_INET) ||
          VIR_SOCKET_ADDR_IS_FAMILY(netaddr, AF_INET6))) {
        iptablesError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                      _("Only IPv4 or IPv6 addresses can be used with iptables"));
        return NULL;
    }

    if (virSocketAddrMaskByPrefix(netaddr, prefix, &network) < 0) {
        iptablesError(VIR_ERR_INTERNAL_ERROR, "%s",
                      _("Failure to mask address"));
        return NULL;
    }

    netstr = virSocketAddrFormat(&network);

    if (!netstr)
        return NULL;

    if (virAsprintf(&ret, "%s/%d", netstr, prefix) < 0)
        virReportOOMError();

    VIR_FREE(netstr);
    return ret;
}


/* Allow all traffic coming from the bridge, with a valid network address
 * to proceed to WAN
 */
static int
iptablesForwardAllowOut(iptablesContext *ctx,
                        virSocketAddr *netaddr,
                        unsigned int prefix,
                        const char *iface,
                        const char *physdev,
                        int action)
{
    int ret;
    char *networkstr;

    if (!(networkstr = iptablesFormatNetwork(netaddr, prefix)))
        return -1;

    if (physdev && physdev[0]) {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--source", networkstr,
                                    "--in-interface", iface,
                                    "--out-interface", physdev,
                                    "--jump", "ACCEPT",
                                    NULL);
    } else {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--source", networkstr,
                                    "--in-interface", iface,
                                    "--jump", "ACCEPT",
                                    NULL);
    }
    VIR_FREE(networkstr);
    return ret;
}

/**
 * iptablesAddForwardAllowOut:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the source interface name
 * @physdev: the physical output device
 *
 * Add a rule to the IP table context to allow the traffic for the
 * network @network via interface @iface to be forwarded to
 * @physdev device. This allow the outbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowOut(iptablesContext *ctx,
                           virSocketAddr *netaddr,
                           unsigned int prefix,
                           const char *iface,
                           const char *physdev)
{
    return iptablesForwardAllowOut(ctx, netaddr, prefix, iface, physdev, ADD);
}

/**
 * iptablesRemoveForwardAllowOut:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the source interface name
 * @physdev: the physical output device
 *
 * Remove a rule from the IP table context hence forbidding forwarding
 * of the traffic for the network @network via interface @iface
 * to the @physdev device output. This stops the outbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowOut(iptablesContext *ctx,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *iface,
                              const char *physdev)
{
    return iptablesForwardAllowOut(ctx, netaddr, prefix, iface, physdev, REMOVE);
}


/* Allow all traffic destined to the bridge, with a valid network address
 * and associated with an existing connection
 */
static int
iptablesForwardAllowRelatedIn(iptablesContext *ctx,
                              virSocketAddr *netaddr,
                              unsigned int prefix,
                              const char *iface,
                              const char *physdev,
                              int action)
{
    int ret;
    char *networkstr;

    if (!(networkstr = iptablesFormatNetwork(netaddr, prefix)))
        return -1;

    if (physdev && physdev[0]) {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--destination", networkstr,
                                    "--in-interface", physdev,
                                    "--out-interface", iface,
                                    "--match", "state",
                                    "--state", "ESTABLISHED,RELATED",
                                    "--jump", "ACCEPT",
                                    NULL);
    } else {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--destination", networkstr,
                                    "--out-interface", iface,
                                    "--match", "state",
                                    "--state", "ESTABLISHED,RELATED",
                                    "--jump", "ACCEPT",
                                    NULL);
    }
    VIR_FREE(networkstr);
    return ret;
}

/**
 * iptablesAddForwardAllowRelatedIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Add rules to the IP table context to allow the traffic for the
 * network @network on @physdev device to be forwarded to
 * interface @iface, if it is part of an existing connection.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowRelatedIn(iptablesContext *ctx,
                                 virSocketAddr *netaddr,
                                 unsigned int prefix,
                                 const char *iface,
                                 const char *physdev)
{
    return iptablesForwardAllowRelatedIn(ctx, netaddr, prefix, iface, physdev, ADD);
}

/**
 * iptablesRemoveForwardAllowRelatedIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Remove rules from the IP table context hence forbidding the traffic for
 * network @network on @physdev device to be forwarded to
 * interface @iface, if it is part of an existing connection.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowRelatedIn(iptablesContext *ctx,
                                    virSocketAddr *netaddr,
                                    unsigned int prefix,
                                    const char *iface,
                                    const char *physdev)
{
    return iptablesForwardAllowRelatedIn(ctx, netaddr, prefix, iface, physdev, REMOVE);
}

/* Allow all traffic destined to the bridge, with a valid network address
 */
static int
iptablesForwardAllowIn(iptablesContext *ctx,
                       virSocketAddr *netaddr,
                       unsigned int prefix,
                       const char *iface,
                       const char *physdev,
                       int action)
{
    int ret;
    char *networkstr;

    if (!(networkstr = iptablesFormatNetwork(netaddr, prefix)))
        return -1;

    if (physdev && physdev[0]) {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--destination", networkstr,
                                    "--in-interface", physdev,
                                    "--out-interface", iface,
                                    "--jump", "ACCEPT",
                                    NULL);
    } else {
        ret = iptablesAddRemoveRule(ctx->forward_filter,
                                    VIR_SOCKET_ADDR_FAMILY(netaddr),
                                    action,
                                    "--destination", networkstr,
                                    "--out-interface", iface,
                                    "--jump", "ACCEPT",
                                    NULL);
    }
    VIR_FREE(networkstr);
    return ret;
}

/**
 * iptablesAddForwardAllowIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Add rules to the IP table context to allow the traffic for the
 * network @network on @physdev device to be forwarded to
 * interface @iface. This allow the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowIn(iptablesContext *ctx,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowIn(ctx, netaddr, prefix, iface, physdev, ADD);
}

/**
 * iptablesRemoveForwardAllowIn:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @iface: the output interface name
 * @physdev: the physical input device or NULL
 *
 * Remove rules from the IP table context hence forbidding the traffic for
 * network @network on @physdev device to be forwarded to
 * interface @iface. This stops the inbound traffic on a bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowIn(iptablesContext *ctx,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowIn(ctx, netaddr, prefix, iface, physdev, REMOVE);
}


/* Allow all traffic between guests on the same bridge,
 * with a valid network address
 */
static int
iptablesForwardAllowCross(iptablesContext *ctx,
                          int family,
                          const char *iface,
                          int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 family,
                                 action,
                                 "--in-interface", iface,
                                 "--out-interface", iface,
                                 "--jump", "ACCEPT",
                                 NULL);
}

/**
 * iptablesAddForwardAllowCross:
 * @ctx: pointer to the IP table context
 * @iface: the input/output interface name
 *
 * Add rules to the IP table context to allow traffic to cross that
 * interface. It allows all traffic between guests on the same bridge
 * represented by that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardAllowCross(iptablesContext *ctx,
                             int family,
                             const char *iface)
{
    return iptablesForwardAllowCross(ctx, family, iface, ADD);
}

/**
 * iptablesRemoveForwardAllowCross:
 * @ctx: pointer to the IP table context
 * @iface: the input/output interface name
 *
 * Remove rules to the IP table context to block traffic to cross that
 * interface. It forbids traffic between guests on the same bridge
 * represented by that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardAllowCross(iptablesContext *ctx,
                                int family,
                                const char *iface)
{
    return iptablesForwardAllowCross(ctx, family, iface, REMOVE);
}


/* Drop all traffic trying to forward from the bridge.
 * ie the bridge is the in interface
 */
static int
iptablesForwardRejectOut(iptablesContext *ctx,
                         int family,
                         const char *iface,
                         int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 family,
                                 action,
                                 "--in-interface", iface,
                                 "--jump", "REJECT",
                                 NULL);
}

/**
 * iptablesAddForwardRejectOut:
 * @ctx: pointer to the IP table context
 * @iface: the output interface name
 *
 * Add rules to the IP table context to forbid all traffic to that
 * interface. It forbids forwarding from the bridge to that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardRejectOut(iptablesContext *ctx,
                            int family,
                            const char *iface)
{
    return iptablesForwardRejectOut(ctx, family, iface, ADD);
}

/**
 * iptablesRemoveForwardRejectOut:
 * @ctx: pointer to the IP table context
 * @iface: the output interface name
 *
 * Remove rules from the IP table context forbidding all traffic to that
 * interface. It reallow forwarding from the bridge to that interface.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardRejectOut(iptablesContext *ctx,
                               int family,
                               const char *iface)
{
    return iptablesForwardRejectOut(ctx, family, iface, REMOVE);
}




/* Drop all traffic trying to forward to the bridge.
 * ie the bridge is the out interface
 */
static int
iptablesForwardRejectIn(iptablesContext *ctx,
                        int family,
                        const char *iface,
                        int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
                                 family,
                                 action,
                                 "--out-interface", iface,
                                 "--jump", "REJECT",
                                 NULL);
}

/**
 * iptablesAddForwardRejectIn:
 * @ctx: pointer to the IP table context
 * @iface: the input interface name
 *
 * Add rules to the IP table context to forbid all traffic from that
 * interface. It forbids forwarding from that interface to the bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardRejectIn(iptablesContext *ctx,
                           int family,
                           const char *iface)
{
    return iptablesForwardRejectIn(ctx, family, iface, ADD);
}

/**
 * iptablesRemoveForwardRejectIn:
 * @ctx: pointer to the IP table context
 * @iface: the input interface name
 *
 * Remove rules from the IP table context forbidding all traffic from that
 * interface. It allows forwarding from that interface to the bridge.
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardRejectIn(iptablesContext *ctx,
                              int family,
                              const char *iface)
{
    return iptablesForwardRejectIn(ctx, family, iface, REMOVE);
}


/* Masquerade all traffic coming from the network associated
 * with the bridge
 */
static int
iptablesForwardMasquerade(iptablesContext *ctx,
                          virSocketAddr *netaddr,
                          unsigned int prefix,
                          const char *physdev,
                          const char *protocol,
                          int action)
{
    int ret;
    char *networkstr;

    if (!(networkstr = iptablesFormatNetwork(netaddr, prefix)))
        return -1;

    if (!VIR_SOCKET_ADDR_IS_FAMILY(netaddr, AF_INET)) {
        /* Higher level code *should* guaranteee it's impossible to get here. */
        iptablesError(VIR_ERR_INTERNAL_ERROR,
                      _("Attempted to NAT '%s'. NAT is only supported for IPv4."),
                      networkstr);
        VIR_FREE(networkstr);
        return -1;
    }

    if (protocol && protocol[0]) {
        if (physdev && physdev[0]) {
            ret = iptablesAddRemoveRule(ctx->nat_postrouting,
                                        AF_INET,
                                        action,
                                        "--source", networkstr,
                                        "-p", protocol,
                                        "!", "--destination", networkstr,
                                        "--out-interface", physdev,
                                        "--jump", "MASQUERADE",
                                        "--to-ports", "1024-65535",
                                        NULL);
        } else {
            ret = iptablesAddRemoveRule(ctx->nat_postrouting,
                                        AF_INET,
                                        action,
                                        "--source", networkstr,
                                        "-p", protocol,
                                        "!", "--destination", networkstr,
                                        "--jump", "MASQUERADE",
                                        "--to-ports", "1024-65535",
                                        NULL);
        }
    } else {
        if (physdev && physdev[0]) {
            ret = iptablesAddRemoveRule(ctx->nat_postrouting,
                                        AF_INET,
                                        action,
                                        "--source", networkstr,
                                        "!", "--destination", networkstr,
                                        "--out-interface", physdev,
                                        "--jump", "MASQUERADE",
                                        NULL);
        } else {
            ret = iptablesAddRemoveRule(ctx->nat_postrouting,
                                        AF_INET,
                                        action,
                                        "--source", networkstr,
                                        "!", "--destination", networkstr,
                                        "--jump", "MASQUERADE",
                                        NULL);
        }
    }
    VIR_FREE(networkstr);
    return ret;
}

/**
 * iptablesAddForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 * @protocol: the network protocol or NULL
 *
 * Add rules to the IP table context to allow masquerading
 * network @network on @physdev. This allow the bridge to
 * masquerade for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardMasquerade(iptablesContext *ctx,
                             virSocketAddr *netaddr,
                             unsigned int prefix,
                             const char *physdev,
                             const char *protocol)
{
    return iptablesForwardMasquerade(ctx, netaddr, prefix, physdev, protocol, ADD);
}

/**
 * iptablesRemoveForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 * @protocol: the network protocol or NULL
 *
 * Remove rules from the IP table context to stop masquerading
 * network @network on @physdev. This stops the bridge from
 * masquerading for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardMasquerade(iptablesContext *ctx,
                                virSocketAddr *netaddr,
                                unsigned int prefix,
                                const char *physdev,
                                const char *protocol)
{
    return iptablesForwardMasquerade(ctx, netaddr, prefix, physdev, protocol, REMOVE);
}


static int
iptablesOutputFixUdpChecksum(iptablesContext *ctx,
                             const char *iface,
                             int port,
                             int action)
{
    char portstr[32];

    snprintf(portstr, sizeof(portstr), "%d", port);
    portstr[sizeof(portstr) - 1] = '\0';

    return iptablesAddRemoveRule(ctx->mangle_postrouting,
                                 AF_INET,
                                 action,
                                 "--out-interface", iface,
                                 "--protocol", "udp",
                                 "--destination-port", portstr,
                                 "--jump", "CHECKSUM", "--checksum-fill",
                                 NULL);
}

/**
 * iptablesAddOutputFixUdpChecksum:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port to match
 *
 * Add a rule to the mangle table's POSTROUTING chain that fixes up the
 * checksum of packets with the given destination @port.
 * the given @iface interface for TCP packets.
 *
 * Returns 0 in case of success or an error code in case of error.
 * (NB: if the system's iptables does not support checksum mangling,
 * this will return an error, which should be ignored.)
 */

int
iptablesAddOutputFixUdpChecksum(iptablesContext *ctx,
                                const char *iface,
                                int port)
{
    return iptablesOutputFixUdpChecksum(ctx, iface, port, ADD);
}

/**
 * iptablesRemoveOutputFixUdpChecksum:
 * @ctx: pointer to the IP table context
 * @iface: the interface name
 * @port: the UDP port of the rule to remove
 *
 * Removes the checksum fixup rule that was previous added with
 * iptablesAddOutputFixUdpChecksum.
 *
 * Returns 0 in case of success or an error code in case of error
 * (again, if iptables doesn't support checksum fixup, this will
 * return an error, which should be ignored)
 */
int
iptablesRemoveOutputFixUdpChecksum(iptablesContext *ctx,
                                   const char *iface,
                                   int port)
{
    return iptablesOutputFixUdpChecksum(ctx, iface, port, REMOVE);
}
