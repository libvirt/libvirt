/*
 * Copyright (C) 2007-2010 Red Hat, Inc.
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
#include "util.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"

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
iptablesAddRemoveRule(iptRules *rules, int action, const char *arg, ...)
{
    va_list args;
    int retval = ENOMEM;
    const char **argv;
    const char *s;
    int n;

    n = 1 + /* /sbin/iptables  */
        2 + /*   --table foo   */
        2 + /*   --insert bar  */
        1;  /*   arg           */

    va_start(args, arg);
    while (va_arg(args, const char *))
        n++;

    va_end(args);

    if (VIR_ALLOC_N(argv, n + 1) < 0)
        goto error;

    n = 0;

    if (!(argv[n++] = strdup(IPTABLES_PATH)))
        goto error;

    if (!(argv[n++] = strdup("--table")))
        goto error;

    if (!(argv[n++] = strdup(rules->table)))
        goto error;

    if (!(argv[n++] = strdup(action == ADD ? "--insert" : "--delete")))
        goto error;

    if (!(argv[n++] = strdup(rules->chain)))
        goto error;

    if (!(argv[n++] = strdup(arg)))
        goto error;

    va_start(args, arg);

    while ((s = va_arg(args, const char *))) {
        if (!(argv[n++] = strdup(s))) {
            va_end(args);
            goto error;
        }
    }

    va_end(args);

    if (virRun(argv, NULL) < 0) {
        retval = errno;
        goto error;
    }

    retval = 0;

 error:
    if (argv) {
        n = 0;
        while (argv[n])
            VIR_FREE(argv[n++]);
        VIR_FREE(argv);
    }

    return retval;
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
    VIR_FREE(ctx);
}

static int
iptablesInput(iptablesContext *ctx,
              const char *iface,
              int port,
              int action,
              int tcp)
{
    char portstr[32];

    snprintf(portstr, sizeof(portstr), "%d", port);
    portstr[sizeof(portstr) - 1] = '\0';

    return iptablesAddRemoveRule(ctx->input_filter,
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
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 1);
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
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 1);
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
                    const char *iface,
                    int port)
{
    return iptablesInput(ctx, iface, port, ADD, 0);
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
                       const char *iface,
                       int port)
{
    return iptablesInput(ctx, iface, port, REMOVE, 0);
}


/* Allow all traffic coming from the bridge, with a valid network address
 * to proceed to WAN
 */
static int
iptablesForwardAllowOut(iptablesContext *ctx,
                         const char *network,
                         const char *iface,
                         const char *physdev,
                         int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--source", network,
                                     "--in-interface", iface,
                                     "--out-interface", physdev,
                                     "--jump", "ACCEPT",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--source", network,
                                     "--in-interface", iface,
                                     "--jump", "ACCEPT",
                                     NULL);
    }
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
                            const char *network,
                            const char *iface,
                            const char *physdev)
{
    return iptablesForwardAllowOut(ctx, network, iface, physdev, ADD);
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
                               const char *network,
                               const char *iface,
                               const char *physdev)
{
    return iptablesForwardAllowOut(ctx, network, iface, physdev, REMOVE);
}


/* Allow all traffic destined to the bridge, with a valid network address
 * and associated with an existing connection
 */
static int
iptablesForwardAllowRelatedIn(iptablesContext *ctx,
                       const char *network,
                       const char *iface,
                       const char *physdev,
                       int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--in-interface", physdev,
                                     "--out-interface", iface,
                                     "--match", "state",
                                     "--state", "ESTABLISHED,RELATED",
                                     "--jump", "ACCEPT",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--out-interface", iface,
                                     "--match", "state",
                                     "--state", "ESTABLISHED,RELATED",
                                     "--jump", "ACCEPT",
                                     NULL);
    }
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
                          const char *network,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowRelatedIn(ctx, network, iface, physdev, ADD);
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
                             const char *network,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowRelatedIn(ctx, network, iface, physdev, REMOVE);
}

/* Allow all traffic destined to the bridge, with a valid network address
 */
static int
iptablesForwardAllowIn(iptablesContext *ctx,
                       const char *network,
                       const char *iface,
                       const char *physdev,
                       int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--in-interface", physdev,
                                     "--out-interface", iface,
                                     "--jump", "ACCEPT",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->forward_filter,
                                     action,
                                     "--destination", network,
                                     "--out-interface", iface,
                                     "--jump", "ACCEPT",
                                     NULL);
    }
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
                          const char *network,
                          const char *iface,
                          const char *physdev)
{
    return iptablesForwardAllowIn(ctx, network, iface, physdev, ADD);
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
                             const char *network,
                             const char *iface,
                             const char *physdev)
{
    return iptablesForwardAllowIn(ctx, network, iface, physdev, REMOVE);
}


/* Allow all traffic between guests on the same bridge,
 * with a valid network address
 */
static int
iptablesForwardAllowCross(iptablesContext *ctx,
                          const char *iface,
                          int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
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
                             const char *iface) {
    return iptablesForwardAllowCross(ctx, iface, ADD);
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
                                const char *iface) {
    return iptablesForwardAllowCross(ctx, iface, REMOVE);
}


/* Drop all traffic trying to forward from the bridge.
 * ie the bridge is the in interface
 */
static int
iptablesForwardRejectOut(iptablesContext *ctx,
                         const char *iface,
                         int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
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
                            const char *iface)
{
    return iptablesForwardRejectOut(ctx, iface, ADD);
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
                               const char *iface)
{
    return iptablesForwardRejectOut(ctx, iface, REMOVE);
}




/* Drop all traffic trying to forward to the bridge.
 * ie the bridge is the out interface
 */
static int
iptablesForwardRejectIn(iptablesContext *ctx,
                        const char *iface,
                        int action)
{
    return iptablesAddRemoveRule(ctx->forward_filter,
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
                           const char *iface)
{
    return iptablesForwardRejectIn(ctx, iface, ADD);
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
                              const char *iface)
{
    return iptablesForwardRejectIn(ctx, iface, REMOVE);
}


/* Masquerade all traffic coming from the network associated
 * with the bridge
 */
static int
iptablesForwardMasquerade(iptablesContext *ctx,
                       const char *network,
                       const char *physdev,
                       int action)
{
    if (physdev && physdev[0]) {
        return iptablesAddRemoveRule(ctx->nat_postrouting,
                                     action,
                                     "--source", network,
                                     "!", "--destination", network,
                                     "--out-interface", physdev,
                                     "--jump", "MASQUERADE",
                                     NULL);
    } else {
        return iptablesAddRemoveRule(ctx->nat_postrouting,
                                     action,
                                     "--source", network,
                                     "!", "--destination", network,
                                     "--jump", "MASQUERADE",
                                     NULL);
    }
}

/**
 * iptablesAddForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 *
 * Add rules to the IP table context to allow masquerading
 * network @network on @physdev. This allow the bridge to
 * masquerade for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesAddForwardMasquerade(iptablesContext *ctx,
                             const char *network,
                             const char *physdev)
{
    return iptablesForwardMasquerade(ctx, network, physdev, ADD);
}

/**
 * iptablesRemoveForwardMasquerade:
 * @ctx: pointer to the IP table context
 * @network: the source network name
 * @physdev: the physical input device or NULL
 *
 * Remove rules from the IP table context to stop masquerading
 * network @network on @physdev. This stops the bridge from
 * masquerading for that network (on @physdev).
 *
 * Returns 0 in case of success or an error code otherwise
 */
int
iptablesRemoveForwardMasquerade(iptablesContext *ctx,
                                const char *network,
                                const char *physdev)
{
    return iptablesForwardMasquerade(ctx, network, physdev, REMOVE);
}
